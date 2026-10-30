package pop

import (
	"context"
	"sync"
	"time"
)

// Replay-cache defaults. The cache TTL (an entry's lifetime) is the proof's
// iat-expiry, which the verifier sets to iat + the freshness window; that
// window MUST be ≤ the cache's effective retention or a late-but-in-window
// replay could find its jti already gone. The verifier passes exp =
// iat + popSkew, so as long as the cache keeps entries until exp, the invariant
// holds (see VerifyProof).
const (
	// DefaultReplayMaxEntries bounds the in-memory cache's entry count. Keys are
	// fixed-width (commitReplay stores a base64url SHA-256 digest, 43 bytes), so
	// the byte bound is maxEntries × ~43 B plus map overhead — roughly 10 MB at
	// this default.
	//
	// Capacity must cover the in-flight window, because every accepted proof
	// occupies a slot until it expires:
	//
	//	maxEntries ≥ peakRequestsPerSecond × (popSkew + replayGrace) × headroom
	//
	// At the defaults that is 100000 / 125s ≈ 800 req/s sustained. Above that
	// the cache fills with still-live entries and fails closed for EVERY caller
	// (see CheckAndStore) — size this deliberately for your peak rate.
	DefaultReplayMaxEntries = 100_000
	// replayJanitorInterval is how often expired entries are swept.
	replayJanitorInterval = time.Minute
	// bucketWidth groups entries by expiry generation. Eviction drops whole
	// generations, so its cost is proportional to the entries actually expiring
	// rather than to the number held — the request path never scans live entries.
	//
	// A generation is dropped only once EVERY expiry it could contain has passed,
	// so an entry may be retained up to bucketWidth beyond its own expiry. That
	// direction of error is safe: over-retention can only reject a replay that
	// would otherwise have been accepted. Under-retention would reopen replay,
	// which is why buckets are never dropped on a partial comparison.
	bucketWidth = 5 * time.Second
)

// ReplayCache records DPoP proof identifiers to reject reuse.
//
// CheckAndStore MUST be atomic: it reports whether a key was already present
// and, only if not, records it — a separate check-then-store pair would race
// two concurrent replays of the same proof past the guard, defeating the whole
// point.
type ReplayCache interface {
	// CheckAndStore reports seen=true if key is already recorded and still
	// within its expiry (a replay). If seen=false it atomically records key
	// until exp. A non-nil error means the cache could not record key (e.g. it
	// is at capacity); callers MUST treat that as a verification failure and
	// reject the proof (fail closed).
	//
	// key is a fixed-width digest of the proof's jti, never the raw claim, so an
	// implementation's memory is bounded by entryCount × keySize regardless of
	// what a caller put in the proof.
	CheckAndStore(key string, exp time.Time) (seen bool, err error)
}

// MemoryReplayCache is an in-process, bounded ReplayCache. It evicts expired
// entries lazily and on a janitor tick, and fails closed when full of still-live
// entries rather than evicting a valid jti (which would reopen replay).
//
// It blocks replay only within a single process. Multi-instance deployments
// (the common case behind a load balancer) need a shared backend implementing
// ReplayCache; the in-memory cache alone leaves cross-instance replay open
// within the freshness window.
type MemoryReplayCache struct {
	mu sync.Mutex
	// index answers "have I seen this key" in O(1).
	index map[string]time.Time
	// buckets group keys by expiry generation so eviction is O(entries expiring)
	// instead of O(entries held). Both structures are kept consistent: a key is
	// in exactly the bucket its indexed expiry maps to.
	buckets         map[int64]map[string]struct{}
	maxEntries      int
	now             func() time.Time
	janitorInterval time.Duration
	stop            chan struct{}
	stopOnce        sync.Once
}

// ReplayCacheOption configures a MemoryReplayCache.
type ReplayCacheOption func(*MemoryReplayCache)

// NewMemoryReplayCache builds a bounded cache and starts a janitor that sweeps
// expired entries until ctx is canceled or Close is called. maxEntries ≤ 0
// uses DefaultReplayMaxEntries.
func NewMemoryReplayCache(ctx context.Context, maxEntries int, opts ...ReplayCacheOption) *MemoryReplayCache {
	if maxEntries <= 0 {
		maxEntries = DefaultReplayMaxEntries
	}
	c := &MemoryReplayCache{
		index:           make(map[string]time.Time),
		buckets:         make(map[int64]map[string]struct{}),
		maxEntries:      maxEntries,
		now:             time.Now,
		janitorInterval: replayJanitorInterval,
		stop:            make(chan struct{}),
	}
	for _, o := range opts {
		o(c)
	}
	go c.janitor(ctx)
	return c
}

// withReplayClock injects a clock for deterministic tests.
func withReplayClock(now func() time.Time) ReplayCacheOption {
	return func(c *MemoryReplayCache) { c.now = now }
}

// withJanitorInterval overrides the sweep interval (tests only).
func withJanitorInterval(d time.Duration) ReplayCacheOption {
	return func(c *MemoryReplayCache) {
		if d > 0 {
			c.janitorInterval = d
		}
	}
}

// Len returns the number of entries currently held. Compare it to Cap to alarm
// on saturation BEFORE the cache starts failing closed: at capacity every caller
// is rejected, not just whoever filled it.
func (c *MemoryReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.index)
}

// Cap returns the configured entry ceiling.
func (c *MemoryReplayCache) Cap() int { return c.maxEntries }

// CheckAndStore implements ReplayCache.
func (c *MemoryReplayCache) CheckAndStore(key string, exp time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.evictLocked(now)

	if existing, ok := c.index[key]; ok {
		if existing.After(now) {
			return true, nil // live entry → replay
		}
		// Expired but its generation has not fully passed: drop it so the entry
		// below lands in the right bucket rather than orphaning the old one.
		c.removeLocked(key, existing)
	}

	if len(c.index) >= c.maxEntries {
		// Full of still-live entries: reject rather than evict a valid key.
		return false, newErr(ErrReplayCacheFull, "replay cache at capacity; cannot record proof id")
	}
	c.addLocked(key, exp)
	return false, nil
}

// bucketOf maps an expiry to its generation.
func bucketOf(t time.Time) int64 { return t.UnixNano() / int64(bucketWidth) }

// addLocked records key in both structures. Caller holds mu.
func (c *MemoryReplayCache) addLocked(key string, exp time.Time) {
	c.index[key] = exp
	id := bucketOf(exp)
	b, ok := c.buckets[id]
	if !ok {
		b = make(map[string]struct{})
		c.buckets[id] = b
	}
	b[key] = struct{}{}
}

// removeLocked deletes key from both structures. Caller holds mu.
func (c *MemoryReplayCache) removeLocked(key string, exp time.Time) {
	delete(c.index, key)
	id := bucketOf(exp)
	if b, ok := c.buckets[id]; ok {
		delete(b, key)
		if len(b) == 0 {
			delete(c.buckets, id)
		}
	}
}

// evictLocked drops every generation whose entries have all expired. It iterates
// generations, not entries, so its cost is bounded by the number of live buckets
// (retention / bucketWidth) plus the entries actually being freed. Caller holds mu.
func (c *MemoryReplayCache) evictLocked(now time.Time) {
	nowNanos := now.UnixNano()
	for id, keys := range c.buckets {
		// Generation id covers expiries [id*w, (id+1)*w). Drop it only when even
		// its latest possible expiry has passed.
		if (id+1)*int64(bucketWidth) > nowNanos {
			continue
		}
		for key := range keys {
			// Only delete an index entry this generation still owns; a key
			// re-recorded into a newer generation must survive.
			if exp, ok := c.index[key]; ok && bucketOf(exp) == id {
				delete(c.index, key)
			}
		}
		delete(c.buckets, id)
	}
}

// Close stops the janitor. Safe to call more than once.
func (c *MemoryReplayCache) Close() {
	c.stopOnce.Do(func() { close(c.stop) })
}

// janitor periodically drops expired generations until ctx is done or Close is
// called, so memory drains when traffic stops.
func (c *MemoryReplayCache) janitor(ctx context.Context) {
	t := time.NewTicker(c.janitorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stop:
			return
		case <-t.C:
			c.mu.Lock()
			c.evictLocked(c.now())
			c.mu.Unlock()
		}
	}
}
