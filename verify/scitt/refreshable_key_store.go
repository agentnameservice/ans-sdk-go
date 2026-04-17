package scitt

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Default refresh configuration values.
const (
	DefaultRefreshInterval  = 24 * time.Hour
	DefaultOnDemandCooldown = 5 * time.Minute
)

// RefreshableKeyStore wraps a KeyStore with snapshot-based reads, on-demand
// refresh gated by cooldown, and optional background refresh. It implements
// KeyLookup and is a drop-in replacement for *KeyStore.
type RefreshableKeyStore struct {
	client   Client // nil for static mode (no refresh)
	logger   *slog.Logger
	clock    ClockFunc
	cooldown time.Duration

	mu            sync.RWMutex
	snapshot      *KeyStore
	lastRefreshed *time.Time

	refreshGate sync.Mutex // serializes concurrent on-demand refreshes
}

// RefreshableKeyStoreOption configures a RefreshableKeyStore.
type RefreshableKeyStoreOption func(*RefreshableKeyStore)

// WithCooldown sets the minimum interval between on-demand refreshes.
func WithCooldown(d time.Duration) RefreshableKeyStoreOption {
	return func(r *RefreshableKeyStore) {
		r.cooldown = d
	}
}

// WithRefreshClock sets the clock function for the refreshable key store.
func WithRefreshClock(clock ClockFunc) RefreshableKeyStoreOption {
	return func(r *RefreshableKeyStore) {
		r.clock = clock
	}
}

// WithRefreshLogger sets the logger for refresh operations.
func WithRefreshLogger(logger *slog.Logger) RefreshableKeyStoreOption {
	return func(r *RefreshableKeyStore) {
		r.logger = logger
	}
}

// NewRefreshableKeyStore creates a new RefreshableKeyStore wrapping the given
// initial KeyStore. If client is nil, the store operates in static mode where
// all refresh operations are no-ops.
func NewRefreshableKeyStore(initial *KeyStore, client Client, opts ...RefreshableKeyStoreOption) *RefreshableKeyStore {
	r := &RefreshableKeyStore{
		client:   client,
		clock:    time.Now,
		cooldown: DefaultOnDemandCooldown,
		snapshot: initial,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// CurrentSnapshot returns the current immutable KeyStore snapshot.
func (r *RefreshableKeyStore) CurrentSnapshot() *KeyStore {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshot
}

// Get looks up a trusted key by kid from the current snapshot.
// Implements KeyLookup.
func (r *RefreshableKeyStore) Get(kid [4]byte) (*TrustedKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshot.Get(kid)
}

// Len returns the number of keys in the current snapshot.
func (r *RefreshableKeyStore) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshot.Len()
}

// IsEmpty returns true if the current snapshot has no keys.
func (r *RefreshableKeyStore) IsEmpty() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshot.IsEmpty()
}

// LastRefreshed returns when the last successful refresh occurred, or nil if never.
func (r *RefreshableKeyStore) LastRefreshed() *time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastRefreshed
}

// DoRefresh fetches root keys from the client and merges them into the current
// snapshot. In static mode (client == nil) this is a no-op. Network errors do
// not update lastRefreshed and the existing snapshot is preserved.
func (r *RefreshableKeyStore) DoRefresh(ctx context.Context) error {
	if r.client == nil {
		return nil
	}

	start := r.clock()

	keys, err := r.client.FetchRootKeys(ctx)
	if err != nil {
		if r.logger != nil {
			r.logger.WarnContext(ctx, "key refresh failed",
				"error", err,
				"last_refreshed", r.LastRefreshed(),
			)
		}
		return err
	}

	r.mu.Lock()
	before := r.snapshot.Len()
	merged, result := r.snapshot.MergeFrom(keys)
	r.snapshot = merged
	now := r.clock()
	r.lastRefreshed = &now
	after := r.snapshot.Len()
	r.mu.Unlock()

	if r.logger != nil {
		r.logger.InfoContext(ctx, "key refresh completed",
			"keys_before", before,
			"keys_after", after,
			"added", result.Added,
			"skipped", result.Skipped,
			"skipped_unparseable", result.SkippedUnparseable,
			"skipped_duplicate", result.SkippedDuplicate,
			"collisions", len(result.Collisions),
			"duration_ms", r.clock().Sub(start).Milliseconds(),
		)
		if result.SkippedUnparseable > 0 || len(result.Collisions) > 0 {
			r.logger.WarnContext(ctx, "key refresh encountered anomalies",
				"skipped_unparseable", result.SkippedUnparseable,
				"collisions", len(result.Collisions),
			)
		}
	}

	return nil
}

// RefreshIfCooldownElapsed performs an on-demand refresh only if enough time
// has elapsed since the last refresh. Concurrent callers are serialized by
// refreshGate — only the first caller fetches, others wait and get the
// updated snapshot. Returns true if a refresh was actually performed.
func (r *RefreshableKeyStore) RefreshIfCooldownElapsed(ctx context.Context) (bool, error) {
	if r.client == nil {
		return false, nil
	}

	// Quick check without the gate — avoid blocking if clearly within cooldown.
	r.mu.RLock()
	lr := r.lastRefreshed
	r.mu.RUnlock()

	if lr != nil && r.clock().Sub(*lr) < r.cooldown {
		if r.logger != nil {
			r.logger.DebugContext(ctx, "refresh skipped, within cooldown",
				"cooldown", r.cooldown,
				"last_refreshed", lr,
			)
		}
		return false, nil
	}

	// Serialize concurrent on-demand refreshes.
	r.refreshGate.Lock()
	defer r.refreshGate.Unlock()

	// Re-check after acquiring gate — another goroutine may have refreshed.
	r.mu.RLock()
	lr = r.lastRefreshed
	r.mu.RUnlock()

	if lr != nil && r.clock().Sub(*lr) < r.cooldown {
		return false, nil
	}

	if err := r.DoRefresh(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// StartBackgroundRefresh spawns a goroutine that periodically calls DoRefresh.
// Returns a cancel function to stop the background goroutine.
func (r *RefreshableKeyStore) StartBackgroundRefresh(ctx context.Context, interval time.Duration) context.CancelFunc {
	bgCtx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-bgCtx.Done():
				return
			case <-ticker.C:
				_ = r.DoRefresh(bgCtx)
			}
		}
	}()
	return cancel
}

// StartBackgroundRefreshDefault starts background refresh with DefaultRefreshInterval (24h).
func (r *RefreshableKeyStore) StartBackgroundRefreshDefault(ctx context.Context) context.CancelFunc {
	return r.StartBackgroundRefresh(ctx, DefaultRefreshInterval)
}
