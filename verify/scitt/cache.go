package scitt

import (
	"sync"
	"time"
)

// ClockFunc returns the current time. Default: time.Now. Override for deterministic tests.
type ClockFunc func() time.Time

// Default cache configuration values.
const (
	defaultReceiptTTL      = 24 * time.Hour
	defaultCacheMaxEntries = 1000
)

// --- ReceiptCache ---

type receiptEntry struct {
	receipt   *VerifiedReceipt
	expiresAt time.Time
}

// ReceiptCache is a thread-safe cache for verified SCITT receipts, keyed by agent ID.
// Eviction is FIFO on insertion order: the oldest inserted entries are dropped first
// when maxEntries is exceeded.
type ReceiptCache struct {
	mu          sync.RWMutex
	entries     map[string]*receiptEntry
	insertOrder []string // FIFO queue of agent IDs in insertion order
	ttl         time.Duration
	maxEntries  int
	clock       ClockFunc
}

// NewReceiptCache creates a new ReceiptCache with the given TTL, max entries, and clock function.
func NewReceiptCache(ttl time.Duration, maxEntries int, clock ClockFunc) *ReceiptCache {
	return &ReceiptCache{
		entries:    make(map[string]*receiptEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
		clock:      clock,
	}
}

// NewReceiptCacheWithDefaults creates a new ReceiptCache with default settings (24h TTL, 1000 entries).
func NewReceiptCacheWithDefaults() *ReceiptCache {
	return NewReceiptCache(defaultReceiptTTL, defaultCacheMaxEntries, time.Now)
}

// Get retrieves a cached receipt by agent ID. Returns nil, false if missing or expired.
func (c *ReceiptCache) Get(agentID string) (*VerifiedReceipt, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[agentID]
	if !ok {
		return nil, false
	}

	if c.clock().After(entry.expiresAt) {
		return nil, false
	}

	return entry.receipt, true
}

// Insert adds a receipt to the cache. Overwrites any existing entry for the same agent ID.
// Evicts entries in FIFO order if the cache exceeds maxEntries.
func (c *ReceiptCache) Insert(agentID string, receipt *VerifiedReceipt) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, existed := c.entries[agentID]; !existed {
		c.insertOrder = append(c.insertOrder, agentID)
	}
	c.entries[agentID] = &receiptEntry{
		receipt:   receipt,
		expiresAt: c.clock().Add(c.ttl),
	}

	c.evictLocked()
}

// Invalidate removes a specific entry from the cache.
func (c *ReceiptCache) Invalidate(agentID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.entries[agentID]; ok {
		delete(c.entries, agentID)
		c.removeFromOrderLocked(agentID)
	}
}

// Len returns the number of entries in the cache.
func (c *ReceiptCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}

// evictLocked removes the oldest entries (FIFO) if the cache exceeds maxEntries.
// Must be called with the write lock held.
func (c *ReceiptCache) evictLocked() {
	if len(c.entries) <= c.maxEntries {
		return
	}

	toRemove := len(c.entries) - c.maxEntries
	for i := 0; i < toRemove && len(c.insertOrder) > 0; i++ {
		oldest := c.insertOrder[0]
		c.insertOrder = c.insertOrder[1:]
		delete(c.entries, oldest)
	}
}

// removeFromOrderLocked removes an agent ID from the insertOrder slice.
// Must be called with the write lock held.
func (c *ReceiptCache) removeFromOrderLocked(agentID string) {
	for i, id := range c.insertOrder {
		if id == agentID {
			c.insertOrder = append(c.insertOrder[:i], c.insertOrder[i+1:]...)
			return
		}
	}
}

// --- StatusTokenCache ---

type tokenEntry struct {
	token     *VerifiedStatusToken
	expiresAt int64
}

// StatusTokenCache is a thread-safe cache for verified status tokens, keyed by agent ID.
// Expiration is per-entry, derived from the token's Payload.Exp claim.
// Eviction is FIFO on insertion order: the oldest inserted entries are dropped first
// when maxEntries is exceeded.
type StatusTokenCache struct {
	mu          sync.RWMutex
	entries     map[string]*tokenEntry
	insertOrder []string // FIFO queue of agent IDs in insertion order
	maxEntries  int
	clock       ClockFunc
}

// NewStatusTokenCache creates a new StatusTokenCache with the given max entries and clock function.
func NewStatusTokenCache(maxEntries int, clock ClockFunc) *StatusTokenCache {
	return &StatusTokenCache{
		entries:    make(map[string]*tokenEntry),
		maxEntries: maxEntries,
		clock:      clock,
	}
}

// NewStatusTokenCacheWithDefaults creates a new StatusTokenCache with default settings (1000 entries).
func NewStatusTokenCacheWithDefaults() *StatusTokenCache {
	return NewStatusTokenCache(defaultCacheMaxEntries, time.Now)
}

// Get retrieves a cached status token by agent ID. Returns nil, false if missing or expired.
func (c *StatusTokenCache) Get(agentID string) (*VerifiedStatusToken, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[agentID]
	if !ok {
		return nil, false
	}

	if c.clock().Unix() > entry.expiresAt {
		return nil, false
	}

	return entry.token, true
}

// Insert adds a status token to the cache. Expiration is derived from token.Payload.Exp.
// Overwrites any existing entry for the same agent ID.
// Evicts entries in FIFO order if the cache exceeds maxEntries.
func (c *StatusTokenCache) Insert(agentID string, token *VerifiedStatusToken) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, existed := c.entries[agentID]; !existed {
		c.insertOrder = append(c.insertOrder, agentID)
	}
	c.entries[agentID] = &tokenEntry{
		token:     token,
		expiresAt: token.Payload.Exp,
	}

	c.evictLocked()
}

// Invalidate removes a specific entry from the cache.
func (c *StatusTokenCache) Invalidate(agentID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.entries[agentID]; ok {
		delete(c.entries, agentID)
		c.removeFromOrderLocked(agentID)
	}
}

// Len returns the number of entries in the cache.
func (c *StatusTokenCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}

// evictLocked removes the oldest entries (FIFO) if the cache exceeds maxEntries.
// Must be called with the write lock held.
func (c *StatusTokenCache) evictLocked() {
	if len(c.entries) <= c.maxEntries {
		return
	}

	toRemove := len(c.entries) - c.maxEntries
	for i := 0; i < toRemove && len(c.insertOrder) > 0; i++ {
		oldest := c.insertOrder[0]
		c.insertOrder = c.insertOrder[1:]
		delete(c.entries, oldest)
	}
}

// removeFromOrderLocked removes an agent ID from the insertOrder slice.
// Must be called with the write lock held.
func (c *StatusTokenCache) removeFromOrderLocked(agentID string) {
	for i, id := range c.insertOrder {
		if id == agentID {
			c.insertOrder = append(c.insertOrder[:i], c.insertOrder[i+1:]...)
			return
		}
	}
}
