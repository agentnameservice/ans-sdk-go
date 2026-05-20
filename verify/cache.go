package verify

import (
	"context"
	"sync"
	"time"

	"github.com/godaddy/ans-sdk-go/models"
)

// RefreshFunc is called during background refresh for each expiring entry.
// It receives the FQDN key and should return a fresh badge, or an error.
type RefreshFunc func(ctx context.Context, fqdn string) (*models.Badge, error)

// Default cache configuration values.
const (
	defaultCacheMaxEntries     = 1000
	defaultCacheTTLMinutes     = 5
	defaultCacheRefreshMinutes = 1
)

// CacheConfig holds configuration for the badge cache.
type CacheConfig struct {
	// MaxEntries is the maximum number of entries in the cache.
	MaxEntries int
	// DefaultTTL is the default time-to-live for cache entries.
	DefaultTTL time.Duration
	// RefreshThreshold is how close to expiration before refreshing.
	RefreshThreshold time.Duration
	// StaleRetention is how long expired entries are kept for fail-open-with-cache.
	// Cleanup will not delete entries within this window past expiration.
	StaleRetention time.Duration
}

// DefaultCacheConfig returns the default cache configuration.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		MaxEntries:       defaultCacheMaxEntries,
		DefaultTTL:       defaultCacheTTLMinutes * time.Minute,
		RefreshThreshold: defaultCacheRefreshMinutes * time.Minute,
		StaleRetention:   defaultMaxStalenessMinutes * time.Minute,
	}
}

// CachedBadge holds a cached badge with metadata.
type CachedBadge struct {
	// Badge is the cached badge.
	Badge *models.Badge
	// FetchedAt is when the badge was fetched.
	FetchedAt time.Time
	// ExpiresAt is when the cache entry expires.
	ExpiresAt time.Time
	// Source records which DNS record (primary _ans-badge or legacy
	// _ra-badge) supplied this badge at fetch time.
	Source BadgeRecordSource
	// PrimaryError is the error returned by the primary _ans-badge lookup
	// at fetch time, when fallback to _ra-badge was triggered by a
	// transient failure. Nil when the cached badge came from _ans-badge or
	// when the primary was simply absent (NXDOMAIN/NODATA).
	PrimaryError error
}

// IsExpired returns true if the cache entry has expired.
func (c *CachedBadge) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// ShouldRefresh returns true if the entry should be refreshed.
func (c *CachedBadge) ShouldRefresh(threshold time.Duration) bool {
	return time.Now().Add(threshold).After(c.ExpiresAt)
}

// cacheEntry is an internal cache entry with expiration.
type cacheEntry struct {
	badge     *CachedBadge
	expiresAt time.Time
}

// BadgeCache is a thread-safe cache for badges.
type BadgeCache struct {
	mu        sync.RWMutex
	config    CacheConfig
	byFqdn    map[string]*cacheEntry
	byFqdnVer map[string]*cacheEntry
}

// NewBadgeCache creates a new badge cache with the given configuration.
func NewBadgeCache(config CacheConfig) *BadgeCache {
	return &BadgeCache{
		config:    config,
		byFqdn:    make(map[string]*cacheEntry),
		byFqdnVer: make(map[string]*cacheEntry),
	}
}

// NewBadgeCacheWithDefaults creates a new badge cache with default configuration.
func NewBadgeCacheWithDefaults() *BadgeCache {
	return NewBadgeCache(DefaultCacheConfig())
}

// fqdnKey generates a cache key for an FQDN.
func fqdnKey(fqdn models.Fqdn) string {
	return fqdn.String()
}

// fqdnVersionKey generates a cache key for an FQDN and version.
func fqdnVersionKey(fqdn models.Fqdn, version models.Version) string {
	return fqdn.String() + ":" + version.String()
}

// GetByFqdn retrieves a cached badge by FQDN.
func (c *BadgeCache) GetByFqdn(fqdn models.Fqdn) (*CachedBadge, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.byFqdn[fqdnKey(fqdn)]
	if !ok {
		return nil, false
	}

	// Check expiration
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.badge, true
}

// GetByFqdnVersion retrieves a cached badge by FQDN and version.
func (c *BadgeCache) GetByFqdnVersion(fqdn models.Fqdn, version models.Version) (*CachedBadge, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.byFqdnVer[fqdnVersionKey(fqdn, version)]
	if !ok {
		return nil, false
	}

	// Check expiration
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.badge, true
}

// Insert adds a badge to the cache by FQDN. The cached entry records no
// provenance; use InsertWithProvenance to also persist the resolved
// BadgeRecordSource and any primary-lookup error so cache hits can re-emit
// fallback warnings.
func (c *BadgeCache) Insert(fqdn models.Fqdn, badge *models.Badge) {
	c.InsertWithProvenance(fqdn, badge, BadgeRecordSourceAnsBadge, nil)
}

// InsertWithProvenance adds a badge to the cache by FQDN, recording the DNS
// source (`_ans-badge` vs `_ra-badge`) and any primary-lookup error captured
// at fetch time. Callers can later use those fields to re-emit a
// fallback-was-used warning on cache hits.
func (c *BadgeCache) InsertWithProvenance(fqdn models.Fqdn, badge *models.Badge, source BadgeRecordSource, primaryErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	expiresAt := now.Add(c.config.DefaultTTL)

	cached := &CachedBadge{
		Badge:        badge,
		FetchedAt:    now,
		ExpiresAt:    expiresAt,
		Source:       source,
		PrimaryError: primaryErr,
	}

	c.byFqdn[fqdnKey(fqdn)] = &cacheEntry{
		badge:     cached,
		expiresAt: expiresAt,
	}

	// Cleanup if over max entries
	c.cleanupLocked()
}

// InsertForVersion adds a badge to the cache by FQDN and version. See
// InsertForVersionWithProvenance for the variant that also persists DNS
// source and primary-lookup error.
func (c *BadgeCache) InsertForVersion(fqdn models.Fqdn, version models.Version, badge *models.Badge) {
	c.InsertForVersionWithProvenance(fqdn, version, badge, BadgeRecordSourceAnsBadge, nil)
}

// InsertForVersionWithProvenance adds a badge to the cache by FQDN+version,
// recording DNS source and any primary-lookup error.
func (c *BadgeCache) InsertForVersionWithProvenance(fqdn models.Fqdn, version models.Version, badge *models.Badge, source BadgeRecordSource, primaryErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	expiresAt := now.Add(c.config.DefaultTTL)

	cached := &CachedBadge{
		Badge:        badge,
		FetchedAt:    now,
		ExpiresAt:    expiresAt,
		Source:       source,
		PrimaryError: primaryErr,
	}

	c.byFqdnVer[fqdnVersionKey(fqdn, version)] = &cacheEntry{
		badge:     cached,
		expiresAt: expiresAt,
	}

	// Cleanup if over max entries
	c.cleanupLocked()
}

// GetStaleByFqdn retrieves a cached badge by FQDN, even if expired,
// as long as it's within the given maxStaleness window.
func (c *BadgeCache) GetStaleByFqdn(fqdn models.Fqdn, maxStaleness time.Duration) (*CachedBadge, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.byFqdn[fqdnKey(fqdn)]
	if !ok {
		return nil, false
	}

	// Accept if within maxStaleness from when it expired
	if time.Since(entry.expiresAt) > maxStaleness {
		return nil, false
	}

	return entry.badge, true
}

// GetStaleByFqdnVersion retrieves a cached badge by FQDN and version, even if expired,
// as long as it's within the given maxStaleness window.
func (c *BadgeCache) GetStaleByFqdnVersion(fqdn models.Fqdn, version models.Version, maxStaleness time.Duration) (*CachedBadge, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.byFqdnVer[fqdnVersionKey(fqdn, version)]
	if !ok {
		return nil, false
	}

	if time.Since(entry.expiresAt) > maxStaleness {
		return nil, false
	}

	return entry.badge, true
}

// Clear removes all entries from the cache.
func (c *BadgeCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.byFqdn = make(map[string]*cacheEntry)
	c.byFqdnVer = make(map[string]*cacheEntry)
}

// StartBackgroundRefresh spawns a goroutine that periodically refreshes
// cache entries approaching expiration. Stops when ctx is cancelled.
func (c *BadgeCache) StartBackgroundRefresh(ctx context.Context, interval time.Duration, refreshFn RefreshFunc) {
	go c.backgroundRefreshLoop(ctx, interval, refreshFn)
}

// backgroundRefreshLoop runs the background refresh ticker.
func (c *BadgeCache) backgroundRefreshLoop(ctx context.Context, interval time.Duration, refreshFn RefreshFunc) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refreshExpiring(ctx, refreshFn)
		}
	}
}

// refreshExpiring finds entries within RefreshThreshold of expiry and refreshes them.
func (c *BadgeCache) refreshExpiring(ctx context.Context, refreshFn RefreshFunc) {
	c.mu.RLock()
	// Collect keys that need refreshing
	var keysToRefresh []string
	for key, entry := range c.byFqdn {
		if entry.badge.ShouldRefresh(c.config.RefreshThreshold) {
			keysToRefresh = append(keysToRefresh, key)
		}
	}
	c.mu.RUnlock()

	for _, key := range keysToRefresh {
		badge, err := refreshFn(ctx, key)
		if err != nil {
			// Refresh errors don't evict entries — keep the old one
			continue
		}
		fqdn, fqdnErr := models.NewFqdn(key)
		if fqdnErr != nil {
			continue
		}
		c.Insert(fqdn, badge)
	}
}

// cleanupLocked removes entries that are expired beyond the stale retention window.
// Entries within the stale retention window are kept for fail-open-with-cache support.
// Must be called with lock held.
func (c *BadgeCache) cleanupLocked() {
	now := time.Now()
	staleDeadline := now.Add(-c.config.StaleRetention)

	// Clean up entries expired beyond stale retention from byFqdn
	for key, entry := range c.byFqdn {
		if staleDeadline.After(entry.expiresAt) {
			delete(c.byFqdn, key)
		}
	}

	// Clean up entries expired beyond stale retention from byFqdnVer
	for key, entry := range c.byFqdnVer {
		if staleDeadline.After(entry.expiresAt) {
			delete(c.byFqdnVer, key)
		}
	}

	// If still over limit, remove oldest entries
	totalEntries := len(c.byFqdn) + len(c.byFqdnVer)
	if totalEntries > c.config.MaxEntries {
		// Simple approach: just remove some entries
		// A more sophisticated approach would track LRU
		toRemove := totalEntries - c.config.MaxEntries
		removed := 0

		for key := range c.byFqdn {
			if removed >= toRemove {
				break
			}
			delete(c.byFqdn, key)
			removed++
		}

		for key := range c.byFqdnVer {
			if removed >= toRemove {
				break
			}
			delete(c.byFqdnVer, key)
			removed++
		}
	}
}
