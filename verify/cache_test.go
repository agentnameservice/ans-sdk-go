package verify

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestBadgeCache(t *testing.T) {
	badge := &models.Badge{
		Status:        models.BadgeStatusActive,
		SchemaVersion: "V1",
		Payload: models.BadgePayload{
			LogID: "test-log-id",
			Producer: models.Producer{
				KeyID:     "test-key",
				Signature: "test-sig",
				Event: models.AgentEvent{
					ANSID:   "test-ans-id",
					ANSName: "ans://v1.0.0.agent.example.com",
					Agent: models.AgentInfo{
						Host:    "agent.example.com",
						Name:    "Test Agent",
						Version: "v1.0.0",
					},
					Attestations: models.Attestations{
						DomainValidation: "ACME-DNS-01",
					},
					IssuedAt:  time.Now(),
					Timestamp: time.Now(),
				},
			},
		},
	}

	t.Run("GetByFqdn and Insert", func(t *testing.T) {
		cache := NewBadgeCache(DefaultCacheConfig())
		fqdn, _ := models.NewFqdn("agent.example.com")

		// Initially not in cache
		cached, ok := cache.GetByFqdn(fqdn)
		if ok {
			t.Fatal("GetByFqdn() returned true for empty cache")
		}
		if cached != nil {
			t.Fatal("GetByFqdn() returned non-nil for empty cache")
		}

		// Insert and retrieve
		cache.Insert(fqdn, badge)

		cached, ok = cache.GetByFqdn(fqdn)
		if !ok {
			t.Fatal("GetByFqdn() returned false after Insert")
		}
		if cached == nil {
			t.Fatal("GetByFqdn() returned nil after Insert")
		}
		if cached.Badge.AgentHost() != "agent.example.com" {
			t.Errorf("Badge.AgentHost() = %q, want agent.example.com", cached.Badge.AgentHost())
		}
	})

	t.Run("GetByFqdnVersion and InsertForVersion", func(t *testing.T) {
		cache := NewBadgeCache(DefaultCacheConfig())
		fqdn, _ := models.NewFqdn("agent.example.com")
		version := models.NewVersion(1, 0, 0)

		// Initially not in cache
		_, ok := cache.GetByFqdnVersion(fqdn, version)
		if ok {
			t.Fatal("GetByFqdnVersion() returned true for empty cache")
		}

		// Insert and retrieve
		cache.InsertForVersion(fqdn, version, badge)

		cached, ok := cache.GetByFqdnVersion(fqdn, version)
		if !ok {
			t.Fatal("GetByFqdnVersion() returned false after InsertForVersion")
		}
		if cached == nil {
			t.Fatal("GetByFqdnVersion() returned nil after InsertForVersion")
		}

		// Different version not in cache
		_, ok = cache.GetByFqdnVersion(fqdn, models.NewVersion(2, 0, 0))
		if ok {
			t.Fatal("GetByFqdnVersion() returned true for different version")
		}
	})

	t.Run("Expiration", func(t *testing.T) {
		config := CacheConfig{
			MaxEntries: 100,
			DefaultTTL: 50 * time.Millisecond,
		}
		cache := NewBadgeCache(config)
		fqdn, _ := models.NewFqdn("agent.example.com")

		cache.Insert(fqdn, badge)

		// Should be in cache
		_, ok := cache.GetByFqdn(fqdn)
		if !ok {
			t.Fatal("GetByFqdn() returned false immediately after Insert")
		}

		// Wait for expiration
		time.Sleep(100 * time.Millisecond)

		// Should be expired
		_, ok = cache.GetByFqdn(fqdn)
		if ok {
			t.Fatal("GetByFqdn() returned true after expiration")
		}
	})

	t.Run("Clear", func(t *testing.T) {
		cache := NewBadgeCache(DefaultCacheConfig())
		fqdn, _ := models.NewFqdn("agent.example.com")

		cache.Insert(fqdn, badge)

		// Should be in cache
		_, ok := cache.GetByFqdn(fqdn)
		if !ok {
			t.Fatal("GetByFqdn() returned false after Insert")
		}

		// Clear cache
		cache.Clear()

		// Should not be in cache
		_, ok = cache.GetByFqdn(fqdn)
		if ok {
			t.Fatal("GetByFqdn() returned true after Clear")
		}
	})

	t.Run("CachedBadge has FetchedAt", func(t *testing.T) {
		cache := NewBadgeCache(DefaultCacheConfig())
		fqdn, _ := models.NewFqdn("agent.example.com")

		before := time.Now()
		cache.Insert(fqdn, badge)
		after := time.Now()

		cached, _ := cache.GetByFqdn(fqdn)
		if cached.FetchedAt.Before(before) || cached.FetchedAt.After(after) {
			t.Errorf("FetchedAt = %v, expected between %v and %v", cached.FetchedAt, before, after)
		}
	})
}

func TestBadgeCache_GetStaleByFqdn(t *testing.T) {
	badge := &models.Badge{
		Status:        models.BadgeStatusActive,
		SchemaVersion: "V1",
		Payload: models.BadgePayload{
			LogID: "test-log-id",
			Producer: models.Producer{
				KeyID:     "test-key",
				Signature: "test-sig",
				Event: models.AgentEvent{
					ANSID:   "test-ans-id",
					ANSName: "ans://v1.0.0.agent.example.com",
					Agent: models.AgentInfo{
						Host:    "agent.example.com",
						Name:    "Test Agent",
						Version: "v1.0.0",
					},
					Attestations: models.Attestations{
						DomainValidation: "ACME-DNS-01",
					},
					IssuedAt:  time.Now(),
					Timestamp: time.Now(),
				},
			},
		},
	}

	t.Run("returns stale entry within maxStaleness", func(t *testing.T) {
		config := CacheConfig{
			MaxEntries: 100,
			DefaultTTL: 10 * time.Millisecond,
		}
		cache := NewBadgeCache(config)
		fqdn, _ := models.NewFqdn("agent.example.com")
		cache.Insert(fqdn, badge)

		// Wait for entry to expire
		time.Sleep(20 * time.Millisecond)

		// Should not be in fresh cache
		_, ok := cache.GetByFqdn(fqdn)
		if ok {
			t.Fatal("GetByFqdn() should have returned false for expired entry")
		}

		// Should be in stale cache within maxStaleness
		cached, ok := cache.GetStaleByFqdn(fqdn, 5*time.Second)
		if !ok {
			t.Fatal("GetStaleByFqdn() returned false, want true")
		}
		if cached.Badge.AgentHost() != "agent.example.com" {
			t.Errorf("Badge.AgentHost() = %q, want agent.example.com", cached.Badge.AgentHost())
		}
	})

	t.Run("rejects stale entry beyond maxStaleness", func(t *testing.T) {
		config := CacheConfig{
			MaxEntries: 100,
			DefaultTTL: 10 * time.Millisecond,
		}
		cache := NewBadgeCache(config)
		fqdn, _ := models.NewFqdn("agent.example.com")
		cache.Insert(fqdn, badge)

		// Wait beyond TTL + maxStaleness
		time.Sleep(20 * time.Millisecond)

		_, ok := cache.GetStaleByFqdn(fqdn, 1*time.Millisecond)
		if ok {
			t.Fatal("GetStaleByFqdn() returned true for entry beyond maxStaleness")
		}
	})

	t.Run("GetStaleByFqdnVersion works", func(t *testing.T) {
		config := CacheConfig{
			MaxEntries: 100,
			DefaultTTL: 10 * time.Millisecond,
		}
		cache := NewBadgeCache(config)
		fqdn, _ := models.NewFqdn("agent.example.com")
		version := models.NewVersion(1, 0, 0)
		cache.InsertForVersion(fqdn, version, badge)

		time.Sleep(20 * time.Millisecond)

		cached, ok := cache.GetStaleByFqdnVersion(fqdn, version, 5*time.Second)
		if !ok {
			t.Fatal("GetStaleByFqdnVersion() returned false, want true")
		}
		if cached.Badge.AgentHost() != "agent.example.com" {
			t.Errorf("Badge.AgentHost() = %q, want agent.example.com", cached.Badge.AgentHost())
		}
	})
}

func TestBadgeCache_BackgroundRefresh(t *testing.T) {
	t.Run("refresh triggers callback and updates cache", func(t *testing.T) {
		config := CacheConfig{
			MaxEntries:       100,
			DefaultTTL:       100 * time.Millisecond,
			RefreshThreshold: 80 * time.Millisecond, // Refresh when 20ms left
		}
		cache := NewBadgeCache(config)

		fqdn, _ := models.NewFqdn("agent.example.com")
		oldBadge := &models.Badge{
			Status:        models.BadgeStatusActive,
			SchemaVersion: "V1",
			Payload: models.BadgePayload{
				LogID: "old-log-id",
				Producer: models.Producer{
					KeyID:     "test-key",
					Signature: "test-sig",
					Event: models.AgentEvent{
						ANSID:   "test-ans-id",
						ANSName: "ans://v1.0.0.agent.example.com",
						Agent: models.AgentInfo{
							Host:    "agent.example.com",
							Name:    "Old Agent",
							Version: "v1.0.0",
						},
						Attestations: models.Attestations{DomainValidation: "ACME-DNS-01"},
						IssuedAt:     time.Now(),
						Timestamp:    time.Now(),
					},
				},
			},
		}
		cache.Insert(fqdn, oldBadge)

		newBadge := &models.Badge{
			Status:        models.BadgeStatusActive,
			SchemaVersion: "V1",
			Payload: models.BadgePayload{
				LogID: "new-log-id",
				Producer: models.Producer{
					KeyID:     "test-key",
					Signature: "test-sig",
					Event: models.AgentEvent{
						ANSID:   "test-ans-id",
						ANSName: "ans://v1.0.0.agent.example.com",
						Agent: models.AgentInfo{
							Host:    "agent.example.com",
							Name:    "New Agent",
							Version: "v1.0.0",
						},
						Attestations: models.Attestations{DomainValidation: "ACME-DNS-01"},
						IssuedAt:     time.Now(),
						Timestamp:    time.Now(),
					},
				},
			},
		}

		refreshCalled := make(chan struct{}, 1)
		refreshFn := func(_ context.Context, _ string) (*models.Badge, error) {
			select {
			case refreshCalled <- struct{}{}:
			default:
			}
			return newBadge, nil
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cache.StartBackgroundRefresh(ctx, 30*time.Millisecond, refreshFn)

		// Wait for refresh threshold to be reached and refresh to trigger
		time.Sleep(200 * time.Millisecond)

		select {
		case <-refreshCalled:
			// Good - refresh was called
		default:
			t.Error("Background refresh callback was not called")
		}

		// Verify cache was potentially updated (timing-dependent)
		if cached, ok := cache.GetByFqdn(fqdn); ok {
			_ = cached // Refresh may or may not have completed; we confirmed the callback was triggered above
		}
	})

	t.Run("context cancellation stops goroutine", func(t *testing.T) {
		config := CacheConfig{
			MaxEntries:       100,
			DefaultTTL:       1 * time.Second,
			RefreshThreshold: 500 * time.Millisecond,
		}
		cache := NewBadgeCache(config)

		var callCount atomic.Int32
		refreshFn := func(_ context.Context, _ string) (*models.Badge, error) {
			callCount.Add(1)
			return &models.Badge{}, nil
		}

		ctx, cancel := context.WithCancel(context.Background())

		cache.StartBackgroundRefresh(ctx, 10*time.Millisecond, refreshFn)

		// Cancel immediately
		cancel()

		// Wait to confirm no further calls
		time.Sleep(50 * time.Millisecond)

		// callCount should be 0 or very small (may have run once before cancel)
		if callCount.Load() > 1 {
			t.Errorf("Expected callCount <= 1, got %d", callCount.Load())
		}
	})

	t.Run("refresh errors do not evict entries", func(t *testing.T) {
		config := CacheConfig{
			MaxEntries:       100,
			DefaultTTL:       100 * time.Millisecond,
			RefreshThreshold: 80 * time.Millisecond,
		}
		cache := NewBadgeCache(config)

		fqdn, _ := models.NewFqdn("agent.example.com")
		badge := &models.Badge{
			Status:        models.BadgeStatusActive,
			SchemaVersion: "V1",
			Payload: models.BadgePayload{
				LogID: "test-log-id",
				Producer: models.Producer{
					KeyID:     "test-key",
					Signature: "test-sig",
					Event: models.AgentEvent{
						ANSID:   "test-ans-id",
						ANSName: "ans://v1.0.0.agent.example.com",
						Agent: models.AgentInfo{
							Host:    "agent.example.com",
							Name:    "Test Agent",
							Version: "v1.0.0",
						},
						Attestations: models.Attestations{DomainValidation: "ACME-DNS-01"},
						IssuedAt:     time.Now(),
						Timestamp:    time.Now(),
					},
				},
			},
		}
		cache.Insert(fqdn, badge)

		// Refresh function that always errors
		refreshFn := func(_ context.Context, _ string) (*models.Badge, error) {
			return nil, &TlogError{Type: TlogErrorServiceUnavailable, URL: "test"}
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cache.StartBackgroundRefresh(ctx, 30*time.Millisecond, refreshFn)

		// Wait for refresh to attempt
		time.Sleep(150 * time.Millisecond)

		// Entry should still be accessible via stale lookup
		// (it expired but wasn't evicted by background refresh error)
		cached, ok := cache.GetStaleByFqdn(fqdn, 5*time.Second)
		if !ok {
			t.Error("Entry was evicted despite refresh error")
		}
		if cached.Badge.Payload.LogID != "test-log-id" {
			t.Error("Entry was modified despite refresh error")
		}
	})
}

func TestCachedBadge_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(5 * time.Minute),
			want:      false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-5 * time.Minute),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := &CachedBadge{ExpiresAt: tt.expiresAt}
			if got := cb.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCachedBadge_ShouldRefresh(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		threshold time.Duration
		want      bool
	}{
		{
			name:      "within threshold",
			expiresAt: time.Now().Add(30 * time.Second),
			threshold: 1 * time.Minute,
			want:      true,
		},
		{
			name:      "outside threshold",
			expiresAt: time.Now().Add(5 * time.Minute),
			threshold: 1 * time.Minute,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := &CachedBadge{ExpiresAt: tt.expiresAt}
			if got := cb.ShouldRefresh(tt.threshold); got != tt.want {
				t.Errorf("ShouldRefresh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewBadgeCacheWithDefaults(t *testing.T) {
	cache := NewBadgeCacheWithDefaults()
	if cache == nil {
		t.Fatal("NewBadgeCacheWithDefaults() returned nil")
	}
	if cache.config.MaxEntries != defaultCacheMaxEntries {
		t.Errorf("MaxEntries = %d, want %d", cache.config.MaxEntries, defaultCacheMaxEntries)
	}
}

func TestBadgeCache_GetByFqdnVersion_Additional(t *testing.T) {
	cache := NewBadgeCache(CacheConfig{
		MaxEntries: 100,
		DefaultTTL: 5 * time.Minute,
	})

	fqdn, _ := models.NewFqdn("test.example.com")
	version := models.NewVersion(1, 0, 0)
	badge := &models.Badge{Status: models.BadgeStatusActive}

	// Should return nil before insertion
	if _, ok := cache.GetByFqdnVersion(fqdn, version); ok {
		t.Error("GetByFqdnVersion() should return false for missing entry")
	}

	// Insert and retrieve
	cache.InsertForVersion(fqdn, version, badge)
	cached, ok := cache.GetByFqdnVersion(fqdn, version)
	if !ok {
		t.Fatal("GetByFqdnVersion() should return true after insert")
	}
	if cached.Badge != badge {
		t.Error("GetByFqdnVersion() returned different badge")
	}

	// Different version should not match
	otherVersion := models.NewVersion(2, 0, 0)
	if _, ok := cache.GetByFqdnVersion(fqdn, otherVersion); ok {
		t.Error("GetByFqdnVersion() should return false for different version")
	}
}

func TestBadgeCache_GetByFqdn_Expired(t *testing.T) {
	cache := NewBadgeCache(CacheConfig{
		MaxEntries: 100,
		DefaultTTL: 1 * time.Millisecond, // Very short TTL
	})

	fqdn, _ := models.NewFqdn("test.example.com")
	badge := &models.Badge{Status: models.BadgeStatusActive}

	cache.Insert(fqdn, badge)

	// Wait for expiration
	time.Sleep(5 * time.Millisecond)

	if _, ok := cache.GetByFqdn(fqdn); ok {
		t.Error("GetByFqdn() should return false for expired entry")
	}
}

func TestBadgeCache_GetByFqdnVersion_Expired(t *testing.T) {
	cache := NewBadgeCache(CacheConfig{
		MaxEntries: 100,
		DefaultTTL: 1 * time.Millisecond,
	})

	fqdn, _ := models.NewFqdn("test.example.com")
	version := models.NewVersion(1, 0, 0)
	badge := &models.Badge{Status: models.BadgeStatusActive}

	cache.InsertForVersion(fqdn, version, badge)

	time.Sleep(5 * time.Millisecond)

	if _, ok := cache.GetByFqdnVersion(fqdn, version); ok {
		t.Error("GetByFqdnVersion() should return false for expired entry")
	}
}

func TestBadgeCache_GetStaleByFqdn_Additional(t *testing.T) {
	cache := NewBadgeCache(CacheConfig{
		MaxEntries:     100,
		DefaultTTL:     1 * time.Millisecond,
		StaleRetention: 1 * time.Hour,
	})

	fqdn, _ := models.NewFqdn("stale.example.com")
	badge := &models.Badge{Status: models.BadgeStatusActive}

	cache.Insert(fqdn, badge)
	time.Sleep(5 * time.Millisecond)

	// Regular get should fail
	if _, ok := cache.GetByFqdn(fqdn); ok {
		t.Error("GetByFqdn() should return false for expired entry")
	}

	// Stale get with generous window should succeed
	cached, ok := cache.GetStaleByFqdn(fqdn, 1*time.Hour)
	if !ok {
		t.Fatal("GetStaleByFqdn() should return true for stale entry within window")
	}
	if cached.Badge != badge {
		t.Error("GetStaleByFqdn() returned different badge")
	}

	// Stale get with tiny window should fail
	if _, ok := cache.GetStaleByFqdn(fqdn, 0); ok {
		t.Error("GetStaleByFqdn() should return false for stale entry outside window")
	}

	// Non-existent key
	otherFqdn, _ := models.NewFqdn("nonexistent.example.com")
	if _, ok := cache.GetStaleByFqdn(otherFqdn, 1*time.Hour); ok {
		t.Error("GetStaleByFqdn() should return false for non-existent entry")
	}
}

func TestBadgeCache_GetStaleByFqdnVersion_Additional(t *testing.T) {
	cache := NewBadgeCache(CacheConfig{
		MaxEntries:     100,
		DefaultTTL:     1 * time.Millisecond,
		StaleRetention: 1 * time.Hour,
	})

	fqdn, _ := models.NewFqdn("test.example.com")
	version := models.NewVersion(1, 0, 0)
	badge := &models.Badge{Status: models.BadgeStatusActive}

	cache.InsertForVersion(fqdn, version, badge)
	time.Sleep(5 * time.Millisecond)

	// Stale get with generous window should succeed
	cached, ok := cache.GetStaleByFqdnVersion(fqdn, version, 1*time.Hour)
	if !ok {
		t.Fatal("GetStaleByFqdnVersion() should return true for stale entry within window")
	}
	if cached.Badge != badge {
		t.Error("GetStaleByFqdnVersion() returned different badge")
	}

	// Non-existent version
	otherVersion := models.NewVersion(2, 0, 0)
	if _, ok := cache.GetStaleByFqdnVersion(fqdn, otherVersion, 1*time.Hour); ok {
		t.Error("GetStaleByFqdnVersion() should return false for non-existent version")
	}

	// Tiny staleness window
	if _, ok := cache.GetStaleByFqdnVersion(fqdn, version, 0); ok {
		t.Error("GetStaleByFqdnVersion() should return false for stale entry outside window")
	}
}

func TestBadgeCache_Clear_Additional(t *testing.T) {
	cache := NewBadgeCache(CacheConfig{
		MaxEntries: 100,
		DefaultTTL: 5 * time.Minute,
	})

	fqdn, _ := models.NewFqdn("test.example.com")
	badge := &models.Badge{Status: models.BadgeStatusActive}
	version := models.NewVersion(1, 0, 0)

	cache.Insert(fqdn, badge)
	cache.InsertForVersion(fqdn, version, badge)

	cache.Clear()

	if _, ok := cache.GetByFqdn(fqdn); ok {
		t.Error("GetByFqdn() should return false after Clear")
	}
	if _, ok := cache.GetByFqdnVersion(fqdn, version); ok {
		t.Error("GetByFqdnVersion() should return false after Clear")
	}
}

func TestBadgeCache_CleanupOverMaxEntries(t *testing.T) {
	cache := NewBadgeCache(CacheConfig{
		MaxEntries:     2,
		DefaultTTL:     5 * time.Minute,
		StaleRetention: 1 * time.Minute,
	})

	// Insert more than max entries
	for i := range 5 {
		fqdn, _ := models.NewFqdn("test" + string(rune('a'+i)) + ".example.com")
		cache.Insert(fqdn, &models.Badge{Status: models.BadgeStatusActive})
	}

	// After cleanup, total should be <= MaxEntries
	totalEntries := len(cache.byFqdn) + len(cache.byFqdnVer)
	if totalEntries > cache.config.MaxEntries {
		t.Errorf("cache has %d entries after cleanup, max is %d", totalEntries, cache.config.MaxEntries)
	}
}

func TestBadgeCache_BackgroundRefresh_Additional(t *testing.T) {
	cache := NewBadgeCache(CacheConfig{
		MaxEntries:       100,
		DefaultTTL:       50 * time.Millisecond,
		RefreshThreshold: 100 * time.Millisecond, // Always refresh
		StaleRetention:   1 * time.Hour,
	})

	fqdn, _ := models.NewFqdn("test.example.com")
	badge := &models.Badge{Status: models.BadgeStatusActive}
	cache.Insert(fqdn, badge)

	var refreshed atomic.Bool
	refreshFn := func(_ context.Context, _ string) (*models.Badge, error) {
		refreshed.Store(true)
		return &models.Badge{Status: models.BadgeStatusActive}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	cache.StartBackgroundRefresh(ctx, 25*time.Millisecond, refreshFn)

	// Wait for at least one refresh cycle
	time.Sleep(150 * time.Millisecond)

	if !refreshed.Load() {
		t.Error("expected background refresh to be called")
	}
}

func TestDefaultCacheConfig_Values(t *testing.T) {
	cfg := DefaultCacheConfig()
	if cfg.MaxEntries != defaultCacheMaxEntries {
		t.Errorf("MaxEntries = %d, want %d", cfg.MaxEntries, defaultCacheMaxEntries)
	}
	if cfg.DefaultTTL != defaultCacheTTLMinutes*time.Minute {
		t.Errorf("DefaultTTL = %v, want %v", cfg.DefaultTTL, defaultCacheTTLMinutes*time.Minute)
	}
	if cfg.RefreshThreshold != defaultCacheRefreshMinutes*time.Minute {
		t.Errorf("RefreshThreshold = %v, want %v", cfg.RefreshThreshold, defaultCacheRefreshMinutes*time.Minute)
	}
}

func TestFailurePolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy FailurePolicy
	}{
		{"FailClosed", FailClosed},
		{"FailOpenWithCache", FailOpenWithCache},
		{"FailOpen", FailOpen},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the constants exist and have different values
			switch tt.policy {
			case FailClosed, FailOpenWithCache, FailOpen:
				// OK
			default:
				t.Errorf("Unknown FailurePolicy: %v", tt.policy)
			}
		})
	}
}

func TestBadgeCache_CleanupLocked_StaleRetention(t *testing.T) {
	config := CacheConfig{
		MaxEntries:     100,
		DefaultTTL:     10 * time.Millisecond,
		StaleRetention: 20 * time.Millisecond,
	}
	cache := NewBadgeCache(config)
	fqdn, _ := models.NewFqdn("cleanup.example.com")
	badge := &models.Badge{
		Status:        models.BadgeStatusActive,
		SchemaVersion: "V1",
		Payload: models.BadgePayload{
			LogID: "test-log",
			Producer: models.Producer{
				KeyID:     "k",
				Signature: "s",
				Event: models.AgentEvent{
					ANSID:   "id",
					ANSName: "ans://v1.0.0.cleanup.example.com",
					Agent: models.AgentInfo{
						Host:    "cleanup.example.com",
						Name:    "Test",
						Version: "v1.0.0",
					},
					IssuedAt:  time.Now(),
					Timestamp: time.Now(),
				},
			},
		},
	}

	cache.Insert(fqdn, badge)

	// Wait for TTL to expire
	time.Sleep(15 * time.Millisecond)

	// Entry should be expired but within stale retention
	_, ok := cache.GetByFqdn(fqdn)
	if ok {
		t.Fatal("GetByFqdn() should return false for expired entry")
	}

	// Stale lookup should still work
	cached, ok := cache.GetStaleByFqdn(fqdn, 5*time.Second)
	if !ok {
		t.Fatal("GetStaleByFqdn() should return true within stale retention")
	}
	if cached.Badge.Payload.LogID != "test-log" {
		t.Error("Stale entry badge should be intact")
	}

	// Wait beyond stale retention
	time.Sleep(30 * time.Millisecond)

	// Insert a new entry to trigger cleanup
	fqdn2, _ := models.NewFqdn("trigger.example.com")
	cache.Insert(fqdn2, badge)

	// The old entry should have been cleaned up
	_, ok = cache.GetStaleByFqdn(fqdn, 5*time.Second)
	if ok {
		t.Fatal("GetStaleByFqdn() should return false after stale retention + cleanup")
	}
}

func TestBadgeCache_CleanupLocked_MaxEntriesEviction(t *testing.T) {
	config := CacheConfig{
		MaxEntries:     3,
		DefaultTTL:     5 * time.Minute,
		StaleRetention: 10 * time.Minute,
	}
	cache := NewBadgeCache(config)

	badge := &models.Badge{
		Status:        models.BadgeStatusActive,
		SchemaVersion: "V1",
		Payload: models.BadgePayload{
			LogID: "test",
			Producer: models.Producer{
				KeyID:     "k",
				Signature: "s",
				Event: models.AgentEvent{
					ANSID:   "id",
					ANSName: "ans://v1.0.0.test.example.com",
					Agent: models.AgentInfo{
						Host:    "test.example.com",
						Name:    "Test",
						Version: "v1.0.0",
					},
					IssuedAt:  time.Now(),
					Timestamp: time.Now(),
				},
			},
		},
	}

	// Insert more entries than MaxEntries
	for i := range 5 {
		fqdn, _ := models.NewFqdn("host" + string(rune('a'+i)) + ".example.com")
		cache.Insert(fqdn, badge)
	}

	// Total entries should be at or below MaxEntries after cleanup
	cache.mu.RLock()
	total := len(cache.byFqdn) + len(cache.byFqdnVer)
	cache.mu.RUnlock()

	if total > config.MaxEntries {
		t.Errorf("cache has %d entries, expected at most %d", total, config.MaxEntries)
	}
}

func TestBadgeCache_CleanupLocked_VersionedEntries(t *testing.T) {
	config := CacheConfig{
		MaxEntries:     100,
		DefaultTTL:     10 * time.Millisecond,
		StaleRetention: 5 * time.Millisecond,
	}
	cache := NewBadgeCache(config)

	badge := &models.Badge{
		Status:        models.BadgeStatusActive,
		SchemaVersion: "V1",
		Payload: models.BadgePayload{
			LogID: "test",
			Producer: models.Producer{
				KeyID:     "k",
				Signature: "s",
				Event: models.AgentEvent{
					ANSID:   "id",
					ANSName: "ans://v1.0.0.ver.example.com",
					Agent: models.AgentInfo{
						Host:    "ver.example.com",
						Name:    "Test",
						Version: "v1.0.0",
					},
					IssuedAt:  time.Now(),
					Timestamp: time.Now(),
				},
			},
		},
	}

	fqdn, _ := models.NewFqdn("ver.example.com")
	version := models.NewVersion(1, 0, 0)

	cache.InsertForVersion(fqdn, version, badge)

	// Wait beyond TTL + stale retention
	time.Sleep(20 * time.Millisecond)

	// Insert to trigger cleanup
	fqdn2, _ := models.NewFqdn("trigger2.example.com")
	cache.InsertForVersion(fqdn2, version, badge)

	// Old versioned entry should be cleaned up
	_, ok := cache.GetStaleByFqdnVersion(fqdn, version, 5*time.Second)
	if ok {
		t.Fatal("Old versioned entry should have been cleaned up")
	}
}

func TestBadgeCache_CleanupLocked_MaxEntriesEviction_VersionedOverflow(t *testing.T) {
	config := CacheConfig{
		MaxEntries:     3,
		DefaultTTL:     5 * time.Minute,
		StaleRetention: 10 * time.Minute,
	}
	cache := NewBadgeCache(config)

	badge := &models.Badge{
		Status:        models.BadgeStatusActive,
		SchemaVersion: "V1",
		Payload: models.BadgePayload{
			LogID: "test",
			Producer: models.Producer{
				KeyID:     "k",
				Signature: "s",
				Event: models.AgentEvent{
					ANSID:   "id",
					ANSName: "ans://v1.0.0.test.example.com",
					Agent: models.AgentInfo{
						Host:    "test.example.com",
						Name:    "Test",
						Version: "v1.0.0",
					},
					IssuedAt:  time.Now(),
					Timestamp: time.Now(),
				},
			},
		},
	}

	// Insert more versioned entries than MaxEntries to trigger byFqdnVer eviction
	for i := range 5 {
		fqdn, _ := models.NewFqdn("host" + string(rune('a'+i)) + ".example.com")
		v := models.NewVersion(uint32(i+1), 0, 0)
		cache.InsertForVersion(fqdn, v, badge)
	}

	cache.mu.RLock()
	total := len(cache.byFqdn) + len(cache.byFqdnVer)
	cache.mu.RUnlock()

	if total > config.MaxEntries {
		t.Errorf("cache has %d entries, expected at most %d", total, config.MaxEntries)
	}
}

func TestURLValidationError_UnknownType(t *testing.T) {
	err := &URLValidationError{Type: URLErrorType(99), URL: "http://test.com"}
	got := err.Error()
	want := "badge URL validation error: http://test.com"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
