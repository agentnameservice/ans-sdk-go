package scitt

import (
	"sync"
	"testing"
	"time"
)

// --- ReceiptCache tests ---

func TestReceiptCache_Get(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	receipt := &VerifiedReceipt{
		TreeSize:  42,
		LeafIndex: 7,
		KeyID:     [4]byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	tests := []struct {
		name      string
		setup     func(c *ReceiptCache)
		clockTime time.Time
		agentID   string
		wantOk    bool
		wantNil   bool
	}{
		{
			name:      "missing key returns false",
			setup:     func(_ *ReceiptCache) {},
			clockTime: baseTime,
			agentID:   "agent-missing",
			wantOk:    false,
			wantNil:   true,
		},
		{
			name: "valid entry returns receipt",
			setup: func(c *ReceiptCache) {
				c.Insert("agent-1", receipt)
			},
			clockTime: baseTime.Add(1 * time.Hour),
			agentID:   "agent-1",
			wantOk:    true,
			wantNil:   false,
		},
		{
			name: "expired entry returns false",
			setup: func(c *ReceiptCache) {
				c.Insert("agent-1", receipt)
			},
			clockTime: baseTime.Add(25 * time.Hour), // past 24h TTL
			agentID:   "agent-1",
			wantOk:    false,
			wantNil:   true,
		},
		{
			name: "entry at exact TTL boundary returns false",
			setup: func(c *ReceiptCache) {
				c.Insert("agent-1", receipt)
			},
			clockTime: baseTime.Add(24*time.Hour + 1*time.Nanosecond),
			agentID:   "agent-1",
			wantOk:    false,
			wantNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			now := baseTime
			clock := func() time.Time { return now }
			c := NewReceiptCache(24*time.Hour, 1000, clock)

			tt.setup(c)
			now = tt.clockTime

			got, ok := c.Get(tt.agentID)
			if ok != tt.wantOk {
				t.Errorf("Get() ok = %v, want %v", ok, tt.wantOk)
			}
			if tt.wantNil && got != nil {
				t.Errorf("Get() = %v, want nil", got)
			}
			if !tt.wantNil && got == nil {
				t.Error("Get() = nil, want non-nil")
			}
		})
	}
}

func TestReceiptCache_Insert(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		setup   func(c *ReceiptCache)
		wantLen int
	}{
		{
			name: "insert single entry",
			setup: func(c *ReceiptCache) {
				c.Insert("agent-1", &VerifiedReceipt{TreeSize: 1})
			},
			wantLen: 1,
		},
		{
			name: "overwrite existing entry for same key",
			setup: func(c *ReceiptCache) {
				c.Insert("agent-1", &VerifiedReceipt{TreeSize: 1})
				c.Insert("agent-1", &VerifiedReceipt{TreeSize: 2})
			},
			wantLen: 1,
		},
		{
			name: "max entries eviction",
			setup: func(c *ReceiptCache) {
				for i := range 4 {
					c.Insert(agentID(i), &VerifiedReceipt{TreeSize: uint64(i)})
				}
			},
			wantLen: 3, // maxEntries is 3
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			clock := func() time.Time { return baseTime }
			c := NewReceiptCache(24*time.Hour, 3, clock)

			tt.setup(c)

			if got := c.Len(); got != tt.wantLen {
				t.Errorf("Len() = %d, want %d", got, tt.wantLen)
			}
		})
	}
}

func TestReceiptCache_InsertOverwrite(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return baseTime }
	c := NewReceiptCache(24*time.Hour, 1000, clock)

	c.Insert("agent-1", &VerifiedReceipt{TreeSize: 10})
	c.Insert("agent-1", &VerifiedReceipt{TreeSize: 20})

	got, ok := c.Get("agent-1")
	if !ok {
		t.Fatal("Get() returned false, want true")
	}
	if got.TreeSize != 20 {
		t.Errorf("TreeSize = %d, want 20", got.TreeSize)
	}
}

func TestReceiptCache_Invalidate(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		insertIDs []string
		removeID  string
		wantLen   int
	}{
		{
			name:      "invalidate existing entry",
			insertIDs: []string{"agent-1", "agent-2"},
			removeID:  "agent-1",
			wantLen:   1,
		},
		{
			name:      "invalidate missing entry is no-op",
			insertIDs: []string{"agent-1"},
			removeID:  "agent-missing",
			wantLen:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			clock := func() time.Time { return baseTime }
			c := NewReceiptCache(24*time.Hour, 1000, clock)

			for _, id := range tt.insertIDs {
				c.Insert(id, &VerifiedReceipt{TreeSize: 1})
			}

			c.Invalidate(tt.removeID)

			if got := c.Len(); got != tt.wantLen {
				t.Errorf("Len() = %d, want %d", got, tt.wantLen)
			}
		})
	}
}

func TestReceiptCache_Len(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		ops     func(c *ReceiptCache)
		wantLen int
	}{
		{
			name:    "empty cache",
			ops:     func(_ *ReceiptCache) {},
			wantLen: 0,
		},
		{
			name: "after inserts and invalidate",
			ops: func(c *ReceiptCache) {
				c.Insert("a", &VerifiedReceipt{})
				c.Insert("b", &VerifiedReceipt{})
				c.Insert("c", &VerifiedReceipt{})
				c.Invalidate("b")
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			clock := func() time.Time { return baseTime }
			c := NewReceiptCache(24*time.Hour, 1000, clock)
			tt.ops(c)

			if got := c.Len(); got != tt.wantLen {
				t.Errorf("Len() = %d, want %d", got, tt.wantLen)
			}
		})
	}
}

func TestReceiptCacheWithDefaults(t *testing.T) {
	t.Parallel()

	c := NewReceiptCacheWithDefaults()
	if c == nil {
		t.Fatal("NewReceiptCacheWithDefaults() returned nil")
	}
	if c.Len() != 0 {
		t.Errorf("Len() = %d, want 0", c.Len())
	}
}

// --- StatusTokenCache tests ---

func TestStatusTokenCache_Get(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		setup     func(c *StatusTokenCache)
		clockTime time.Time
		agentID   string
		wantOk    bool
		wantNil   bool
	}{
		{
			name:      "missing key returns false",
			setup:     func(_ *StatusTokenCache) {},
			clockTime: baseTime,
			agentID:   "agent-missing",
			wantOk:    false,
			wantNil:   true,
		},
		{
			name: "valid entry returns token",
			setup: func(c *StatusTokenCache) {
				c.Insert("agent-1", &VerifiedStatusToken{
					Payload: StatusTokenPayload{Exp: baseTime.Add(2 * time.Hour).Unix()},
					KeyID:   [4]byte{0x01, 0x02, 0x03, 0x04},
				})
			},
			clockTime: baseTime.Add(1 * time.Hour),
			agentID:   "agent-1",
			wantOk:    true,
			wantNil:   false,
		},
		{
			name: "expired per token Exp returns false",
			setup: func(c *StatusTokenCache) {
				c.Insert("agent-1", &VerifiedStatusToken{
					Payload: StatusTokenPayload{Exp: baseTime.Add(1 * time.Hour).Unix()},
				})
			},
			clockTime: baseTime.Add(2 * time.Hour), // past Exp
			agentID:   "agent-1",
			wantOk:    false,
			wantNil:   true,
		},
		{
			name: "entry at exact Exp boundary returns false",
			setup: func(c *StatusTokenCache) {
				expTime := baseTime.Add(1 * time.Hour)
				c.Insert("agent-1", &VerifiedStatusToken{
					Payload: StatusTokenPayload{Exp: expTime.Unix()},
				})
			},
			clockTime: baseTime.Add(1*time.Hour + 1*time.Second),
			agentID:   "agent-1",
			wantOk:    false,
			wantNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			now := baseTime
			clock := func() time.Time { return now }
			c := NewStatusTokenCache(1000, clock)

			tt.setup(c)
			now = tt.clockTime

			got, ok := c.Get(tt.agentID)
			if ok != tt.wantOk {
				t.Errorf("Get() ok = %v, want %v", ok, tt.wantOk)
			}
			if tt.wantNil && got != nil {
				t.Errorf("Get() = %v, want nil", got)
			}
			if !tt.wantNil && got == nil {
				t.Error("Get() = nil, want non-nil")
			}
		})
	}
}

func TestStatusTokenCache_Insert(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		setup   func(c *StatusTokenCache)
		wantLen int
	}{
		{
			name: "insert single entry",
			setup: func(c *StatusTokenCache) {
				c.Insert("agent-1", &VerifiedStatusToken{
					Payload: StatusTokenPayload{Exp: baseTime.Add(1 * time.Hour).Unix()},
				})
			},
			wantLen: 1,
		},
		{
			name: "overwrite existing entry for same key",
			setup: func(c *StatusTokenCache) {
				c.Insert("agent-1", &VerifiedStatusToken{
					Payload: StatusTokenPayload{Exp: baseTime.Add(1 * time.Hour).Unix()},
				})
				c.Insert("agent-1", &VerifiedStatusToken{
					Payload: StatusTokenPayload{Exp: baseTime.Add(2 * time.Hour).Unix()},
				})
			},
			wantLen: 1,
		},
		{
			name: "max entries eviction",
			setup: func(c *StatusTokenCache) {
				for i := range 4 {
					c.Insert(agentID(i), &VerifiedStatusToken{
						Payload: StatusTokenPayload{Exp: baseTime.Add(1 * time.Hour).Unix()},
					})
				}
			},
			wantLen: 3, // maxEntries is 3
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			clock := func() time.Time { return baseTime }
			c := NewStatusTokenCache(3, clock)

			tt.setup(c)

			if got := c.Len(); got != tt.wantLen {
				t.Errorf("Len() = %d, want %d", got, tt.wantLen)
			}
		})
	}
}

func TestStatusTokenCache_InsertOverwrite(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return baseTime }
	c := NewStatusTokenCache(1000, clock)

	c.Insert("agent-1", &VerifiedStatusToken{
		Payload: StatusTokenPayload{Exp: baseTime.Add(1 * time.Hour).Unix()},
		KeyID:   [4]byte{0x01},
	})
	c.Insert("agent-1", &VerifiedStatusToken{
		Payload: StatusTokenPayload{Exp: baseTime.Add(2 * time.Hour).Unix()},
		KeyID:   [4]byte{0x02},
	})

	got, ok := c.Get("agent-1")
	if !ok {
		t.Fatal("Get() returned false, want true")
	}
	if got.KeyID != [4]byte{0x02} {
		t.Errorf("KeyID = %v, want [0x02 0 0 0]", got.KeyID)
	}
}

func TestStatusTokenCache_Invalidate(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		insertIDs []string
		removeID  string
		wantLen   int
	}{
		{
			name:      "invalidate existing entry",
			insertIDs: []string{"agent-1", "agent-2"},
			removeID:  "agent-1",
			wantLen:   1,
		},
		{
			name:      "invalidate missing entry is no-op",
			insertIDs: []string{"agent-1"},
			removeID:  "agent-missing",
			wantLen:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			clock := func() time.Time { return baseTime }
			c := NewStatusTokenCache(1000, clock)

			for _, id := range tt.insertIDs {
				c.Insert(id, &VerifiedStatusToken{
					Payload: StatusTokenPayload{Exp: baseTime.Add(1 * time.Hour).Unix()},
				})
			}

			c.Invalidate(tt.removeID)

			if got := c.Len(); got != tt.wantLen {
				t.Errorf("Len() = %d, want %d", got, tt.wantLen)
			}
		})
	}
}

func TestStatusTokenCache_Len(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		ops     func(c *StatusTokenCache)
		wantLen int
	}{
		{
			name:    "empty cache",
			ops:     func(_ *StatusTokenCache) {},
			wantLen: 0,
		},
		{
			name: "after inserts and invalidate",
			ops: func(c *StatusTokenCache) {
				c.Insert("a", &VerifiedStatusToken{Payload: StatusTokenPayload{Exp: baseTime.Add(1 * time.Hour).Unix()}})
				c.Insert("b", &VerifiedStatusToken{Payload: StatusTokenPayload{Exp: baseTime.Add(1 * time.Hour).Unix()}})
				c.Insert("c", &VerifiedStatusToken{Payload: StatusTokenPayload{Exp: baseTime.Add(1 * time.Hour).Unix()}})
				c.Invalidate("b")
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			clock := func() time.Time { return baseTime }
			c := NewStatusTokenCache(1000, clock)
			tt.ops(c)

			if got := c.Len(); got != tt.wantLen {
				t.Errorf("Len() = %d, want %d", got, tt.wantLen)
			}
		})
	}
}

func TestStatusTokenCacheWithDefaults(t *testing.T) {
	t.Parallel()

	c := NewStatusTokenCacheWithDefaults()
	if c == nil {
		t.Fatal("NewStatusTokenCacheWithDefaults() returned nil")
	}
	if c.Len() != 0 {
		t.Errorf("Len() = %d, want 0", c.Len())
	}
}

// --- FIFO eviction tests ---

func TestReceiptCache_FIFOEviction(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return baseTime }
	c := NewReceiptCache(24*time.Hour, 3, clock)

	c.Insert("oldest", &VerifiedReceipt{TreeSize: 1})
	c.Insert("middle", &VerifiedReceipt{TreeSize: 2})
	c.Insert("newest", &VerifiedReceipt{TreeSize: 3})
	c.Insert("overflow", &VerifiedReceipt{TreeSize: 4})

	if _, ok := c.Get("oldest"); ok {
		t.Error("oldest entry should have been evicted, but was present")
	}
	for _, id := range []string{"middle", "newest", "overflow"} {
		if _, ok := c.Get(id); !ok {
			t.Errorf("entry %q should still be present after FIFO eviction", id)
		}
	}
}

func TestReceiptCache_InvalidateRemovesFromOrder(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return baseTime }
	c := NewReceiptCache(24*time.Hour, 2, clock)

	c.Insert("a", &VerifiedReceipt{TreeSize: 1})
	c.Insert("b", &VerifiedReceipt{TreeSize: 2})
	c.Invalidate("a")
	// Invalidating "a" should also remove it from insertOrder so "b" is not evicted
	// when we add "c".
	c.Insert("c", &VerifiedReceipt{TreeSize: 3})

	if _, ok := c.Get("b"); !ok {
		t.Error("b should still be present after invalidating a and inserting c")
	}
	if _, ok := c.Get("c"); !ok {
		t.Error("c should be present")
	}
}

func TestStatusTokenCache_FIFOEviction(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return baseTime }
	c := NewStatusTokenCache(3, clock)

	exp := baseTime.Add(1 * time.Hour).Unix()
	c.Insert("oldest", &VerifiedStatusToken{Payload: StatusTokenPayload{Exp: exp}})
	c.Insert("middle", &VerifiedStatusToken{Payload: StatusTokenPayload{Exp: exp}})
	c.Insert("newest", &VerifiedStatusToken{Payload: StatusTokenPayload{Exp: exp}})
	c.Insert("overflow", &VerifiedStatusToken{Payload: StatusTokenPayload{Exp: exp}})

	if _, ok := c.Get("oldest"); ok {
		t.Error("oldest entry should have been evicted, but was present")
	}
	for _, id := range []string{"middle", "newest", "overflow"} {
		if _, ok := c.Get(id); !ok {
			t.Errorf("entry %q should still be present after FIFO eviction", id)
		}
	}
}

func TestStatusTokenCache_InvalidateRemovesFromOrder(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return baseTime }
	c := NewStatusTokenCache(2, clock)

	exp := baseTime.Add(1 * time.Hour).Unix()
	c.Insert("a", &VerifiedStatusToken{Payload: StatusTokenPayload{Exp: exp}})
	c.Insert("b", &VerifiedStatusToken{Payload: StatusTokenPayload{Exp: exp}})
	c.Invalidate("a")
	c.Insert("c", &VerifiedStatusToken{Payload: StatusTokenPayload{Exp: exp}})

	if _, ok := c.Get("b"); !ok {
		t.Error("b should still be present after invalidating a and inserting c")
	}
	if _, ok := c.Get("c"); !ok {
		t.Error("c should be present")
	}
}

// --- Concurrent access tests ---

func TestReceiptCache_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return baseTime }
	c := NewReceiptCache(24*time.Hour, 1000, clock)

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := agentID(idx)
			c.Insert(id, &VerifiedReceipt{TreeSize: uint64(idx)})
			c.Get(id)
			c.Len()
			c.Invalidate(id)
		}(i)
	}
	wg.Wait()
}

func TestStatusTokenCache_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return baseTime }
	c := NewStatusTokenCache(1000, clock)

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := agentID(idx)
			c.Insert(id, &VerifiedStatusToken{
				Payload: StatusTokenPayload{Exp: baseTime.Add(1 * time.Hour).Unix()},
			})
			c.Get(id)
			c.Len()
			c.Invalidate(id)
		}(i)
	}
	wg.Wait()
}

// agentID returns a deterministic agent ID string for test use.
func agentID(i int) string {
	return "agent-" + itoa(i)
}

// itoa converts an int to a string without importing strconv.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}
