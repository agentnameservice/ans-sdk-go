package pop

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryReplayCache_CheckAndStore(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewMemoryReplayCache(context.Background(), 10, withReplayClock(func() time.Time { return now }))
	defer c.Close()
	exp := now.Add(time.Minute)

	if seen, err := c.CheckAndStore("a", exp); err != nil || seen {
		t.Fatalf("first store: seen=%v err=%v", seen, err)
	}
	if seen, err := c.CheckAndStore("a", exp); err != nil || !seen {
		t.Fatalf("replay should be seen: seen=%v err=%v", seen, err)
	}
	if seen, err := c.CheckAndStore("b", exp); err != nil || seen {
		t.Fatalf("distinct jti: seen=%v err=%v", seen, err)
	}
}

func TestMemoryReplayCache_ExpiredEntryNotReplay(t *testing.T) {
	var nowUnix atomic.Int64
	nowUnix.Store(1000)
	clock := func() time.Time { return time.Unix(nowUnix.Load(), 0) }
	c := NewMemoryReplayCache(context.Background(), 10, withReplayClock(clock))
	defer c.Close()

	c.CheckAndStore("a", time.Unix(1100, 0)) // expires at 1100
	nowUnix.Store(2000)                      // now past expiry
	if seen, err := c.CheckAndStore("a", time.Unix(2100, 0)); err != nil || seen {
		t.Fatalf("expired entry must not be a replay: seen=%v err=%v", seen, err)
	}
}

func TestMemoryReplayCache_CapacityFailsClosed(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewMemoryReplayCache(context.Background(), 1, withReplayClock(func() time.Time { return now }))
	defer c.Close()
	exp := now.Add(time.Minute)
	if _, err := c.CheckAndStore("a", exp); err != nil {
		t.Fatalf("store a: %v", err)
	}
	_, err := c.CheckAndStore("b", exp) // full of a live entry → must reject
	assertProofErr(t, err, ErrReplayCacheFull)
}

func TestMemoryReplayCache_CapacityPurgeMakesRoom(t *testing.T) {
	var nowUnix atomic.Int64
	nowUnix.Store(1000)
	clock := func() time.Time { return time.Unix(nowUnix.Load(), 0) }
	c := NewMemoryReplayCache(context.Background(), 1, withReplayClock(clock))
	defer c.Close()
	c.CheckAndStore("a", time.Unix(1100, 0)) // expires 1100
	nowUnix.Store(2000)                      // a now expired
	if seen, err := c.CheckAndStore("b", time.Unix(2100, 0)); err != nil || seen {
		t.Fatalf("purge should make room: seen=%v err=%v", seen, err)
	}
}

func TestMemoryReplayCache_JanitorSweeps(t *testing.T) {
	var nowUnix atomic.Int64
	nowUnix.Store(1000)
	clock := func() time.Time { return time.Unix(nowUnix.Load(), 0) }
	c := NewMemoryReplayCache(context.Background(), 10,
		withReplayClock(clock), withJanitorInterval(2*time.Millisecond))
	defer c.Close()

	c.CheckAndStore("a", time.Unix(1100, 0))
	if c.Len() != 1 {
		t.Fatalf("size after store = %d, want 1", c.Len())
	}
	nowUnix.Store(2000) // a is now expired
	deadline := time.Now().Add(2 * time.Second)
	for c.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if c.Len() != 0 {
		t.Fatalf("janitor did not sweep expired entry; size=%d", c.Len())
	}
}

// TestMemoryReplayCache_LiveEntrySurvivesSameGenerationEviction is the safety
// property the bucketed design must not violate. Entries are grouped by expiry
// generation, and a generation spans bucketWidth, so one bucket can hold both an
// already-expired entry and a still-live one. Dropping the bucket on a partial
// comparison would evict the live entry and silently reopen replay.
func TestMemoryReplayCache_LiveEntrySurvivesSameGenerationEviction(t *testing.T) {
	// Anchor to a generation boundary so both expiries land in one bucket.
	base := time.Unix(0, (time.Unix(1_700_000_000, 0).UnixNano()/int64(bucketWidth))*int64(bucketWidth))
	var nowUnixNano atomic.Int64
	nowUnixNano.Store(base.UnixNano())
	clock := func() time.Time { return time.Unix(0, nowUnixNano.Load()) }

	c := NewMemoryReplayCache(context.Background(), 10, withReplayClock(clock))
	defer c.Close()

	expEarly := base.Add(time.Second)    // same bucket, expires first
	expLate := base.Add(bucketWidth - 1) // same bucket, still live at expEarly
	if bucketOf(expEarly) != bucketOf(expLate) {
		t.Fatalf("test setup: expiries must share a generation (%d vs %d)",
			bucketOf(expEarly), bucketOf(expLate))
	}
	if _, err := c.CheckAndStore("early", expEarly); err != nil {
		t.Fatalf("store early: %v", err)
	}
	if _, err := c.CheckAndStore("late", expLate); err != nil {
		t.Fatalf("store late: %v", err)
	}

	// Advance past "early"'s expiry but not past the generation.
	nowUnixNano.Store(base.Add(2 * time.Second).UnixNano())
	seen, err := c.CheckAndStore("late", expLate)
	if err != nil {
		t.Fatalf("replay of live entry: %v", err)
	}
	if !seen {
		t.Fatal("live entry was evicted with its generation — replay reopened")
	}
	// The expired one is correctly no longer a replay.
	if seen, err := c.CheckAndStore("early", base.Add(bucketWidth*3)); err != nil || seen {
		t.Fatalf("expired entry treated as replay: seen=%v err=%v", seen, err)
	}
}

func TestMemoryReplayCache_EvictionDrainsWholeGenerations(t *testing.T) {
	var nowUnix atomic.Int64
	nowUnix.Store(1000)
	clock := func() time.Time { return time.Unix(nowUnix.Load(), 0) }
	c := NewMemoryReplayCache(context.Background(), 1000, withReplayClock(clock))
	defer c.Close()

	for i := range 50 {
		if _, err := c.CheckAndStore("k"+strconv.Itoa(i), time.Unix(1010, 0)); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}
	if c.Len() != 50 {
		t.Fatalf("Len = %d, want 50", c.Len())
	}
	if c.Cap() != 1000 {
		t.Fatalf("Cap = %d, want 1000", c.Cap())
	}
	// Past the generation containing exp=1010: one insert drains all 50.
	nowUnix.Store(1100)
	if _, err := c.CheckAndStore("fresh", time.Unix(1200, 0)); err != nil {
		t.Fatalf("store after expiry: %v", err)
	}
	if got := c.Len(); got != 1 {
		t.Fatalf("Len after eviction = %d, want 1 (only the fresh entry)", got)
	}
}

func TestMemoryReplayCache_ConcurrentSameKey(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewMemoryReplayCache(context.Background(), 1000, withReplayClock(func() time.Time { return now }))
	defer c.Close()
	exp := now.Add(time.Minute)

	const goroutines = 64
	var accepted atomic.Int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			seen, err := c.CheckAndStore("contended", exp)
			if err == nil && !seen {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("%d goroutines were told the key was unseen, want exactly 1", got)
	}
}

// BenchmarkMemoryReplayCache_Loaded measures the request-path cost while the
// cache holds a full default working set of live entries. The previous
// implementation scanned every held entry under the mutex once occupancy reached
// capacity; eviction now walks generations, so this cost must not scale with the
// number of entries held. Capacity is left far above the working set so the
// measurement is eviction cost, not fail-closed behavior.
func BenchmarkMemoryReplayCache_Loaded(b *testing.B) {
	const liveEntries = 100_000
	now := time.Unix(1_700_000_000, 0)
	c := NewMemoryReplayCache(context.Background(), 0, // 0 → DefaultReplayMaxEntries
		withReplayClock(func() time.Time { return now }))
	defer c.Close()
	// Spread expiries across the generations a real 125s retention window covers.
	for i := range liveEntries {
		exp := now.Add(time.Duration(i%125+1) * time.Second)
		if _, err := c.CheckAndStore("fill"+strconv.Itoa(i), exp); err != nil {
			b.Fatalf("fill at %d: %v", i, err)
		}
	}
	if c.Len() != liveEntries {
		b.Fatalf("setup: Len = %d, want %d", c.Len(), liveEntries)
	}
	exp := now.Add(125 * time.Second)
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		// Re-presenting a held key exercises lookup + eviction without growing
		// the set, so occupancy stays at the working-set size throughout.
		if _, err := c.CheckAndStore("fill"+strconv.Itoa(i%liveEntries), exp); err != nil {
			b.StopTimer()
			b.Fatalf("bench store: %v", err)
		}
	}
}

func TestMemoryReplayCache_Lifecycle(t *testing.T) {
	// stop branch: created with a live ctx, stopped via Close (idempotent).
	c := NewMemoryReplayCache(context.Background(), 0) // 0 → default max
	c.Close()
	c.Close()
	if c.Len() != 0 {
		t.Errorf("new cache size = %d, want 0", c.Len())
	}

	// ctx.Done branch: janitor returns when ctx is canceled.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c2 := NewMemoryReplayCache(ctx, 10)
	c2.Close()
	if c2.Len() != 0 {
		t.Errorf("ctx-canceled cache size = %d, want 0", c2.Len())
	}
}
