package scitt

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestRefreshableKeyStoreGet(t *testing.T) {
	t.Parallel()

	name, kidHex, spkiB64, _ := mustGenerateTestKey(t)
	keyStr := fmt.Sprintf("%s+%s+%s", name, kidHex, spkiB64)

	initial, err := NewKeyStore([]string{keyStr})
	if err != nil {
		t.Fatalf("failed to create initial store: %v", err)
	}

	kidBytes, _ := hexDecodeKid(kidHex)

	tests := []struct {
		name    string
		kid     [4]byte
		wantErr bool
	}{
		{
			name:    "known kid returns key",
			kid:     kidBytes,
			wantErr: false,
		},
		{
			name:    "unknown kid returns error",
			kid:     [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rks := NewRefreshableKeyStore(initial, nil)
			got, err := rks.Get(tt.kid)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("expected non-nil TrustedKey")
			}
		})
	}
}

func TestRefreshableKeyStoreCurrentSnapshot(t *testing.T) {
	t.Parallel()

	name, kidHex, spkiB64, _ := mustGenerateTestKey(t)
	keyStr := fmt.Sprintf("%s+%s+%s", name, kidHex, spkiB64)

	initial, err := NewKeyStore([]string{keyStr})
	if err != nil {
		t.Fatalf("failed to create initial store: %v", err)
	}

	tests := []struct {
		name    string
		initial *KeyStore
		wantLen int
	}{
		{
			name:    "returns snapshot with keys",
			initial: initial,
			wantLen: 1,
		},
		{
			name:    "returns empty snapshot",
			initial: mustEmptyStore(t),
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rks := NewRefreshableKeyStore(tt.initial, nil)
			snap := rks.CurrentSnapshot()
			if snap.Len() != tt.wantLen {
				t.Errorf("Len() = %d, want %d", snap.Len(), tt.wantLen)
			}
		})
	}
}

func TestRefreshableKeyStoreLenIsEmpty(t *testing.T) {
	t.Parallel()

	name, kidHex, spkiB64, _ := mustGenerateTestKey(t)
	keyStr := fmt.Sprintf("%s+%s+%s", name, kidHex, spkiB64)

	nonEmpty, err := NewKeyStore([]string{keyStr})
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	tests := []struct {
		name      string
		initial   *KeyStore
		wantLen   int
		wantEmpty bool
	}{
		{
			name:      "non-empty store",
			initial:   nonEmpty,
			wantLen:   1,
			wantEmpty: false,
		},
		{
			name:      "empty store",
			initial:   mustEmptyStore(t),
			wantLen:   0,
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rks := NewRefreshableKeyStore(tt.initial, nil)
			if rks.Len() != tt.wantLen {
				t.Errorf("Len() = %d, want %d", rks.Len(), tt.wantLen)
			}
			if rks.IsEmpty() != tt.wantEmpty {
				t.Errorf("IsEmpty() = %v, want %v", rks.IsEmpty(), tt.wantEmpty)
			}
		})
	}
}

func TestRefreshableKeyStoreImplementsKeyLookup(t *testing.T) {
	t.Parallel()
	var _ KeyLookup = (*RefreshableKeyStore)(nil)
}

func TestRefreshableKeyStoreDoRefresh(t *testing.T) {
	t.Parallel()

	name1, kid1Hex, spki1B64, _ := mustGenerateTestKey(t)
	name2, kid2Hex, spki2B64, _ := mustGenerateTestKey(t)

	key1Str := fmt.Sprintf("%s+%s+%s", name1, kid1Hex, spki1B64)
	key2Str := fmt.Sprintf("%s+%s+%s", name2, kid2Hex, spki2B64)

	tests := []struct {
		name        string
		initialKeys []string
		fetchKeys   []string
		fetchErr    error
		wantErr     bool
		wantLen     int
		wantRefresh bool // whether LastRefreshed should be non-nil
		clientIsNil bool
	}{
		{
			name:        "fetches and merges new keys",
			initialKeys: []string{key1Str},
			fetchKeys:   []string{key2Str},
			wantErr:     false,
			wantLen:     2,
			wantRefresh: true,
		},
		{
			name:        "network error preserves snapshot",
			initialKeys: []string{key1Str},
			fetchErr:    &TransportError{Type: TransportErrHTTPError, Message: "network fail"},
			wantErr:     true,
			wantLen:     1,
			wantRefresh: false,
		},
		{
			name:        "static mode - nil client is no-op",
			initialKeys: []string{key1Str},
			clientIsNil: true,
			wantErr:     false,
			wantLen:     1,
			wantRefresh: false,
		},
		{
			name:        "merge into empty store",
			initialKeys: []string{},
			fetchKeys:   []string{key1Str, key2Str},
			wantErr:     false,
			wantLen:     2,
			wantRefresh: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			initial, err := NewKeyStore(tt.initialKeys)
			if err != nil {
				t.Fatalf("failed to create initial store: %v", err)
			}

			var client Client
			if !tt.clientIsNil {
				mc := NewMockClient()
				if tt.fetchErr != nil {
					mc.WithError("root-keys", tt.fetchErr)
				} else {
					mc.WithRootKeys(tt.fetchKeys)
				}
				client = mc
			}

			rks := NewRefreshableKeyStore(initial, client,
				WithRefreshLogger(slog.Default()),
			)

			err = rks.DoRefresh(context.Background())
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if rks.Len() != tt.wantLen {
				t.Errorf("Len() = %d, want %d", rks.Len(), tt.wantLen)
			}

			lr := rks.LastRefreshed()
			if tt.wantRefresh && lr == nil {
				t.Error("expected LastRefreshed to be non-nil")
			}
			if !tt.wantRefresh && lr != nil {
				t.Errorf("expected LastRefreshed to be nil, got %v", lr)
			}
		})
	}
}

func TestRefreshableKeyStoreRefreshIfCooldownElapsed(t *testing.T) {
	t.Parallel()

	name1, kid1Hex, spki1B64, _ := mustGenerateTestKey(t)
	name2, kid2Hex, spki2B64, _ := mustGenerateTestKey(t)

	key1Str := fmt.Sprintf("%s+%s+%s", name1, kid1Hex, spki1B64)
	key2Str := fmt.Sprintf("%s+%s+%s", name2, kid2Hex, spki2B64)

	tests := []struct {
		name          string
		initialKeys   []string
		fetchKeys     []string
		cooldown      time.Duration
		clockOffset   time.Duration // how far past the initial time the clock returns
		preRefresh    bool          // whether to DoRefresh first to set lastRefreshed
		wantRefreshed bool
		wantLen       int
	}{
		{
			name:          "first refresh always triggers",
			initialKeys:   []string{key1Str},
			fetchKeys:     []string{key2Str},
			cooldown:      5 * time.Minute,
			wantRefreshed: true,
			wantLen:       2,
		},
		{
			name:          "within cooldown - skipped",
			initialKeys:   []string{key1Str},
			fetchKeys:     []string{key2Str},
			cooldown:      5 * time.Minute,
			clockOffset:   1 * time.Minute,
			preRefresh:    true,
			wantRefreshed: false,
			wantLen:       1,
		},
		{
			name:          "past cooldown - triggers",
			initialKeys:   []string{key1Str},
			fetchKeys:     []string{key2Str},
			cooldown:      5 * time.Minute,
			clockOffset:   6 * time.Minute,
			preRefresh:    true,
			wantRefreshed: true,
			wantLen:       2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			initial, err := NewKeyStore(tt.initialKeys)
			if err != nil {
				t.Fatalf("failed to create initial store: %v", err)
			}

			mc := NewMockClient().WithRootKeys(tt.fetchKeys)
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			currentTime := now

			rks := NewRefreshableKeyStore(initial, mc,
				WithCooldown(tt.cooldown),
				WithRefreshClock(func() time.Time { return currentTime }),
			)

			if tt.preRefresh {
				// Initial DoRefresh — but we give it an empty fetch so len stays at initial.
				mc2 := NewMockClient().WithRootKeys([]string{})
				rks.client = mc2
				if err := rks.DoRefresh(context.Background()); err != nil {
					t.Fatalf("pre-refresh failed: %v", err)
				}
				// Reset to the real mock for the cooldown test.
				rks.client = mc
				currentTime = now.Add(tt.clockOffset)
			}

			refreshed, err := rks.RefreshIfCooldownElapsed(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if refreshed != tt.wantRefreshed {
				t.Errorf("refreshed = %v, want %v", refreshed, tt.wantRefreshed)
			}
			if rks.Len() != tt.wantLen {
				t.Errorf("Len() = %d, want %d", rks.Len(), tt.wantLen)
			}
		})
	}
}

func TestRefreshIfCooldownElapsed_WithLogger(t *testing.T) {
	t.Parallel()

	name1, kid1Hex, spki1B64, _ := mustGenerateTestKey(t)
	key1Str := fmt.Sprintf("%s+%s+%s", name1, kid1Hex, spki1B64)

	initial, err := NewKeyStore([]string{key1Str})
	if err != nil {
		t.Fatalf("failed to create initial store: %v", err)
	}

	mc := NewMockClient().WithRootKeys([]string{})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	currentTime := now

	rks := NewRefreshableKeyStore(initial, mc,
		WithCooldown(5*time.Minute),
		WithRefreshClock(func() time.Time { return currentTime }),
		WithRefreshLogger(slog.Default()),
	)

	// Pre-refresh to set lastRefreshed.
	if err := rks.DoRefresh(context.Background()); err != nil {
		t.Fatalf("pre-refresh failed: %v", err)
	}

	// Within cooldown — should skip and log debug message.
	currentTime = now.Add(1 * time.Minute)
	refreshed, err := rks.RefreshIfCooldownElapsed(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if refreshed {
		t.Error("expected no refresh within cooldown")
	}
}

func TestRefreshIfCooldownElapsed_DoRefreshFails(t *testing.T) {
	t.Parallel()

	initial, err := NewKeyStore([]string{})
	if err != nil {
		t.Fatalf("failed to create initial store: %v", err)
	}

	mc := NewMockClient().WithError("root-keys", &TransportError{
		Type:    TransportErrHTTPError,
		Message: "server error",
	})

	rks := NewRefreshableKeyStore(initial, mc)

	refreshed, err := rks.RefreshIfCooldownElapsed(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if refreshed {
		t.Error("expected refreshed=false on error")
	}
}

func TestRefreshableKeyStoreBackgroundRefresh(t *testing.T) {
	t.Parallel()

	name1, kid1Hex, spki1B64, _ := mustGenerateTestKey(t)
	name2, kid2Hex, spki2B64, _ := mustGenerateTestKey(t)

	key1Str := fmt.Sprintf("%s+%s+%s", name1, kid1Hex, spki1B64)
	key2Str := fmt.Sprintf("%s+%s+%s", name2, kid2Hex, spki2B64)

	initial, err := NewKeyStore([]string{key1Str})
	if err != nil {
		t.Fatalf("failed to create initial store: %v", err)
	}

	mc := NewMockClient().WithRootKeys([]string{key2Str})
	rks := NewRefreshableKeyStore(initial, mc)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cancelBg := rks.StartBackgroundRefresh(ctx, 50*time.Millisecond)
	defer cancelBg()

	// Wait for at least one refresh cycle.
	deadline := time.After(2 * time.Second)
	for rks.Len() < 2 {
		select {
		case <-deadline:
			t.Fatalf("background refresh did not merge keys within deadline, Len()=%d", rks.Len())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestRefreshableKeyStoreConcurrentAccess(t *testing.T) {
	t.Parallel()

	name1, kid1Hex, spki1B64, _ := mustGenerateTestKey(t)
	key1Str := fmt.Sprintf("%s+%s+%s", name1, kid1Hex, spki1B64)

	initial, err := NewKeyStore([]string{key1Str})
	if err != nil {
		t.Fatalf("failed to create initial store: %v", err)
	}

	kidBytes, _ := hexDecodeKid(kid1Hex)
	mc := NewMockClient().WithRootKeys([]string{key1Str})
	rks := NewRefreshableKeyStore(initial, mc)

	var wg sync.WaitGroup
	const goroutines = 20

	// Half doing Get, half doing DoRefresh — test for races.
	for i := range goroutines {
		wg.Add(1)
		if i%2 == 0 {
			go func() {
				defer wg.Done()
				_, _ = rks.Get(kidBytes)
			}()
		} else {
			go func() {
				defer wg.Done()
				_ = rks.DoRefresh(context.Background())
			}()
		}
	}

	wg.Wait()

	// Verify store is still consistent.
	if rks.Len() < 1 {
		t.Errorf("expected at least 1 key after concurrent access, got %d", rks.Len())
	}
}

func TestRefreshableKeyStoreStartBackgroundRefreshDefault(t *testing.T) {
	t.Parallel()

	initial, err := NewKeyStore([]string{})
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	mc := NewMockClient().WithRootKeys([]string{})
	rks := NewRefreshableKeyStore(initial, mc)

	ctx, cancel := context.WithCancel(context.Background())
	cancelBg := rks.StartBackgroundRefreshDefault(ctx)

	// Immediately cancel — just verify it starts without panic.
	cancel()
	cancelBg()
}

// hexDecodeKid is a test helper that decodes a hex kid string to [4]byte.
func hexDecodeKid(kidHex string) ([4]byte, error) {
	var kid [4]byte
	raw, err := hex.DecodeString(kidHex)
	if err != nil {
		return kid, err
	}
	copy(kid[:], raw)
	return kid, nil
}

// mustEmptyStore creates an empty KeyStore for tests.
func mustEmptyStore(t *testing.T) *KeyStore {
	t.Helper()
	s, err := NewKeyStore([]string{})
	if err != nil {
		t.Fatalf("failed to create empty store: %v", err)
	}
	return s
}
