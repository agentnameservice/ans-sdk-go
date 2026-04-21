package scitt

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestOutgoingHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		headers   *OutgoingHeaders
		wantEmpty bool
	}{
		{
			name:      "empty when both fields empty",
			headers:   &OutgoingHeaders{},
			wantEmpty: true,
		},
		{
			name:      "not empty with receipt",
			headers:   &OutgoingHeaders{ReceiptBase64: "abc"},
			wantEmpty: false,
		},
		{
			name:      "not empty with status token",
			headers:   &OutgoingHeaders{StatusTokenBase64: "xyz"},
			wantEmpty: false,
		},
		{
			name: "not empty with both",
			headers: &OutgoingHeaders{
				ReceiptBase64:     "abc",
				StatusTokenBase64: "xyz",
			},
			wantEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.headers.IsEmpty(); got != tt.wantEmpty {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.wantEmpty)
			}
		})
	}
}

func TestOutgoingHeadersToHTTPHeaders(t *testing.T) {
	t.Parallel()

	receipt := []byte("receipt-data")
	token := []byte("token-data")

	h := &OutgoingHeaders{
		ReceiptBase64:     base64.StdEncoding.EncodeToString(receipt),
		StatusTokenBase64: base64.StdEncoding.EncodeToString(token),
	}

	httpHeaders, err := h.ToHTTPHeaders()
	if err != nil {
		t.Fatalf("ToHTTPHeaders() unexpected error: %v", err)
	}

	gotReceipt := httpHeaders.Get(HeaderReceipt) //nolint:canonicalheader // spec-defined header names
	if gotReceipt != h.ReceiptBase64 {
		t.Errorf("receipt header = %q, want %q", gotReceipt, h.ReceiptBase64)
	}

	gotToken := httpHeaders.Get(HeaderStatusToken) //nolint:canonicalheader // spec-defined header names
	if gotToken != h.StatusTokenBase64 {
		t.Errorf("status token header = %q, want %q", gotToken, h.StatusTokenBase64)
	}
}

func TestOutgoingHeadersToHTTPHeadersEmpty(t *testing.T) {
	t.Parallel()

	h := &OutgoingHeaders{}
	httpHeaders, err := h.ToHTTPHeaders()
	if err != nil {
		t.Fatalf("ToHTTPHeaders() unexpected error: %v", err)
	}

	if gotReceipt := httpHeaders.Get(HeaderReceipt); gotReceipt != "" { //nolint:canonicalheader // spec-defined header names
		t.Errorf("expected no receipt header, got %q", gotReceipt)
	}
	if gotToken := httpHeaders.Get(HeaderStatusToken); gotToken != "" { //nolint:canonicalheader // spec-defined header names
		t.Errorf("expected no token header, got %q", gotToken)
	}
}

func TestOutgoingHeadersToHTTPHeadersMalformedBase64(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers *OutgoingHeaders
		wantErr string
	}{
		{
			name:    "invalid receipt base64",
			headers: &OutgoingHeaders{ReceiptBase64: "!!!not-base64"},
			wantErr: "decode receipt base64",
		},
		{
			name:    "invalid status token base64",
			headers: &OutgoingHeaders{StatusTokenBase64: "!!!not-base64"},
			wantErr: "decode status token base64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.headers.ToHTTPHeaders()
			if err == nil {
				t.Fatalf("ToHTTPHeaders() expected error, got nil (headers=%v)", got)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ToHTTPHeaders() error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestHeaderSupplierCurrentHeaders(t *testing.T) {
	t.Parallel()

	receiptData := []byte("receipt-bytes")
	tokenData := []byte("token-bytes")

	tests := []struct {
		name        string
		setupClient func() Client
		setupStore  func() *RefreshableKeyStore
		wantEmpty   bool
		wantReceipt string
		wantToken   string
	}{
		{
			name: "returns empty when client fails",
			setupClient: func() Client {
				return NewMockClient().
					WithError("agent-1", &TransportError{
						Type:    TransportErrNotFound,
						Message: "not found",
					})
			},
			setupStore: func() *RefreshableKeyStore {
				store, _ := NewKeyStore([]string{})
				return NewRefreshableKeyStore(store, nil)
			},
			wantEmpty: true,
		},
		{
			name: "returns empty when receipt fetch fails",
			setupClient: func() Client {
				mc := NewMockClient()
				mc.WithError("agent-1", &TransportError{
					Type:    TransportErrHTTPError,
					Message: "server error",
				})
				return mc
			},
			setupStore: func() *RefreshableKeyStore {
				store, _ := NewKeyStore([]string{})
				return NewRefreshableKeyStore(store, nil)
			},
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			supplier := NewHeaderSupplier("agent-1", tt.setupClient(), tt.setupStore(),
				WithInitTimeout(1*time.Second),
			)

			headers := supplier.CurrentHeaders()

			if tt.wantEmpty {
				if !headers.IsEmpty() {
					t.Errorf("expected empty headers, got receipt=%q token=%q",
						headers.ReceiptBase64, headers.StatusTokenBase64)
				}
				return
			}

			_ = receiptData
			_ = tokenData
			if headers.ReceiptBase64 != tt.wantReceipt {
				t.Errorf("receipt = %q, want %q", headers.ReceiptBase64, tt.wantReceipt)
			}
			if headers.StatusTokenBase64 != tt.wantToken {
				t.Errorf("token = %q, want %q", headers.StatusTokenBase64, tt.wantToken)
			}
		})
	}
}

func TestHeaderSupplierHealthy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		setup       func() *HeaderSupplier
		wantHealthy bool
	}{
		{
			name: "not healthy before init",
			setup: func() *HeaderSupplier {
				store, _ := NewKeyStore([]string{})
				rks := NewRefreshableKeyStore(store, nil)
				return NewHeaderSupplier("agent-1", NewMockClient(), rks)
			},
			wantHealthy: false,
		},
		{
			name: "not healthy after failed init",
			setup: func() *HeaderSupplier {
				mc := NewMockClient().WithError("agent-1", &TransportError{
					Type:    TransportErrHTTPError,
					Message: "fail",
				})
				store, _ := NewKeyStore([]string{})
				rks := NewRefreshableKeyStore(store, nil)
				s := NewHeaderSupplier("agent-1", mc, rks,
					WithInitTimeout(500*time.Millisecond),
				)
				_ = s.CurrentHeaders() // trigger init
				return s
			},
			wantHealthy: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := tt.setup()
			if got := s.Healthy(); got != tt.wantHealthy {
				t.Errorf("Healthy() = %v, want %v", got, tt.wantHealthy)
			}
		})
	}
}

func TestHeaderSupplierLastError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func() *HeaderSupplier
		wantNil bool
	}{
		{
			name: "nil before any operation",
			setup: func() *HeaderSupplier {
				store, _ := NewKeyStore([]string{})
				rks := NewRefreshableKeyStore(store, nil)
				return NewHeaderSupplier("agent-1", NewMockClient(), rks)
			},
			wantNil: true,
		},
		{
			name: "non-nil after failed init",
			setup: func() *HeaderSupplier {
				mc := NewMockClient().WithError("agent-1", &TransportError{
					Type:    TransportErrHTTPError,
					Message: "fail",
				})
				store, _ := NewKeyStore([]string{})
				rks := NewRefreshableKeyStore(store, nil)
				s := NewHeaderSupplier("agent-1", mc, rks,
					WithInitTimeout(500*time.Millisecond),
				)
				_ = s.CurrentHeaders()
				return s
			},
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := tt.setup()
			err := s.LastError()
			if tt.wantNil && err != nil {
				t.Errorf("LastError() = %v, want nil", err)
			}
			if !tt.wantNil && err == nil {
				t.Error("LastError() = nil, want non-nil")
			}
		})
	}
}

func TestHeaderSupplierRefreshNow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func() (*HeaderSupplier, Client)
		wantErr bool
	}{
		{
			name: "returns error when client fails",
			setup: func() (*HeaderSupplier, Client) {
				mc := NewMockClient().WithError("agent-1", &TransportError{
					Type:    TransportErrHTTPError,
					Message: "server error",
				})
				store, _ := NewKeyStore([]string{})
				rks := NewRefreshableKeyStore(store, nil)
				s := NewHeaderSupplier("agent-1", mc, rks)
				return s, mc
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, _ := tt.setup()
			err := s.RefreshNow(context.Background())
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestHeaderSupplierStaticKeysConstructor(t *testing.T) {
	t.Parallel()

	store, err := NewKeyStore([]string{})
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	mc := NewMockClient().WithError("agent-1", &TransportError{
		Type:    TransportErrHTTPError,
		Message: "fail",
	})

	s := NewHeaderSupplierWithStaticKeys("agent-1", mc, store,
		WithInitTimeout(500*time.Millisecond),
	)

	if s == nil {
		t.Fatal("NewHeaderSupplierWithStaticKeys returned nil")
	}

	// The supplier should exist and be callable.
	headers := s.CurrentHeaders()
	if headers == nil {
		t.Fatal("CurrentHeaders returned nil")
	}
}

func TestHeaderSupplierAutoRefreshStartStop(t *testing.T) {
	t.Parallel()

	store, _ := NewKeyStore([]string{})
	rks := NewRefreshableKeyStore(store, nil)
	mc := NewMockClient().WithReceipt("agent-1", []byte("r")).
		WithStatusToken("agent-1", []byte("t"))

	s := NewHeaderSupplier("agent-1", mc, rks)

	ctx := context.Background()
	cancel := s.StartAutoRefresh(ctx)

	// Immediately cancel — just verify it starts and stops without panic.
	cancel()
}

// TestNewHeaderSupplierDefaults verifies default option values.
func TestNewHeaderSupplierDefaults(t *testing.T) {
	t.Parallel()

	store, _ := NewKeyStore([]string{})
	rks := NewRefreshableKeyStore(store, nil)
	mc := NewMockClient()

	s := NewHeaderSupplier("agent-1", mc, rks)

	if s.clockSkew != defaultSupplierClockSkew {
		t.Errorf("clockSkew = %v, want %v", s.clockSkew, defaultSupplierClockSkew)
	}
	if s.initTimeout != defaultSupplierInitTimeout {
		t.Errorf("initTimeout = %v, want %v", s.initTimeout, defaultSupplierInitTimeout)
	}
	if s.agentID != "agent-1" {
		t.Errorf("agentID = %q, want %q", s.agentID, "agent-1")
	}

	// Should not be initialized or healthy yet.
	if s.Healthy() {
		t.Error("expected not healthy before init")
	}
	if s.LastError() != nil {
		t.Error("expected nil LastError before any operation")
	}
}

func TestHeaderSupplierOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		opts        []HeaderSupplierOption
		wantSkew    time.Duration
		wantTimeout time.Duration
	}{
		{
			name:        "defaults",
			opts:        nil,
			wantSkew:    defaultSupplierClockSkew,
			wantTimeout: defaultSupplierInitTimeout,
		},
		{
			name:        "custom clock skew",
			opts:        []HeaderSupplierOption{WithSupplierClockSkew(1 * time.Minute)},
			wantSkew:    1 * time.Minute,
			wantTimeout: defaultSupplierInitTimeout,
		},
		{
			name:        "custom init timeout",
			opts:        []HeaderSupplierOption{WithInitTimeout(10 * time.Second)},
			wantSkew:    defaultSupplierClockSkew,
			wantTimeout: 10 * time.Second,
		},
		{
			name: "all custom",
			opts: []HeaderSupplierOption{
				WithSupplierClockSkew(45 * time.Second),
				WithInitTimeout(5 * time.Second),
			},
			wantSkew:    45 * time.Second,
			wantTimeout: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, _ := NewKeyStore([]string{})
			rks := NewRefreshableKeyStore(store, nil)
			s := NewHeaderSupplier("agent-1", NewMockClient(), rks, tt.opts...)

			if s.clockSkew != tt.wantSkew {
				t.Errorf("clockSkew = %v, want %v", s.clockSkew, tt.wantSkew)
			}
			if s.initTimeout != tt.wantTimeout {
				t.Errorf("initTimeout = %v, want %v", s.initTimeout, tt.wantTimeout)
			}
		})
	}
}

func TestWithSupplierClockSkew_Clamping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    time.Duration
		wantSkew time.Duration
	}{
		{
			name:     "negative clamped to zero",
			input:    -1 * time.Minute,
			wantSkew: 0,
		},
		{
			name:     "massive clamped to MaxClockSkew",
			input:    100 * 24 * time.Hour,
			wantSkew: MaxClockSkew,
		},
		{
			name:     "normal passes through",
			input:    5 * time.Minute,
			wantSkew: 5 * time.Minute,
		},
		{
			name:     "exactly MaxClockSkew allowed",
			input:    MaxClockSkew,
			wantSkew: MaxClockSkew,
		},
		{
			name:     "zero stays zero",
			input:    0,
			wantSkew: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, _ := NewKeyStore([]string{})
			rks := NewRefreshableKeyStore(store, nil)
			s := NewHeaderSupplier("agent-1", NewMockClient(), rks,
				WithSupplierClockSkew(tt.input),
			)

			if s.clockSkew != tt.wantSkew {
				t.Errorf("clockSkew = %v, want %v", s.clockSkew, tt.wantSkew)
			}
		})
	}
}

func TestOutgoingHeaders_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers *OutgoingHeaders
		want    string
	}{
		{
			name:    "empty headers",
			headers: &OutgoingHeaders{},
			want:    "OutgoingHeaders{empty}",
		},
		{
			name:    "receipt only",
			headers: &OutgoingHeaders{ReceiptBase64: "abc"},
			want:    "OutgoingHeaders{receipt=3 chars, token=0 chars}",
		},
		{
			name: "both populated",
			headers: &OutgoingHeaders{
				ReceiptBase64:     "abcdef",
				StatusTokenBase64: "xyz",
			},
			want: "OutgoingHeaders{receipt=6 chars, token=3 chars}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.headers.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHeaderSupplierWithClockAndLogger(t *testing.T) {
	t.Parallel()

	store, _ := NewKeyStore([]string{})
	rks := NewRefreshableKeyStore(store, nil)
	mc := NewMockClient()

	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fixedClock := func() time.Time { return fixedTime }

	logger := slog.Default()

	s := NewHeaderSupplier("agent-1", mc, rks,
		WithSupplierClock(fixedClock),
		WithSupplierLogger(logger),
	)

	// Verify clock was set by checking it returns the fixed time.
	if got := s.clock(); !got.Equal(fixedTime) {
		t.Errorf("clock() = %v, want %v", got, fixedTime)
	}
	if s.logger != logger {
		t.Error("logger was not set by WithSupplierLogger")
	}
}

func TestEncodeIfNonEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "nil returns empty",
			data: nil,
			want: "",
		},
		{
			name: "empty slice returns empty",
			data: []byte{},
			want: "",
		},
		{
			name: "non-empty returns base64",
			data: []byte("hello"),
			want: base64.StdEncoding.EncodeToString([]byte("hello")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := encodeIfNonEmpty(tt.data); got != tt.want {
				t.Errorf("encodeIfNonEmpty() = %q, want %q", got, tt.want)
			}
		})
	}
}

// buildSupplierTestFixture creates a valid receipt + token pair and matching key store for supplier tests.
func buildSupplierTestFixture(t *testing.T) ([]byte, []byte, *RefreshableKeyStore) {
	t.Helper()

	bundle := generateTestKey(t, "supplier-test")

	vds := int64(1)
	receipt := buildValidReceipt(t, bundle, []byte("test-payload"), &vds, nil, nil, 1, 0, nil)

	now := time.Now()
	payload := buildStatusPayloadCBOR(t, "agent-1", "ans://v1.0.0.test.example.com",
		StatusActive, now.Unix(), now.Add(1*time.Hour).Unix(), nil, nil, nil)
	token := signStatusToken(t, bundle.priv, bundle.kid, payload, nil)

	// Build a proper KeyStore from C2SP key string.
	ks := buildKeyStoreFromBundle(t, bundle)
	rks := NewRefreshableKeyStore(ks, nil)

	return receipt, token, rks
}

// buildKeyStoreFromBundle creates a KeyStore from a testKeyBundle using C2SP format.
func buildKeyStoreFromBundle(t *testing.T, bundle *testKeyBundle) *KeyStore {
	t.Helper()

	spkiDer, err := x509.MarshalPKIXPublicKey(bundle.pub)
	if err != nil {
		t.Fatalf("failed to marshal SPKI: %v", err)
	}

	kidHex := hex.EncodeToString(bundle.kid[:])
	spkiB64 := base64.StdEncoding.EncodeToString(spkiDer)
	keyStr := fmt.Sprintf("%s+%s+%s", bundle.name, kidHex, spkiB64)

	ks, err := NewKeyStore([]string{keyStr})
	if err != nil {
		t.Fatalf("failed to create key store: %v", err)
	}
	return ks
}

func TestHeaderSupplier_FetchAndVerify(t *testing.T) {
	t.Parallel()

	receiptBytes, tokenBytes, rks := buildSupplierTestFixture(t)

	tests := []struct {
		name        string
		setupClient func() Client
		store       *RefreshableKeyStore
		wantErr     bool
	}{
		{
			name: "FetchReceipt fails",
			setupClient: func() Client {
				return NewMockClient().WithError("agent-1", &TransportError{
					Type:    TransportErrHTTPError,
					Message: "receipt fetch error",
				})
			},
			store:   rks,
			wantErr: true,
		},
		{
			name: "VerifyReceipt fails with garbage bytes",
			setupClient: func() Client {
				return NewMockClient().
					WithReceipt("agent-1", []byte{0xDE, 0xAD}).
					WithStatusToken("agent-1", tokenBytes)
			},
			store:   rks,
			wantErr: true,
		},
		{
			name: "VerifyStatusToken fails with garbage token",
			setupClient: func() Client {
				return NewMockClient().
					WithReceipt("agent-1", receiptBytes).
					WithStatusToken("agent-1", []byte{0xCA, 0xFE})
			},
			store:   rks,
			wantErr: true,
		},
		{
			name: "full success",
			setupClient: func() Client {
				return NewMockClient().
					WithReceipt("agent-1", receiptBytes).
					WithStatusToken("agent-1", tokenBytes)
			},
			store:   rks,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := NewHeaderSupplier("agent-1", tt.setupClient(), tt.store,
				WithInitTimeout(2*time.Second),
				WithSupplierClockSkew(1*time.Minute),
			)

			err := s.RefreshNow(context.Background())
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if s.LastError() != nil {
				t.Errorf("expected nil LastError, got %v", s.LastError())
			}
			headers := s.CurrentHeaders()
			if headers.IsEmpty() {
				t.Error("expected non-empty headers after successful refresh")
			}
		})
	}
}

func TestHeaderSupplier_FetchAndVerify_ClearsError(t *testing.T) {
	t.Parallel()

	receiptBytes, tokenBytes, rks := buildSupplierTestFixture(t)

	// First call fails.
	mc := NewMockClient().WithError("agent-1", &TransportError{
		Type:    TransportErrHTTPError,
		Message: "fail",
	})
	s := NewHeaderSupplier("agent-1", mc, rks,
		WithInitTimeout(1*time.Second),
		WithSupplierClockSkew(1*time.Minute),
	)

	err := s.RefreshNow(context.Background())
	if err == nil {
		t.Fatal("expected error on first call")
	}
	if s.LastError() == nil {
		t.Fatal("expected non-nil LastError after failure")
	}

	// Swap to working client and retry.
	mc2 := NewMockClient().
		WithReceipt("agent-1", receiptBytes).
		WithStatusToken("agent-1", tokenBytes)
	s.client = mc2

	err = s.RefreshNow(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on retry: %v", err)
	}
	if s.LastError() != nil {
		t.Errorf("expected nil LastError after success, got %v", s.LastError())
	}
}

func TestHeaderSupplier_InitOnce(t *testing.T) {
	t.Parallel()

	receiptBytes, tokenBytes, rks := buildSupplierTestFixture(t)

	tests := []struct {
		name        string
		setupClient func() Client
		useLogger   bool
		wantHealthy bool
	}{
		{
			name: "successful init marks healthy",
			setupClient: func() Client {
				return NewMockClient().
					WithReceipt("agent-1", receiptBytes).
					WithStatusToken("agent-1", tokenBytes)
			},
			wantHealthy: true,
		},
		{
			name: "failed init with logger does not panic",
			setupClient: func() Client {
				return NewMockClient().WithError("agent-1", &TransportError{
					Type:    TransportErrHTTPError,
					Message: "fail",
				})
			},
			useLogger:   true,
			wantHealthy: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := []HeaderSupplierOption{
				WithInitTimeout(2 * time.Second),
				WithSupplierClockSkew(1 * time.Minute),
			}
			if tt.useLogger {
				opts = append(opts, WithSupplierLogger(slog.Default()))
			}

			s := NewHeaderSupplier("agent-1", tt.setupClient(), rks, opts...)
			_ = s.CurrentHeaders() // triggers initOnce

			if s.Healthy() != tt.wantHealthy {
				t.Errorf("Healthy() = %v, want %v", s.Healthy(), tt.wantHealthy)
			}
		})
	}
}

func TestHeaderSupplier_InitOnce_RetryAfterFailure(t *testing.T) {
	t.Parallel()

	receiptBytes, tokenBytes, rks := buildSupplierTestFixture(t)

	mc := NewMockClient().WithError("agent-1", &TransportError{
		Type:    TransportErrHTTPError,
		Message: "transient fail",
	})

	s := NewHeaderSupplier("agent-1", mc, rks,
		WithInitTimeout(1*time.Second),
		WithSupplierClockSkew(1*time.Minute),
	)

	_ = s.CurrentHeaders() // first init fails
	if s.Healthy() {
		t.Fatal("expected not healthy after failed init")
	}

	// Swap to working client.
	s.client = NewMockClient().
		WithReceipt("agent-1", receiptBytes).
		WithStatusToken("agent-1", tokenBytes)

	_ = s.CurrentHeaders() // retries since not initialized
	if !s.Healthy() {
		t.Error("expected healthy after successful retry")
	}
}

func TestHeaderSupplier_ComputeRefreshInterval(t *testing.T) {
	t.Parallel()

	// computeRefreshInterval uses time.Until (real clock), so exp must be relative to now.
	now := time.Now()

	tests := []struct {
		name    string
		exp     *int64
		minWant time.Duration
		maxWant time.Duration
	}{
		{
			name:    "nil expiry returns minimum",
			exp:     nil,
			minWant: minAutoRefreshInterval,
			maxWant: minAutoRefreshInterval,
		},
		{
			name:    "future expiry 100s",
			exp:     int64Ptr(now.Add(100 * time.Second).Unix()),
			minWant: 44 * time.Second,
			maxWant: 56 * time.Second,
		},
		{
			name:    "very short TTL clamped to minimum",
			exp:     int64Ptr(now.Add(2 * time.Second).Unix()),
			minWant: minAutoRefreshInterval,
			maxWant: minAutoRefreshInterval,
		},
		{
			name:    "past expiry clamped to minimum",
			exp:     int64Ptr(now.Add(-100 * time.Second).Unix()),
			minWant: minAutoRefreshInterval,
			maxWant: minAutoRefreshInterval,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, _ := NewKeyStore([]string{})
			rks := NewRefreshableKeyStore(store, nil)
			s := NewHeaderSupplier("agent-1", NewMockClient(), rks)
			s.tokenExp = tt.exp

			got := s.computeRefreshInterval()
			if got < tt.minWant || got > tt.maxWant {
				t.Errorf("computeRefreshInterval() = %v, want in [%v, %v]", got, tt.minWant, tt.maxWant)
			}
		})
	}
}

func TestHeaderSupplier_AutoRefreshLoop_Success(t *testing.T) {
	t.Parallel()

	receiptBytes, tokenBytes, rks := buildSupplierTestFixture(t)

	mc := NewMockClient().
		WithReceipt("agent-1", receiptBytes).
		WithStatusToken("agent-1", tokenBytes)

	// Use a clock that returns a fixed time to make computeRefreshInterval return minimum.
	s := NewHeaderSupplier("agent-1", mc, rks,
		WithSupplierClockSkew(1*time.Minute),
	)
	// Set tokenExp to nil so computeRefreshInterval returns minAutoRefreshInterval (10s).
	// The auto-refresh loop will fire after that interval.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = s.StartAutoRefresh(ctx)

	// Poll for healthy state.
	deadline := time.After(15 * time.Second)
	for !s.Healthy() {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for auto-refresh to set healthy")
		case <-time.After(100 * time.Millisecond):
		}
	}

	cancel()
}

func TestHeaderSupplier_AutoRefreshLoop_FailureWithLogger(t *testing.T) {
	t.Parallel()

	mc := NewMockClient().WithError("agent-1", &TransportError{
		Type:    TransportErrHTTPError,
		Message: "auto-refresh fail",
	})

	store, _ := NewKeyStore([]string{})
	rks := NewRefreshableKeyStore(store, nil)

	s := NewHeaderSupplier("agent-1", mc, rks,
		WithSupplierLogger(slog.Default()),
	)

	ctx, cancel := context.WithCancel(context.Background())
	_ = s.StartAutoRefresh(ctx)

	// Poll for LastError to be set (meaning auto-refresh loop ran and failed).
	deadline := time.After(15 * time.Second)
	for s.LastError() == nil {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for auto-refresh failure")
		case <-time.After(100 * time.Millisecond):
		}
	}

	cancel()

	if s.Healthy() {
		t.Error("expected not healthy after auto-refresh failure")
	}
}

func TestHeaderSupplier_CurrentHeaders_ExpiryFiltering(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	nowUnix := fixedNow.Unix()

	tests := []struct {
		name        string
		tokenExp    *int64
		clockTime   time.Time
		wantToken   bool
		wantWarnLog bool
	}{
		{
			name:        "token not expired — returned",
			tokenExp:    int64Ptr(nowUnix + 3600),
			clockTime:   fixedNow,
			wantToken:   true,
			wantWarnLog: false,
		},
		{
			name:        "token expired — suppressed",
			tokenExp:    int64Ptr(nowUnix - 60),
			clockTime:   fixedNow,
			wantToken:   false,
			wantWarnLog: true,
		},
		{
			name:        "tokenExp nil — token returned",
			tokenExp:    nil,
			clockTime:   fixedNow,
			wantToken:   true,
			wantWarnLog: false,
		},
		{
			name:        "clock exactly at exp boundary — suppressed",
			tokenExp:    int64Ptr(nowUnix),
			clockTime:   fixedNow,
			wantToken:   false,
			wantWarnLog: true,
		},
		{
			name:        "clock one second before exp — returned",
			tokenExp:    int64Ptr(nowUnix),
			clockTime:   fixedNow.Add(-1 * time.Second),
			wantToken:   true,
			wantWarnLog: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

			store, _ := NewKeyStore([]string{})
			rks := NewRefreshableKeyStore(store, nil)
			s := NewHeaderSupplier("agent-1", NewMockClient(), rks,
				WithSupplierClock(func() time.Time { return tt.clockTime }),
				WithSupplierLogger(logger),
			)

			s.mu.Lock()
			s.initialized = true
			s.receipt = []byte("fake-receipt")
			s.statusToken = []byte("fake-token")
			s.tokenExp = tt.tokenExp
			s.mu.Unlock()

			headers := s.CurrentHeaders()

			if headers.ReceiptBase64 == "" {
				t.Error("receipt should always be returned")
			}

			gotToken := headers.StatusTokenBase64 != ""
			if gotToken != tt.wantToken {
				t.Errorf("StatusTokenBase64 present = %v, want %v", gotToken, tt.wantToken)
			}

			gotWarn := strings.Contains(logBuf.String(), "suppressed expired status token")
			if gotWarn != tt.wantWarnLog {
				t.Errorf("WARN log present = %v, want %v (log: %q)", gotWarn, tt.wantWarnLog, logBuf.String())
			}
		})
	}
}

func int64Ptr(v int64) *int64 {
	return &v
}

// Compile-time interface assertions.
var _ fmt.Stringer = (*OutgoingHeaders)(nil)
