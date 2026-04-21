package scitt

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"
)

// Default HeaderSupplier configuration values.
const (
	defaultSupplierClockSkew   = 30 * time.Second
	defaultSupplierInitTimeout = 30 * time.Second
	minAutoRefreshInterval     = 10 * time.Second
)

// OutgoingHeaders holds base64-encoded SCITT proof headers ready for HTTP transport.
type OutgoingHeaders struct {
	ReceiptBase64     string
	StatusTokenBase64 string
}

// IsEmpty returns true when neither header has a value.
func (h *OutgoingHeaders) IsEmpty() bool {
	return h.ReceiptBase64 == "" && h.StatusTokenBase64 == ""
}

// String implements fmt.Stringer for logging.
func (h *OutgoingHeaders) String() string {
	if h.IsEmpty() {
		return "OutgoingHeaders{empty}"
	}
	return fmt.Sprintf("OutgoingHeaders{receipt=%d chars, token=%d chars}",
		len(h.ReceiptBase64), len(h.StatusTokenBase64))
}

// ToHTTPHeaders converts to http.Header using GenerateHeaders. The raw bytes
// are reconstructed from the base64 strings — this round-trip is intentional
// to ensure consistency with the canonical GenerateHeaders encoding.
// Returns an error if either base64 field is malformed.
func (h *OutgoingHeaders) ToHTTPHeaders() (http.Header, error) {
	var receipt, token []byte
	var err error
	if h.ReceiptBase64 != "" {
		receipt, err = base64.StdEncoding.DecodeString(h.ReceiptBase64)
		if err != nil {
			return nil, fmt.Errorf("decode receipt base64: %w", err)
		}
	}
	if h.StatusTokenBase64 != "" {
		token, err = base64.StdEncoding.DecodeString(h.StatusTokenBase64)
		if err != nil {
			return nil, fmt.Errorf("decode status token base64: %w", err)
		}
	}
	return GenerateHeaders(receipt, token), nil
}

// HeaderSupplier fetches, verifies, caches, and base64-encodes SCITT proof
// headers for agent-side HTTP requests. Thread-safe.
type HeaderSupplier struct {
	agentID     string
	client      Client
	keyStore    *RefreshableKeyStore
	clockSkew   time.Duration
	clock       ClockFunc
	initTimeout time.Duration
	logger      *slog.Logger

	mu          sync.RWMutex
	receipt     []byte // raw COSE_Sign1
	statusToken []byte // raw COSE_Sign1
	tokenExp    *int64 // for refresh scheduling
	initialized bool
	lastError   error

	initGate sync.Mutex // serializes init attempts
}

// HeaderSupplierOption configures a HeaderSupplier.
type HeaderSupplierOption func(*HeaderSupplier)

// WithInitTimeout sets the timeout for the lazy initialization fetch.
func WithInitTimeout(d time.Duration) HeaderSupplierOption {
	return func(s *HeaderSupplier) {
		s.initTimeout = d
	}
}

// WithSupplierClockSkew sets the clock skew tolerance for token verification.
// Negative values are clamped to 0. Values exceeding MaxClockSkew are clamped.
func WithSupplierClockSkew(d time.Duration) HeaderSupplierOption {
	return func(s *HeaderSupplier) {
		if d < 0 {
			d = 0
		}
		if d > MaxClockSkew {
			d = MaxClockSkew
		}
		s.clockSkew = d
	}
}

// WithSupplierClock sets the clock function.
func WithSupplierClock(clock ClockFunc) HeaderSupplierOption {
	return func(s *HeaderSupplier) {
		s.clock = clock
	}
}

// WithSupplierLogger sets the logger.
func WithSupplierLogger(logger *slog.Logger) HeaderSupplierOption {
	return func(s *HeaderSupplier) {
		s.logger = logger
	}
}

// NewHeaderSupplier creates a HeaderSupplier backed by a RefreshableKeyStore.
func NewHeaderSupplier(agentID string, client Client, keyStore *RefreshableKeyStore, opts ...HeaderSupplierOption) *HeaderSupplier {
	s := &HeaderSupplier{
		agentID:     agentID,
		client:      client,
		keyStore:    keyStore,
		clockSkew:   defaultSupplierClockSkew,
		clock:       time.Now,
		initTimeout: defaultSupplierInitTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// NewHeaderSupplierWithStaticKeys creates a HeaderSupplier using a plain
// KeyStore wrapped in a static (no-refresh) RefreshableKeyStore.
func NewHeaderSupplierWithStaticKeys(agentID string, client Client, keyStore *KeyStore, opts ...HeaderSupplierOption) *HeaderSupplier {
	rks := NewRefreshableKeyStore(keyStore, nil)
	return NewHeaderSupplier(agentID, client, rks, opts...)
}

// CurrentHeaders returns the current base64-encoded SCITT headers. On first
// call, triggers lazy initialization with a timeout. Returns empty headers
// if init fails or times out — never blocks indefinitely.
func (s *HeaderSupplier) CurrentHeaders() *OutgoingHeaders {
	s.mu.RLock()
	initialized := s.initialized
	receipt := s.receipt
	token := s.statusToken
	tokenExp := s.tokenExp
	s.mu.RUnlock()

	if !initialized {
		s.initOnce()

		s.mu.RLock()
		receipt = s.receipt
		token = s.statusToken
		tokenExp = s.tokenExp
		s.mu.RUnlock()
	}

	if token != nil && tokenExp != nil && s.clock().Unix() >= *tokenExp {
		token = nil
		s.logger.Warn("suppressed expired status token from outgoing headers",
			slog.Int64("exp", *tokenExp))
	}

	return &OutgoingHeaders{
		ReceiptBase64:     encodeIfNonEmpty(receipt),
		StatusTokenBase64: encodeIfNonEmpty(token),
	}
}

// RefreshNow forces an immediate re-fetch and verification of receipt and
// status token.
func (s *HeaderSupplier) RefreshNow(ctx context.Context) error {
	return s.fetchAndVerify(ctx)
}

// StartAutoRefresh spawns a background goroutine that refreshes at 50% of
// the remaining token TTL (min 10s) with ±10% jitter. Returns a cancel func.
func (s *HeaderSupplier) StartAutoRefresh(ctx context.Context) context.CancelFunc {
	bgCtx, cancel := context.WithCancel(ctx)
	go s.autoRefreshLoop(bgCtx)
	return cancel
}

// LastError returns the most recent fetch or verification error.
func (s *HeaderSupplier) LastError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastError
}

// Healthy returns true if initialized and no recent errors.
func (s *HeaderSupplier) Healthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.initialized && s.lastError == nil
}

// initOnce performs lazy initialization with timeout. Uses sync.Mutex + bool
// (NOT sync.Once) so transient failures can be retried on next call.
func (s *HeaderSupplier) initOnce() {
	s.initGate.Lock()
	defer s.initGate.Unlock()

	// Re-check after acquiring gate.
	s.mu.RLock()
	if s.initialized {
		s.mu.RUnlock()
		return
	}
	s.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), s.initTimeout)
	defer cancel()

	err := s.fetchAndVerify(ctx)
	if err != nil {
		s.mu.Lock()
		s.lastError = err
		s.mu.Unlock()

		if s.logger != nil {
			s.logger.Warn("header supplier init failed",
				"agent_id", s.agentID,
				"error", err,
			)
		}
		return
	}

	s.mu.Lock()
	s.initialized = true
	s.lastError = nil
	s.mu.Unlock()
}

// fetchAndVerify fetches receipt + status token, verifies each against the
// key store, and caches the raw bytes.
func (s *HeaderSupplier) fetchAndVerify(ctx context.Context) error {
	receiptBytes, err := s.client.FetchReceipt(ctx, s.agentID)
	if err != nil {
		return s.recordError(err)
	}

	tokenBytes, err := s.client.FetchStatusToken(ctx, s.agentID)
	if err != nil {
		return s.recordError(err)
	}

	// Verify receipt.
	_, err = VerifyReceipt(receiptBytes, s.keyStore)
	if err != nil {
		return s.recordError(err)
	}

	// Verify status token.
	now := s.clock().Unix()
	verified, err := VerifyStatusTokenAt(tokenBytes, s.keyStore, s.clockSkew, now)
	if err != nil {
		return s.recordError(err)
	}

	// Cache verified artifacts.
	s.mu.Lock()
	s.receipt = receiptBytes
	s.statusToken = tokenBytes
	s.tokenExp = &verified.Payload.Exp
	s.lastError = nil
	s.mu.Unlock()

	return nil
}

// recordError stores the error under the write lock and returns it for chaining.
func (s *HeaderSupplier) recordError(err error) error {
	s.mu.Lock()
	s.lastError = err
	s.mu.Unlock()
	return err
}

// autoRefreshLoop runs until ctx is cancelled, refreshing at 50% remaining TTL.
func (s *HeaderSupplier) autoRefreshLoop(ctx context.Context) {
	for {
		interval := s.computeRefreshInterval()

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			if err := s.fetchAndVerify(ctx); err != nil {
				if s.logger != nil {
					s.logger.WarnContext(ctx, "auto-refresh failed",
						"agent_id", s.agentID,
						"error", err,
					)
				}
			} else {
				s.mu.Lock()
				s.initialized = true
				s.mu.Unlock()
			}
		}
	}
}

// computeRefreshInterval returns 50% of the remaining token TTL with ±10%
// jitter, clamped to a minimum of minAutoRefreshInterval.
func (s *HeaderSupplier) computeRefreshInterval() time.Duration {
	s.mu.RLock()
	exp := s.tokenExp
	s.mu.RUnlock()

	if exp == nil {
		return minAutoRefreshInterval
	}

	remaining := time.Until(time.Unix(*exp, 0))
	half := remaining / 2 //nolint:mnd // 50% of TTL is the design intent

	// Apply ±10% jitter.
	jitter := float64(half) * 0.1 * (2*rand.Float64() - 1) //nolint:mnd,gosec // G404: jitter doesn't need crypto/rand
	interval := time.Duration(float64(half) + jitter)

	if interval < minAutoRefreshInterval {
		interval = minAutoRefreshInterval
	}

	return interval
}

func encodeIfNonEmpty(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}
