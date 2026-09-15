package pop

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

func TestProofError_UnwrapAndIs(t *testing.T) {
	sentinel := errors.New("root cause")
	err := wrapErr(ErrCertInvalid, "wrapped", sentinel)
	if !errors.Is(err, sentinel) {
		t.Fatal("errors.Is did not reach the wrapped cause")
	}
	var pe *ProofError
	if !errors.As(err, &pe) || pe.Type != ErrCertInvalid {
		t.Fatalf("errors.As failed: %v", err)
	}
	// No-cause error still formats and unwraps to nil.
	plain := newErr(ErrReplay, "no cause")
	if plain.Unwrap() != nil {
		t.Error("expected nil cause")
	}
	if plain.Error() == "" {
		t.Error("empty Error()")
	}
}

func TestNormalizeHTU_ParseError(t *testing.T) {
	if _, err := normalizeHTU("https://%zz"); err == nil {
		t.Fatal("expected url.Parse error")
	}
}

// TestVerifyProof_NonPositiveSkewDefaultsBothChecks pins that a non-positive
// skew defaults the freshness window AND the replay-cache retention to the same
// value. Defaulting only one of them silently shortens the replay window: the
// freshness check keeps accepting a proof the cache has already forgotten, and
// MemoryReplayCache treats an expired entry as "not seen", so the proof is
// replayable.
func TestVerifyProof_NonPositiveSkewDefaultsBothChecks(t *testing.T) {
	const method, rawURL = "GET", "https://h.example/x"
	for _, skew := range []time.Duration{0, -time.Second, -10 * time.Second} {
		t.Run(skew.String(), func(t *testing.T) {
			h := newHarness(t)
			var nowUnix atomic.Int64
			nowUnix.Store(h.now.Unix())
			cache := NewMemoryReplayCache(context.Background(), 10,
				withReplayClock(func() time.Time { return time.Unix(nowUnix.Load(), 0) }))
			defer cache.Close()

			token := h.proof(t, method, rawURL)
			if _, err := VerifyProof(context.Background(), token, method, rawURL, h.now, skew, cache); err != nil {
				t.Fatalf("non-positive skew should default and accept: %v", err)
			}
			// Past replayGrace but far inside DefaultPoPSkew: still fresh, so the
			// cache must still be holding the jti.
			later := h.now.Add(replayGrace + time.Second)
			nowUnix.Store(later.Unix())
			_, err := VerifyProof(context.Background(), token, method, rawURL, later, skew, cache)
			assertProofErr(t, err, ErrReplay)
		})
	}
}

func TestVerifyProof_BadRequestURL(t *testing.T) {
	h := newHarness(t)
	htu, _ := normalizeHTU("https://h.example/x")
	token := craftProof(t, h.agentKey, h.goodHeader(), h.goodPayload(t, "POST", htu))
	// htm matches, but the request URL cannot be normalized.
	_, err := VerifyProof(context.Background(), token, "POST", "/relative-only", h.now, DefaultPoPSkew, h.replay)
	assertProofErr(t, err, ErrMalformedProof)
}

func TestVerifyCaller_CanceledContext(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := VerifyCaller(ctx, "x.y.z", h.headers(t), "GET", "https://h/x", h.keys, h.replay, h.callerOpts()...)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	// A client that hung up is its own category, not an authentication failure:
	// it must not pollute auth-rejection metrics or log at ERROR.
	if got := errorCategory(err); got != string(ErrClientGone) {
		t.Errorf("errorCategory = %q, want %s", got, ErrClientGone)
	}
}

func TestErrorCategory(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"typed ProofError", newErr(ErrReplay, "dup"), string(ErrReplay)},
		{"canceled context", context.Canceled, string(ErrClientGone)},
		{"deadline exceeded", context.DeadlineExceeded, string(ErrClientGone)},
		{"unclassified", errors.New("not a ProofError"), categoryUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errorCategory(tt.err); got != tt.want {
				t.Errorf("errorCategory = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestVerifyCaller_SuccessLogsAtDebug pins the level policy: a successful
// authentication is per-request and duplicates the access log, so it must not
// occupy INFO.
func TestVerifyCaller_SuccessLogsAtDebug(t *testing.T) {
	h := newHarness(t)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if _, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), h.headers(t),
		callMethod, callURL, h.keys, h.replay, h.callerOpts(WithLogger(log))...); err != nil {
		t.Fatalf("VerifyCaller: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "caller authenticated") {
		t.Fatalf("success not logged: %s", out)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if strings.Contains(line, "caller authenticated") && !strings.Contains(line, "level=DEBUG") {
			t.Errorf("success logged above DEBUG: %s", line)
		}
	}
}

func TestVerifyCaller_NilDependencies(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name   string
		keys   scitt.KeyLookup
		replay ReplayCache
	}{
		{"nil KeyLookup", nil, h.replay},
		{"nil ReplayCache", h.keys, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), h.headers(t),
				callMethod, callURL, tc.keys, tc.replay, h.callerOpts()...)
			assertProofErr(t, err, ErrMisconfigured)
		})
	}
	t.Run("VerifyProof with nil ReplayCache", func(t *testing.T) {
		_, err := VerifyProof(context.Background(), h.proof(t, callMethod, callURL),
			callMethod, callURL, h.now, DefaultPoPSkew, nil)
		assertProofErr(t, err, ErrMisconfigured)
	})
}

func TestMiddleware_PanicsAtWiringTime(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name   string
		keys   scitt.KeyLookup
		replay ReplayCache
		opts   []MiddlewareOption
	}{
		{name: "nil KeyLookup", keys: nil, replay: h.replay},
		{name: "nil ReplayCache", keys: h.keys, replay: nil},
		{name: "malformed expected-peer pin", keys: h.keys, replay: h.replay, opts: []MiddlewareOption{
			quiet(), WithTrustedHosts("callee.example"), WithMiddlewareCallerOptions(WithExpectedAnsName("not-an-ans-name"))}},
		{name: "empty allow-list", keys: h.keys, replay: h.replay, opts: []MiddlewareOption{
			quiet(), WithTrustedHosts("callee.example"), WithMiddlewareCallerOptions(WithAllowedAnsNames())}},
		{name: "no trusted authority", keys: h.keys, replay: h.replay, opts: []MiddlewareOption{quiet()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("expected panic at wiring time, got none")
				}
			}()
			Middleware(tc.keys, tc.replay, tc.opts...)
		})
	}
}

func TestLogRejection_Levels(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantLevel slog.Level
	}{
		{"routine rejection is INFO", newErr(ErrSignatureInvalid, "bad sig"), slog.LevelInfo},
		{"binding failure is INFO", newErr(ErrBindingFailed, "no match"), slog.LevelInfo},
		{"saturated replay cache is ERROR", newErr(ErrReplayCacheFull, "full"), slog.LevelError},
		{"misconfiguration is ERROR", newErr(ErrMisconfigured, "nil dep"), slog.LevelError},
		{"unclassified failure is ERROR", errors.New("bug"), slog.LevelError},
		{"client disconnect is DEBUG", wrapErr(ErrClientGone, "gone", context.Canceled), slog.LevelDebug},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			logRejection(context.Background(), log, tt.err)
			want := "level=" + tt.wantLevel.String()
			if !strings.Contains(buf.String(), want) {
				t.Errorf("log line %q does not contain %q", buf.String(), want)
			}
		})
	}
}

func TestReceiptNamesAgent_Gaps(t *testing.T) {
	t.Run("names no agent", func(t *testing.T) {
		h := newHarness(t)
		bad := receipt(t, h.tlKey, eventJSON(t, "", ""))
		hdrs := &scitt.Headers{Receipt: bad, StatusToken: h.statusToken(t)}
		_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), hdrs,
			callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
		assertProofErr(t, err, ErrReceiptInvalid)
	})
	t.Run("ansName mismatch (agentId matches)", func(t *testing.T) {
		h := newHarness(t)
		bad := receipt(t, h.tlKey, eventJSON(t, h.agentID, "ans://v1.0.0.elsewhere.example"))
		hdrs := &scitt.Headers{Receipt: bad, StatusToken: h.statusToken(t)}
		_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), hdrs,
			callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
		assertProofErr(t, err, ErrBindingFailed)
	})
}

// TestReceiptLeafSchemas pins the leaf shape a transparency log signs: the event
// wrapped in payload.producer.event, naming the agent "ansId" (V1/V2) or
// "agentId" (V0). The flat object is the /events REST representation and never
// appears in a receipt; an envelope naming no agent, or only half of one, fails
// closed.
func TestReceiptLeafSchemas(t *testing.T) {
	tests := []struct {
		name    string
		event   func(t testing.TB, agentID, ansName string) []byte
		wantErr ErrorType
	}{
		{name: "V1 envelope with ansId", event: eventJSON},
		{name: "V0 envelope with agentId", event: eventJSONV0},
		{
			name: "envelope with both spellings agreeing",
			event: func(t testing.TB, agentID, ansName string) []byte {
				return leafJSON(t, leafEvent{AnsID: agentID, AgentID: agentID, AnsName: ansName})
			},
		},
		{
			name: "envelope with both spellings disagreeing",
			event: func(t testing.TB, agentID, ansName string) []byte {
				return leafJSON(t, leafEvent{AnsID: agentID, AgentID: "someone-else", AnsName: ansName})
			},
			wantErr: ErrReceiptInvalid,
		},
		{
			name: "flat REST event shape",
			event: func(t testing.TB, agentID, ansName string) []byte {
				t.Helper()
				b, err := json.Marshal(map[string]string{"ansId": agentID, "ansName": ansName})
				if err != nil {
					t.Fatalf("marshal flat event: %v", err)
				}
				return b
			},
			wantErr: ErrReceiptInvalid,
		},
		{
			name: "envelope missing ansName",
			event: func(t testing.TB, agentID, _ string) []byte {
				return leafJSON(t, leafEvent{AnsID: agentID})
			},
			wantErr: ErrReceiptInvalid,
		},
		{
			name: "envelope missing agent id",
			event: func(t testing.TB, _, ansName string) []byte {
				return leafJSON(t, leafEvent{AnsName: ansName})
			},
			wantErr: ErrReceiptInvalid,
		},
		{
			name: "envelope whose ansName is not an ans:// name",
			event: func(t testing.TB, agentID, _ string) []byte {
				return leafJSON(t, leafEvent{AnsID: agentID, AnsName: "payments.acme.example"})
			},
			wantErr: ErrReceiptInvalid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			hdrs := &scitt.Headers{
				Receipt:     receipt(t, h.tlKey, tt.event(t, h.agentID, h.ansName)),
				StatusToken: h.statusToken(t),
			}
			id, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), hdrs,
				callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
			if tt.wantErr != "" {
				assertProofErr(t, err, tt.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("VerifyCaller: %v", err)
			}
			if id.AgentID != h.agentID {
				t.Errorf("AgentID = %q, want %q", id.AgentID, h.agentID)
			}
		})
	}
}

// TestReceiptLeafGolden verifies receipts over the envelopes the ANS
// transparency log actually signs, byte-for-byte from the log's own golden
// fixtures (agentnameservice/ans internal/tl/event/{,v1/}testdata). The same
// leaf must then fail to vouch for a different agent, proving the identity was
// read rather than defaulted.
func TestReceiptLeafGolden(t *testing.T) {
	const ansName = "ans://v1.0.0.agent.example.com"
	tests := []struct {
		name    string
		file    string
		agentID string
	}{
		{name: "V1", file: "tl_leaf_v1.json", agentID: "10000000-0000-4000-8000-0000000000a1"},
		{name: "V2", file: "tl_leaf_v2.json", agentID: "10000000-0000-4000-8000-000000000001"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaf, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatalf("read golden leaf: %v", err)
			}

			h := newHarnessFor(t, tt.agentID, ansName)
			hdrs := &scitt.Headers{Receipt: receipt(t, h.tlKey, leaf), StatusToken: h.statusToken(t)}
			id, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), hdrs,
				callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
			if err != nil {
				t.Fatalf("VerifyCaller over golden leaf: %v", err)
			}
			if id.AgentID != tt.agentID {
				t.Errorf("AgentID = %q, want %q", id.AgentID, tt.agentID)
			}

			other := newHarnessFor(t, "some-other-agent", ansName)
			hdrs = &scitt.Headers{Receipt: receipt(t, other.tlKey, leaf), StatusToken: other.statusToken(t)}
			_, err = VerifyCaller(context.Background(), other.proof(t, callMethod, callURL), hdrs,
				callMethod, callURL, other.keys, other.replay, other.callerOpts()...)
			assertProofErr(t, err, ErrBindingFailed)
		})
	}
}

func TestMiddleware_LoggerAndBadScittHeader(t *testing.T) {
	h := newHarness(t)
	clock := func() time.Time { return h.now }
	replay := NewMemoryReplayCache(context.Background(), 100, withReplayClock(clock))
	defer replay.Close()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := newTestServer(t, h.keys, replay, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}),
		WithMiddlewareLogger(logger),
		WithMiddlewareCallerOptions(withCallerClock(clock)))

	t.Run("invalid SCITT header -> 401 and logged", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/x", nil)
		req.Header.Set("X-SCITT-Receipt", "!!! not base64 !!!") //nolint:canonicalheader // verbatim SCITT header name
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("missing identity -> 401 and logged via shared logger", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/y", nil)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
	})

	if !strings.Contains(buf.String(), "component=pop") {
		t.Errorf("expected component=pop in logs, got: %s", buf.String())
	}
}

func TestVerifyCaller_WithPoPSkew(t *testing.T) {
	h := newHarness(t)
	if _, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), h.headers(t),
		callMethod, callURL, h.keys, h.replay, h.callerOpts(WithPoPSkew(time.Second))...); err != nil {
		t.Fatalf("WithPoPSkew valid call: %v", err)
	}
}

func TestVerifyCaller_MalformedStatusAnsName(t *testing.T) {
	h := newHarness(t)
	// A status token whose AnsName is non-empty (passes scitt validation) but
	// not a parseable ans:// name — exercises the binding parse-error branch.
	st := statusToken(t, h.tlKey, h.agentID, "garbage-not-an-ans-name", scitt.StatusActive,
		h.now.Add(-time.Minute).Unix(), h.now.Add(time.Hour).Unix(), h.fp)
	hdrs := &scitt.Headers{Receipt: h.receipt(t), StatusToken: st}
	_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), hdrs,
		callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
	assertProofErr(t, err, ErrBindingFailed)
}
