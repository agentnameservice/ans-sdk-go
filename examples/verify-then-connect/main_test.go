package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/examples/internal/demokit"
	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// slideOrder is every slide title prefix after the setup slide, in the order
// the demo narrates them.
var slideOrder = []string{
	"① Client side", "② Client side", "③ Client side", "④ Client side",
	"⑤ Server side", "⑥ Server side", "⑦ Server side", "⑧ Server side",
	"Verify, then connect.",
}

// TestRunNarratesEveryScenario drives the whole demo at pace zero and checks
// that each scenario reached the outcome the storyline claims. run itself
// fails on any unexpected status, so a nil error already means every
// verification behaved; the assertions below pin the narrated evidence.
func TestRunNarratesEveryScenario(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := run(context.Background(), &buf, 0); err != nil {
		t.Fatalf("run: %v", err)
	}
	raw := buf.String()
	if !strings.HasPrefix(raw, ansiHideCursor) || !strings.HasSuffix(raw, ansiShowCursor) {
		t.Error("run must hide the cursor first and restore it last")
	}
	out := stripANSI(raw)

	for _, want := range append([]string{
		// setup
		"callee    ans://v1.0.0.payments.acme.example     leaf 0   ACTIVE",
		"caller    ans://v1.0.0.orders.acme.example       leaf 1   ACTIVE",
		"revoked   ans://v1.0.0.ledger.acme.example       leaf 2   REVOKED",
		"stale     ans://v1.0.0.billing.acme.example      leaf 3   status token expired 10 minutes ago",
		// client side: genuine callee
		"TLS handshake with payments.acme.example: certificate CN=payments.acme.example",
		"VERIFIED (tier FullScitt). Now connect: POST /v1/pay",
		"verify  VerifyWithScitt: verification succeeded",
		"fqdn=payments.acme.example tier=FullScitt tree_size=1 leaf_index=0 agent_status=ACTIVE",
		// client side: revoked callee
		"③ Client side — the agent has been revoked",
		"GET https://ledger.acme.example/healthz",
		`fqdn=ledger.acme.example error="terminal status [REVOKED]: agent status is REVOKED"`,
		"receipt: signed by the log key — the agent was registered (leaf 2)",
		"status token: signed by the log key, and it says REVOKED",
		// client side: expired status token
		"④ Client side — the status token has expired",
		"GET https://billing.acme.example/healthz",
		`fqdn=billing.acme.example error="token expired (exp=`,
		"receipt: signed by the log key — the agent was registered (leaf 3)",
		"status token: signed by the log key, but it expired 10 minutes ago",
		// server side: authenticated
		"pop     possession proof verified (DPoP)",
		"pop     liveness verified (status token)",
		"ansName=ans://v1.0.0.orders.acme.example agentId=agent-orders status=ACTIVE",
		"pop     identity verified (SCITT receipt)",
		"leafIndex=1 treeSize=2",
		"200  payment accepted — authenticated caller: ans://v1.0.0.orders.acme.example",
		// server side: refused
		"401  REPLAY",
		"category=REPLAY",
		"401  BINDING_FAILED",
		"category=BINDING_FAILED",
		"ValidIdentityCerts",
		"401  STATUS_INVALID",
		"category=STATUS_INVALID",
		"terminal status [REVOKED]",
	}, slideOrder...) {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if got := strings.Count(out, "verify  VerifyWithScitt: status token verification failed"); got != 2 {
		t.Errorf("SDK logged %d status-token failures, want 2 (revoked, expired)", got)
	}
	if got := strings.Count(out, refusedLine); got != 2 {
		t.Errorf("client refused %d endpoints, want 2 (revoked, expired)", got)
	}
	for _, line := range strings.Split(out, "\n") {
		if n := len([]rune(line)); n > termWidth {
			t.Errorf("line is %d columns, over %d: %q", n, termWidth, line)
		}
	}
}

func TestCLI(t *testing.T) {
	t.Parallel()
	canceled := func(t *testing.T) context.Context {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		return ctx
	}
	tests := []struct {
		name       string
		ctx        func(*testing.T) context.Context
		args       []string
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "no flags runs the demo", wantStdout: "Verify, then connect."},
		{name: "pace as record.sh passes it", args: []string{"--pace", "1ns"}, wantStdout: "Verify, then connect."},
		{name: "help prints usage", args: []string{"-h"}, wantStderr: "delay between narrated lines"},
		{name: "pace is not a duration", args: []string{"--pace", "fast"}, wantCode: exitUsage, wantStderr: "invalid value"},
		{name: "unknown flag", args: []string{"--speed", "2"}, wantCode: exitUsage, wantStderr: "not defined"},
		{name: "demo fails", ctx: canceled, wantCode: exitFailure, wantStderr: "demo failed: "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if tt.ctx != nil {
				ctx = tt.ctx(t)
			}
			var stdout, stderr bytes.Buffer
			if got := cli(ctx, tt.args, &stdout, &stderr); got != tt.wantCode {
				t.Errorf("exit code %d, want %d\nstderr: %s", got, tt.wantCode, stderr.String())
			}
			if !strings.Contains(stripANSI(stdout.String()), tt.wantStdout) {
				t.Errorf("stdout missing %q", tt.wantStdout)
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr %q missing %q", stderr.String(), tt.wantStderr)
			}
			if tt.wantCode == exitUsage && stdout.Len() != 0 {
				t.Errorf("a usage error must not start the demo; stdout has %d bytes", stdout.Len())
			}
		})
	}
}

// cancelOnWrite cancels a context the moment the demo narrates trigger.
type cancelOnWrite struct {
	buf     bytes.Buffer
	trigger string
	cancel  context.CancelFunc
}

func (w *cancelOnWrite) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(w.trigger)) {
		w.cancel()
	}
	return w.buf.Write(p)
}

// TestRunStopsAtTheFirstFailure interrupts the demo as a slide begins: run
// must return the failure, narrate nothing past that slide, and restore the
// cursor.
func TestRunStopsAtTheFirstFailure(t *testing.T) {
	t.Parallel()
	// Slide ② is absent: it makes no call that can be interrupted.
	for _, at := range []int{0, 2, 3, 4, 5, 6, 7} {
		t.Run(slideOrder[at], func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w := &cancelOnWrite{trigger: slideOrder[at], cancel: cancel}

			err := run(ctx, w, 0)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("run returned %v, want context.Canceled", err)
			}
			out := w.buf.String()
			if !strings.HasSuffix(out, ansiShowCursor) {
				t.Error("run did not restore the cursor")
			}
			if next := slideOrder[at+1]; strings.Contains(out, next) {
				t.Errorf("run narrated %q after failing in %q", next, slideOrder[at])
			}
		})
	}
}

// newTestDemo provisions a demo that narrates nowhere and starts its
// endpoints. mutate, when set, alters the provisioned world before the
// endpoints start.
func newTestDemo(t *testing.T, mutate func(*demo)) (*demo, *http.Client) {
	t.Helper()
	d, err := provision(io.Discard, 0)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(d)
	}
	client, closeEndpoints, err := d.startEndpoints(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeEndpoints)
	return d, client
}

// TestRefusedOnStatusToken pins the demo's own guard: a client-side refusal
// slide only narrates a refusal the SDK actually made, for the reason the
// slide claims.
func TestRefusedOnStatusToken(t *testing.T) {
	t.Parallel()
	d, client := newTestDemo(t, nil)

	tests := []struct {
		name       string
		agent      *demokit.Agent
		want       scitt.TokenErrorType
		wantStatus scitt.AgentStatus
		wantErr    bool
		wantErrIs  error // nil accepts any error
	}{
		{name: "revoked agent", agent: d.revoked, want: scitt.TokenErrTerminalStatus, wantStatus: scitt.StatusRevoked},
		{name: "expired status token", agent: d.stale, want: scitt.TokenErrExpired},
		{
			name: "verified agent is not a refusal", agent: d.callee, want: scitt.TokenErrExpired,
			wantErr: true, wantErrIs: errUnexpectedOutcome,
		},
		{name: "revocation is not an expiry", agent: d.revoked, want: scitt.TokenErrExpired, wantErr: true},
		{name: "expiry is not a revocation", agent: d.stale, want: scitt.TokenErrTerminalStatus, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			cert, hdrs, err := preflight(ctx, client, "https://"+tt.agent.Host+healthPath)
			if err != nil {
				t.Fatal(err)
			}
			refusal, err := d.refusedOnStatusToken(ctx, tt.agent, cert, hdrs, tt.want)
			if tt.wantErr {
				if err == nil || (tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs)) {
					t.Fatalf("got refusal %v, err %v; want an error (is %v)", refusal, err, tt.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("refusedOnStatusToken: %v", err)
			}
			if refusal.Type != tt.want || refusal.Status != tt.wantStatus {
				t.Fatalf("refusal type=%d status=%q, want type=%d status=%q",
					refusal.Type, refusal.Status, tt.want, tt.wantStatus)
			}
			if tt.want == scitt.TokenErrExpired && refusal.Now-refusal.Exp < int64(staleTokenAge.Seconds()) {
				t.Fatalf("token expired %ds ago, want at least %s", refusal.Now-refusal.Exp, staleTokenAge)
			}
		})
	}
}

// TestSlidesFailOnTheWrongOutcome pins the guards that stop the demo narrating
// a result the SDK did not produce.
func TestSlidesFailOnTheWrongOutcome(t *testing.T) {
	t.Parallel()
	callerSigner := func(t *testing.T, d *demo) *pop.Signer {
		t.Helper()
		signer, err := pop.NewSigner(d.caller.Bundle.AgentKey, d.caller.Bundle.CertDER)
		if err != nil {
			t.Fatal(err)
		}
		return signer
	}
	payURL := func(d *demo) string { return "https://" + d.callee.Host + payPath }
	unreachable := newClient(map[string]string{}, x509.NewCertPool())
	const noSuchHost = `no such host "payments.acme.example"`

	tests := []struct {
		name    string
		mutate  func(*demo)
		act     func(t *testing.T, d *demo, client *http.Client) error
		wantMsg string
	}{
		{
			name:   "verified slide, callee does not verify",
			mutate: func(d *demo) { d.callee = d.revoked },
			act: func(t *testing.T, d *demo, client *http.Client) error {
				return d.verifiedCalleeSlides(t.Context(), client)
			},
			wantMsg: "terminal status [REVOKED]",
		},
		{
			name: "authenticated slide, callee rejects the caller",
			act: func(t *testing.T, d *demo, client *http.Client) error {
				_, err := d.authenticatedSlide(t.Context(), client, payURL(d), callerSigner(t, d), http.Header{})
				return err
			},
			wantMsg: "got 401",
		},
		{
			name: "refusal slide, callee accepts the request",
			act: func(t *testing.T, d *demo, client *http.Client) error {
				fresh, err := signedHeaders(t.Context(), callerSigner(t, d), scittHeaders(d.caller), payURL(d))
				if err != nil {
					t.Fatal(err)
				}
				return d.expectRefused(t.Context(), client, payURL(d), fresh, "REPLAY")
			},
			wantMsg: "REPLAY: got 200, want 401",
		},
		{
			name: "refusal check, host is not a domain name",
			act: func(t *testing.T, d *demo, _ *http.Client) error {
				_, err := d.refusedOnStatusToken(t.Context(), &demokit.Agent{Host: "not a host!"}, nil, nil, scitt.TokenErrExpired)
				return err
			},
			wantMsg: "invalid character",
		},
		{
			name:   "revoked-agent slide, agent verifies",
			mutate: func(d *demo) { d.revoked = d.callee },
			act: func(t *testing.T, d *demo, client *http.Client) error {
				return d.revokedCalleeSlide(t.Context(), client)
			},
			wantMsg: "want a status-token refusal",
		},
		{
			name:   "expired-token slide, agent verifies",
			mutate: func(d *demo) { d.stale = d.callee },
			act: func(t *testing.T, d *demo, client *http.Client) error {
				return d.staleCalleeSlide(t.Context(), client)
			},
			wantMsg: "want a status-token refusal",
		},
		{
			name:   "server-side slides, caller has no identity certificate",
			mutate: func(d *demo) { d.caller.Bundle.CertDER = nil },
			act: func(t *testing.T, d *demo, client *http.Client) error {
				return d.serverSideSlides(t.Context(), client)
			},
			wantMsg: "parse certificate",
		},
		{
			name: "authenticated slide, callee unreachable",
			act: func(t *testing.T, d *demo, _ *http.Client) error {
				_, err := d.authenticatedSlide(t.Context(), unreachable, payURL(d), callerSigner(t, d), scittHeaders(d.caller))
				return err
			},
			wantMsg: noSuchHost,
		},
		{
			name: "forgery slide, callee unreachable",
			act: func(t *testing.T, d *demo, _ *http.Client) error {
				return d.forgerySlide(t.Context(), unreachable, payURL(d), scittHeaders(d.caller))
			},
			wantMsg: noSuchHost,
		},
		{
			name:   "revoked-caller slide, revoked agent has no identity certificate",
			mutate: func(d *demo) { d.revoked.Bundle.CertDER = nil },
			act: func(t *testing.T, d *demo, client *http.Client) error {
				return d.revokedCallerSlide(t.Context(), client, payURL(d))
			},
			wantMsg: "parse certificate",
		},
		{
			name: "revoked-caller slide, callee unreachable",
			act: func(t *testing.T, d *demo, _ *http.Client) error {
				return d.revokedCallerSlide(t.Context(), unreachable, payURL(d))
			},
			wantMsg: noSuchHost,
		},
		{
			name: "signing without a signer",
			act: func(t *testing.T, d *demo, _ *http.Client) error {
				_, err := signedHeaders(t.Context(), nil, scittHeaders(d.caller), payURL(d))
				return err
			},
			wantMsg: "nil signer",
		},
		{
			name: "signing for a malformed URL",
			act: func(t *testing.T, d *demo, _ *http.Client) error {
				_, err := signedHeaders(t.Context(), callerSigner(t, d), scittHeaders(d.caller), "://bad")
				return err
			},
			wantMsg: "missing protocol scheme",
		},
		{
			name: "sending, response cut short",
			act: func(t *testing.T, _ *demo, _ *http.Client) error {
				srv := httptest.NewTLSServer(http.HandlerFunc(cutShort))
				t.Cleanup(srv.Close)
				_, _, err := send(t.Context(), srv.Client(), srv.URL+payPath, http.Header{})
				return err
			},
			wantMsg: "unexpected EOF",
		},
		{
			name: "sending to a malformed URL",
			act: func(t *testing.T, _ *demo, client *http.Client) error {
				_, _, err := send(t.Context(), client, "://bad", http.Header{})
				return err
			},
			wantMsg: "missing protocol scheme",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d, client := newTestDemo(t, tt.mutate)
			err := tt.act(t, d, client)
			if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("got %v, want an error containing %q", err, tt.wantMsg)
			}
		})
	}
}

// TestStartEndpointsRejectsUnparseableCertificate covers a failure at each
// position, so the endpoints already started are shut down on the way out.
func TestStartEndpointsRejectsUnparseableCertificate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		agent func(*demo) *demokit.Agent
	}{
		{name: "callee, nothing started yet", agent: func(d *demo) *demokit.Agent { return d.callee }},
		{name: "revoked, one endpoint started", agent: func(d *demo) *demokit.Agent { return d.revoked }},
		{name: "stale, two endpoints started", agent: func(d *demo) *demokit.Agent { return d.stale }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d, err := provision(io.Discard, 0)
			if err != nil {
				t.Fatal(err)
			}
			tt.agent(d).Server.CertDER = []byte("not a certificate")
			client, closeEndpoints, err := d.startEndpoints(t.Context())
			if err == nil {
				closeEndpoints()
				t.Fatal("startEndpoints accepted an unparseable server certificate")
			}
			if client != nil || closeEndpoints != nil {
				t.Fatal("startEndpoints returned a client or a close func alongside its error")
			}
		})
	}
}

// cutShort declares more content than it sends, so reading the response body
// fails on the client.
func cutShort(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Length", "64")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("short"))
}

// TestAcceptPaymentRequiresAnAuthenticatedCaller reaches the application
// without pop.Middleware in front of it.
func TestAcceptPaymentRequiresAnAuthenticatedCaller(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	acceptPayment(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, payPath, strings.NewReader(payBody)))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "payment accepted") {
		t.Fatalf("got %d %q, want 500 and no payment", rec.Code, rec.Body.String())
	}
}

func TestPreflightErrors(t *testing.T) {
	t.Parallel()
	noHosts := func(*testing.T) *http.Client { return newClient(map[string]string{}, x509.NewCertPool()) }

	tests := []struct {
		name    string
		setup   func(t *testing.T) (*http.Client, string)
		wantMsg string
	}{
		{
			name:    "malformed URL",
			setup:   func(t *testing.T) (*http.Client, string) { return noHosts(t), "://bad" },
			wantMsg: "missing protocol scheme",
		},
		{
			name: "host the demo does not serve",
			setup: func(t *testing.T) (*http.Client, string) {
				return noHosts(t), "https://unknown.example" + healthPath
			},
			wantMsg: `no such host "unknown.example"`,
		},
		{
			name: "response cut short",
			setup: func(t *testing.T) (*http.Client, string) {
				srv := httptest.NewTLSServer(http.HandlerFunc(cutShort))
				t.Cleanup(srv.Close)
				return srv.Client(), srv.URL + healthPath
			},
			wantMsg: "unexpected EOF",
		},
		{
			name: "plain HTTP presents no certificate",
			setup: func(t *testing.T) (*http.Client, string) {
				srv := httptest.NewServer(healthMux())
				t.Cleanup(srv.Close)
				return srv.Client(), srv.URL + healthPath
			},
			wantMsg: "no TLS peer certificate",
		},
		{
			name: "SCITT header is not base64",
			setup: func(t *testing.T) (*http.Client, string) {
				bad := http.Header{}
				bad.Set(scitt.HeaderReceipt, "!!not-base64")
				srv := httptest.NewTLSServer(withResponseHeaders(bad, healthMux()))
				t.Cleanup(srv.Close)
				return srv.Client(), srv.URL + healthPath
			},
			wantMsg: "base64 decode failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			client, target := tt.setup(t)
			cert, hdrs, err := preflight(t.Context(), client, target)
			if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("got cert=%v hdrs=%v err=%v, want an error containing %q", cert != nil, hdrs, err, tt.wantMsg)
			}
		})
	}
}

func TestTraceHandlerLayout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		log  func(*slog.Logger)
		want string
	}{
		{
			name: "component column, abbreviated hex, quoted value",
			log: func(l *slog.Logger) {
				l.With("component", "pop").Info("possession proof verified (DPoP)",
					"jti", "0123456789abcdef0123456789abcdef",
					"err", "pop: REPLAY: jti already seen",
					"n", 7)
			},
			want: "      " + ansiDim + "pop     possession proof verified (DPoP)\n" +
				"              jti=01234567… err=\"pop: REPLAY: jti already seen\" n=7" + ansiReset + "\n",
		},
		{
			name: "group is ignored",
			log:  func(l *slog.Logger) { l.WithGroup("g").Info("hello", "k", "v") },
			want: "      " + ansiDim + "        hello\n              k=v" + ansiReset + "\n",
		},
		{
			name: "no component, no attributes",
			log:  func(l *slog.Logger) { l.Info("hello") },
			want: "      " + ansiDim + "        hello" + ansiReset + "\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			tt.log(slog.New(newTraceHandler(&buf, 0)))
			if got := buf.String(); got != tt.want {
				t.Fatalf("unexpected rendering\n got %q\nwant %q", got, tt.want)
			}
		})
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestTraceHandlerReportsWriteFailure(t *testing.T) {
	t.Parallel()
	errWrite := errors.New("terminal closed")
	h := newTraceHandler(failingWriter{err: errWrite}, 0)
	err := h.Handle(t.Context(), slog.NewRecord(time.Now(), slog.LevelInfo, "hello", 0))
	if !errors.Is(err, errWrite) {
		t.Fatalf("Handle returned %v, want the writer's error", err)
	}
}

func TestWrap(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		in    string
		width int
		want  []string
	}{
		{"empty", "", 10, nil},
		{"fits", "a b c", 10, []string{"a b c"}},
		{"breaks on space", "aaa bbb ccc ddd", 7, []string{"aaa bbb", "ccc ddd"}},
		{"long word alone", "aaa bbbbbbbbbbbb cc", 7, []string{"aaa", "bbbbbbbbbbbb", "cc"}},
		{"runes not bytes", "ééé ééé", 7, []string{"ééé ééé"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := wrap(tt.in, tt.width)
			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Fatalf("wrap(%q, %d) = %q, want %q", tt.in, tt.width, got, tt.want)
			}
		})
	}
}

func stripANSI(s string) string {
	return regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`).ReplaceAllString(s, "")
}
