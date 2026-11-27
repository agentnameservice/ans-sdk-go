// Command verify-then-connect is the README demo: two ANS agents talking over
// HTTPS with no mutual TLS, each verifying the other with SCITT artifacts.
//
// Client side: before sending anything that matters, the caller reads the
// callee's SCITT receipt and status token from the response headers of a
// preflight request, verifies both against the transparency-log key, and binds
// the TLS certificate it just shook hands with to that status token. An agent
// whose status token says REVOKED, and one whose status token has expired, are
// refused before the first real request.
//
// Server side: the callee authenticates every request with pop.Middleware —
// the DPoP possession proof, the status token (liveness) and the receipt
// (identity), bound to one identity certificate. A replayed proof, a forged
// certificate presented with stolen headers, and a revoked caller are refused.
//
// --pace adds a delay between narrated lines, for recording (see record.sh).
package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agentnameservice/ans-sdk-go/examples/internal/demokit"
	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

const (
	calleeName  = "ans://v1.0.0.payments.acme.example"
	callerName  = "ans://v1.0.0.orders.acme.example"
	revokedName = "ans://v1.0.0.ledger.acme.example"
	staleName   = "ans://v1.0.0.billing.acme.example"

	// staleTokenAge is how long ago the stale agent's status token expired:
	// well past the verifier's clock-skew tolerance.
	staleTokenAge = 10 * time.Minute

	refusedLine = "REFUSED before the first real request. Nothing was sent."

	payPath    = "/v1/pay"
	healthPath = "/healthz"
	payBody    = `{"amount":"42.00","currency":"USD"}`

	replayCacheSize = 1000
	clientTimeout   = 5 * time.Second

	// termWidth is the column the trace wraps at; record.sh records at a
	// slightly wider terminal so nothing is cut.
	termWidth = 100
	// traceIndent is the left margin of the SDK trace under the narration, and
	// traceCont the margin of its wrapped attribute lines.
	traceIndent = 6
	traceCont   = 14
	// hexAbbrev is how many hex digits of a long identifier the trace keeps.
	hexAbbrev = 8
	// holdFactor is how many paces a finished slide stays on screen; trace lines
	// print at pace/tracePaceDivisor so the SDK's own output reads as detail.
	holdFactor       = 5
	tracePaceDivisor = 2
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiClear  = "\033[2J\033[H"
	// The cursor is hidden while the demo narrates so it does not blink in the
	// recording; run restores it on every exit path.
	ansiHideCursor = "\033[?25l"
	ansiShowCursor = "\033[?25h"
)

// Process exit codes.
const (
	exitFailure = 1
	exitUsage   = 2
)

var errUnexpectedOutcome = errors.New("unexpected verification outcome")

func main() {
	os.Exit(cli(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// cli parses the command line and runs the demo, returning the exit code.
func cli(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify-then-connect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	pace := flags.Duration("pace", 0, "delay between narrated lines, for recording")
	switch err := flags.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		return 0
	case err != nil:
		return exitUsage
	}
	if err := run(ctx, stdout, *pace); err != nil {
		fmt.Fprintln(stderr, "demo failed:", err)
		return exitFailure
	}
	return 0
}

// syncWriter serializes writes from the narrator and from the server
// goroutine's logger onto one terminal.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// narrator prints the annotated storyline and paces it for recording.
type narrator struct {
	w    io.Writer
	pace time.Duration
}

func (n *narrator) sayf(format string, args ...any) {
	fmt.Fprintf(n.w, format+"\n", args...)
	time.Sleep(n.pace)
}

func (n *narrator) slide(title string) {
	fmt.Fprint(n.w, ansiClear)
	n.sayf("%s%s%s", ansiBold, title, ansiReset)
	n.sayf("")
}

func (n *narrator) ok(s string)   { n.sayf("  %s✓%s %s", ansiGreen, ansiReset, s) }
func (n *narrator) bad(s string)  { n.sayf("  %s✗%s %s", ansiRed, ansiReset, s) }
func (n *narrator) step(s string) { n.sayf("  %s→%s %s", ansiCyan, ansiReset, s) }
func (n *narrator) warn(s string) { n.sayf("  %s!%s %s", ansiYellow, ansiReset, s) }
func (n *narrator) cont(s string) { n.sayf("    %s", s) }
func (n *narrator) note(s string) { n.sayf("  %s%s%s", ansiDim, s, ansiReset) }
func (n *narrator) hold()         { time.Sleep(holdFactor * n.pace) }

// traceHandler is a slog.Handler that renders the SDK's own log records as a
// dimmed trace under the narration: the component and message on one line,
// the attributes word-wrapped beneath, long hex identifiers abbreviated. The
// messages and attributes are the SDK's, untouched; only the layout is the
// demo's, so the real verification steps fit a README-width terminal.
type traceHandler struct {
	w       io.Writer
	pace    time.Duration
	attrs   []slog.Attr
	longHex *regexp.Regexp
}

func newTraceHandler(w io.Writer, pace time.Duration) *traceHandler {
	return &traceHandler{w: w, pace: pace, longHex: regexp.MustCompile(`[0-9a-f]{32,}`)}
}

func (h *traceHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &c
}

// WithGroup is a no-op: the SDK does not log grouped attributes.
func (h *traceHandler) WithGroup(string) slog.Handler { return h }

func (h *traceHandler) Handle(_ context.Context, r slog.Record) error {
	component := ""
	fields := make([]string, 0, r.NumAttrs()+len(h.attrs))
	add := func(a slog.Attr) bool {
		if a.Key == "component" {
			component = a.Value.String()
			return true
		}
		fields = append(fields, a.Key+"="+h.format(a.Value.String()))
		return true
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(add)

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s%s%-8s%s", strings.Repeat(" ", traceIndent), ansiDim, component, r.Message)
	for _, line := range wrap(strings.Join(fields, " "), termWidth-traceCont) {
		sb.WriteString("\n" + strings.Repeat(" ", traceCont) + line)
	}
	sb.WriteString(ansiReset + "\n")
	if _, err := io.WriteString(h.w, sb.String()); err != nil {
		return err
	}
	time.Sleep(h.pace)
	return nil
}

// format abbreviates long hex identifiers and quotes values containing
// spaces, as slog's TextHandler would.
func (h *traceHandler) format(v string) string {
	v = h.longHex.ReplaceAllStringFunc(v, func(s string) string { return s[:hexAbbrev] + "…" })
	if strings.ContainsAny(v, " \"") {
		return strconv.Quote(v)
	}
	return v
}

// wrap greedily breaks s on spaces into lines of at most width runes; a single
// word longer than width stands alone on its line.
func wrap(s string, width int) []string {
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		switch {
		case line == "":
			line = word
		case len([]rune(line))+1+len([]rune(word)) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// demo holds the provisioned world: the log and the four registered agents.
type demo struct {
	n        *narrator
	log      *demokit.Log
	callee   *demokit.Agent
	caller   *demokit.Agent
	revoked  *demokit.Agent
	stale    *demokit.Agent
	verifier *verify.ServerVerifier
	trace    *slog.Logger
}

func run(ctx context.Context, out io.Writer, pace time.Duration) error {
	// Canceling on return stops the callee's replay-cache janitor.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := &syncWriter{w: out}
	fmt.Fprint(w, ansiHideCursor)
	defer fmt.Fprint(w, ansiShowCursor)
	d, err := provision(w, pace)
	if err != nil {
		return err
	}
	d.setupSlide()

	client, closeEndpoints, err := d.startEndpoints(ctx)
	if err != nil {
		return err
	}
	defer closeEndpoints()

	if err := d.clientSideSlides(ctx, client); err != nil {
		return err
	}
	if err := d.serverSideSlides(ctx, client); err != nil {
		return err
	}
	d.closingSlide()
	return nil
}

func provision(w io.Writer, pace time.Duration) (*demo, error) {
	log, err := demokit.NewLog()
	if err != nil {
		return nil, err
	}
	callee, err := log.Register(calleeName, "agent-payments", scitt.StatusActive)
	if err != nil {
		return nil, err
	}
	caller, err := log.Register(callerName, "agent-orders", scitt.StatusActive)
	if err != nil {
		return nil, err
	}
	revoked, err := log.Register(revokedName, "agent-ledger", scitt.StatusRevoked)
	if err != nil {
		return nil, err
	}
	stale, err := log.Register(staleName, "agent-billing", scitt.StatusActive)
	if err != nil {
		return nil, err
	}
	stale.Bundle.StatusToken, err = log.IssueStatusToken(stale, scitt.StatusActive, time.Now().Add(-staleTokenAge))
	if err != nil {
		return nil, err
	}
	trace := slog.New(newTraceHandler(w, pace/tracePaceDivisor))
	return &demo{
		n:       &narrator{w: w, pace: pace},
		log:     log,
		callee:  callee,
		caller:  caller,
		revoked: revoked,
		stale:   stale,
		// The mock resolver has no records, so a response without SCITT headers
		// would fall back to "not an ANS agent" instead of a live DNS query.
		verifier: verify.NewServerVerifier(
			verify.WithScittKeyLookup(log.KeyLookup()),
			verify.WithDNSResolver(verify.NewMockDNSResolver()),
			verify.WithTlogClient(verify.NewMockTransparencyLogClient()),
			verify.WithLogger(trace.With("component", "verify")),
		),
		trace: trace,
	}, nil
}

func (d *demo) setupSlide() {
	n := d.n
	n.slide("ANS · verify, then connect")
	n.sayf("  Two agents over plain HTTPS. No mutual TLS. Each side proves itself with artifacts")
	n.sayf("  from the transparency log; the other side checks them locally against one trusted key.")
	n.sayf("")
	kid := d.log.KeyID()
	n.sayf("  %-9s kid=%s", "log key", hex.EncodeToString(kid[:]))
	for _, a := range []struct {
		role  string
		agent *demokit.Agent
		state string
	}{
		{"callee", d.callee, string(scitt.StatusActive)},
		{"caller", d.caller, string(scitt.StatusActive)},
		{"revoked", d.revoked, string(scitt.StatusRevoked)},
		{"stale", d.stale, fmt.Sprintf("status token expired %d minutes ago", int(staleTokenAge.Minutes()))},
	} {
		n.sayf("  %-9s %-38s leaf %d   %s", a.role, a.agent.AnsName, a.agent.LeafIndex, a.state)
	}
	n.hold()
}

// clientSideSlides: the caller decides whether to trust an endpoint before it
// sends anything that matters.
func (d *demo) clientSideSlides(ctx context.Context, client *http.Client) error {
	if err := d.verifiedCalleeSlides(ctx, client); err != nil {
		return err
	}
	if err := d.revokedCalleeSlide(ctx, client); err != nil {
		return err
	}
	return d.staleCalleeSlide(ctx, client)
}

// verifiedCalleeSlides contrasts what the TLS handshake alone establishes with
// what the SCITT artifacts add, for the genuine callee.
func (d *demo) verifiedCalleeSlides(ctx context.Context, client *http.Client) error {
	n := d.n
	host := d.callee.Host
	target := "https://" + host + healthPath

	n.slide("① Client side — connect and pray?")
	cert, hdrs, err := preflight(ctx, client, target)
	if err != nil {
		return err
	}
	n.ok(fmt.Sprintf("TLS handshake with %s: certificate CN=%s, chain trusted", host, cert.Subject.CommonName))
	n.warn("That is everything TLS tells you. Not whether this host is an ANS agent, whether")
	n.cont("this is the certificate the log vouches for, or whether the agent is still ACTIVE.")
	n.step("connect-and-pray would POST " + payPath + " now, and hope.")
	n.hold()

	n.slide("② Client side — verify, then connect")
	n.step(fmt.Sprintf("GET %s   (preflight — nothing sensitive sent)", target))
	n.cont(fmt.Sprintf("response carries %s (%d B) and %s (%d B)",
		scitt.HeaderReceipt, len(hdrs.Receipt), scitt.HeaderStatusToken, len(hdrs.StatusToken)))
	outcome, err := d.verifyServer(ctx, host, cert, hdrs)
	if err != nil {
		return err
	}
	if !outcome.IsSuccess() {
		return fmt.Errorf("verify %s: %w", host, cmp.Or(outcome.ToError(), errUnexpectedOutcome))
	}
	n.ok("receipt: signed by the log key, leaf is in the tree (inclusion proof walked)")
	n.ok("status token: signed by the log key, not expired, status ACTIVE")
	n.ok("server certificate " + shortFingerprint(cert) + " is in the token's valid_server_certs")
	n.step(fmt.Sprintf("VERIFIED (tier %s). Now connect: POST %s", outcome.Tier, payPath))
	n.hold()
	return nil
}

// revokedCalleeSlide: the log has revoked the agent, and its status token says
// so.
func (d *demo) revokedCalleeSlide(ctx context.Context, client *http.Client) error {
	n := d.n
	n.slide("③ Client side — the agent has been revoked")
	n.note("The receipt proves the agent was registered. The status token says whether it still is.")
	cert, hdrs, err := d.preflightStep(ctx, client, d.revoked)
	if err != nil {
		return err
	}
	n.cont(ansiRed + "connect-and-pray is already paying a revoked agent." + ansiReset)
	refusal, err := d.refusedOnStatusToken(ctx, d.revoked, cert, hdrs, scitt.TokenErrTerminalStatus)
	if err != nil {
		return err
	}
	n.bad(fmt.Sprintf("status token: signed by the log key, and it says %s", refusal.Status))
	n.step(refusedLine)
	n.hold()
	return nil
}

// staleCalleeSlide: the agent presents a status token that has run out. The
// verifier cannot tell a revoked agent hiding behind its last good token from
// a broken one, and does not need to.
func (d *demo) staleCalleeSlide(ctx context.Context, client *http.Client) error {
	n := d.n
	n.slide("④ Client side — the status token has expired")
	n.note("Status tokens are short-lived. An agent the log has stopped vouching for can only")
	n.note("replay its last good one, and that one runs out.")
	cert, hdrs, err := d.preflightStep(ctx, client, d.stale)
	if err != nil {
		return err
	}
	refusal, err := d.refusedOnStatusToken(ctx, d.stale, cert, hdrs, scitt.TokenErrExpired)
	if err != nil {
		return err
	}
	age := time.Duration(refusal.Now-refusal.Exp) * time.Second
	n.bad(fmt.Sprintf("status token: signed by the log key, but it expired %d minutes ago", int(age.Minutes())))
	n.step(refusedLine)
	n.hold()
	return nil
}

// preflightStep narrates and performs the unauthenticated preflight GET to an
// agent's endpoint.
func (d *demo) preflightStep(ctx context.Context, client *http.Client, agent *demokit.Agent) (*x509.Certificate, *scitt.Headers, error) {
	target := "https://" + agent.Host + healthPath
	d.n.step(fmt.Sprintf("GET %s   (preflight — nothing sensitive sent)", target))
	cert, hdrs, err := preflight(ctx, client, target)
	if err != nil {
		return nil, nil, err
	}
	d.n.ok(fmt.Sprintf("TLS handshake: certificate CN=%s, chain trusted", cert.Subject.CommonName))
	return cert, hdrs, nil
}

// refusedOnStatusToken verifies an agent the client must refuse and returns
// the status-token error VerifyWithScitt refused it with. The receipt is
// verified before the status token, so reaching a TokenError means the receipt
// passed.
func (d *demo) refusedOnStatusToken(ctx context.Context, agent *demokit.Agent, cert *x509.Certificate,
	hdrs *scitt.Headers, want scitt.TokenErrorType) (*scitt.TokenError, error) {
	outcome, err := d.verifyServer(ctx, agent.Host, cert, hdrs)
	if err != nil {
		return nil, err
	}
	var refusal *scitt.TokenError
	if outcome.IsSuccess() || !errors.As(outcome.Error, &refusal) || refusal.Type != want {
		return nil, fmt.Errorf("verify %s: want a status-token refusal: %w", agent.Host,
			cmp.Or(outcome.ToError(), errUnexpectedOutcome))
	}
	d.n.ok(fmt.Sprintf("receipt: signed by the log key — the agent was registered (leaf %d)", agent.LeafIndex))
	return refusal, nil
}

// verifyServer runs the SDK's SCITT server verification for host against the
// certificate and headers its preflight returned.
func (d *demo) verifyServer(ctx context.Context, host string, cert *x509.Certificate, hdrs *scitt.Headers) (*verify.VerificationOutcome, error) {
	fqdn, err := models.NewFqdn(host)
	if err != nil {
		return nil, err
	}
	return d.verifier.VerifyWithScitt(ctx, fqdn, verify.CertIdentityFromX509(cert), hdrs), nil
}

// serverSideSlides: the callee authenticates whoever is calling.
func (d *demo) serverSideSlides(ctx context.Context, client *http.Client) error {
	target := "https://" + d.callee.Host + payPath
	signer, err := pop.NewSigner(d.caller.Bundle.AgentKey, d.caller.Bundle.CertDER)
	if err != nil {
		return err
	}
	headers := scittHeaders(d.caller)
	signed, err := d.authenticatedSlide(ctx, client, target, signer, headers)
	if err != nil {
		return err
	}
	if err := d.replaySlide(ctx, client, target, signed); err != nil {
		return err
	}
	if err := d.forgerySlide(ctx, client, target, headers); err != nil {
		return err
	}
	return d.revokedCallerSlide(ctx, client, target)
}

// authenticatedSlide makes the genuine call and returns the headers it sent,
// so replaySlide can present the identical proof again.
func (d *demo) authenticatedSlide(ctx context.Context, client *http.Client, target string,
	signer *pop.Signer, headers http.Header) (http.Header, error) {
	n := d.n
	n.slide("⑤ Server side — the callee verifies the caller (no client certificate)")
	n.step("POST " + target)
	n.cont(fmt.Sprintf("with DPoP proof + %s + %s", scitt.HeaderReceipt, scitt.HeaderStatusToken))
	n.note("the proof signs method, URL, body digest, a fresh jti and iat with the caller's identity key")
	signed, err := signedHeaders(ctx, signer, headers, target)
	if err != nil {
		return nil, err
	}
	status, body, err := send(ctx, client, target, signed)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("authenticated call: got %d (%s), want 200", status, body)
	}
	n.ok(fmt.Sprintf("%d  %s", status, body))
	n.hold()
	return signed, nil
}

func (d *demo) replaySlide(ctx context.Context, client *http.Client, target string, signed http.Header) error {
	n := d.n
	n.slide("⑥ Server side — a captured proof is replayed")
	n.step("the same request again: same DPoP proof, same jti")
	if err := d.expectRefused(ctx, client, target, signed, "REPLAY"); err != nil {
		return err
	}
	n.hold()
	return nil
}

// forgerySlide: the attacker holds the caller's public SCITT headers and mints
// its own key and certificate for the caller's name. The proof verifies under
// that certificate; the binding to the status token is what fails.
func (d *demo) forgerySlide(ctx context.Context, client *http.Client, target string, stolen http.Header) error {
	n := d.n
	n.slide("⑦ Server side — stolen headers, forged certificate")
	n.note("the attacker has the caller's public receipt and status token, and mints its own")
	n.note("key and certificate for the caller's ans:// name. The proof signature is valid.")
	forgedKey, forgedCert, err := demokit.SelfSignedIdentity(callerName)
	if err != nil {
		return err
	}
	forger, err := pop.NewSigner(forgedKey, forgedCert)
	if err != nil {
		return err
	}
	forged, err := signedHeaders(ctx, forger, stolen, target)
	if err != nil {
		return err
	}
	n.step("POST " + target + "   with the attacker's proof")
	if err := d.expectRefused(ctx, client, target, forged, "BINDING_FAILED"); err != nil {
		return err
	}
	n.hold()
	return nil
}

func (d *demo) revokedCallerSlide(ctx context.Context, client *http.Client, target string) error {
	n := d.n
	n.slide("⑧ Server side — a revoked caller")
	n.note("right key, right certificate, valid proof — but the log says REVOKED.")
	signer, err := pop.NewSigner(d.revoked.Bundle.AgentKey, d.revoked.Bundle.CertDER)
	if err != nil {
		return err
	}
	hdrs, err := signedHeaders(ctx, signer, scittHeaders(d.revoked), target)
	if err != nil {
		return err
	}
	n.step("POST " + target + "   as " + revokedName)
	if err := d.expectRefused(ctx, client, target, hdrs, "STATUS_INVALID"); err != nil {
		return err
	}
	n.hold()
	return nil
}

func (d *demo) expectRefused(ctx context.Context, client *http.Client, target string, h http.Header, category string) error {
	status, _, err := send(ctx, client, target, h)
	if err != nil {
		return err
	}
	if status != http.StatusUnauthorized {
		return fmt.Errorf("%s: got %d, want 401", category, status)
	}
	d.n.bad(fmt.Sprintf("%d  %s", status, category))
	return nil
}

func (d *demo) closingSlide() {
	n := d.n
	n.slide("Verify, then connect.")
	n.sayf("  %sclient → server%s   preflight; receipt + status token checked against the log key and bound", ansiBold, ansiReset)
	n.sayf("                    to the TLS certificate. Revoked or expired: refused before the first request.")
	n.sayf("  %sserver → client%s   DPoP proof + receipt + status token on every request, bound to one", ansiBold, ansiReset)
	n.sayf("                    identity certificate. Replay, forgery and revocation refused. No mTLS.")
	n.sayf("")
	n.note("go run ./examples/verify-then-connect     verify.ServerVerifier.VerifyWithScitt · pop.Middleware")
	n.hold()
}

// startEndpoints serves one HTTPS endpoint per agent the demo calls, each
// answering with its own SCITT headers, and returns a client that resolves
// agent hostnames to those endpoints and trusts their server certificates: the
// demo's DNS and public CA. The returned func shuts the endpoints down.
func (d *demo) startEndpoints(ctx context.Context) (*http.Client, func(), error) {
	endpoints := []struct {
		agent   *demokit.Agent
		handler http.Handler
	}{
		{d.callee, d.calleeHandler(ctx)},
		{d.revoked, healthMux()},
		{d.stale, healthMux()},
	}
	dns := make(map[string]string, len(endpoints))
	roots := x509.NewCertPool()
	servers := make([]*httptest.Server, 0, len(endpoints))
	closeAll := func() {
		for _, srv := range servers {
			srv.Close()
		}
	}
	for _, e := range endpoints {
		cert, err := x509.ParseCertificate(e.agent.Server.CertDER)
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		roots.AddCert(cert)
		srv := startTLS(e.agent.Server, withResponseHeaders(scittHeaders(e.agent), e.handler))
		servers = append(servers, srv)
		dns[e.agent.Host] = srv.Listener.Addr().String()
	}
	return newClient(dns, roots), closeAll, nil
}

// calleeHandler is the genuine callee: the preflight path open, everything
// else behind pop.Middleware.
func (d *demo) calleeHandler(ctx context.Context) http.Handler {
	replay := pop.NewMemoryReplayCache(ctx, replayCacheSize)
	mux := healthMux()
	mux.Handle("/", pop.Middleware(d.log.KeyLookup(), replay,
		pop.WithMiddlewareLogger(d.trace),
		pop.WithTrustedHosts(d.callee.Host),
	)(http.HandlerFunc(acceptPayment)))
	return mux
}

// acceptPayment is the callee's application. It runs behind pop.Middleware,
// which puts the authenticated caller in the request context.
func acceptPayment(w http.ResponseWriter, r *http.Request) {
	id, ok := pop.CallerFromContext(r.Context())
	if !ok {
		http.Error(w, "no caller in context", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "payment accepted — authenticated caller: %s", id.AnsName) //nolint:gosec // G705: text/plain, type set above
}

// healthMux answers the unauthenticated preflight path.
func healthMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(healthPath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return mux
}

// scittHeaders are the receipt and status token an agent presents, on its
// responses as a callee and on its requests as a caller.
func scittHeaders(a *demokit.Agent) http.Header {
	return scitt.GenerateHeaders(a.Bundle.Receipt, a.Bundle.StatusToken)
}

func withResponseHeaders(h http.Header, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, vals := range h {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func startTLS(id *demokit.ServerIdentity, h http.Handler) *httptest.Server {
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{id.CertDER}, PrivateKey: id.Key}},
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	return srv
}

// newClient resolves agent hostnames through dns (host to listener address)
// and trusts roots, so URLs carry real agent hostnames.
func newClient(dns map[string]string, roots *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				listener, ok := dns[host]
				if !ok {
					return nil, fmt.Errorf("no such host %q", host)
				}
				var d net.Dialer
				return d.DialContext(ctx, network, listener)
			},
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		},
	}
}

// preflight performs the unauthenticated GET and returns the server's TLS leaf
// certificate and the SCITT headers it answered with.
func preflight(ctx context.Context, client *http.Client, target string) (*x509.Certificate, *scitt.Headers, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req) //nolint:gosec // G704: the client dials a fixed loopback listener
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err = io.Copy(io.Discard, resp.Body); err != nil {
		return nil, nil, err
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, nil, errors.New("preflight: no TLS peer certificate")
	}
	hdrs, err := scitt.ExtractHeaders(resp.Header)
	if err != nil {
		return nil, nil, err
	}
	return resp.TLS.PeerCertificates[0], hdrs, nil
}

// signedHeaders builds the headers for a POST of payBody to target: a fresh
// DPoP proof from signer plus the caller's SCITT headers.
func signedHeaders(ctx context.Context, signer *pop.Signer, scittHdrs http.Header, target string) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(payBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := pop.AttachIdentity(req, signer, scittHdrs); err != nil {
		return nil, err
	}
	return req.Header.Clone(), nil
}

// send POSTs payBody to target with exactly the given headers.
func send(ctx context.Context, client *http.Client, target string, h http.Header) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(payBody))
	if err != nil {
		return 0, "", err
	}
	req.Header = h.Clone()
	resp, err := client.Do(req) //nolint:gosec // G704: the client dials a fixed loopback listener
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, strings.TrimSpace(string(body)), nil
}

func shortFingerprint(cert *x509.Certificate) string {
	fp := verify.CertFingerprintFromDER(cert.Raw).ToHex()
	return "SHA256:" + fp[:hexAbbrev] + "…"
}
