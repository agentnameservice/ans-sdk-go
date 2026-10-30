// Command server is the callee side of the no-mTLS agent-to-agent demo: a plain
// HTTP server fronted by pop.Middleware. On startup it provisions a demo agent
// credential bundle into --dir (standing in for the RA/TL), then verifies the
// three proofs (DPoP possession + SCITT receipt + status token) on every
// request. With --debug it logs each verification step. No client certificate.
//
//nolint:forbidigo,gosec,mnd // demo binary: writes to stdout, fixed demo values
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/agentnameservice/ans-sdk-go/examples/a2a-no-mtls/demokit"
	"github.com/agentnameservice/ans-sdk-go/pop"
)

func main() {
	dir := flag.String("dir", "", "shared directory to write the agent bundle into")
	addr := flag.String("addr", "127.0.0.1:18099", "listen address (may be a wildcard like :18099)")
	externalHost := flag.String("external-host", "127.0.0.1:18099",
		"externally-visible authority callers dial; this is what htu is checked against, NOT the bind address")
	debug := flag.Bool("debug", true, "log each verification step at DEBUG")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "server: --dir is required")
		os.Exit(2)
	}
	if err := run(*dir, *addr, *externalHost, *debug); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(1)
	}
}

func run(dir, addr, externalHost string, debug bool) error {
	// Provision the demo agent's credentials (RA/TL stand-in) and keep the TL
	// key to build the verifier trust store.
	tlKey, bundle, err := demokit.Provision(demokit.DemoAnsName, demokit.DemoAgentID)
	if err != nil {
		return err
	}
	if err := bundle.Save(dir); err != nil {
		return err
	}
	keys, err := demokit.KeyLookup(&tlKey.PublicKey)
	if err != nil {
		return err
	}

	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	replay := pop.NewMemoryReplayCache(context.Background(), 10000)
	defer replay.Close()

	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := pop.CallerFromContext(r.Context())
		if !ok {
			http.Error(w, "no caller in context", http.StatusInternalServerError)
			return
		}
		// pop has AUTHENTICATED the caller. Authorization is this handler's job,
		// including the second half of RFC 9449 token binding when the request
		// also presents a DPoP-bound access token.
		scope, authErr := authorize(r, id, logger)
		if authErr != nil {
			logger.Warn("authorization refused", "ansName", id.AnsName, "err", authErr.Error())
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// Explicit, because part of the body derives from the request: never let
		// Go sniff a Content-Type for caller-influenced output.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "hello from callee — authenticated caller: %s%s", id.AnsName, scope)
	})
	// /healthz is unauthenticated (for readiness probes); everything else goes
	// through pop.Middleware.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("/", pop.Middleware(keys, replay,
		pop.WithMiddlewareLogger(logger),
		// htu is compared against this authority instead of the request's own
		// Host header, which a client controls. Without this a proof captured
		// from a call to another origin would satisfy the htu check here.
		//
		// This is the EXTERNAL authority, deliberately not the bind address: a
		// production service listens on :port or 0.0.0.0:port, neither of which
		// any client ever sends as Host.
		pop.WithTrustedHosts(externalHost),
	)(app))

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	fmt.Printf("callee listening on http://%s (no mTLS); agent bundle written to %s\n", addr, dir)
	return srv.Serve(ln)
}

// authorize is the callee's own decision, made on the identity pop proved.
//
// When the request carries a DPoP-bound OAuth2 access token, pop has already
// verified the proof's ath against it (half of RFC 9449 §4.3). The other half is
// here and cannot be delegated: the token's cnf.jkt must name the same key that
// signed the proof, or a token stolen from another agent would be accepted from
// whoever presents it. CallerIdentity.JKT is that key's RFC 7638 thumbprint.
func authorize(r *http.Request, id *pop.CallerIdentity, log *slog.Logger) (string, error) {
	// Use the SDK's parser, never a second copy: Middleware verified the proof's
	// ath against exactly the bytes this returns. A handler-local parser that
	// disagreed (on the tab separator, say) would read "no token" and skip the
	// cnf.jkt check below while pop had already accepted the token.
	tok, ok := pop.AccessTokenFromAuthorization(r.Header.Get("Authorization"))
	if !ok {
		return "", nil // no token presented: ANS identity alone
	}
	// DEMO ONLY: this token is unsigned and self-issued, so any caller can mint
	// one naming any sub and scope — the cnf.jkt check below would still pass,
	// because the caller binds it to its own key. A real handler MUST validate
	// the issuer signature, exp, and aud BEFORE reaching that comparison.
	at, err := demokit.ParseUnsignedDemoToken(tok)
	if err != nil {
		return "", err
	}
	if at.Cnf.JKT != id.JKT {
		return "", fmt.Errorf("access token cnf.jkt %q is not the proof key %q: token was issued to another agent",
			at.Cnf.JKT, id.JKT)
	}
	log.Info("access token binding confirmed (cnf.jkt matches the proof key)",
		"sub", at.Sub, "scope", at.Scope, "jkt", at.Cnf.JKT)
	return " with scope " + at.Scope, nil
}

// A Bearer-presented token is ignored by AccessTokenFromAuthorization, which is
// deliberate: such a token is not sender-constrained, so honoring it here would
// silently downgrade every DPoP-bound token to a bearer token (RFC 9449 §7.1).
