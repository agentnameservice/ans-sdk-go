// Command a2a-no-mtls demonstrates ANS agent-to-agent authentication at the
// HTTP layer with NO mutual TLS, in a single process.
//
// The caller proves its identity to the callee with a DPoP proof bound to its
// ANS identity certificate (possession), plus its SCITT receipt (identity) and
// status token (liveness). The callee verifies all three with pop.Middleware
// over ordinary server-authenticated HTTPS — no client certificate is presented
// in the TLS handshake.
//
// It prints five outcomes: an authenticated call succeeds, and a replayed proof,
// a method-tampered proof, a wrong-peer proof, and a proof minted for another
// origin (presented with a spoofed Host) are all rejected. For a two-process
// version over a real socket — including the OAuth2 token-binding scenarios —
// see ./server, ./client, and run.sh.
//
//nolint:forbidigo,gosec,mnd // runnable demo: writes to stdout, fixed demo values
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/agentnameservice/ans-sdk-go/examples/a2a-no-mtls/demokit"
	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "demo failed:", err)
		os.Exit(1)
	}
}

// agent is the caller's material plus the callee's trust store, provisioned once
// and shared by every scenario.
type agent struct {
	keys   scitt.KeyLookup
	signer *pop.Signer
	scitt  http.Header
}

func run() error {
	ctx := context.Background()
	a, err := provision()
	if err != nil {
		return err
	}

	replay := pop.NewMemoryReplayCache(ctx, 1000)
	defer replay.Close()
	srv := startCallee(a.keys, replay)
	defer srv.Close()

	fmt.Println("ANS agent-to-agent — no mTLS (DPoP possession + SCITT identity/liveness)")
	fmt.Println()

	if err := a.authAndReplay(ctx, srv); err != nil {
		return err
	}
	if err := a.methodTamper(ctx, srv); err != nil {
		return err
	}
	if err := a.wrongPeer(ctx); err != nil {
		return err
	}
	if err := a.spoofedAuthority(ctx, srv); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("All five outcomes as expected — no mutual TLS was used.")
	return nil
}

// provision generates the agent's credentials (the RA/TL stand-in) and the
// callee's trust store from the same TL key.
func provision() (*agent, error) {
	tlKey, bundle, err := demokit.Provision(demokit.DemoAnsName, demokit.DemoAgentID)
	if err != nil {
		return nil, err
	}
	keys, err := demokit.KeyLookup(&tlKey.PublicKey)
	if err != nil {
		return nil, err
	}
	signer, err := pop.NewSigner(bundle.AgentKey, bundle.CertDER)
	if err != nil {
		return nil, err
	}
	return &agent{
		keys:   keys,
		signer: signer,
		scitt:  scitt.GenerateHeaders(bundle.Receipt, bundle.StatusToken),
	}, nil
}

// startCallee brings up a TLS server, then points pop.Middleware at that
// server's own authority: htu is never derived from a client-supplied Host
// header. Extra middleware options are appended after the trusted host.
func startCallee(keys scitt.KeyLookup, replay pop.ReplayCache, opts ...pop.MiddlewareOption) *httptest.Server {
	srv := httptest.NewUnstartedServer(nil)
	// The listener is bound by NewUnstartedServer and StartTLS only wraps it, so
	// the authority is known here. Assign the handler BEFORE starting: writing
	// srv.Config.Handler after StartTLS races the connection goroutines that read
	// it.
	authority := srv.Listener.Addr().String()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := pop.CallerFromContext(r.Context())
		if !ok {
			http.Error(w, "no caller in context", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "authenticated caller: %s", id.AnsName)
	})
	srv.Config.Handler = pop.Middleware(keys, replay,
		append([]pop.MiddlewareOption{pop.WithTrustedHosts(authority)}, opts...)...)(handler)
	srv.StartTLS()
	return srv
}

// authAndReplay: an authenticated call succeeds, and the identical proof
// presented again is rejected as a replay.
func (a *agent) authAndReplay(ctx context.Context, srv *httptest.Server) error {
	target := srv.URL + "/v1/do"
	headers, err := a.signedGetHeaders(ctx, target)
	if err != nil {
		return err
	}
	if err := expect(ctx, srv.Client(), http.MethodGet, target, headers, http.StatusOK,
		"authenticated no-mTLS call"); err != nil {
		return err
	}
	return expect(ctx, srv.Client(), http.MethodGet, target, headers, http.StatusUnauthorized,
		"replayed proof rejected")
}

// methodTamper: a GET-bound proof presented on a POST request.
func (a *agent) methodTamper(ctx context.Context, srv *httptest.Server) error {
	target := srv.URL + "/v1/do"
	headers, err := a.signedGetHeaders(ctx, target)
	if err != nil {
		return err
	}
	return expect(ctx, srv.Client(), http.MethodPost, target, headers, http.StatusUnauthorized,
		"method-tampered proof rejected")
}

// wrongPeer: a callee that only accepts a different ANS name.
func (a *agent) wrongPeer(ctx context.Context) error {
	replay := pop.NewMemoryReplayCache(ctx, 1000)
	defer replay.Close()
	srv := startCallee(a.keys, replay,
		pop.WithMiddlewareCallerOptions(pop.WithExpectedAnsName("ans://v1.0.0.other.example")))
	defer srv.Close()

	target := srv.URL + "/v1/do"
	headers, err := a.signedGetHeaders(ctx, target)
	if err != nil {
		return err
	}
	return expect(ctx, srv.Client(), http.MethodGet, target, headers, http.StatusUnauthorized,
		"wrong-peer proof rejected")
}

// spoofedAuthority: a proof minted for another origin, presented here with a
// matching Host header. WithTrustedHosts is what refuses it.
func (a *agent) spoofedAuthority(ctx context.Context, srv *httptest.Server) error {
	const victim = "victim.example"
	headers, err := a.signedGetHeaders(ctx, "https://"+victim+"/v1/do")
	if err != nil {
		return err
	}
	return expectWithHost(ctx, srv.Client(), http.MethodGet, srv.URL+"/v1/do", victim, headers,
		http.StatusUnauthorized, "proof for another origin rejected (spoofed Host)")
}

// signedGetHeaders builds the headers a caller attaches for a GET of rawURL: a
// fresh DPoP proof bound to that method and URL, plus the SCITT identity
// headers. Scenarios that send a different method reuse these deliberately, to
// show the htm binding rejecting the mismatch.
func (a *agent) signedGetHeaders(ctx context.Context, rawURL string) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if err := pop.AttachIdentity(req, a.signer, a.scitt); err != nil {
		return nil, err
	}
	return req.Header.Clone(), nil
}

// expect sends a request with the given headers and checks the status code.
func expect(ctx context.Context, client *http.Client, method, rawURL string, headers http.Header, want int, label string) error {
	return expectWithHost(ctx, client, method, rawURL, "", headers, want, label)
}

// expectWithHost is expect with an optional spoofed Host header, for showing
// that the htu authority is not taken from the request.
func expectWithHost(ctx context.Context, client *http.Client, method, rawURL, host string,
	headers http.Header, want int, label string) error {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header = headers.Clone()
	if host != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != want {
		return fmt.Errorf("%s: got status %d (%s), want %d", label, resp.StatusCode, body, want)
	}
	if len(body) > 0 {
		fmt.Printf("  [ok] %s -> %d %q\n", label, resp.StatusCode, body)
	} else {
		fmt.Printf("  [ok] %s -> %d\n", label, resp.StatusCode)
	}
	return nil
}
