// Command client is the caller side of the no-mTLS agent-to-agent demo. It
// loads the agent credential bundle from --dir, attaches a DPoP proof plus its
// SCITT receipt and status token to a request, and calls --url over plain HTTP
// — no client certificate. It narrates each step (component=caller). Modes:
// auth (default), replay, noident, oauth, stolentoken.
//
//nolint:gosec,mnd // demo binary: fixed demo values, talks to a demo URL
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/agentnameservice/ans-sdk-go/examples/a2a-no-mtls/demokit"
	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

func main() {
	dir := flag.String("dir", "", "shared directory holding the agent bundle")
	rawURL := flag.String("url", "http://127.0.0.1:18099/v1/do", "callee URL")
	mode := flag.String("mode", "auth", "auth | replay | noident | oauth | stolentoken")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "client: --dir is required")
		os.Exit(2)
	}
	if err := run(*dir, *rawURL, *mode); err != nil {
		fmt.Fprintln(os.Stderr, "client:", err)
		os.Exit(1)
	}
}

// caller bundles everything one demo caller needs to make authenticated calls.
type caller struct {
	client *http.Client
	signer *pop.Signer
	scitt  http.Header
	jkt    string // RFC 7638 thumbprint of our identity key, for cnf.jkt
	log    *slog.Logger
}

func run(dir, rawURL, mode string) error {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})).
		With("component", "caller")

	bundle, err := loadWithRetry(dir)
	if err != nil {
		return err
	}
	signer, err := pop.NewSigner(bundle.AgentKey, bundle.CertDER)
	if err != nil {
		return err
	}
	log.Info("loaded agent identity (no client certificate will be presented)",
		"ansName", demokit.DemoAnsName)

	c := &caller{
		client: &http.Client{Timeout: 5 * time.Second},
		signer: signer,
		scitt:  scitt.GenerateHeaders(bundle.Receipt, bundle.StatusToken),
		jkt:    signer.JKT(),
		log:    log,
	}
	c.waitForServer(rawURL)

	switch mode {
	case "auth":
		return c.auth(rawURL)
	case "replay":
		return c.replay(rawURL)
	case "noident":
		return c.noident(rawURL)
	case "oauth":
		return c.oauth(rawURL)
	case "stolentoken":
		return c.stolenToken(rawURL)
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
}

func (c *caller) auth(rawURL string) error {
	c.log.Info("sending request with DPoP proof + SCITT receipt/status headers",
		"method", http.MethodGet, "url", rawURL)
	req, err := c.signed(http.MethodGet, rawURL)
	if err != nil {
		return err
	}
	status, body, err := c.send(req)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("authenticated call: got %d (%s), want 200", status, body)
	}
	c.log.Info("authenticated over plain HTTP, no mTLS", "status", status, "body", body)
	return nil
}

func (c *caller) replay(rawURL string) error {
	req, err := c.signed(http.MethodGet, rawURL)
	if err != nil {
		return err
	}
	captured := req.Header.Clone() // the SAME proof (same jti) reused below
	c.log.Info("sending a proof, then replaying the identical proof", "method", http.MethodGet, "url", rawURL)

	s1, _, err := c.send(cloneReq(req, captured))
	if err != nil {
		return err
	}
	s2, _, err := c.send(cloneReq(req, captured))
	if err != nil {
		return err
	}
	if s1 != http.StatusOK || s2 != http.StatusUnauthorized {
		return fmt.Errorf("replay: got first=%d second=%d, want 200 then 401", s1, s2)
	}
	c.log.Info("replay rejected by the callee", "first", s1, "replay", s2)
	return nil
}

func (c *caller) noident(rawURL string) error {
	c.log.Info("sending a request with NO identity (no DPoP, no SCITT headers)",
		"method", http.MethodGet, "url", rawURL)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	status, _, err := c.send(req)
	if err != nil {
		return err
	}
	if status != http.StatusUnauthorized {
		return fmt.Errorf("no-identity call: got %d, want 401", status)
	}
	c.log.Info("unidentified request rejected by the callee", "status", status)
	return nil
}

// oauth presents a DPoP-bound OAuth2 access token alongside the ANS identity.
// The token is issued to this agent's own key, so the callee's cnf.jkt check
// passes and the scoped call is authorized.
func (c *caller) oauth(rawURL string) error {
	tok, err := demokit.MintUnsignedDemoToken("agent-demo-1", "payments:read", c.jkt)
	if err != nil {
		return err
	}
	c.log.Info("sending request with a DPoP-bound access token (ath + cnf.jkt bind it to our key)",
		"scope", "payments:read", "jkt", c.jkt)
	req, err := c.signedWithToken(http.MethodGet, rawURL, tok)
	if err != nil {
		return err
	}
	status, body, err := c.send(req)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("oauth call: got %d (%s), want 200", status, body)
	}
	c.log.Info("token binding accepted by the callee", "status", status, "body", body)
	return nil
}

// stolenToken models the attack ath alone does not stop: a valid ANS agent
// presents a token issued to a DIFFERENT agent's key. pop authenticates the
// caller and the ath matches (the thief holds the token bytes), so only the
// callee's cnf.jkt comparison refuses it.
func (c *caller) stolenToken(rawURL string) error {
	const victimJKT = "0000000000000000000000000000000000000000000"
	tok, err := demokit.MintUnsignedDemoToken("agent-victim", "payments:write", victimJKT)
	if err != nil {
		return err
	}
	c.log.Info("sending a token issued to another agent's key (ath will match, cnf.jkt will not)",
		"victimJkt", victimJKT, "ourJkt", c.jkt)
	req, err := c.signedWithToken(http.MethodGet, rawURL, tok)
	if err != nil {
		return err
	}
	status, _, err := c.send(req)
	if err != nil {
		return err
	}
	if status != http.StatusForbidden {
		return fmt.Errorf("stolen-token call: got %d, want 403", status)
	}
	c.log.Info("stolen token refused: authenticated, but not authorized for a token bound to another key",
		"status", status)
	return nil
}

// signed builds a request and attaches a fresh DPoP proof + SCITT headers.
func (c *caller) signed(method, rawURL string) (*http.Request, error) {
	return c.signedWithToken(method, rawURL, "")
}

// signedWithToken builds a request, optionally presenting an access token under
// the DPoP auth scheme. The Authorization header MUST be set before
// AttachIdentity so the proof carries the matching ath.
func (c *caller) signedWithToken(method, rawURL, token string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "DPoP "+token)
	}
	if err := pop.AttachIdentity(req, c.signer, c.scitt); err != nil {
		return nil, err
	}
	return req, nil
}

func (c *caller) send(req *http.Request) (int, string, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, string(body), nil
}

// waitForServer polls the unauthenticated /healthz endpoint until the callee
// accepts connections (so the readiness probe doesn't show up as an auth
// rejection in the callee's logs).
func (c *caller) waitForServer(rawURL string) {
	probe := healthURL(rawURL)
	for range 50 {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, probe, nil)
		if err != nil {
			return
		}
		resp, err := c.client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// healthURL rewrites a callee URL to its /healthz path.
func healthURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Path = "/healthz"
	u.RawQuery = ""
	return u.String()
}

// cloneReq returns a fresh request to the same target carrying the given headers.
func cloneReq(base *http.Request, headers http.Header) *http.Request {
	r := base.Clone(context.Background())
	r.Header = headers.Clone()
	return r
}

// loadWithRetry waits for the server to provision the bundle into dir.
func loadWithRetry(dir string) (*demokit.Bundle, error) {
	var lastErr error
	for range 50 {
		b, err := demokit.LoadBundle(dir)
		if err == nil {
			return b, nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("bundle not available after retries: %w", lastErr)
}
