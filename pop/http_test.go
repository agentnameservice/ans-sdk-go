package pop

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// newTestServer starts a TLS test server whose own authority is the trusted
// one, in the order a deployment follows: the listener exists before the
// handler is wired, so the authority is known when Middleware is built.
func newTestServer(t *testing.T, keys scitt.KeyLookup, replay ReplayCache, handler http.Handler,
	opts ...MiddlewareOption) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	authority := srv.Listener.Addr().String()
	srv.Config.Handler = Middleware(keys, replay,
		append([]MiddlewareOption{WithTrustedHosts(authority)}, opts...)...)(handler)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// addHeaders copies all values from src onto req.
func addHeaders(req *http.Request, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
}

func TestMiddleware_EndToEnd(t *testing.T) {
	h := newHarness(t)
	clock := func() time.Time { return h.now }
	replay := NewMemoryReplayCache(context.Background(), 100, withReplayClock(clock))
	defer replay.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := CallerFromContext(r.Context())
		if !ok {
			http.Error(w, "no caller in context", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, id.AnsName)
	})
	srv := newTestServer(t, h.keys, replay, handler,
		quiet(), WithMiddlewareCallerOptions(withCallerClock(clock)))
	client := srv.Client()

	scittHeaders := scitt.GenerateHeaders(h.receipt(t), h.statusToken(t))

	t.Run("authenticated no-mTLS call -> 200", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/v1/do", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if err := AttachIdentity(req, h.signer, scittHeaders); err != nil {
			t.Fatalf("AttachIdentity: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
		}
		if string(body) != h.ansName {
			t.Errorf("body = %q, want %q", body, h.ansName)
		}
	})

	t.Run("no identity headers -> 401", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/v1/do", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
		if resp.Header.Get("WWW-Authenticate") != DPoPHeader {
			t.Errorf("WWW-Authenticate = %q", resp.Header.Get("WWW-Authenticate"))
		}
	})

	t.Run("replayed proof -> 401", func(t *testing.T) {
		signed, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/replay", nil)
		if err := AttachIdentity(signed, h.signer, scittHeaders); err != nil {
			t.Fatalf("AttachIdentity: %v", err)
		}
		dpop := signed.Header.Get(DPoPHeader)
		mk := func() *http.Request {
			r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/replay", nil)
			r.Header.Set(DPoPHeader, dpop)
			addHeaders(r, scittHeaders)
			return r
		}
		resp1, err := client.Do(mk())
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		resp1.Body.Close()
		if resp1.StatusCode != http.StatusOK {
			t.Fatalf("first replay-test request = %d, want 200", resp1.StatusCode)
		}
		resp2, err := client.Do(mk())
		if err != nil {
			t.Fatalf("second: %v", err)
		}
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusUnauthorized {
			t.Fatalf("replay = %d, want 401", resp2.StatusCode)
		}
	})
}

func TestMiddleware_ExternalURL(t *testing.T) {
	h := newHarness(t)
	clock := func() time.Time { return h.now }
	replay := NewMemoryReplayCache(context.Background(), 100, withReplayClock(clock))
	defer replay.Close()

	const externalBase = "https://public.example"
	mw := Middleware(h.keys, replay,
		quiet(),
		WithMiddlewareCallerOptions(withCallerClock(clock)),
		// Correct usage: a trusted authority joined with THIS request's path, so
		// htu still binds the target.
		WithExternalURL(func(r *http.Request) string { return externalBase + r.URL.RequestURI() }))
	srv := httptest.NewTLSServer(mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer srv.Close()

	send := func(t *testing.T, signedPath, requestPath string) int {
		t.Helper()
		proof, err := h.signer.Sign(context.Background(), http.MethodPost, externalBase+signedPath)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+requestPath, nil)
		req.Header.Set(DPoPHeader, proof)
		addHeaders(req, scitt.GenerateHeaders(h.receipt(t), h.statusToken(t)))
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	t.Run("proof bound to the external URL is accepted", func(t *testing.T) {
		if got := send(t, "/v1/do", "/v1/do"); got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
	})
	t.Run("proof for a different path is rejected", func(t *testing.T) {
		if got := send(t, "/v1/status", "/v1/admin/keys"); got != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 — htu must bind the path", got)
		}
	})
}

func TestWithExternalURL_RejectsPathIgnoringFunction(t *testing.T) {
	h := newHarness(t)
	defer func() {
		if recover() == nil {
			t.Error("expected panic for an externalURL function that ignores the path")
		}
	}()
	Middleware(h.keys, h.replay, quiet(),
		WithExternalURL(func(*http.Request) string { return "https://public.example/api" }))
}

func TestAccessTokenFromAuthorization(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		wantTok string
		wantOK  bool
	}{
		{"DPoP scheme", "DPoP abc.def", "abc.def", true},
		{"case-insensitive scheme", "dpop tok", "tok", true},
		{"extra spaces before token", "DPoP   tok", "tok", true},
		{"Bearer scheme ignored", "Bearer tok", "", false},
		{"absent", "", "", false},
		{"scheme only", "DPoP", "", false},
		{"scheme with only spaces", "DPoP   ", "", false},
		{"no space separator", "DPoPtok", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, ok := AccessTokenFromAuthorization(tt.header)
			if ok != tt.wantOK || tok != tt.wantTok {
				t.Errorf("AccessTokenFromAuthorization(%q) = (%q, %v), want (%q, %v)",
					tt.header, tok, ok, tt.wantTok, tt.wantOK)
			}
		})
	}
}

func TestMiddleware_TokenBinding(t *testing.T) {
	h := newHarness(t)
	clock := func() time.Time { return h.now }
	replay := NewMemoryReplayCache(context.Background(), 100, withReplayClock(clock))
	defer replay.Close()

	srv := newTestServer(t, h.keys, replay, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}),
		quiet(), WithMiddlewareCallerOptions(withCallerClock(clock)))
	client := srv.Client()
	scittHeaders := scitt.GenerateHeaders(h.receipt(t), h.statusToken(t))
	const tok = "oauth-access-token"

	do := func(t *testing.T, req *http.Request) int {
		t.Helper()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	t.Run("DPoP-bound token with matching ath -> 200", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/v1/a", nil)
		req.Header.Set("Authorization", "DPoP "+tok)
		// AttachIdentity sees the DPoP-scheme token and mints ath automatically.
		if err := AttachIdentity(req, h.signer, scittHeaders); err != nil {
			t.Fatalf("AttachIdentity: %v", err)
		}
		if got := do(t, req); got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
	})

	t.Run("DPoP-bound token but proof without ath -> 401", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/v1/b", nil)
		if err := AttachIdentity(req, h.signer, scittHeaders); err != nil { // no token yet: no ath
			t.Fatalf("AttachIdentity: %v", err)
		}
		req.Header.Set("Authorization", "DPoP "+tok) // token added after signing
		if got := do(t, req); got != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", got)
		}
	})

	t.Run("proof with ath but no token on request -> 401", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/v1/c", nil)
		req.Header.Set("Authorization", "DPoP "+tok)
		if err := AttachIdentity(req, h.signer, scittHeaders); err != nil {
			t.Fatalf("AttachIdentity: %v", err)
		}
		req.Header.Del("Authorization") // proof carries ath, request carries no token
		if got := do(t, req); got != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", got)
		}
	})

	t.Run("Bearer token is not DPoP-bound: proof must carry no ath -> 200", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/v1/d", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		if err := AttachIdentity(req, h.signer, scittHeaders); err != nil {
			t.Fatalf("AttachIdentity: %v", err)
		}
		if got := do(t, req); got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
	})
}

// TestMiddleware_TrustedHosts proves the spoofed-Host attack is closed: a proof
// minted for another origin must not be accepted just because the client sets a
// matching Host header.
func TestMiddleware_TrustedHosts(t *testing.T) {
	h := newHarness(t)
	clock := func() time.Time { return h.now }
	replay := NewMemoryReplayCache(context.Background(), 100, withReplayClock(clock))
	defer replay.Close()

	mw := Middleware(h.keys, replay,
		quiet(),
		WithMiddlewareCallerOptions(withCallerClock(clock)),
		WithTrustedHosts("Callee.Example:443", " "))
	srv := httptest.NewTLSServer(mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer srv.Close()
	scittHeaders := scitt.GenerateHeaders(h.receipt(t), h.statusToken(t))

	send := func(t *testing.T, host string) int {
		t.Helper()
		target := "https://" + host + "/v1/do"
		proof, err := h.signer.Sign(context.Background(), http.MethodGet, target)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/v1/do", nil)
		req.Host = host // spoofed authority the htu is bound to
		req.Header.Set(DPoPHeader, proof)
		addHeaders(req, scittHeaders)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	t.Run("untrusted spoofed Host rejected", func(t *testing.T) {
		if got := send(t, "victim.example"); got != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 for spoofed Host", got)
		}
	})
	t.Run("trusted Host accepted case-insensitively", func(t *testing.T) {
		if got := send(t, "callee.example:443"); got != http.StatusOK {
			t.Fatalf("status = %d, want 200 for trusted Host", got)
		}
	})
	t.Run("WithExternalURL still enforces the trusted authority", func(t *testing.T) {
		const externalBase = "https://only.example"
		emw := Middleware(h.keys, replay,
			quiet(),
			WithMiddlewareCallerOptions(withCallerClock(clock)),
			WithTrustedHosts("only.example"),
			WithExternalURL(func(r *http.Request) string { return externalBase + r.URL.RequestURI() }))
		esrv := httptest.NewTLSServer(emw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))
		defer esrv.Close()
		proof, err := h.signer.Sign(context.Background(), http.MethodPost, externalBase+"/x")
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, esrv.URL+"/x", nil)
		req.Host = "anything.example" // spoofed, but the authority comes from the option
		req.Header.Set(DPoPHeader, proof)
		addHeaders(req, scittHeaders)
		resp, err := esrv.Client().Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})
}

func TestTrustedKey(t *testing.T) {
	tests := []struct {
		name   string
		scheme string
		in     string
		want   string
	}{
		{"lowercases", "https", "API.Example.COM", "https://api.example.com"},
		{"drops the https default port under https", "https", "api.example.com:443", "https://api.example.com"},
		{"keeps port 80 under https", "https", "api.example.com:80", "https://api.example.com:80"},
		{"drops the http default port under http", "http", "api.example.com:80", "http://api.example.com"},
		{"keeps port 443 under http", "http", "api.example.com:443", "http://api.example.com:443"},
		{"keeps a non-default port", "https", "api.example.com:8443", "https://api.example.com:8443"},
		{"trims space", "https", "  api.example.com  ", "https://api.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trustedKey(tt.scheme, tt.in); got != tt.want {
				t.Errorf("trustedKey(%q, %q) = %q, want %q", tt.scheme, tt.in, got, tt.want)
			}
		})
	}
}

// TestMiddleware_TrustedAuthorityPorts: an allowlist entry names an origin, so a
// port that is not the request scheme's default is a different origin even when
// it is the other scheme's default. The proof is minted for the spoofed
// authority, so only the allowlist stands between it and a 200.
func TestMiddleware_TrustedAuthorityPorts(t *testing.T) {
	tests := []struct {
		name    string
		tls     bool
		trusted string
		host    string
		want    int
	}{
		{"https: bare host", true, "callee.example", "callee.example", http.StatusOK},
		{"https: explicit default port", true, "callee.example", "callee.example:443", http.StatusOK},
		{"https: port 80 is another origin", true, "callee.example", "callee.example:80", http.StatusUnauthorized},
		{"https: unrelated port", true, "callee.example", "callee.example:8443", http.StatusUnauthorized},
		{"https: non-default entry matches exactly", true, "callee.example:8443", "callee.example:8443", http.StatusOK},
		{"https: non-default entry does not cover the bare host", true, "callee.example:8443", "callee.example",
			http.StatusUnauthorized},
		{"http: explicit default port", false, "callee.example", "callee.example:80", http.StatusOK},
		{"http: port 443 is another origin", false, "callee.example", "callee.example:443", http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			clock := func() time.Time { return h.now }
			replay := NewMemoryReplayCache(context.Background(), 100, withReplayClock(clock))
			defer replay.Close()
			mw := Middleware(h.keys, replay, quiet(),
				WithMiddlewareCallerOptions(withCallerClock(clock)), WithTrustedHosts(tt.trusted))
			ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			scheme := "http"
			var srv *httptest.Server
			if tt.tls {
				scheme = "https"
				srv = httptest.NewTLSServer(mw(ok))
			} else {
				srv = httptest.NewServer(mw(ok))
			}
			defer srv.Close()

			proof, err := h.signer.Sign(context.Background(), http.MethodGet, scheme+"://"+tt.host+"/v1/do")
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/v1/do", nil)
			req.Host = tt.host
			req.Header.Set(DPoPHeader, proof)
			addHeaders(req, scitt.GenerateHeaders(h.receipt(t), h.statusToken(t)))
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
}

func TestWithTrustedHosts_PanicsWhenAllEmpty(t *testing.T) {
	h := newHarness(t)
	defer func() {
		if recover() == nil {
			t.Error("expected panic when every trusted host is empty")
		}
	}()
	// The shape an unset environment variable produces.
	Middleware(h.keys, h.replay, quiet(), WithTrustedHosts("", "  "))
}

func TestMiddleware_DuplicateHeadersRejected(t *testing.T) {
	h := newHarness(t)
	clock := func() time.Time { return h.now }
	replay := NewMemoryReplayCache(context.Background(), 100, withReplayClock(clock))
	defer replay.Close()

	srv := newTestServer(t, h.keys, replay, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}),
		quiet(), WithMiddlewareCallerOptions(withCallerClock(clock)))
	scittHeaders := scitt.GenerateHeaders(h.receipt(t), h.statusToken(t))

	cases := []struct {
		name string
		mut  func(*http.Request, string)
	}{
		{"duplicate DPoP header", func(r *http.Request, proof string) { r.Header.Add(DPoPHeader, proof) }},
		{"duplicate Authorization header", func(r *http.Request, _ string) {
			r.Header.Add("Authorization", "DPoP a")
			r.Header.Add("Authorization", "DPoP b")
		}},
		// Identity headers decide WHICH agent is authenticated, and Header.Get
		// takes the first value — a duplicate would split this verifier's view
		// of the caller from any other hop's.
		{"duplicate status token", func(r *http.Request, _ string) {
			r.Header.Add(scitt.HeaderStatusToken, "ZHVwbGljYXRl")
		}},
		{"duplicate receipt", func(r *http.Request, _ string) {
			r.Header.Add(scitt.HeaderReceipt, "ZHVwbGljYXRl")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/v1/dup", nil)
			if err := AttachIdentity(req, h.signer, scittHeaders); err != nil {
				t.Fatalf("AttachIdentity: %v", err)
			}
			tc.mut(req, req.Header.Get(DPoPHeader))
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
		})
	}
}

// TestMiddleware_BareOriginTarget covers the RFC 3986 §6.2.3 path normalization:
// a proof minted for an origin with no path must match the "/" the wire carries.
func TestMiddleware_BareOriginTarget(t *testing.T) {
	h := newHarness(t)
	clock := func() time.Time { return h.now }
	replay := NewMemoryReplayCache(context.Background(), 100, withReplayClock(clock))
	defer replay.Close()

	srv := newTestServer(t, h.keys, replay, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}),
		quiet(), WithMiddlewareCallerOptions(withCallerClock(clock)))

	// Sign the bare origin (no trailing slash); the client will send "/".
	proof, err := h.signer.Sign(context.Background(), http.MethodGet, srv.URL)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	req.Header.Set(DPoPHeader, proof)
	addHeaders(req, scitt.GenerateHeaders(h.receipt(t), h.statusToken(t)))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bare-origin target status = %d, want 200", resp.StatusCode)
	}
}

func TestCallerFromContext_AbsentWithoutMiddleware(t *testing.T) {
	if _, ok := CallerFromContext(context.Background()); ok {
		t.Fatal("expected ok=false when no middleware ran")
	}
}

// TestAttachIdentity_BindsContent: the proof carries the body's digest and the
// body stays readable, with a known length, for the transport.
func TestAttachIdentity_BindsContent(t *testing.T) {
	h := newHarness(t)
	scittHeaders := scitt.GenerateHeaders(h.receipt(t), h.statusToken(t))
	body := `{"amount":100}`
	tests := []struct {
		name string
		body io.Reader
		want string
	}{
		{name: "no body binds the empty digest", want: EmptyContentDigest},
		{name: "body is hashed", body: strings.NewReader(body), want: b64urlEncode(digestOf([]byte(body)))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://callee.example/v1/do", tt.body)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			if err := AttachIdentity(req, h.signer, scittHeaders); err != nil {
				t.Fatalf("AttachIdentity: %v", err)
			}
			_, pB64, _, err := splitCompactJWS(req.Header.Get(DPoPHeader))
			if err != nil {
				t.Fatalf("split: %v", err)
			}
			pl, err := decodeProofPayload(pB64)
			if err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			if pl.ContentDigest != tt.want {
				t.Errorf("ans_content_digest = %q, want %q", pl.ContentDigest, tt.want)
			}
			if tt.body == nil {
				return
			}
			got, err := io.ReadAll(req.Body)
			if err != nil || string(got) != body {
				t.Fatalf("body after AttachIdentity = %q, %v; want %q", got, err, body)
			}
			if req.ContentLength != int64(len(body)) {
				t.Errorf("ContentLength = %d, want %d", req.ContentLength, len(body))
			}
			if req.GetBody == nil {
				t.Fatal("GetBody not set; the transport could not replay the body")
			}
			again, err := req.GetBody()
			if err != nil {
				t.Fatalf("GetBody: %v", err)
			}
			if got, _ := io.ReadAll(again); string(got) != body {
				t.Errorf("GetBody = %q, want %q", got, body)
			}
		})
	}
}

// TestMiddleware_ContentBinding: the callee verifies ans_content_digest against
// the content it received before the handler sees the request, and hands the
// verified bytes on.
func TestMiddleware_ContentBinding(t *testing.T) {
	h := newHarness(t)
	clock := func() time.Time { return h.now }
	replay := NewMemoryReplayCache(context.Background(), 100, withReplayClock(clock))
	defer replay.Close()
	scittHeaders := scitt.GenerateHeaders(h.receipt(t), h.statusToken(t))
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		_, _ = w.Write(got)
	})
	srv := newTestServer(t, h.keys, replay, echo, quiet(), WithMiddlewareCallerOptions(withCallerClock(clock)))
	small := newTestServer(t, h.keys, replay, echo, quiet(), WithMiddlewareCallerOptions(withCallerClock(clock)),
		WithMaxContentBytes(8))
	orig := `{"amount":100}`

	tests := []struct {
		name   string
		srv    *httptest.Server
		signed []byte // content the proof binds; nil binds empty content
		sent   string
		want   int
	}{
		{name: "matching content", srv: srv, signed: []byte(orig), sent: orig, want: http.StatusOK},
		{name: "no content either side", srv: srv, want: http.StatusOK},
		{name: "tampered content", srv: srv, signed: []byte(orig), sent: `{"amount":9000}`, want: http.StatusUnauthorized},
		{name: "content added to an empty request", srv: srv, sent: orig, want: http.StatusUnauthorized},
		{name: "content removed", srv: srv, signed: []byte(orig), want: http.StatusUnauthorized},
		{name: "content over the size cap", srv: small, signed: []byte(orig), sent: orig,
			want: http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := tt.srv.URL + "/v1/do"
			proof, err := h.signer.Sign(context.Background(), http.MethodPost, target, WithContent(tt.signed))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(tt.sent))
			req.Header.Set(DPoPHeader, proof)
			addHeaders(req, scittHeaders)
			resp, err := tt.srv.Client().Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer resp.Body.Close()
			echoed, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tt.want {
				t.Fatalf("status = %d, want %d (%s)", resp.StatusCode, tt.want, echoed)
			}
			if tt.want == http.StatusOK && string(echoed) != tt.sent {
				t.Errorf("handler received %q, want %q", echoed, tt.sent)
			}
		})
	}
}

func TestAttachIdentity_UnreadableBody(t *testing.T) {
	h := newHarness(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://callee.example/v1/do",
		iotest.ErrReader(errors.New("body vanished")))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	assertProofErr(t, AttachIdentity(req, h.signer, nil), ErrContentUnreadable)
}

func TestAttachIdentity_Errors(t *testing.T) {
	h := newHarness(t)
	if err := AttachIdentity(nil, h.signer, nil); err == nil {
		t.Fatal("expected error for nil request")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://h.example/x", nil)
	if err := AttachIdentity(req, nil, nil); err == nil {
		t.Fatal("expected error for nil signer")
	}
	relative := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/relative-only"}, Header: http.Header{}}
	if err := AttachIdentity(relative, h.signer, nil); err == nil {
		t.Fatal("expected error for non-absolute request URL")
	}
}

func TestDefaultRequestURL(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/a/b?q=1", nil)
	req.Host = "example.test"
	if got := defaultRequestURL(req); got != "http://example.test/a/b?q=1" {
		t.Errorf("defaultRequestURL = %q", got)
	}
}
