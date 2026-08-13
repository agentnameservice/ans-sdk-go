package pop

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

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
	mw := Middleware(h.keys, replay,
		quiet(), WithMiddlewareCallerOptions(withCallerClock(clock)))
	srv := httptest.NewTLSServer(mw(handler))
	defer srv.Close()
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

	mw := Middleware(h.keys, replay,
		quiet(), WithMiddlewareCallerOptions(withCallerClock(clock)))
	srv := httptest.NewTLSServer(mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer srv.Close()
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

func TestWithTrustedHosts_Normalization(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lowercases", "API.Example.COM", "api.example.com"},
		{"drops https default port", "api.example.com:443", "api.example.com"},
		{"drops http default port", "api.example.com:80", "api.example.com"},
		{"keeps non-default port", "api.example.com:8443", "api.example.com:8443"},
		{"trims space", "  api.example.com  ", "api.example.com"},
		{"empty stays empty", "   ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeAuthority(tt.in); got != tt.want {
				t.Errorf("normalizeAuthority(%q) = %q, want %q", tt.in, got, tt.want)
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

	mw := Middleware(h.keys, replay,
		quiet(), WithMiddlewareCallerOptions(withCallerClock(clock)))
	srv := httptest.NewTLSServer(mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer srv.Close()
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

	mw := Middleware(h.keys, replay,
		quiet(), WithMiddlewareCallerOptions(withCallerClock(clock)))
	srv := httptest.NewTLSServer(mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer srv.Close()

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
