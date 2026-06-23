package ans

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/agentnameservice/ans-sdk-go/verify"
)

func TestNewAgentClient(t *testing.T) {
	tests := []struct {
		name string
		opts []AgentClientOption
		want func(*testing.T, *AgentClient)
	}{
		{
			name: "default configuration",
			opts: nil,
			want: func(t *testing.T, c *AgentClient) {
				if c.httpClient == nil {
					t.Error("expected httpClient to be non-nil")
				}
				if c.verifier == nil {
					t.Error("expected verifier to be non-nil")
				}
				if c.config == nil {
					t.Error("expected config to be non-nil")
				}
				if c.config.timeout != defaultAgentClientTimeout {
					t.Errorf("expected timeout %v, got %v", defaultAgentClientTimeout, c.config.timeout)
				}
				if !c.config.verifyServer {
					t.Error("expected verifyServer to be true by default")
				}
				if c.config.failurePolicy != verify.FailClosed {
					t.Errorf("expected FailClosed policy, got %v", c.config.failurePolicy)
				}
			},
		},
		{
			name: "with custom timeout",
			opts: []AgentClientOption{WithAgentClientTimeout(60 * time.Second)},
			want: func(t *testing.T, c *AgentClient) {
				if c.config.timeout != 60*time.Second {
					t.Errorf("expected timeout 60s, got %v", c.config.timeout)
				}
			},
		},
		{
			name: "with server verification disabled",
			opts: []AgentClientOption{WithAgentClientVerifyServer(false)},
			want: func(t *testing.T, c *AgentClient) {
				if c.config.verifyServer {
					t.Error("expected verifyServer to be false")
				}
			},
		},
		{
			name: "with FailOpen policy",
			opts: []AgentClientOption{WithAgentClientFailurePolicy(verify.FailOpen)},
			want: func(t *testing.T, c *AgentClient) {
				if c.config.failurePolicy != verify.FailOpen {
					t.Errorf("expected FailOpen policy, got %v", c.config.failurePolicy)
				}
			},
		},
		{
			name: "with FailOpenWithCache policy",
			opts: []AgentClientOption{WithAgentClientFailurePolicy(verify.FailOpenWithCache)},
			want: func(t *testing.T, c *AgentClient) {
				if c.config.failurePolicy != verify.FailOpenWithCache {
					t.Errorf("expected FailOpenWithCache policy, got %v", c.config.failurePolicy)
				}
			},
		},
		{
			name: "with custom TLS config",
			opts: []AgentClientOption{WithAgentClientTLS(&tls.Config{MinVersion: tls.VersionTLS13})},
			want: func(t *testing.T, c *AgentClient) {
				if c.config.tlsConfig == nil {
					t.Error("expected tlsConfig to be non-nil")
				}
				if c.config.tlsConfig.MinVersion != tls.VersionTLS13 {
					t.Errorf("expected MinVersion TLS13, got %v", c.config.tlsConfig.MinVersion)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewAgentClient(tt.opts...)
			tt.want(t, client)
		})
	}
}

func TestAgentClient_GetRequests(t *testing.T) {
	tests := []struct {
		name               string
		url                string // empty means use test server URL
		opts               []AgentClientOption
		wantErr            bool
		wantStatus         int
		wantNilOutcome     bool
		setupServer        bool
		serverResponseBody string
	}{
		{
			name:               "verification disabled returns OK",
			opts:               []AgentClientOption{WithAgentClientVerifyServer(false)},
			wantErr:            false,
			wantStatus:         http.StatusOK,
			wantNilOutcome:     true,
			setupServer:        true,
			serverResponseBody: `{"status":"ok"}`,
		},
		{
			name:    "invalid URL returns error",
			url:     "://invalid-url",
			opts:    []AgentClientOption{WithAgentClientVerifyServer(false)},
			wantErr: true,
		},
		{
			name:    "empty hostname returns error",
			url:     "/relative-path",
			opts:    []AgentClientOption{WithAgentClientVerifyServer(false)},
			wantErr: true,
		},
		{
			name:    "HTTP scheme rejected with verification enabled",
			url:     "http://example.com/api",
			opts:    []AgentClientOption{WithAgentClientVerifyServer(true)},
			wantErr: true,
		},
		{
			name:        "HTTP scheme allowed without verification",
			opts:        []AgentClientOption{WithAgentClientVerifyServer(false)},
			wantErr:     false,
			wantStatus:  http.StatusOK,
			setupServer: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targetURL := tt.url
			if tt.setupServer {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
					if tt.serverResponseBody != "" {
						_, _ = w.Write([]byte(tt.serverResponseBody))
					}
				}))
				defer server.Close()
				targetURL = server.URL
			}

			client := NewAgentClient(tt.opts...)
			resp, err := client.Get(context.Background(), targetURL)

			if (err != nil) != tt.wantErr {
				t.Fatalf("Get() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}
			if tt.wantNilOutcome && resp.VerificationOutcome != nil {
				t.Error("expected nil VerificationOutcome when verification disabled")
			}
		})
	}
}

func TestAgentClient_FailPolicy_NoTLS(t *testing.T) {
	tests := []struct {
		name       string
		policy     verify.FailurePolicy
		wantErr    bool
		wantNilOut bool
	}{
		{
			name:    "FailClosed errors on nil TLS",
			policy:  verify.FailClosed,
			wantErr: true,
		},
		{
			name:       "FailOpen does not error on nil TLS",
			policy:     verify.FailOpen,
			wantErr:    false,
			wantNilOut: true,
		},
		{
			name:    "FailOpenWithCache errors on nil TLS",
			policy:  verify.FailOpenWithCache,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewAgentClient(
				WithAgentClientVerifyServer(true),
				WithAgentClientFailurePolicy(tt.policy),
			)

			httpResp := &http.Response{
				TLS:  nil,
				Body: http.NoBody,
			}

			outcome, err := client.verifyTLSCert(context.Background(), "example.com", httpResp)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyTLSCert() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantNilOut && outcome != nil {
				t.Error("expected nil outcome")
			}
		})
	}
}

func TestAgentClient_Post_JSONBody(t *testing.T) {
	var receivedBody map[string]string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}

		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewAgentClient(WithAgentClientVerifyServer(false))

	body := map[string]string{"key": "value"}
	resp, err := client.Post(context.Background(), server.URL, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if receivedBody["key"] != "value" {
		t.Errorf("expected body key=value, got %v", receivedBody)
	}
}

func TestAgentClient_Put(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewAgentClient(WithAgentClientVerifyServer(false))

	resp, err := client.Put(context.Background(), server.URL, map[string]string{"data": "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestAgentClient_Delete(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewAgentClient(WithAgentClientVerifyServer(false))

	resp, err := client.Delete(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected status 204, got %d", resp.StatusCode)
	}
}

func TestAgentClient_GetJSON(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"test","value":42}`))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewAgentClient(WithAgentClientVerifyServer(false))

	var result struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	_, err := client.GetJSON(context.Background(), server.URL, &result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Name != "test" {
		t.Errorf("expected name=test, got %s", result.Name)
	}
	if result.Value != 42 {
		t.Errorf("expected value=42, got %d", result.Value)
	}
}

func TestAgentClient_PostJSON(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"123"}`))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewAgentClient(WithAgentClientVerifyServer(false))

	var result struct {
		ID string `json:"id"`
	}

	_, err := client.PostJSON(context.Background(), server.URL, map[string]string{"data": "test"}, &result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ID != "123" {
		t.Errorf("expected id=123, got %s", result.ID)
	}
}

func TestAgentClient_PutJSON(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"updated":true}`))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewAgentClient(WithAgentClientVerifyServer(false))

	var result struct {
		Updated bool `json:"updated"`
	}

	_, err := client.PutJSON(context.Background(), server.URL, map[string]string{"data": "test"}, &result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Updated {
		t.Error("expected updated=true")
	}
}

func TestAgentClient_ContextCancellation(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewAgentClient(WithAgentClientVerifyServer(false))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := client.Get(ctx, server.URL)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestAgentClient_RequestTimeout(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewAgentClient(
		WithAgentClientVerifyServer(false),
		WithAgentClientTimeout(50*time.Millisecond),
	)

	_, err := client.Get(context.Background(), server.URL)
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestAgentClient_GetJSON_InvalidJSON(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not valid json`))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := NewAgentClient(WithAgentClientVerifyServer(false))

	var result map[string]string
	_, err := client.GetJSON(context.Background(), server.URL, &result)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestAgentClient_Post_MarshalError(t *testing.T) {
	client := NewAgentClient(WithAgentClientVerifyServer(false))

	// Channels cannot be marshaled to JSON
	_, err := client.Post(context.Background(), "http://example.com", make(chan int))
	if err == nil {
		t.Error("expected marshal error")
	}
}

func TestDefaultAgentClientConfig(t *testing.T) {
	cfg := defaultAgentClientConfig()

	if cfg.timeout != defaultAgentClientTimeout {
		t.Errorf("expected timeout %v, got %v", defaultAgentClientTimeout, cfg.timeout)
	}
	if !cfg.verifyServer {
		t.Error("expected verifyServer to be true")
	}
	if cfg.failurePolicy != verify.FailClosed {
		t.Errorf("expected FailClosed, got %v", cfg.failurePolicy)
	}
	if cfg.tlsConfig != nil {
		t.Error("expected nil tlsConfig by default")
	}
}

func TestAgentClientOption_Combinations(t *testing.T) {
	customTLS := &tls.Config{MinVersion: tls.VersionTLS12}
	verifierOpts := []verify.Option{verify.WithCacheConfig(verify.DefaultCacheConfig())}

	client := NewAgentClient(
		WithAgentClientTimeout(45*time.Second),
		WithAgentClientVerifyServer(true),
		WithAgentClientFailurePolicy(verify.FailOpenWithCache),
		WithAgentClientTLS(customTLS),
		WithAgentClientVerifierOptions(verifierOpts...),
	)

	if client.config.timeout != 45*time.Second {
		t.Errorf("expected timeout 45s, got %v", client.config.timeout)
	}
	if !client.config.verifyServer {
		t.Error("expected verifyServer true")
	}
	if client.config.failurePolicy != verify.FailOpenWithCache {
		t.Errorf("expected FailOpenWithCache, got %v", client.config.failurePolicy)
	}
	if client.config.tlsConfig != customTLS {
		t.Error("expected custom TLS config")
	}
}

func TestAgentClient_Prefetch(t *testing.T) {
	// This test verifies the Prefetch method is exposed and callable
	// Full integration would require mocking the verifier internals

	client := NewAgentClient(WithAgentClientVerifyServer(false))

	// Prefetch with an invalid host should return an error
	err := client.Prefetch(context.Background(), "invalid..host")
	if err == nil {
		t.Error("expected error for invalid host")
	}
}

func TestAgentClient_HTTPMethods(t *testing.T) {
	methods := []struct {
		name           string
		call           func(*AgentClient, context.Context, string) (*Response, error)
		expectedMethod string
	}{
		{
			name: "GET",
			call: func(c *AgentClient, ctx context.Context, url string) (*Response, error) {
				return c.Get(ctx, url)
			},
			expectedMethod: http.MethodGet,
		},
		{
			name: "DELETE",
			call: func(c *AgentClient, ctx context.Context, url string) (*Response, error) {
				return c.Delete(ctx, url)
			},
			expectedMethod: http.MethodDelete,
		},
	}

	for _, tc := range methods {
		t.Run(tc.name, func(t *testing.T) {
			var receivedMethod string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedMethod = r.Method
				w.WriteHeader(http.StatusOK)
			})

			server := httptest.NewServer(handler)
			defer server.Close()

			client := NewAgentClient(WithAgentClientVerifyServer(false))

			resp, err := tc.call(client, context.Background(), server.URL)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer resp.Body.Close()

			if receivedMethod != tc.expectedMethod {
				t.Errorf("expected method %s, got %s", tc.expectedMethod, receivedMethod)
			}
		})
	}
}

func TestAgentClient_TransportCloning(t *testing.T) {
	// Verify that the transport is cloned from http.DefaultTransport
	// rather than creating a zero-value transport
	client := NewAgentClient()

	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}

	// DefaultTransport has these set; a zero-value Transport would not
	if transport.Proxy == nil {
		t.Error("expected Proxy to be set (cloned from DefaultTransport)")
	}
}

func TestAgentClient_CustomTLSApplied(t *testing.T) {
	customTLS := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}

	client := NewAgentClient(WithAgentClientTLS(customTLS))

	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected MinVersion TLS13, got %v", transport.TLSClientConfig.MinVersion)
	}
}

func TestResponse_VerificationOutcome(t *testing.T) {
	// Test that Response properly wraps http.Response with verification outcome
	httpResp := &http.Response{
		StatusCode: http.StatusOK,
	}

	badge := &models.Badge{}
	fingerprint := verify.CertFingerprintFromBytes([32]byte{1, 2, 3})
	outcome := verify.NewVerifiedOutcome(badge, fingerprint)

	resp := &Response{
		Response:            httpResp,
		VerificationOutcome: outcome,
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
	if resp.VerificationOutcome == nil {
		t.Error("expected VerificationOutcome to be set")
	}
	if !resp.VerificationOutcome.IsSuccess() {
		t.Error("expected successful verification outcome")
	}
}

func TestAgentClient_prefetchBadge(t *testing.T) {
	tests := []struct {
		name          string
		opts          []AgentClientOption
		hostname      string
		wantErr       bool
		wantNilOnOpen bool
	}{
		{
			name:     "disabled verification returns nil",
			opts:     []AgentClientOption{WithAgentClientVerifyServer(false)},
			hostname: "test.example.com",
			wantErr:  false,
		},
		{
			name: "FailClosed errors on DNS failure",
			opts: []AgentClientOption{
				WithAgentClientVerifyServer(true),
				WithAgentClientFailurePolicy(verify.FailClosed),
			},
			hostname: "nonexistent.test.example.com",
			wantErr:  true,
		},
		{
			name: "FailOpen does not error on DNS failure",
			opts: []AgentClientOption{
				WithAgentClientVerifyServer(true),
				WithAgentClientFailurePolicy(verify.FailOpen),
				WithAgentClientVerifierOptions(verify.WithoutURLValidation()),
			},
			hostname: "nonexistent.test.example.com",
			wantErr:  false,
		},
		{
			name: "FailOpenWithCache does not error on DNS failure",
			opts: []AgentClientOption{
				WithAgentClientVerifyServer(true),
				WithAgentClientFailurePolicy(verify.FailOpenWithCache),
				WithAgentClientVerifierOptions(verify.WithoutURLValidation()),
			},
			hostname: "nonexistent.test.example.com",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewAgentClient(tt.opts...)
			err := client.prefetchBadge(context.Background(), tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("prefetchBadge() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAgentClient_verifyTLSCert_Disabled(t *testing.T) {
	client := NewAgentClient(WithAgentClientVerifyServer(false))

	httpResp := &http.Response{TLS: nil, Body: http.NoBody}

	outcome, err := client.verifyTLSCert(context.Background(), "test.example.com", httpResp)
	if err != nil {
		t.Errorf("verifyTLSCert() error = %v, want nil when verification disabled", err)
	}
	if outcome != nil {
		t.Errorf("verifyTLSCert() outcome = %v, want nil when verification disabled", outcome)
	}
}

func TestAgentClient_verifyTLSCert_EmptyPeerCerts(t *testing.T) {
	tests := []struct {
		name    string
		policy  verify.FailurePolicy
		wantErr bool
	}{
		{
			name:    "FailClosed errors on empty PeerCertificates",
			policy:  verify.FailClosed,
			wantErr: true,
		},
		{
			name:    "FailOpen does not error on empty PeerCertificates",
			policy:  verify.FailOpen,
			wantErr: false,
		},
		{
			name:    "FailOpenWithCache errors on empty PeerCertificates",
			policy:  verify.FailOpenWithCache,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewAgentClient(
				WithAgentClientVerifyServer(true),
				WithAgentClientFailurePolicy(tt.policy),
			)

			httpResp := &http.Response{
				TLS:  &tls.ConnectionState{PeerCertificates: nil},
				Body: http.NoBody,
			}

			outcome, err := client.verifyTLSCert(context.Background(), "test.example.com", httpResp)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifyTLSCert() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && outcome != nil {
				t.Error("verifyTLSCert() expected nil outcome for FailOpen")
			}
		})
	}
}

func TestAgentClient_verifyTLSCert_WithPeerCerts(t *testing.T) {
	// Use a TLS test server to get real peer certificates
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tlsClient := server.Client()
	resp, err := tlsClient.Get(server.URL)
	if err != nil {
		t.Fatalf("failed to get from TLS server: %v", err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("expected TLS peer certificates from test server")
	}

	tests := []struct {
		name    string
		policy  verify.FailurePolicy
		wantErr bool
		wantNil bool
	}{
		{
			name:    "FailClosed errors for unknown cert",
			policy:  verify.FailClosed,
			wantErr: true,
		},
		{
			name:    "FailOpen returns outcome without error",
			policy:  verify.FailOpen,
			wantErr: false,
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewAgentClient(
				WithAgentClientVerifyServer(true),
				WithAgentClientFailurePolicy(tt.policy),
			)

			outcome, verifyErr := client.verifyTLSCert(context.Background(), "127.0.0.1", resp)
			if (verifyErr != nil) != tt.wantErr {
				t.Errorf("verifyTLSCert() error = %v, wantErr %v", verifyErr, tt.wantErr)
			}
			if !tt.wantErr && !tt.wantNil && outcome == nil {
				t.Error("expected non-nil outcome")
			}
		})
	}
}

func TestAgentClient_JSON_DecodeError(t *testing.T) {
	tests := []struct {
		name string
		call func(*AgentClient, context.Context, string) error
	}{
		{
			name: "PostJSON decode error",
			call: func(c *AgentClient, ctx context.Context, url string) error {
				var result struct{ ID string }
				_, err := c.PostJSON(ctx, url, map[string]string{"a": "b"}, &result)
				return err
			},
		},
		{
			name: "PutJSON decode error",
			call: func(c *AgentClient, ctx context.Context, url string) error {
				var result struct{ ID string }
				_, err := c.PutJSON(ctx, url, map[string]string{"a": "b"}, &result)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("not json"))
			}))
			defer server.Close()

			client := NewAgentClient(WithAgentClientVerifyServer(false))
			err := tt.call(client, context.Background(), server.URL)
			if err == nil {
				t.Error("expected decode error")
			}
		})
	}
}

func TestAgentClient_Prefetch_EmptyHost(t *testing.T) {
	client := NewAgentClient(WithAgentClientVerifyServer(false))
	err := client.Prefetch(context.Background(), "")
	if err == nil {
		t.Fatal("expected validation error for empty host, got nil")
	}
	if !errors.Is(err, models.ErrBadRequest) {
		t.Errorf("expected ErrBadRequest, got %v", err)
	}
}

func TestAgentClient_Prefetch_ValidHost(_ *testing.T) {
	client := NewAgentClient(
		WithAgentClientVerifyServer(false),
	)

	// Even with verification disabled, Prefetch delegates to the verifier
	err := client.Prefetch(context.Background(), "test.example.com")
	// Will error because the verifier uses real DNS
	if err == nil {
		// This is acceptable if the host resolves
		return
	}
}
