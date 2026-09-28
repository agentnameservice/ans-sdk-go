package scitt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPClient(t *testing.T) {
	tests := []struct {
		name           string
		method         string // "receipt", "status", "rootkeys"
		agentID        string
		serverStatus   int
		serverBody     []byte
		wantBytes      []byte
		wantKeys       []string
		wantPath       string
		wantErr        bool
		wantErrType    TransportErrorType
		wantStatusCode int
	}{
		{
			name:         "FetchReceipt 200 returns bytes",
			method:       "receipt",
			agentID:      "agent-1",
			serverStatus: http.StatusOK,
			serverBody:   []byte("receipt-data"),
			wantBytes:    []byte("receipt-data"),
			wantPath:     "/v1/agents/agent-1/receipt",
		},
		{
			name:         "FetchReceipt PathEscape special characters",
			method:       "receipt",
			agentID:      "agent/special",
			serverStatus: http.StatusOK,
			serverBody:   []byte("escaped-receipt"),
			wantBytes:    []byte("escaped-receipt"),
			wantPath:     "/v1/agents/agent%2Fspecial/receipt",
		},
		{
			name:           "FetchReceipt 404 returns TransportErrNotFound",
			method:         "receipt",
			agentID:        "agent-missing",
			serverStatus:   http.StatusNotFound,
			wantErr:        true,
			wantErrType:    TransportErrNotFound,
			wantStatusCode: 404,
		},
		{
			name:           "FetchReceipt 410 returns TransportErrAgentTerminal",
			method:         "receipt",
			agentID:        "agent-gone",
			serverStatus:   http.StatusGone,
			wantErr:        true,
			wantErrType:    TransportErrAgentTerminal,
			wantStatusCode: 410,
		},
		{
			name:           "FetchReceipt 501 returns TransportErrNotSupported",
			method:         "receipt",
			agentID:        "agent-unsupported",
			serverStatus:   http.StatusNotImplemented,
			wantErr:        true,
			wantErrType:    TransportErrNotSupported,
			wantStatusCode: 501,
		},
		{
			name:           "FetchReceipt 500 returns TransportErrHTTPError",
			method:         "receipt",
			agentID:        "agent-error",
			serverStatus:   http.StatusInternalServerError,
			wantErr:        true,
			wantErrType:    TransportErrHTTPError,
			wantStatusCode: 500,
		},
		{
			name:         "FetchStatusToken 200 returns bytes",
			method:       "status",
			agentID:      "agent-1",
			serverStatus: http.StatusOK,
			serverBody:   []byte("token-data"),
			wantBytes:    []byte("token-data"),
			wantPath:     "/v1/agents/agent-1/status-token",
		},
		{
			name:           "FetchStatusToken 404 returns TransportErrNotFound",
			method:         "status",
			agentID:        "agent-missing",
			serverStatus:   http.StatusNotFound,
			wantErr:        true,
			wantErrType:    TransportErrNotFound,
			wantStatusCode: 404,
		},
		{
			name:         "FetchRootKeys 200 returns string slice",
			method:       "rootkeys",
			serverStatus: http.StatusOK,
			serverBody:   []byte("key-1\nkey-2\nkey-3\n"),
			wantKeys:     []string{"key-1", "key-2", "key-3"},
			wantPath:     "/root-keys",
		},
		{
			name:           "FetchRootKeys 404 returns error",
			method:         "rootkeys",
			serverStatus:   http.StatusNotFound,
			wantErr:        true,
			wantErrType:    TransportErrNotFound,
			wantStatusCode: 404,
		},
		{
			name:         "FetchRootKeys empty body returns error",
			method:       "rootkeys",
			serverStatus: http.StatusOK,
			serverBody:   []byte("   \n  \n  "),
			wantErr:      true,
			wantErrType:  TransportErrHTTPError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.wantPath != "" {
					gotPath := r.URL.RawPath
					if gotPath == "" {
						gotPath = r.URL.Path
					}
					if gotPath != tt.wantPath {
						t.Errorf("request path = %q, want %q", gotPath, tt.wantPath)
					}
				}
				w.WriteHeader(tt.serverStatus)
				if tt.serverBody != nil {
					_, _ = w.Write(tt.serverBody)
				}
			}))
			defer server.Close()

			client, err := NewHTTPClient(server.URL, WithAllowInsecureTransport())
			if err != nil {
				t.Fatalf("NewHTTPClient() error = %v", err)
			}
			ctx := context.Background()

			switch tt.method {
			case "receipt":
				got, err := client.FetchReceipt(ctx, tt.agentID)
				assertClientResult(t, got, tt.wantBytes, err, tt.wantErr, tt.wantErrType, tt.wantStatusCode)

			case "status":
				got, err := client.FetchStatusToken(ctx, tt.agentID)
				assertClientResult(t, got, tt.wantBytes, err, tt.wantErr, tt.wantErrType, tt.wantStatusCode)

			case "rootkeys":
				keys, err := client.FetchRootKeys(ctx)
				if tt.wantErr {
					assertTransportError(t, err, tt.wantErrType, tt.wantStatusCode)
				} else {
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if len(keys) != len(tt.wantKeys) {
						t.Fatalf("got %d keys, want %d", len(keys), len(tt.wantKeys))
					}
					for i, k := range keys {
						if k != tt.wantKeys[i] {
							t.Errorf("key[%d] = %q, want %q", i, k, tt.wantKeys[i])
						}
					}
				}
			}
		})
	}
}

func TestHTTPClientResponseSizeLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		bodySize    int64
		wantErr     bool
		errContains string
	}{
		{
			name:     "response at max size succeeds",
			bodySize: maxResponseBytes,
			wantErr:  false,
		},
		{
			name:        "response exceeds max size returns error",
			bodySize:    maxResponseBytes + 1,
			wantErr:     true,
			errContains: "exceeds maximum size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				// Write bodySize bytes in chunks to avoid allocating the full body in memory.
				chunk := make([]byte, 32*1024) // 32 KiB chunks
				var written int64
				for written < tt.bodySize {
					remaining := tt.bodySize - written
					if remaining < int64(len(chunk)) {
						chunk = chunk[:remaining]
					}
					n, err := w.Write(chunk)
					if err != nil {
						return
					}
					written += int64(n)
				}
			}))
			defer server.Close()

			client, err := NewHTTPClient(server.URL, WithAllowInsecureTransport())
			if err != nil {
				t.Fatalf("NewHTTPClient() error = %v", err)
			}
			_, err = client.FetchReceipt(context.Background(), "agent-1")

			if !tt.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("expected error, got nil")
			}
			assertTransportError(t, err, TransportErrHTTPError, 0)
			if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestHTTPClientWithCustomHTTPClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("custom-client"))
	}))
	defer server.Close()

	customClient := &http.Client{}
	client, err := NewHTTPClient(server.URL, WithAllowInsecureTransport(), WithHTTPClient(customClient))
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}

	got, err := client.FetchReceipt(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "custom-client" {
		t.Errorf("got %q, want %q", string(got), "custom-client")
	}
}

func TestMockClient(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *MockClient
		action   string // "receipt", "status", "rootkeys"
		agentID  string
		wantData []byte
		wantKeys []string
		wantErr  bool
	}{
		{
			name: "receipt round-trip",
			setup: func() *MockClient {
				return NewMockClient().
					WithReceipt("agent-1", []byte("mock-receipt"))
			},
			action:   "receipt",
			agentID:  "agent-1",
			wantData: []byte("mock-receipt"),
		},
		{
			name: "status token round-trip",
			setup: func() *MockClient {
				return NewMockClient().
					WithStatusToken("agent-1", []byte("mock-token"))
			},
			action:   "status",
			agentID:  "agent-1",
			wantData: []byte("mock-token"),
		},
		{
			name: "root keys round-trip",
			setup: func() *MockClient {
				return NewMockClient().
					WithRootKeys([]string{"k1", "k2"})
			},
			action:   "rootkeys",
			wantKeys: []string{"k1", "k2"},
		},
		{
			name:    "receipt not found",
			setup:   NewMockClient,
			action:  "receipt",
			agentID: "missing",
			wantErr: true,
		},
		{
			name: "configured error returned",
			setup: func() *MockClient {
				return NewMockClient().
					WithError("agent-1", &TransportError{
						Type:    TransportErrAgentTerminal,
						Message: "gone",
					})
			},
			action:  "receipt",
			agentID: "agent-1",
			wantErr: true,
		},
		{
			name: "root keys error",
			setup: func() *MockClient {
				return NewMockClient().
					WithError("root-keys", &TransportError{
						Type:    TransportErrHTTPError,
						Message: "server error",
					})
			},
			action:  "rootkeys",
			wantErr: true,
		},
		{
			name: "builder chaining",
			setup: func() *MockClient {
				return NewMockClient().
					WithReceipt("a1", []byte("r1")).
					WithStatusToken("a1", []byte("t1")).
					WithRootKeys([]string{"k"})
			},
			action:   "receipt",
			agentID:  "a1",
			wantData: []byte("r1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := tt.setup()
			ctx := context.Background()

			switch tt.action {
			case "receipt":
				got, err := mock.FetchReceipt(ctx, tt.agentID)
				if tt.wantErr {
					if err == nil {
						t.Fatal("expected error, got nil")
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if string(got) != string(tt.wantData) {
					t.Errorf("got %q, want %q", got, tt.wantData)
				}

			case "status":
				got, err := mock.FetchStatusToken(ctx, tt.agentID)
				if tt.wantErr {
					if err == nil {
						t.Fatal("expected error, got nil")
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if string(got) != string(tt.wantData) {
					t.Errorf("got %q, want %q", got, tt.wantData)
				}

			case "rootkeys":
				keys, err := mock.FetchRootKeys(ctx)
				if tt.wantErr {
					if err == nil {
						t.Fatal("expected error, got nil")
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(keys) != len(tt.wantKeys) {
					t.Fatalf("got %d keys, want %d", len(keys), len(tt.wantKeys))
				}
				for i, k := range keys {
					if k != tt.wantKeys[i] {
						t.Errorf("key[%d] = %q, want %q", i, k, tt.wantKeys[i])
					}
				}
			}
		})
	}
}

// Verify MockClient satisfies Client interface at compile time.
var _ Client = (*MockClient)(nil)
var _ Client = (*HTTPClient)(nil)

func assertClientResult(t *testing.T, got, want []byte, err error, wantErr bool, wantErrType TransportErrorType, wantStatusCode int) {
	t.Helper()

	if wantErr {
		assertTransportError(t, err, wantErrType, wantStatusCode)
		return
	}

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(got) != string(want) {
		t.Errorf("body = %q, want %q", got, want)
	}
}

func TestNewHTTPClientOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		opts        []HTTPClientOption
		wantHeaders map[string]string // header name -> expected value
	}{
		{
			name:        "no options produces no custom headers",
			opts:        nil,
			wantHeaders: map[string]string{},
		},
		{
			name: "WithHeader sets single header",
			opts: []HTTPClientOption{
				WithHeader("X-Custom", "value1"),
			},
			wantHeaders: map[string]string{
				"X-Custom": "value1",
			},
		},
		{
			name: "multiple WithHeader calls stack",
			opts: []HTTPClientOption{
				WithHeader("X-First", "one"),
				WithHeader("X-Second", "two"),
			},
			wantHeaders: map[string]string{
				"X-First":  "one",
				"X-Second": "two",
			},
		},
		{
			name: "WithHeader overwrites same header name",
			opts: []HTTPClientOption{
				WithHeader("X-Custom", "old"),
				WithHeader("X-Custom", "new"),
			},
			wantHeaders: map[string]string{
				"X-Custom": "new",
			},
		},
		{
			name: "WithHeaders merges multiple headers",
			opts: []HTTPClientOption{
				WithHeaders(http.Header{
					"X-Batch-A": {"a1"},
					"X-Batch-B": {"b1"},
				}),
			},
			wantHeaders: map[string]string{
				"X-Batch-A": "a1",
				"X-Batch-B": "b1",
			},
		},
		{
			name: "WithHeader then WithHeaders combines",
			opts: []HTTPClientOption{
				WithHeader("X-Single", "solo"),
				WithHeaders(http.Header{
					"X-Batch": {"batch-val"},
				}),
			},
			wantHeaders: map[string]string{
				"X-Single": "solo",
				"X-Batch":  "batch-val",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var receivedHeaders http.Header
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedHeaders = r.Header
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			}))
			defer server.Close()

			opts := append([]HTTPClientOption{WithAllowInsecureTransport()}, tt.opts...)
			client, err := NewHTTPClient(server.URL, opts...)
			if err != nil {
				t.Fatalf("NewHTTPClient() error = %v", err)
			}
			_, err = client.FetchReceipt(context.Background(), "agent-1")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for name, wantVal := range tt.wantHeaders {
				gotVal := receivedHeaders.Get(name)
				if gotVal != wantVal {
					t.Errorf("header %q = %q, want %q", name, gotVal, wantVal)
				}
			}
		})
	}
}

func TestCustomHeadersSentOnAllEndpoints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string // "receipt", "status", "rootkeys"
	}{
		{name: "receipt includes custom headers", method: "receipt"},
		{name: "status includes custom headers", method: "status"},
		{name: "rootkeys includes custom headers", method: "rootkeys"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var receivedHeader string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedHeader = r.Header.Get("X-Api-Key")
				w.WriteHeader(http.StatusOK)
				if tt.method == "rootkeys" {
					_, _ = w.Write([]byte(`["key1"]`))
				} else {
					_, _ = w.Write([]byte("data"))
				}
			}))
			defer server.Close()

			client, err := NewHTTPClient(server.URL,
				WithAllowInsecureTransport(),
				WithHeader("X-Api-Key", "secret-123"),
			)
			if err != nil {
				t.Fatalf("NewHTTPClient() error = %v", err)
			}
			ctx := context.Background()

			switch tt.method {
			case "receipt":
				_, _ = client.FetchReceipt(ctx, "agent-1")
			case "status":
				_, _ = client.FetchStatusToken(ctx, "agent-1")
			case "rootkeys":
				_, _ = client.FetchRootKeys(ctx)
			}

			if receivedHeader != "secret-123" {
				t.Errorf("X-Api-Key = %q, want %q", receivedHeader, "secret-123")
			}
		})
	}
}

func TestNewHTTPClient_HTTPSValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		baseURL string
		opts    []HTTPClientOption
		wantErr string
	}{
		{
			name:    "https scheme accepted",
			baseURL: "https://example.com",
			wantErr: "",
		},
		{
			name:    "http scheme rejected by default",
			baseURL: "http://example.com",
			wantErr: "must use https scheme",
		},
		{
			name:    "http scheme accepted with WithAllowInsecureTransport",
			baseURL: "http://example.com",
			opts:    []HTTPClientOption{WithAllowInsecureTransport()},
			wantErr: "",
		},
		{
			name:    "malformed URL returns error",
			baseURL: "://bad",
			wantErr: "invalid baseURL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewHTTPClient(tt.baseURL, tt.opts...)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestNewHTTPClient_DefaultTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		opts        []HTTPClientOption
		wantTimeout time.Duration
	}{
		{
			name:        "no options applies defaultTimeout",
			opts:        nil,
			wantTimeout: defaultTimeout,
		},
		{
			name:        "WithHTTPClient with zero Timeout gets default",
			opts:        []HTTPClientOption{WithHTTPClient(&http.Client{})},
			wantTimeout: defaultTimeout,
		},
		{
			name:        "WithHTTPClient preserves non-zero Timeout",
			opts:        []HTTPClientOption{WithHTTPClient(&http.Client{Timeout: 5 * time.Second})},
			wantTimeout: 5 * time.Second,
		},
		{
			name:        "WithTimeout overrides default",
			opts:        []HTTPClientOption{WithTimeout(2 * time.Second)},
			wantTimeout: 2 * time.Second,
		},
		{
			name:        "WithTimeout overrides client Timeout",
			opts:        []HTTPClientOption{WithHTTPClient(&http.Client{Timeout: 5 * time.Second}), WithTimeout(1 * time.Second)},
			wantTimeout: 1 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := append([]HTTPClientOption{WithAllowInsecureTransport()}, tt.opts...)
			client, err := NewHTTPClient("http://example.com", opts...)
			if err != nil {
				t.Fatalf("NewHTTPClient() error = %v", err)
			}
			if got := client.httpClient.Timeout; got != tt.wantTimeout {
				t.Errorf("Timeout = %v, want %v", got, tt.wantTimeout)
			}
		})
	}
}

func TestNewHTTPClient_Smoke(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []HTTPClientOption
	}{
		{
			name: "default",
		},
		{
			name: "with custom http client",
			opts: []HTTPClientOption{WithHTTPClient(&http.Client{})},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("works"))
			}))
			defer server.Close()

			opts := append([]HTTPClientOption{WithAllowInsecureTransport()}, tt.opts...)
			client, err := NewHTTPClient(server.URL, opts...)
			if err != nil {
				t.Fatalf("NewHTTPClient() error = %v", err)
			}
			got, err := client.FetchReceipt(context.Background(), "agent-1")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != "works" {
				t.Errorf("got %q, want %q", string(got), "works")
			}
		})
	}
}

func assertTransportError(t *testing.T, err error, wantType TransportErrorType, wantStatusCode int) {
	t.Helper()

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var transportErr *TransportError
	if !errors.As(err, &transportErr) {
		t.Fatalf("expected TransportError, got %T: %v", err, err)
	}

	if transportErr.Type != wantType {
		t.Errorf("error type = %v, want %v", transportErr.Type, wantType)
	}

	if wantStatusCode != 0 && transportErr.StatusCode != wantStatusCode {
		t.Errorf("status code = %d, want %d", transportErr.StatusCode, wantStatusCode)
	}
}

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{name: "absent header yields zero", header: "", want: 0},
		{name: "delta-seconds", header: "30", want: 30 * time.Second},
		{name: "zero delta-seconds", header: "0", want: 0},
		{name: "surrounding whitespace is tolerated", header: "  15 ", want: 15 * time.Second},
		{name: "negative delta is ignored", header: "-5", want: 0},
		{name: "fractional delta is ignored", header: "1.5", want: 0},
		{name: "garbage is ignored", header: "soon", want: 0},
		{name: "delta at the cap is kept", header: "86400", want: 24 * time.Hour},
		{name: "delta above the cap is clamped to a day", header: "86401", want: 24 * time.Hour},
		{name: "absurd delta is clamped to a day", header: "99999999999", want: 24 * time.Hour},
		{name: "HTTP-date in the future", header: now.Add(90 * time.Second).Format(http.TimeFormat), want: 90 * time.Second},
		{name: "RFC 850 date is accepted", header: now.Add(2 * time.Minute).Format(time.RFC850), want: 2 * time.Minute},
		{name: "HTTP-date in the past yields zero", header: now.Add(-time.Minute).Format(http.TimeFormat), want: 0},
		{name: "HTTP-date beyond the cap is clamped to a day", header: now.Add(48 * time.Hour).Format(http.TimeFormat), want: 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := parseRetryAfter(tt.header, now); got != tt.want {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tt.header, got, tt.want)
			}
		})
	}
}

func TestHTTPClientRetryAfter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		serverStatus int
		retryAfter   func() string
		wantMin      time.Duration
		wantMax      time.Duration
	}{
		{
			name:         "503 with delta-seconds",
			serverStatus: http.StatusServiceUnavailable,
			retryAfter:   func() string { return "30" },
			wantMin:      30 * time.Second,
			wantMax:      30 * time.Second,
		},
		{
			name:         "429 with delta-seconds",
			serverStatus: http.StatusTooManyRequests,
			retryAfter:   func() string { return "2" },
			wantMin:      2 * time.Second,
			wantMax:      2 * time.Second,
		},
		{
			name:         "503 with HTTP-date",
			serverStatus: http.StatusServiceUnavailable,
			retryAfter:   func() string { return time.Now().Add(time.Minute).UTC().Format(http.TimeFormat) },
			wantMin:      30 * time.Second,
			wantMax:      time.Minute,
		},
		{
			name:         "503 without the header leaves zero",
			serverStatus: http.StatusServiceUnavailable,
			retryAfter:   func() string { return "" },
		},
		{
			name:         "500 does not parse the header",
			serverStatus: http.StatusInternalServerError,
			retryAfter:   func() string { return "30" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if v := tt.retryAfter(); v != "" {
					w.Header().Set("Retry-After", v)
				}
				w.WriteHeader(tt.serverStatus)
			}))
			defer server.Close()

			client, err := NewHTTPClient(server.URL, WithAllowInsecureTransport())
			if err != nil {
				t.Fatalf("NewHTTPClient() error = %v", err)
			}
			_, err = client.FetchReceipt(context.Background(), "agent-1")
			assertTransportError(t, err, TransportErrHTTPError, tt.serverStatus)

			var transportErr *TransportError
			if !errors.As(err, &transportErr) {
				t.Fatalf("expected TransportError, got %T", err)
			}
			if transportErr.RetryAfter < tt.wantMin || transportErr.RetryAfter > tt.wantMax {
				t.Errorf("RetryAfter = %v, want within [%v, %v]", transportErr.RetryAfter, tt.wantMin, tt.wantMax)
			}
		})
	}
}
