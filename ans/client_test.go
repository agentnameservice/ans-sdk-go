package ans

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{
			name:    "default config",
			opts:    nil,
			wantErr: false,
		},
		{
			name: "with base URL",
			opts: []Option{
				WithBaseURL("https://api.godaddy.com"),
			},
			wantErr: false,
		},
		{
			name: "with JWT",
			opts: []Option{
				WithJWT("test-token"),
			},
			wantErr: false,
		},
		{
			name: "with API key",
			opts: []Option{
				WithAPIKey("key", "secret"),
			},
			wantErr: false,
		},
		{
			name: "with timeout",
			opts: []Option{
				WithTimeout(60 * time.Second),
			},
			wantErr: false,
		},
		{
			name: "with verbose",
			opts: []Option{
				WithVerbose(true),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewClient() returned nil client")
			}
		})
	}
}

func TestClient_RegisterAgent(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		response       any
		wantErr        bool
		wantStatusCode int
	}{
		{
			name:       "successful registration",
			statusCode: http.StatusOK,
			response: &models.RegistrationPending{
				Status:  "PENDING",
				ANSName: "test-agent.ans.godaddy",
				AgentID: "test-id-123",
			},
			wantErr: false,
		},
		{
			name:       "bad request",
			statusCode: http.StatusBadRequest,
			response: &models.APIError{
				Status:  "error",
				Code:    "BAD_REQUEST",
				Message: "Invalid request",
			},
			wantErr:        true,
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:       "unauthorized",
			statusCode: http.StatusUnauthorized,
			response: &models.APIError{
				Status:  "error",
				Code:    "UNAUTHORIZED",
				Message: "Invalid token",
			},
			wantErr:        true,
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name:       "not found",
			statusCode: http.StatusNotFound,
			response: &models.APIError{
				Status:  "error",
				Code:    "NOT_FOUND",
				Message: "Resource not found",
			},
			wantErr:        true,
			wantStatusCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request method
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST request, got %s", r.Method)
				}

				// Verify request path
				if r.URL.Path != "/v1/agents/register" {
					t.Errorf("Expected path /v1/agents/register, got %s", r.URL.Path)
				}

				// Write response
				w.WriteHeader(tt.statusCode)
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			// Create client with test server URL
			client, err := NewClient(
				WithBaseURL(server.URL),
				WithJWT("test-token"),
			)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			// Create test request
			req := &models.AgentRegistrationRequest{
				AgentDisplayName: "Test Agent",
				AgentHost:        "test-agent.example.com",
				Version:          "1.0.0",
				IdentityCSRPEM:   "test-csr",
				Endpoints: []models.AgentEndpoint{
					{
						AgentURL:   "https://test.com",
						Protocol:   "HTTP-API",
						Transports: []string{"REST"},
					},
				},
			}

			// Execute test
			ctx := context.Background()
			result, err := client.RegisterAgent(ctx, req)

			// Verify error
			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterAgent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify error status code if expected
			if tt.wantErr && tt.wantStatusCode != 0 {
				var respErr *models.ResponseError
				if !errors.As(err, &respErr) {
					t.Fatalf("expected *models.ResponseError, got %T", err)
				}
				if respErr.StatusCode != tt.wantStatusCode {
					t.Errorf("StatusCode = %d, want %d", respErr.StatusCode, tt.wantStatusCode)
				}
			}

			// Verify result for successful case
			if !tt.wantErr {
				if result == nil {
					t.Error("RegisterAgent() returned nil result")
					return
				}
				expected := tt.response.(*models.RegistrationPending)
				if result.Status != expected.Status {
					t.Errorf("Status = %v, want %v", result.Status, expected.Status)
				}
				if result.ANSName != expected.ANSName {
					t.Errorf("ANSName = %v, want %v", result.ANSName, expected.ANSName)
				}
			}
		})
	}
}

func TestClient_SearchAgents(t *testing.T) {
	tests := []struct {
		name       string
		queryName  string
		queryHost  string
		limit      int
		offset     int
		statusCode int
		response   *models.AgentSearchResponse
		wantErr    bool
	}{
		{
			name:       "successful search",
			queryName:  "Test Agent",
			queryHost:  "test.com",
			limit:      20,
			offset:     0,
			statusCode: http.StatusOK,
			response: &models.AgentSearchResponse{
				Agents: []models.AgentSearchResult{
					{
						AgentDisplayName: "Test Agent",
						AgentHost:        "test.com",
						ANSName:          "test-agent.ans.godaddy",
					},
				},
				TotalCount:    1,
				ReturnedCount: 1,
				Limit:         20,
				Offset:        0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request method
				if r.Method != http.MethodGet {
					t.Errorf("Expected GET request, got %s", r.Method)
				}

				// Verify query parameters
				query := r.URL.Query()
				if tt.queryName != "" {
					if query.Get("agentDisplayName") != tt.queryName {
						t.Errorf("Expected agentDisplayName=%s, got %s", tt.queryName, query.Get("agentDisplayName"))
					}
				}

				// Write response
				w.WriteHeader(tt.statusCode)
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			// Create client
			client, err := NewClient(
				WithBaseURL(server.URL),
				WithJWT("test-token"),
			)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			// Execute test
			ctx := context.Background()
			result, err := client.SearchAgents(ctx,
				WithSearchName(tt.queryName),
				WithSearchHost(tt.queryHost),
				WithSearchLimit(tt.limit),
				WithSearchOffset(tt.offset),
			)

			// Verify error
			if (err != nil) != tt.wantErr {
				t.Errorf("SearchAgents() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify result
			if !tt.wantErr {
				if result == nil {
					t.Error("SearchAgents() returned nil result")
					return
				}
				if result.TotalCount != tt.response.TotalCount {
					t.Errorf("TotalCount = %v, want %v", result.TotalCount, tt.response.TotalCount)
				}
			}
		})
	}
}

func TestClient_ContextCancellation(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(
		WithBaseURL(server.URL),
		WithJWT("test-token"),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Execute request that should timeout
	req := &models.AgentRegistrationRequest{
		AgentDisplayName: "Test",
		AgentHost:        "test.com",
		Version:          "1.0.0",
		IdentityCSRPEM:   "test",
		Endpoints:        []models.AgentEndpoint{},
	}

	_, err = client.RegisterAgent(ctx, req)
	if err == nil {
		t.Error("Expected context deadline error, got nil")
	}
}

// Helper function to check if error contains specific error type
// --- Merged from client_error_test.go ---

// testServerError creates a test server that always returns 500.
func testServerError(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"status":"error","message":"server error"}`))
	}))
}

var errBadOption = context.DeadlineExceeded // reuse a standard error for test

func TestClient_ServerErrorResponses(t *testing.T) {
	tests := []struct {
		name string
		call func(context.Context, *Client) error
	}{
		{
			name: "GetChallengeDetails",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetChallengeDetails(ctx, "agent-123")
				return err
			},
		},
		{
			name: "VerifyACME",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.VerifyACME(ctx, "agent-123")
				return err
			},
		},
		{
			name: "VerifyDNS",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.VerifyDNS(ctx, "agent-123")
				return err
			},
		},
		{
			name: "GetIdentityCertificates",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetIdentityCertificates(ctx, "agent-123")
				return err
			},
		},
		{
			name: "GetServerCertificates",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetServerCertificates(ctx, "agent-123")
				return err
			},
		},
		{
			name: "SubmitIdentityCSR",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.SubmitIdentityCSR(ctx, "agent-123", "csr-pem")
				return err
			},
		},
		{
			name: "SubmitServerCSR",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.SubmitServerCSR(ctx, "agent-123", "csr-pem")
				return err
			},
		},
		{
			name: "GetCSRStatus",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetCSRStatus(ctx, "agent-123", "csr-123")
				return err
			},
		},
		{
			name: "ResolveAgent",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.ResolveAgent(ctx, "host.example.com", "*")
				return err
			},
		},
		{
			name: "RevokeAgent",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.RevokeAgent(ctx, "agent-123", "KEY_COMPROMISE", "test")
				return err
			},
		},
		{
			name: "GetAgentEvents",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetAgentEvents(ctx, 20, "", "")
				return err
			},
		},
		{
			name: "SearchAgents",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.SearchAgents(ctx, WithSearchName("test"), WithSearchLimit(20))
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := testServerError(t)
			defer server.Close()

			client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))
			err := tt.call(context.Background(), client)
			if err == nil {
				t.Fatalf("expected error for server error response in %s", tt.name)
			}
		})
	}
}

func TestClient_NewClient_OptionError(t *testing.T) {
	tests := []struct {
		name    string
		newFunc func(opts ...Option) (any, error)
	}{
		{
			name: "Client with bad option",
			newFunc: func(opts ...Option) (any, error) {
				return NewClient(opts...)
			},
		},
		{
			name: "TransparencyClient with bad option",
			newFunc: func(opts ...Option) (any, error) {
				return NewTransparencyClient(opts...)
			},
		},
	}

	badOption := func(_ *clientConfig) error {
		return errBadOption
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.newFunc(badOption)
			if err == nil {
				t.Fatal("expected error for bad option")
			}
		})
	}
}

func TestClient_GetCheckpoint_Error(t *testing.T) {
	server := testServerError(t)
	defer server.Close()

	client, _ := NewTransparencyClient(WithBaseURL(server.URL))
	_, err := client.GetCheckpoint(context.Background())
	if err == nil {
		t.Fatal("expected error for server error response")
	}
}

func TestClient_SearchAgents_Variants(t *testing.T) {
	tests := []struct {
		name        string
		opts        []SearchOption
		wantParams  map[string]string
		wantStatus  []string
		wantNoQuery bool
	}{
		{
			name: "with all scalar params",
			opts: []SearchOption{
				WithSearchName("test"),
				WithSearchHost("example.com"),
				WithSearchVersion("1.0.0"),
				WithSearchProtocol(models.AgentProtocolMCP),
				WithSearchLimit(10),
				WithSearchOffset(5),
			},
			wantParams: map[string]string{
				"agentDisplayName": "test",
				"agentHost":        "example.com",
				"version":          "1.0.0",
				"protocol":         "MCP",
				"limit":            "10",
				"offset":           "5",
			},
		},
		{
			name: "single status filter",
			opts: []SearchOption{
				WithSearchStatus(models.AgentStatusPendingDNS),
			},
			wantStatus: []string{"PENDING_DNS"},
		},
		{
			name: "multiple status filters emitted as repeated keys",
			opts: []SearchOption{
				WithSearchStatus(models.AgentStatusPendingDNS, models.AgentStatusActive),
			},
			wantStatus: []string{"PENDING_DNS", "ACTIVE"},
		},
		{
			name: "WithSearchStatus replaces previous values",
			opts: []SearchOption{
				WithSearchStatus(models.AgentStatusRevoked),
				WithSearchStatus(models.AgentStatusAll),
			},
			wantStatus: []string{"ALL"},
		},
		{
			name:        "no opts produces empty query",
			opts:        nil,
			wantNoQuery: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.wantNoQuery && r.URL.RawQuery != "" {
					t.Errorf("expected no query params, got %s", r.URL.RawQuery)
				}
				for k, v := range tt.wantParams {
					if got := r.URL.Query().Get(k); got != v {
						t.Errorf("param %s = %q, want %q", k, got, v)
					}
				}
				if tt.wantStatus != nil {
					got := r.URL.Query()["status"]
					if len(got) != len(tt.wantStatus) {
						t.Fatalf("status param count = %d, want %d (%v vs %v)", len(got), len(tt.wantStatus), got, tt.wantStatus)
					}
					for i, v := range tt.wantStatus {
						if got[i] != v {
							t.Errorf("status[%d] = %q, want %q", i, got[i], v)
						}
					}
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"totalCount":0,"returnedCount":0,"agents":[]}`))
			}))
			defer server.Close()

			client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))
			result, err := client.SearchAgents(context.Background(), tt.opts...)
			if err != nil {
				t.Fatalf("SearchAgents() error = %v", err)
			}
			if result == nil {
				t.Fatal("SearchAgents() returned nil")
			}
		})
	}
}

func TestClient_SearchAgents_OptionValidation(t *testing.T) {
	client, err := NewClient(WithBaseURL("http://unused.invalid"), WithJWT("t"))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	tests := []struct {
		name string
		opt  SearchOption
	}{
		{"negative limit", WithSearchLimit(-1)},
		{"limit above max", WithSearchLimit(MaxSearchLimit + 1)},
		{"negative offset", WithSearchOffset(-1)},
		{"invalid protocol", WithSearchProtocol("GRPC")},
		{"invalid status", WithSearchStatus(models.AgentLifecycleStatus("NOT_A_STATUS"))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := client.SearchAgents(context.Background(), tt.opt)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, models.ErrBadRequest) {
				t.Errorf("error = %v, want wrapped ErrBadRequest", err)
			}
		})
	}
}

func TestClient_SearchAgents_EmptyProtocolResets(t *testing.T) {
	// WithSearchProtocol("") should clear, not reject.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("protocol") != "" {
			t.Errorf("protocol should be cleared, got %q", r.URL.Query().Get("protocol"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"totalCount":0,"returnedCount":0,"agents":[]}`))
	}))
	defer server.Close()

	client, _ := NewClient(WithBaseURL(server.URL), WithJWT("t"))
	_, err := client.SearchAgents(context.Background(),
		WithSearchProtocol(models.AgentProtocolMCP),
		WithSearchProtocol(""),
	)
	if err != nil {
		t.Fatalf("SearchAgents() error = %v", err)
	}
}

// --- Merged from client_methods_test.go ---

func TestClient_GetAgentDetails(t *testing.T) {
	tests := []struct {
		name       string
		agentID    string
		statusCode int
		response   any
		wantErr    bool
	}{
		{
			name:       "successful retrieval",
			agentID:    "agent-123",
			statusCode: http.StatusOK,
			response: &models.AgentDetails{
				AgentID:          "agent-123",
				AgentDisplayName: "Test Agent",
				ANSName:          "test.ans.godaddy",
			},
			wantErr: false,
		},
		{
			name:       "not found",
			agentID:    "nonexistent",
			statusCode: http.StatusNotFound,
			response: &models.APIError{
				Status:  "error",
				Message: "Agent not found",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", r.Method)
				}
				w.WriteHeader(tt.statusCode)
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))

			result, err := client.GetAgentDetails(context.Background(), tt.agentID)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == nil {
				t.Error("expected non-nil result")
			}
		})
	}
}

func TestClient_GetChallengeDetails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&models.ChallengeDetails{
			Status: "PENDING",
			Challenges: []models.ChallengeInfo{
				{Type: "dns-01"},
			},
		})
	}))
	defer server.Close()

	client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))

	result, err := client.GetChallengeDetails(context.Background(), "agent-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "PENDING" {
		t.Errorf("Status = %q, want %q", result.Status, "PENDING")
	}
}

func TestClient_VerifyACME(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&models.AgentStatus{
			Status: "VERIFYING",
			Phase:  "ACME_VALIDATION",
		})
	}))
	defer server.Close()

	client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))

	result, err := client.VerifyACME(context.Background(), "agent-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "VERIFYING" {
		t.Errorf("Status = %q, want %q", result.Status, "VERIFYING")
	}
}

func TestClient_VerifyDNS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&models.AgentStatus{
			Status: "ACTIVE",
		})
	}))
	defer server.Close()

	client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))

	result, err := client.VerifyDNS(context.Background(), "agent-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ACTIVE" {
		t.Errorf("Status = %q, want %q", result.Status, "ACTIVE")
	}
}

func TestClient_VerifyDNS_422_ReturnsDNSVerificationError(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		contentType      string
		wantTyped        bool // expect *models.DNSVerificationError
		wantMissingCount int
		wantIncorrCount  int
	}{
		{
			name: "missingRecords only",
			body: `{
				"status": "ERROR",
				"missingRecords": [
					{"name":"_ans.example.com","type":"TXT","value":"v=ans1","required":true},
					{"name":"example.com","type":"HTTPS","value":"1 . alpn=h2"}
				],
				"incorrectRecords": []
			}`,
			contentType:      "application/json",
			wantTyped:        true,
			wantMissingCount: 2,
			wantIncorrCount:  0,
		},
		{
			name: "incorrectRecords only",
			body: `{
				"status": "ERROR",
				"missingRecords": [],
				"incorrectRecords": [
					{"record":{"name":"a.b","type":"TXT","value":"expected-val"},
					 "expected":"expected-val","found":"actual-val"}
				]
			}`,
			contentType:      "application/json",
			wantTyped:        true,
			wantMissingCount: 0,
			wantIncorrCount:  1,
		},
		{
			name: "both populated",
			body: `{
				"status": "ERROR",
				"missingRecords": [{"name":"a","type":"TXT","value":"x"}],
				"incorrectRecords": [
					{"record":{"name":"b","type":"TXT","value":"expected-y"},
					 "expected":"expected-y","found":"actual-y"}
				]
			}`,
			contentType:      "application/json",
			wantTyped:        true,
			wantMissingCount: 1,
			wantIncorrCount:  1,
		},
		{
			name:             "neither array (degenerate)",
			body:             `{"status":"ERROR"}`,
			contentType:      "application/json",
			wantTyped:        true,
			wantMissingCount: 0,
			wantIncorrCount:  0,
		},
		{
			name:        "malformed JSON falls back to *ResponseError",
			body:        `{not json`,
			contentType: "application/json",
			wantTyped:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))
			_, err := client.VerifyDNS(context.Background(), "agent-123")
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			// *ResponseError must always be reachable for backwards compat.
			var respErr *models.ResponseError
			if !errors.As(err, &respErr) {
				t.Fatal("errors.As(*ResponseError) failed; backwards compat broken")
			}
			if respErr.StatusCode != http.StatusUnprocessableEntity {
				t.Errorf("StatusCode = %d, want 422", respErr.StatusCode)
			}

			var dnsErr *models.DNSVerificationError
			gotTyped := errors.As(err, &dnsErr)
			if gotTyped != tt.wantTyped {
				t.Fatalf("errors.As(*DNSVerificationError) = %v, want %v", gotTyped, tt.wantTyped)
			}
			if !tt.wantTyped {
				return
			}
			if len(dnsErr.MissingRecords) != tt.wantMissingCount {
				t.Errorf("MissingRecords len = %d, want %d", len(dnsErr.MissingRecords), tt.wantMissingCount)
			}
			if len(dnsErr.IncorrectRecords) != tt.wantIncorrCount {
				t.Errorf("IncorrectRecords len = %d, want %d", len(dnsErr.IncorrectRecords), tt.wantIncorrCount)
			}
		})
	}
}

func TestClient_VerifyDNS_NonDNSStatusCodesUnchanged(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{name: "400 stays *ResponseError", status: http.StatusBadRequest},
		{name: "401 stays *ResponseError", status: http.StatusUnauthorized},
		{name: "500 stays *ResponseError", status: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_ = json.NewEncoder(w).Encode(&models.APIError{Status: "error", Code: "X", Message: "y"})
			}))
			defer server.Close()

			client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))
			_, err := client.VerifyDNS(context.Background(), "agent-123")
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			var dnsErr *models.DNSVerificationError
			if errors.As(err, &dnsErr) {
				t.Fatalf("non-422 status %d should not produce DNSVerificationError", tt.status)
			}
			var respErr *models.ResponseError
			if !errors.As(err, &respErr) {
				t.Fatal("expected *ResponseError")
			}
			if respErr.StatusCode != tt.status {
				t.Errorf("StatusCode = %d, want %d", respErr.StatusCode, tt.status)
			}
		})
	}
}

func TestAsDNSVerificationError_NonResponseErrorPassesThrough(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "nil", err: nil},
		{name: "plain error", err: errors.New("network down")},
		{name: "validation error", err: errors.New("agentID is required")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := asDNSVerificationError(tt.err)
			// Identity comparison is intentional: we are asserting the function
			// returned the *same* error reference unchanged, not just an
			// equivalent error in the chain.
			//nolint:errorlint // identity check, not chain comparison
			if got != tt.err {
				t.Errorf("asDNSVerificationError = %v, want unchanged input %v", got, tt.err)
			}
		})
	}
}

func TestClient_GetIdentityCertificates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]models.CertificateResponse{
			{CsrID: "csr-1"},
		})
	}))
	defer server.Close()

	client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))

	result, err := client.GetIdentityCertificates(context.Background(), "agent-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 cert, got %d", len(result))
	}
}

func TestClient_GetServerCertificates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode([]models.CertificateResponse{
			{CsrID: "csr-s1"},
			{CsrID: "csr-s2"},
		})
	}))
	defer server.Close()

	client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))

	result, err := client.GetServerCertificates(context.Background(), "agent-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 certs, got %d", len(result))
	}
}

func TestClient_SubmitIdentityCSR(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var req models.CsrSubmissionRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.CsrPEM == "" {
			t.Error("expected non-empty CsrPEM")
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(&models.CsrSubmissionResponse{
			CsrID: "csr-new-1",
		})
	}))
	defer server.Close()

	client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))

	result, err := client.SubmitIdentityCSR(context.Background(), "agent-123", "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CsrID != "csr-new-1" {
		t.Errorf("CsrID = %q, want %q", result.CsrID, "csr-new-1")
	}
}

func TestClient_SubmitServerCSR(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(&models.CsrSubmissionResponse{
			CsrID: "csr-server-1",
		})
	}))
	defer server.Close()

	client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))

	result, err := client.SubmitServerCSR(context.Background(), "agent-123", "test-csr-pem")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CsrID != "csr-server-1" {
		t.Errorf("CsrID = %q, want %q", result.CsrID, "csr-server-1")
	}
}

func TestClient_GetCSRStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&models.CsrStatusResponse{
			CsrID:  "csr-123",
			Type:   "IDENTITY",
			Status: "SIGNED",
		})
	}))
	defer server.Close()

	client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))

	result, err := client.GetCSRStatus(context.Background(), "agent-123", "csr-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "SIGNED" {
		t.Errorf("Status = %q, want %q", result.Status, "SIGNED")
	}
}

func TestClient_GetAgentEvents(t *testing.T) {
	tests := []struct {
		name       string
		limit      int
		providerID string
		lastLogID  string
		wantParams map[string]string
	}{
		{
			name:       "with all params",
			limit:      50,
			providerID: "provider-1",
			lastLogID:  "log-last",
			wantParams: map[string]string{
				"limit":      "50",
				"providerId": "provider-1",
				"lastLogId":  "log-last",
			},
		},
		{
			name:  "with only limit",
			limit: 20,
			wantParams: map[string]string{
				"limit": "20",
			},
		},
		{
			name:       "with no params",
			limit:      0,
			wantParams: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query := r.URL.Query()
				for k, v := range tt.wantParams {
					if query.Get(k) != v {
						t.Errorf("param %s = %q, want %q", k, query.Get(k), v)
					}
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(&models.EventPageResponse{
					Items: []models.EventItem{},
				})
			}))
			defer server.Close()

			client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))

			result, err := client.GetAgentEvents(context.Background(), tt.limit, tt.providerID, tt.lastLogID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Error("expected non-nil result")
			}
		})
	}
}

func TestClient_ResolveAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var req models.AgentCapabilityRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.AgentHost != "test.example.com" {
			t.Errorf("AgentHost = %q, want %q", req.AgentHost, "test.example.com")
		}
		if req.Version != "^1.0.0" {
			t.Errorf("Version = %q, want %q", req.Version, "^1.0.0")
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&models.AgentCapabilityResponse{
			AnsName: "ans://v1.0.0.test.example.com",
		})
	}))
	defer server.Close()

	client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))

	result, err := client.ResolveAgent(context.Background(), "test.example.com", "^1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AnsName != "ans://v1.0.0.test.example.com" {
		t.Errorf("AnsName = %q, want %q", result.AnsName, "ans://v1.0.0.test.example.com")
	}
}

func TestClient_RevokeAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var req models.AgentRevocationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Reason != models.RevocationReasonKeyCompromise {
			t.Errorf("Reason = %q, want %q", req.Reason, models.RevocationReasonKeyCompromise)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&models.AgentRevocationResponse{
			AgentID: "agent-123",
			Status:  "REVOKED",
		})
	}))
	defer server.Close()

	client, _ := NewClient(WithBaseURL(server.URL), WithJWT("token"))

	result, err := client.RevokeAgent(context.Background(), "agent-123", models.RevocationReasonKeyCompromise, "key was compromised")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "REVOKED" {
		t.Errorf("Status = %q, want %q", result.Status, "REVOKED")
	}
}

func TestClient_ParameterValidation(t *testing.T) {
	client, err := NewClient(WithBaseURL("http://localhost"), WithJWT("token"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "RegisterAgent nil request",
			call: func() error { _, err := client.RegisterAgent(ctx, nil); return err },
		},
		{
			name: "GetAgentDetails empty agentID",
			call: func() error { _, err := client.GetAgentDetails(ctx, ""); return err },
		},
		{
			name: "GetChallengeDetails empty agentID",
			call: func() error { _, err := client.GetChallengeDetails(ctx, ""); return err },
		},
		{
			name: "VerifyACME empty agentID",
			call: func() error { _, err := client.VerifyACME(ctx, ""); return err },
		},
		{
			name: "VerifyDNS empty agentID",
			call: func() error { _, err := client.VerifyDNS(ctx, ""); return err },
		},
		{
			name: "SearchAgents negative limit",
			call: func() error { _, err := client.SearchAgents(ctx, WithSearchLimit(-1)); return err },
		},
		{
			name: "SearchAgents limit above MaxSearchLimit",
			call: func() error { _, err := client.SearchAgents(ctx, WithSearchLimit(MaxSearchLimit+1)); return err },
		},
		{
			name: "SearchAgents negative offset",
			call: func() error { _, err := client.SearchAgents(ctx, WithSearchOffset(-1)); return err },
		},
		{
			name: "GetIdentityCertificates empty agentID",
			call: func() error { _, err := client.GetIdentityCertificates(ctx, ""); return err },
		},
		{
			name: "GetServerCertificates empty agentID",
			call: func() error { _, err := client.GetServerCertificates(ctx, ""); return err },
		},
		{
			name: "SubmitIdentityCSR empty agentID",
			call: func() error { _, err := client.SubmitIdentityCSR(ctx, "", "csr"); return err },
		},
		{
			name: "SubmitIdentityCSR empty csrPEM",
			call: func() error { _, err := client.SubmitIdentityCSR(ctx, "agent-1", ""); return err },
		},
		{
			name: "SubmitServerCSR empty agentID",
			call: func() error { _, err := client.SubmitServerCSR(ctx, "", "csr"); return err },
		},
		{
			name: "SubmitServerCSR empty csrPEM",
			call: func() error { _, err := client.SubmitServerCSR(ctx, "agent-1", ""); return err },
		},
		{
			name: "GetCSRStatus empty agentID",
			call: func() error { _, err := client.GetCSRStatus(ctx, "", "csr-1"); return err },
		},
		{
			name: "GetCSRStatus empty csrID",
			call: func() error { _, err := client.GetCSRStatus(ctx, "agent-1", ""); return err },
		},
		{
			name: "ResolveAgent empty host",
			call: func() error { _, err := client.ResolveAgent(ctx, "", "*"); return err },
		},
		{
			name: "RevokeAgent empty agentID",
			call: func() error {
				_, err := client.RevokeAgent(ctx, "", "KEY_COMPROMISE", "test")
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !errors.Is(err, models.ErrBadRequest) {
				t.Errorf("expected ErrBadRequest, got %v", err)
			}
		})
	}
}

func TestClient_WithHTTPClient(t *testing.T) {
	customClient := &http.Client{}
	client, err := NewClient(WithHTTPClient(customClient))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestAppendAuditParams(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		params   *models.AgentAuditParams
		wantPath string
	}{
		{
			name:     "with offset and limit",
			path:     "/v1/agents/123/audit",
			params:   &models.AgentAuditParams{Offset: 10, Limit: 20},
			wantPath: "/v1/agents/123/audit?limit=20&offset=10",
		},
		{
			name:     "with limit only",
			path:     "/v1/agents/123/audit",
			params:   &models.AgentAuditParams{Limit: 5},
			wantPath: "/v1/agents/123/audit?limit=5",
		},
		{
			name:     "with offset only",
			path:     "/v1/agents/123/audit",
			params:   &models.AgentAuditParams{Offset: 10},
			wantPath: "/v1/agents/123/audit?offset=10",
		},
		{
			name:     "no params",
			path:     "/v1/agents/123/audit",
			params:   &models.AgentAuditParams{},
			wantPath: "/v1/agents/123/audit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendAuditParams(tt.path, tt.params)
			if got != tt.wantPath {
				t.Errorf("appendAuditParams() = %q, want %q", got, tt.wantPath)
			}
		})
	}
}

func TestAppendCheckpointHistoryParams(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		params   *models.CheckpointHistoryParams
		contains []string
	}{
		{
			name: "with all params",
			path: "/v1/log/checkpoint/history",
			params: &models.CheckpointHistoryParams{
				Limit:    10,
				Offset:   5,
				FromSize: 100,
				ToSize:   200,
				Order:    "DESC",
			},
			contains: []string{"limit=10", "offset=5", "fromSize=100", "toSize=200", "order=DESC"},
		},
		{
			name:     "no params",
			path:     "/v1/log/checkpoint/history",
			params:   &models.CheckpointHistoryParams{},
			contains: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendCheckpointHistoryParams(tt.path, tt.params)
			for _, want := range tt.contains {
				if !containsSubstring(got, want) {
					t.Errorf("appendCheckpointHistoryParams() = %q, want it to contain %q", got, want)
				}
			}
		})
	}
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
