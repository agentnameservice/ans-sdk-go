package httputility

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/godaddy/ans-sdk-go/models"
)

func TestDoRequest(t *testing.T) {
	type respData struct {
		Message string `json:"message"`
	}

	tests := []struct {
		name           string
		method         string
		body           any
		serverStatus   int
		serverResponse any
		wantResult     *respData
		wantErr        bool
		errContains    string
	}{
		{
			name:           "successful GET with result",
			method:         http.MethodGet,
			body:           nil,
			serverStatus:   http.StatusOK,
			serverResponse: &respData{Message: "hello"},
			wantResult:     &respData{Message: "hello"},
			wantErr:        false,
		},
		{
			name:           "successful POST with body",
			method:         http.MethodPost,
			body:           map[string]string{"key": "value"},
			serverStatus:   http.StatusOK,
			serverResponse: &respData{Message: "created"},
			wantResult:     &respData{Message: "created"},
			wantErr:        false,
		},
		{
			name:         "successful request with nil result",
			method:       http.MethodDelete,
			body:         nil,
			serverStatus: http.StatusNoContent,
			wantErr:      false,
		},
		{
			name:         "400 bad request with API error",
			method:       http.MethodPost,
			body:         nil,
			serverStatus: http.StatusBadRequest,
			serverResponse: &models.APIError{
				Status:  "error",
				Code:    "BAD_REQUEST",
				Message: "invalid input",
			},
			wantErr:     true,
			errContains: "Bad Request",
		},
		{
			name:         "401 unauthorized",
			method:       http.MethodGet,
			body:         nil,
			serverStatus: http.StatusUnauthorized,
			serverResponse: &models.APIError{
				Status:  "error",
				Code:    "UNAUTHORIZED",
				Message: "bad token",
			},
			wantErr:     true,
			errContains: "Unauthorized",
		},
		{
			name:         "403 forbidden",
			method:       http.MethodGet,
			body:         nil,
			serverStatus: http.StatusForbidden,
			serverResponse: &models.APIError{
				Status:  "error",
				Code:    "FORBIDDEN",
				Message: "not allowed",
			},
			wantErr:     true,
			errContains: "Forbidden",
		},
		{
			name:         "404 not found",
			method:       http.MethodGet,
			body:         nil,
			serverStatus: http.StatusNotFound,
			serverResponse: &models.APIError{
				Status:  "error",
				Code:    "NOT_FOUND",
				Message: "missing",
			},
			wantErr:     true,
			errContains: "Not Found",
		},
		{
			name:         "409 conflict",
			method:       http.MethodPost,
			body:         nil,
			serverStatus: http.StatusConflict,
			serverResponse: &models.APIError{
				Status:  "error",
				Code:    "CONFLICT",
				Message: "duplicate",
			},
			wantErr:     true,
			errContains: "Conflict",
		},
		{
			name:         "429 too many requests",
			method:       http.MethodGet,
			body:         nil,
			serverStatus: http.StatusTooManyRequests,
			serverResponse: &models.APIError{
				Status:  "error",
				Code:    "TOO_MANY_REQUESTS",
				Message: "rate limited",
			},
			wantErr:     true,
			errContains: "Too Many Requests",
		},
		{
			name:         "500 internal server error",
			method:       http.MethodGet,
			body:         nil,
			serverStatus: http.StatusInternalServerError,
			serverResponse: &models.APIError{
				Status:  "error",
				Code:    "INTERNAL_ERROR",
				Message: "server error",
			},
			wantErr:     true,
			errContains: "Internal Server Error",
		},
		{
			name:         "error response with non-JSON body",
			method:       http.MethodGet,
			body:         nil,
			serverStatus: http.StatusBadGateway,
			wantErr:      true,
			errContains:  "bad gateway html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tt.method {
					t.Errorf("expected method %s, got %s", tt.method, r.Method)
				}

				// Verify headers
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
				}
				if r.Header.Get("Accept") != "application/json" {
					t.Errorf("expected Accept application/json, got %s", r.Header.Get("Accept"))
				}

				w.WriteHeader(tt.serverStatus)
				if tt.serverResponse != nil {
					_ = json.NewEncoder(w).Encode(tt.serverResponse)
				} else if tt.serverStatus == http.StatusBadGateway {
					_, _ = w.Write([]byte("bad gateway html"))
				}
			}))
			defer server.Close()

			cfg := &ClientConfig{
				BaseURL:    server.URL,
				HTTPClient: http.DefaultClient,
				AuthHeader: "sso-jwt test-token",
			}

			var result respData
			var resultPtr any
			if tt.wantResult != nil || tt.serverStatus < http.StatusBadRequest {
				resultPtr = &result
			}

			err := DoRequest(context.Background(), cfg, tt.method, "/test", tt.body, resultPtr)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}

				// Verify all error responses are wrapped in ResponseError
				var respErr *models.ResponseError
				if !errors.As(err, &respErr) {
					t.Fatal("expected error to be *models.ResponseError")
				}
				if respErr.StatusCode != tt.serverStatus {
					t.Errorf("ResponseError.StatusCode = %d, want %d", respErr.StatusCode, tt.serverStatus)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantResult != nil {
				if result.Message != tt.wantResult.Message {
					t.Errorf("result.Message = %q, want %q", result.Message, tt.wantResult.Message)
				}
			}
		})
	}
}

func TestDoRequest_AuthHeader(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantAuth   string
	}{
		{
			name:       "with auth header",
			authHeader: "sso-jwt my-token",
			wantAuth:   "sso-jwt my-token",
		},
		{
			name:       "without auth header",
			authHeader: "",
			wantAuth:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth := r.Header.Get("Authorization")
				if gotAuth != tt.wantAuth {
					t.Errorf("Authorization header = %q, want %q", gotAuth, tt.wantAuth)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			cfg := &ClientConfig{
				BaseURL:    server.URL,
				HTTPClient: http.DefaultClient,
				AuthHeader: tt.authHeader,
			}

			_ = DoRequest(context.Background(), cfg, http.MethodGet, "/test", nil, nil)
		})
	}
}

func TestDoRequest_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &ClientConfig{
		BaseURL:    server.URL,
		HTTPClient: http.DefaultClient,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := DoRequest(ctx, cfg, http.MethodGet, "/test", nil, nil)
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
}

func TestDoRequest_InvalidURL(t *testing.T) {
	cfg := &ClientConfig{
		BaseURL:    "://invalid",
		HTTPClient: http.DefaultClient,
	}

	err := DoRequest(context.Background(), cfg, http.MethodGet, "/test", nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

func TestDoRequest_UnmarshalableBody(t *testing.T) {
	cfg := &ClientConfig{
		BaseURL:    "http://localhost",
		HTTPClient: http.DefaultClient,
	}

	// Use a channel which cannot be marshaled to JSON
	err := DoRequest(context.Background(), cfg, http.MethodPost, "/test", make(chan int), nil)
	if err == nil {
		t.Fatal("expected marshal error, got nil")
	}
}

func TestHandleErrorResponse_PreservesRawBody(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    []byte
		wantRaw []byte
	}{
		{
			name:    "standard APIError JSON",
			status:  http.StatusBadRequest,
			body:    []byte(`{"status":"error","code":"BAD","message":"bad request"}`),
			wantRaw: []byte(`{"status":"error","code":"BAD","message":"bad request"}`),
		},
		{
			name:    "non-standard JSON (verify-dns 422)",
			status:  http.StatusUnprocessableEntity,
			body:    []byte(`{"status":"ERROR","missingRecords":[{"name":"a","type":"TXT","value":"x"}],"incorrectRecords":[]}`),
			wantRaw: []byte(`{"status":"ERROR","missingRecords":[{"name":"a","type":"TXT","value":"x"}],"incorrectRecords":[]}`),
		},
		{
			name:    "non-JSON body",
			status:  http.StatusBadGateway,
			body:    []byte(`bad gateway html`),
			wantRaw: []byte(`bad gateway html`),
		},
		{
			name:    "empty body",
			status:  http.StatusInternalServerError,
			body:    []byte{},
			wantRaw: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := HandleErrorResponse(tt.status, tt.body)
			var re *models.ResponseError
			if !errors.As(err, &re) {
				t.Fatal("expected error to be *models.ResponseError")
			}
			if string(re.RawBody) != string(tt.wantRaw) {
				t.Errorf("RawBody = %q, want %q", re.RawBody, tt.wantRaw)
			}
		})
	}
}

func TestDoRequest_InvalidResponseJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()

	cfg := &ClientConfig{
		BaseURL:    server.URL,
		HTTPClient: http.DefaultClient,
	}

	var result map[string]string
	err := DoRequest(context.Background(), cfg, http.MethodGet, "/test", nil, &result)
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
