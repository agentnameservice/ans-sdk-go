package ans

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/models"
)

// fakeTokenSource returns queued tokens in order (holding the last one) or a
// fixed error. Safe for concurrent use; Calls reports how many times Token ran.
type fakeTokenSource struct {
	mu     sync.Mutex
	tokens []string
	err    error
	calls  int
}

func (f *fakeTokenSource) Token(_ context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	if len(f.tokens) == 0 {
		return "", errors.New("fakeTokenSource: no tokens queued")
	}
	token := f.tokens[0]
	if len(f.tokens) > 1 {
		f.tokens = f.tokens[1:]
	}
	return token, nil
}

func (f *fakeTokenSource) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestAuthOptions_LastOptionWins(t *testing.T) {
	tests := []struct {
		name       string
		opts       []Option
		wantHeader string
		wantErrIs  error
		bannedText string
	}{
		{
			name:       "bearer token only",
			opts:       []Option{WithBearerToken("tok")},
			wantHeader: "Bearer tok",
		},
		{
			name:       "token source only",
			opts:       []Option{WithTokenSource(&fakeTokenSource{tokens: []string{"dyn"}})},
			wantHeader: "Bearer dyn",
		},
		{
			name: "bearer then source - source wins",
			opts: []Option{
				WithBearerToken("static"),
				WithTokenSource(&fakeTokenSource{tokens: []string{"dyn"}}),
			},
			wantHeader: "Bearer dyn",
		},
		{
			name: "source then bearer - bearer wins",
			opts: []Option{
				WithTokenSource(&fakeTokenSource{tokens: []string{"dyn"}}),
				WithBearerToken("static"),
			},
			wantHeader: "Bearer static",
		},
		{
			name: "source then API key - API key wins",
			opts: []Option{
				WithTokenSource(&fakeTokenSource{tokens: []string{"dyn"}}),
				WithAPIKey("k", "s"),
			},
			wantHeader: "sso-key k:s",
		},
		{
			name: "source then JWT - JWT wins",
			opts: []Option{
				WithTokenSource(&fakeTokenSource{tokens: []string{"dyn"}}),
				WithJWT("jwt-tok"),
			},
			wantHeader: "sso-jwt jwt-tok",
		},
		{
			name:       "empty bearer token passes through as-is",
			opts:       []Option{WithBearerToken("")},
			wantHeader: "Bearer ",
		},
		{
			name:      "nil token source rejected at construction",
			opts:      []Option{WithTokenSource(nil)},
			wantErrIs: models.ErrBadRequest,
		},
		{
			name:       "static bearer token with control characters rejected at construction",
			opts:       []Option{WithBearerToken("tok\r\nInjected: 1")},
			wantErrIs:  models.ErrBadRequest,
			bannedText: "Injected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.opts...)
			if tt.wantErrIs != nil {
				if err == nil {
					t.Fatal("NewClient() expected error, got nil")
				}
				if !errors.Is(err, tt.wantErrIs) {
					t.Errorf("NewClient() error = %v, want errors.Is %v", err, tt.wantErrIs)
				}
				if tt.bannedText != "" && strings.Contains(err.Error(), tt.bannedText) {
					t.Errorf("NewClient() error %q leaks token content %q", err.Error(), tt.bannedText)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewClient() unexpected error: %v", err)
			}

			got, err := client.config.authorizationHeader(context.Background())
			if err != nil {
				t.Fatalf("authorizationHeader() unexpected error: %v", err)
			}
			if got != tt.wantHeader {
				t.Errorf("authorizationHeader() = %q, want %q", got, tt.wantHeader)
			}
		})
	}
}

func TestClientConfig_AuthorizationHeader(t *testing.T) {
	sourceErr := errors.New("token endpoint unavailable")

	tests := []struct {
		name        string
		opts        []Option
		want        string
		wantErrIs   error
		wantErrText string
		bannedText  string
	}{
		{
			name: "static header passes through",
			opts: []Option{WithAPIKey("k", "s")},
			want: "sso-key k:s",
		},
		{
			name: "no credentials returns empty header",
			opts: nil,
			want: "",
		},
		{
			name: "source success returns Bearer header",
			opts: []Option{WithTokenSource(&fakeTokenSource{tokens: []string{"tok"}})},
			want: "Bearer tok",
		},
		{
			name:        "source error is wrapped with stable prefix",
			opts:        []Option{WithTokenSource(&fakeTokenSource{err: sourceErr})},
			wantErrIs:   sourceErr,
			wantErrText: "failed to obtain bearer token",
		},
		{
			name:      "empty token rejected",
			opts:      []Option{WithTokenSource(&fakeTokenSource{tokens: []string{""}})},
			wantErrIs: models.ErrBadRequest,
		},
		{
			name:       "token with CRLF rejected without echoing token",
			opts:       []Option{WithTokenSource(&fakeTokenSource{tokens: []string{"tok\r\nInjected: 1"}})},
			wantErrIs:  models.ErrBadRequest,
			bannedText: "Injected",
		},
		{
			name:      "token with space rejected",
			opts:      []Option{WithTokenSource(&fakeTokenSource{tokens: []string{"tok en"}})},
			wantErrIs: models.ErrBadRequest,
		},
		{
			name:      "token with DEL byte rejected",
			opts:      []Option{WithTokenSource(&fakeTokenSource{tokens: []string{"tok\x7fen"}})},
			wantErrIs: models.ErrBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			for _, opt := range tt.opts {
				if err := opt(cfg); err != nil {
					t.Fatalf("applying option: %v", err)
				}
			}

			got, err := cfg.authorizationHeader(context.Background())
			if tt.wantErrIs != nil || tt.wantErrText != "" {
				if err == nil {
					t.Fatal("authorizationHeader() expected error, got nil")
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Errorf("authorizationHeader() error = %v, want errors.Is %v", err, tt.wantErrIs)
				}
				if tt.wantErrText != "" && !strings.Contains(err.Error(), tt.wantErrText) {
					t.Errorf("authorizationHeader() error = %q, want substring %q", err.Error(), tt.wantErrText)
				}
				if tt.bannedText != "" && strings.Contains(err.Error(), tt.bannedText) {
					t.Errorf("authorizationHeader() error %q leaks token content %q", err.Error(), tt.bannedText)
				}
				return
			}
			if err != nil {
				t.Fatalf("authorizationHeader() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("authorizationHeader() = %q, want %q", got, tt.want)
			}
		})
	}
}
