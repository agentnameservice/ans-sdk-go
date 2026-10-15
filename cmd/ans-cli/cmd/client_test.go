package cmd

import (
	"strings"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
)

func TestCreateClient(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *config.Config
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid API key",
			cfg: &config.Config{
				APIVersion: "v1",
				BaseURL:    "https://api.example.com",
				APIKey:     "mykey:mysecret",
			},
			wantErr: false,
		},
		{
			name: "invalid API key format - no colon",
			cfg: &config.Config{
				APIVersion: "v1",
				BaseURL:    "https://api.example.com",
				APIKey:     "invalidkey",
			},
			wantErr:   true,
			errSubstr: "invalid API key format",
		},
		{
			name: "invalid API key format points PAT holders at --token",
			cfg: &config.Config{
				APIVersion: "v1",
				BaseURL:    "https://api.example.com",
				APIKey:     "a-personal-access-token-pasted-into-the-wrong-variable",
			},
			wantErr:   true,
			errSubstr: "set --token/ANS_TOKEN instead",
		},
		{
			name: "no credentials at all",
			cfg: &config.Config{
				APIVersion: "v1",
				BaseURL:    "https://api.example.com",
				APIKey:     "",
			},
			wantErr:   true,
			errSubstr: "bearer token or API key is required",
		},
		{
			name: "valid API key with verbose",
			cfg: &config.Config{
				APIVersion: "v1",
				BaseURL:    "https://api.example.com",
				APIKey:     "key:secret",
				Verbose:    true,
			},
			wantErr: false,
		},
		{
			name: "token only",
			cfg: &config.Config{
				APIVersion: "v1",
				BaseURL:    "https://api.example.com",
				Token:      "tok",
			},
			wantErr: false,
		},
		{
			name: "token wins over malformed API key",
			cfg: &config.Config{
				APIVersion: "v1",
				BaseURL:    "https://api.example.com",
				APIKey:     "no-colon-here",
				Token:      "tok",
			},
			wantErr: false,
		},
		{
			name: "token with verbose",
			cfg: &config.Config{
				APIVersion: "v1",
				BaseURL:    "https://api.example.com",
				Token:      "tok",
				Verbose:    true,
			},
			wantErr: false,
		},
		{
			name: "token supplied under a deprecated name still authenticates",
			cfg: &config.Config{
				APIVersion:              "v1",
				BaseURL:                 "https://api.example.com",
				Token:                   "tok",
				TokenFromDeprecatedName: true,
			},
			wantErr: false,
		},
		{
			name: "token kept while a different deprecated value is ignored",
			cfg: &config.Config{
				APIVersion:             "v1",
				BaseURL:                "https://api.example.com",
				Token:                  "tok",
				DeprecatedTokenIgnored: true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := createClient(tt.cfg)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if client == nil {
				t.Fatal("expected non-nil client")
			}
		})
	}
}

func TestAuthOption(t *testing.T) {
	tests := []struct {
		name       string
		cfg        *config.Config
		wantMethod string
		wantErr    bool
		errSubstr  string
	}{
		{
			name:       "token only",
			cfg:        &config.Config{Token: "tok"},
			wantMethod: "bearer token",
		},
		{
			name:       "API key only",
			cfg:        &config.Config{APIKey: "key:secret"},
			wantMethod: "API key",
		},
		{
			name:       "token wins when both are set",
			cfg:        &config.Config{APIKey: "key:secret", Token: "tok"},
			wantMethod: "bearer token",
		},
		{
			name:      "no credentials",
			cfg:       &config.Config{},
			wantErr:   true,
			errSubstr: "bearer token or API key is required",
		},
		{
			name:      "malformed API key without token",
			cfg:       &config.Config{APIKey: "no-colon-here"},
			wantErr:   true,
			errSubstr: "invalid API key format",
		},
		{
			name:      "malformed API key error points PAT holders at --token",
			cfg:       &config.Config{APIKey: "no-colon-here"},
			wantErr:   true,
			errSubstr: "set --token/ANS_TOKEN instead",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt, method, err := authOption(tt.cfg)

			if tt.wantErr {
				if err == nil {
					t.Fatal("authOption() expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("authOption() error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
				return
			}

			if err != nil {
				t.Fatalf("authOption() unexpected error: %v", err)
			}
			if opt == nil {
				t.Fatal("authOption() returned nil option")
			}
			if method != tt.wantMethod {
				t.Errorf("authOption() method = %q, want %q", method, tt.wantMethod)
			}
		})
	}
}
