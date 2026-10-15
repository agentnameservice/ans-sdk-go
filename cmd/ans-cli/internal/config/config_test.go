package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// writeTokenFile creates a token file in a per-test directory and returns its path.
func writeTokenFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name                string
		setup               func(t *testing.T)
		stdin               string
		wantBaseURL         string
		wantAPIKey          string
		wantToken           string
		wantTokenDeprecated bool
		wantLegacyIgnored   bool
		wantVerbose         bool
		wantJSON            bool
		wantErr             string
	}{
		{
			name:  "default values",
			setup: func(*testing.T) {},
		},
		{
			name: "with all values set",
			setup: func(*testing.T) {
				viper.Set("base-url", "https://api.example.com")
				viper.Set("api-key", "test-key:test-secret")
				viper.Set("token", "test-token")
				viper.Set("verbose", true)
				viper.Set("json", true)
			},
			wantBaseURL: "https://api.example.com",
			wantAPIKey:  "test-key:test-secret",
			wantToken:   "test-token",
			wantVerbose: true,
			wantJSON:    true,
		},
		{
			name: "with partial values",
			setup: func(*testing.T) {
				viper.Set("base-url", "https://api.test.com")
				viper.Set("verbose", true)
			},
			wantBaseURL: "https://api.test.com",
			wantVerbose: true,
		},
		{
			name: "ANS_TOKEN is trimmed",
			setup: func(*testing.T) {
				viper.Set("token", "  padded-token\n")
			},
			wantToken: "padded-token",
		},
		{
			name: "whitespace-only ANS_TOKEN is treated as unset",
			setup: func(*testing.T) {
				viper.Set("token", "   \t\n")
			},
		},
		{
			name: "deprecated ANS_OAUTH_TOKEN is used when nothing else is set",
			setup: func(*testing.T) {
				viper.Set("oauth-token-env", "legacy-token")
			},
			wantToken:           "legacy-token",
			wantTokenDeprecated: true,
		},
		{
			name: "ANS_TOKEN wins over a different ANS_OAUTH_TOKEN and flags the collision",
			setup: func(*testing.T) {
				viper.Set("token", "new-token")
				viper.Set("oauth-token-env", "legacy-token")
			},
			wantToken:         "new-token",
			wantLegacyIgnored: true,
		},
		{
			name: "identical ANS_TOKEN and ANS_OAUTH_TOKEN are not a collision",
			setup: func(*testing.T) {
				viper.Set("token", "same-token")
				viper.Set("oauth-token-env", " same-token ")
			},
			wantToken: "same-token",
		},
		{
			name: "whitespace-only ANS_TOKEN falls back to ANS_OAUTH_TOKEN",
			setup: func(*testing.T) {
				viper.Set("token", "  ")
				viper.Set("oauth-token-env", "  legacy-token\n")
			},
			wantToken:           "legacy-token",
			wantTokenDeprecated: true,
		},
		{
			name: "whitespace-only ANS_OAUTH_TOKEN is treated as unset",
			setup: func(*testing.T) {
				viper.Set("oauth-token-env", "   \t\n")
			},
		},
		{
			name: "deprecated --oauth-token flag beats ANS_TOKEN",
			setup: func(*testing.T) {
				viper.Set("oauth-token", "flag-token")
				viper.Set("token", "env-token")
				viper.Set("oauth-token-env", "legacy-env-token")
			},
			wantToken:           "flag-token",
			wantTokenDeprecated: true,
		},
		{
			name: "--token-file beats ANS_TOKEN and the deprecated names",
			setup: func(t *testing.T) {
				viper.Set("token-file", writeTokenFile(t, "file-token\n"))
				viper.Set("token", "env-token")
				viper.Set("oauth-token-env", "legacy-token")
			},
			wantToken: "file-token",
		},
		{
			name: "--token-file content is trimmed",
			setup: func(t *testing.T) {
				viper.Set("token-file", writeTokenFile(t, "  file-token \n\n"))
			},
			wantToken: "file-token",
		},
		{
			name: "--token-file - reads stdin",
			setup: func(*testing.T) {
				viper.Set("token-file", "-")
			},
			stdin:     "stdin-token\n",
			wantToken: "stdin-token",
		},
		{
			name: "--token-file and --oauth-token together are rejected",
			setup: func(t *testing.T) {
				viper.Set("token-file", writeTokenFile(t, "file-token"))
				viper.Set("oauth-token", "flag-token")
			},
			wantErr: "--token-file and --oauth-token cannot both be set",
		},
		{
			name: "missing token file is an error",
			setup: func(t *testing.T) {
				viper.Set("token-file", filepath.Join(t.TempDir(), "missing"))
			},
			wantErr: "--token-file: open ",
		},
		{
			name: "empty token file is an error",
			setup: func(t *testing.T) {
				viper.Set("token-file", writeTokenFile(t, "\n"))
			},
			wantErr: "no token found",
		},
		{
			name: "empty stdin is an error",
			setup: func(*testing.T) {
				viper.Set("token-file", "-")
			},
			stdin:   "",
			wantErr: "--token-file -: no token found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(func() { viper.Reset() })
			tt.setup(t)

			cfg, err := load(strings.NewReader(tt.stdin))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("load() expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("load() error = %q, want substring %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("load() unexpected error: %v", err)
			}
			if cfg == nil {
				t.Fatal("load() returned nil config")
			}

			if cfg.BaseURL != tt.wantBaseURL {
				t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, tt.wantBaseURL)
			}
			if cfg.APIKey != tt.wantAPIKey {
				t.Errorf("APIKey = %q, want %q", cfg.APIKey, tt.wantAPIKey)
			}
			if cfg.Token != tt.wantToken {
				t.Errorf("Token = %q, want %q", cfg.Token, tt.wantToken)
			}
			if cfg.TokenFromDeprecatedName != tt.wantTokenDeprecated {
				t.Errorf("TokenFromDeprecatedName = %v, want %v", cfg.TokenFromDeprecatedName, tt.wantTokenDeprecated)
			}
			if cfg.DeprecatedTokenIgnored != tt.wantLegacyIgnored {
				t.Errorf("DeprecatedTokenIgnored = %v, want %v", cfg.DeprecatedTokenIgnored, tt.wantLegacyIgnored)
			}
			if cfg.Verbose != tt.wantVerbose {
				t.Errorf("Verbose = %v, want %v", cfg.Verbose, tt.wantVerbose)
			}
			if cfg.JSON != tt.wantJSON {
				t.Errorf("JSON = %v, want %v", cfg.JSON, tt.wantJSON)
			}
		})
	}
}

// TestLoad_PublicEntryPoint covers the exported wrapper, which only differs
// from load by reading the real stdin; without --token-file it must not
// touch stdin at all.
func TestLoad_PublicEntryPoint(t *testing.T) {
	viper.Reset()
	t.Cleanup(func() { viper.Reset() })
	viper.Set("api-key", "key:secret")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.APIKey != "key:secret" || cfg.Token != "" {
		t.Errorf("Load() = APIKey %q Token %q, want key:secret and no token", cfg.APIKey, cfg.Token)
	}
}

func TestRequireCredentials(t *testing.T) {
	tests := []struct {
		name         string
		cfg          *Config
		wantErr      bool
		wantInMsg    []string
		wantNotInMsg []string
	}{
		{
			name:    "neither credential set",
			cfg:     &Config{},
			wantErr: true,
			wantInMsg: []string{
				"ANS_TOKEN", "--token-file", "Personal Access Token",
				"--api-key", "ANS_API_KEY",
			},
			// Guidance must steer users to the current names only.
			wantNotInMsg: []string{"--oauth-token", "ANS_OAUTH_TOKEN"},
		},
		{
			name: "API key only",
			cfg:  &Config{APIKey: "key:secret"},
		},
		{
			name: "token only",
			cfg:  &Config{Token: "tok"},
		},
		{
			name: "both credentials set",
			cfg:  &Config{APIKey: "key:secret", Token: "tok"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.RequireCredentials()

			if !tt.wantErr {
				if err != nil {
					t.Fatalf("RequireCredentials() unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("RequireCredentials() expected error, got nil")
			}
			for _, want := range tt.wantInMsg {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("RequireCredentials() error = %q, want it to mention %q", err.Error(), want)
				}
			}
			for _, notWant := range tt.wantNotInMsg {
				if strings.Contains(err.Error(), notWant) {
					t.Errorf("RequireCredentials() error = %q, must not mention deprecated name %q", err.Error(), notWant)
				}
			}
		})
	}
}
