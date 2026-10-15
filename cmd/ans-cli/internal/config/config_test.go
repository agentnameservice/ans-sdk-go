package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name                string
		setup               func()
		wantBaseURL         string
		wantAPIKey          string
		wantToken           string
		wantTokenDeprecated bool
		wantLegacyIgnored   bool
		wantVerbose         bool
		wantJSON            bool
	}{
		{
			name: "default values",
			setup: func() {
				viper.Reset()
			},
		},
		{
			name: "with all values set",
			setup: func() {
				viper.Reset()
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
			setup: func() {
				viper.Reset()
				viper.Set("base-url", "https://api.test.com")
				viper.Set("verbose", true)
			},
			wantBaseURL: "https://api.test.com",
			wantVerbose: true,
		},
		{
			name: "token is trimmed",
			setup: func() {
				viper.Reset()
				viper.Set("token", "  padded-token\n")
			},
			wantToken: "padded-token",
		},
		{
			name: "whitespace-only token is treated as unset",
			setup: func() {
				viper.Reset()
				viper.Set("token", "   \t\n")
			},
		},
		{
			name: "deprecated oauth-token key is used when token is unset",
			setup: func() {
				viper.Reset()
				viper.Set("oauth-token", "legacy-token")
			},
			wantToken:           "legacy-token",
			wantTokenDeprecated: true,
		},
		{
			name: "token key wins over a different deprecated value and flags the collision",
			setup: func() {
				viper.Reset()
				viper.Set("token", "new-token")
				viper.Set("oauth-token", "legacy-token")
			},
			wantToken:         "new-token",
			wantLegacyIgnored: true,
		},
		{
			name: "identical value under both names is not a collision",
			setup: func() {
				viper.Reset()
				viper.Set("token", "same-token")
				viper.Set("oauth-token", " same-token ")
			},
			wantToken: "same-token",
		},
		{
			name: "whitespace-only token falls back to the deprecated key and is trimmed",
			setup: func() {
				viper.Reset()
				viper.Set("token", "  ")
				viper.Set("oauth-token", "  legacy-token\n")
			},
			wantToken:           "legacy-token",
			wantTokenDeprecated: true,
		},
		{
			name: "whitespace-only deprecated token is treated as unset",
			setup: func() {
				viper.Reset()
				viper.Set("oauth-token", "   \t\n")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}

			if cfg == nil {
				t.Fatal("Load() returned nil config")
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
				"--token", "ANS_TOKEN", "Personal Access Token",
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
