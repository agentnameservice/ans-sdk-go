package config

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name           string
		setup          func()
		wantBaseURL    string
		wantAPIKey     string
		wantOAuthToken string
		wantVerbose    bool
		wantJSON       bool
	}{
		{
			name: "default values",
			setup: func() {
				viper.Reset()
			},
			wantBaseURL: "",
			wantAPIKey:  "",
			wantVerbose: false,
			wantJSON:    false,
		},
		{
			name: "with all values set",
			setup: func() {
				viper.Reset()
				viper.Set("base-url", "https://api.example.com")
				viper.Set("api-key", "test-key:test-secret")
				viper.Set("oauth-token", "test-oauth-token")
				viper.Set("verbose", true)
				viper.Set("json", true)
			},
			wantBaseURL:    "https://api.example.com",
			wantAPIKey:     "test-key:test-secret",
			wantOAuthToken: "test-oauth-token",
			wantVerbose:    true,
			wantJSON:       true,
		},
		{
			name: "with partial values",
			setup: func() {
				viper.Reset()
				viper.Set("base-url", "https://api.test.com")
				viper.Set("verbose", true)
			},
			wantBaseURL: "https://api.test.com",
			wantAPIKey:  "",
			wantVerbose: true,
			wantJSON:    false,
		},
		{
			name: "oauth token is trimmed",
			setup: func() {
				viper.Reset()
				viper.Set("oauth-token", "  padded-token\n")
			},
			wantOAuthToken: "padded-token",
		},
		{
			name: "whitespace-only oauth token is treated as unset",
			setup: func() {
				viper.Reset()
				viper.Set("oauth-token", "   \t\n")
			},
			wantOAuthToken: "",
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
			if cfg.OAuthToken != tt.wantOAuthToken {
				t.Errorf("OAuthToken = %q, want %q", cfg.OAuthToken, tt.wantOAuthToken)
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
		name      string
		cfg       *Config
		wantErr   bool
		wantInMsg []string
	}{
		{
			name:    "neither credential set",
			cfg:     &Config{},
			wantErr: true,
			wantInMsg: []string{
				"--oauth-token", "ANS_OAUTH_TOKEN",
				"--api-key", "ANS_API_KEY",
			},
		},
		{
			name: "API key only",
			cfg:  &Config{APIKey: "key:secret"},
		},
		{
			name: "OAuth token only",
			cfg:  &Config{OAuthToken: "tok"},
		},
		{
			name: "both credentials set",
			cfg:  &Config{APIKey: "key:secret", OAuthToken: "tok"},
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
		})
	}
}
