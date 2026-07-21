package config

import (
	"errors"
	"strings"

	"github.com/spf13/viper"
)

// Config represents application configuration
type Config struct {
	BaseURL    string
	APIKey     string //nolint:gosec // G117 - config struct field definition, not logged
	OAuthToken string //nolint:gosec // G117 - config struct field definition, not logged
	APIVersion string
	Verbose    bool
	JSON       bool
}

// Load loads configuration from environment and flags
func Load() (*Config, error) {
	cfg := &Config{
		BaseURL: viper.GetString("base-url"),
		APIKey:  viper.GetString("api-key"),
		// Trimmed at the boundary so a padded or whitespace-only token from
		// env plumbing is treated as unset and never wins precedence.
		OAuthToken: strings.TrimSpace(viper.GetString("oauth-token")),
		// Normalized here so "V2" from env plumbing selects the lane;
		// value validation happens in cmd.createClient where the SDK
		// option can reject with proper guidance. Empty means the flag
		// default ("v1") — viper returns "" only in tests that bypass
		// flag binding.
		APIVersion: strings.ToLower(strings.TrimSpace(viper.GetString("api-version"))),
		Verbose:    viper.GetBool("verbose"),
		JSON:       viper.GetBool("json"),
	}

	return cfg, nil
}

// ErrNoCredentials is returned when neither an OAuth token nor an API key is
// configured. It is the single source of truth for the guidance message —
// cmd.authOption returns it directly for its no-credentials branch.
var ErrNoCredentials = errors.New("OAuth token or API key is required. Set --oauth-token/ANS_OAUTH_TOKEN or --api-key/ANS_API_KEY")

// RequireCredentials returns ErrNoCredentials when neither an OAuth token nor
// an API key is configured. Commands call this before any other validation so
// users get clear guidance instead of a late failure.
func (c *Config) RequireCredentials() error {
	if c.OAuthToken == "" && c.APIKey == "" {
		return ErrNoCredentials
	}
	return nil
}
