package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/ans"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
)

const (
	// apiKeyParts is the expected number of parts in an API key (key:secret)
	apiKeyParts = 2
)

// createClient creates an ANS client using the configured credentials.
// The OAuth bearer token takes precedence over the API key when both are set.
func createClient(cfg *config.Config) (*ans.Client, error) {
	authOpt, method, err := authOption(cfg)
	if err != nil {
		return nil, err
	}

	// The ambiguous both-set configuration always gets a notice (method name
	// only, never the token) so an unexpected 401 is diagnosable without -v.
	// Diagnostics go to stderr so JSON output on stdout stays parseable.
	if cfg.OAuthToken != "" && cfg.APIKey != "" {
		fmt.Fprintln(os.Stderr, "Note: both an OAuth token and an API key are configured; using the OAuth bearer token")
	}
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "Using %s authentication\n", method)
	}

	opts := []ans.Option{
		ans.WithBaseURL(cfg.BaseURL),
		ans.WithVerbose(cfg.Verbose),
		authOpt,
	}

	// Empty means "flag default" (config tests bypass flag binding);
	// anything else is validated by the SDK option so an unknown value
	// fails fast with guidance instead of silently using the V1 lane.
	if cfg.APIVersion != "" {
		opts = append(opts, ans.WithAPIVersion(ans.APIVersion(cfg.APIVersion)))
	}

	return ans.NewClient(opts...)
}

// authOption selects the credential to use and returns the SDK option, a
// display name for auth-method notices, and any error. The OAuth token wins
// over the API key when both are set.
func authOption(cfg *config.Config) (ans.Option, string, error) {
	if cfg.OAuthToken != "" {
		return ans.WithBearerToken(cfg.OAuthToken), "OAuth bearer token", nil
	}

	if cfg.APIKey == "" {
		// No credentials at all — return the shared guidance error directly
		// (always non-nil, so a nil ans.Option can never reach NewClient).
		return nil, "", config.ErrNoCredentials
	}

	// API key format: key:secret
	parts := strings.SplitN(cfg.APIKey, ":", apiKeyParts)
	if len(parts) != apiKeyParts {
		return nil, "", errors.New("invalid API key format, expected key:secret")
	}

	return ans.WithAPIKey(parts[0], parts[1]), "API key", nil
}
