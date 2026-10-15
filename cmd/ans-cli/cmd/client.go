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
// The bearer token takes precedence over the API key when both are set.
func createClient(cfg *config.Config) (*ans.Client, error) {
	authOpt, method, err := authOption(cfg)
	if err != nil {
		return nil, err
	}

	// Diagnostics go to stderr so JSON output on stdout stays parseable, and
	// they name the credential method only (never the value) so an
	// unexpected 401 is diagnosable without -v.
	if cfg.TokenFromDeprecatedName {
		fmt.Fprintln(os.Stderr, "Note: --oauth-token and ANS_OAUTH_TOKEN are deprecated; use --token or ANS_TOKEN")
	}
	if cfg.DeprecatedTokenIgnored {
		fmt.Fprintln(os.Stderr, "Note: both --token/ANS_TOKEN and the deprecated --oauth-token/ANS_OAUTH_TOKEN are set; using --token/ANS_TOKEN")
	}
	if cfg.Token != "" && cfg.APIKey != "" {
		fmt.Fprintln(os.Stderr, "Note: both a bearer token and an API key are configured; using the bearer token")
	}
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "Using %s authentication\n", method)
	}

	// cfg.APIVersion is never empty (config.Load defaults it to "v1"),
	// so the SDK option validates every value — an unknown version
	// fails fast with guidance instead of silently using the V1 lane.
	opts := []ans.Option{
		ans.WithBaseURL(cfg.BaseURL),
		ans.WithVerbose(cfg.Verbose),
		ans.WithAPIVersion(ans.APIVersion(cfg.APIVersion)),
		authOpt,
	}

	return ans.NewClient(opts...)
}

// authOption selects the credential to use and returns the SDK option, a
// display name for auth-method notices, and any error. The bearer token wins
// over the API key when both are set.
func authOption(cfg *config.Config) (ans.Option, string, error) {
	if cfg.Token != "" {
		return ans.WithBearerToken(cfg.Token), "bearer token", nil
	}

	if cfg.APIKey == "" {
		// No credentials at all — return the shared guidance error directly
		// (always non-nil, so a nil ans.Option can never reach NewClient).
		return nil, "", config.ErrNoCredentials
	}

	// API key format: key:secret
	parts := strings.SplitN(cfg.APIKey, ":", apiKeyParts)
	if len(parts) != apiKeyParts {
		return nil, "", errors.New("invalid API key format, expected key:secret (for a Personal Access Token, set --token/ANS_TOKEN instead)")
	}

	return ans.WithAPIKey(parts[0], parts[1]), "API key", nil
}
