package cmd

import (
	"errors"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/ans"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
)

const (
	// apiKeyParts is the expected number of parts in an API key (key:secret)
	apiKeyParts = 2
)

// createClient creates an ANS client with API key authentication
// API key format: key:secret
func createClient(cfg *config.Config) (*ans.Client, error) {
	// API key format: key:secret
	parts := strings.SplitN(cfg.APIKey, ":", apiKeyParts)
	if len(parts) != apiKeyParts {
		return nil, errors.New("invalid API key format, expected key:secret")
	}

	opts := []ans.Option{
		ans.WithBaseURL(cfg.BaseURL),
		ans.WithVerbose(cfg.Verbose),
		ans.WithAPIKey(parts[0], parts[1]),
	}

	return ans.NewClient(opts...)
}
