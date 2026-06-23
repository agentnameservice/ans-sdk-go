package ans

import (
	"fmt"
	"net/http"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
)

const (
	// DefaultTimeout is the default HTTP client timeout
	DefaultTimeout = 120 * time.Second

	// MaxSearchLimit is the maximum value accepted by SearchAgents' limit
	// option. Matches the server-side cap — the SDK rejects values above
	// this locally so callers fail fast instead of round-tripping to a 400.
	MaxSearchLimit = 100
)

// Option is a functional option for configuring ANS clients
type Option func(*clientConfig) error

// clientConfig holds the configuration for ANS clients
type clientConfig struct {
	baseURL    string
	httpClient *http.Client
	authHeader string // Can be "sso-jwt <token>" or "sso-key <key>:<secret>"
	verbose    bool
	timeout    time.Duration
}

// defaultConfig returns the default client configuration
func defaultConfig() *clientConfig {
	return &clientConfig{
		baseURL: "https://api.godaddy.com",
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		verbose: false,
		timeout: DefaultTimeout,
	}
}

// WithBaseURL sets the base URL for the API
func WithBaseURL(baseURL string) Option {
	return func(c *clientConfig) error {
		c.baseURL = baseURL
		return nil
	}
}

// WithJWT sets JWT authentication (for internal endpoints)
func WithJWT(jwt string) Option {
	return func(c *clientConfig) error {
		c.authHeader = "sso-jwt " + jwt
		return nil
	}
}

// WithAPIKey sets API key authentication (for public gateway endpoints)
func WithAPIKey(key, secret string) Option {
	return func(c *clientConfig) error {
		c.authHeader = "sso-key " + key + ":" + secret
		return nil
	}
}

// WithTimeout sets the HTTP client timeout
func WithTimeout(timeout time.Duration) Option {
	return func(c *clientConfig) error {
		c.timeout = timeout
		if c.httpClient != nil {
			c.httpClient.Timeout = timeout
		}
		return nil
	}
}

// WithVerbose enables verbose logging
func WithVerbose(verbose bool) Option {
	return func(c *clientConfig) error {
		c.verbose = verbose
		return nil
	}
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) Option {
	return func(c *clientConfig) error {
		c.httpClient = client
		return nil
	}
}

// SearchOption is a functional option for Client.SearchAgents.
type SearchOption func(*searchConfig) error

// searchConfig accumulates filter values for a single SearchAgents call.
type searchConfig struct {
	name     string
	host     string
	version  string
	protocol models.AgentProtocol
	statuses []models.AgentLifecycleStatus
	limit    int
	offset   int
}

// WithSearchName filters by agent display name (partial matching supported server-side).
func WithSearchName(name string) SearchOption {
	return func(c *searchConfig) error {
		c.name = name
		return nil
	}
}

// WithSearchHost filters by agent host domain (partial matching supported server-side).
func WithSearchHost(host string) SearchOption {
	return func(c *searchConfig) error {
		c.host = host
		return nil
	}
}

// WithSearchVersion filters by agent version (flexible matching supported server-side).
func WithSearchVersion(version string) SearchOption {
	return func(c *searchConfig) error {
		c.version = version
		return nil
	}
}

// WithSearchProtocol filters by endpoint protocol. Pass a models.AgentProtocol
// constant (AgentProtocolA2A, AgentProtocolMCP, AgentProtocolHTTPAPI).
func WithSearchProtocol(protocol models.AgentProtocol) SearchOption {
	return func(c *searchConfig) error {
		if protocol == "" {
			c.protocol = ""
			return nil
		}
		if !models.IsValidAgentProtocol(protocol) {
			return fmt.Errorf("%w: invalid protocol %q", models.ErrBadRequest, protocol)
		}
		c.protocol = protocol
		return nil
	}
}

// WithSearchStatus filters by one or more lifecycle statuses. If omitted, the
// API defaults to ACTIVE — pass AgentStatusPendingDNS to locate pending
// registrations, or AgentStatusAll to see every lifecycle state. Repeated
// calls replace the previous set.
func WithSearchStatus(statuses ...models.AgentLifecycleStatus) SearchOption {
	return func(c *searchConfig) error {
		for _, s := range statuses {
			if !models.IsValidAgentLifecycleStatus(s) {
				return fmt.Errorf("%w: invalid lifecycle status %q", models.ErrBadRequest, s)
			}
		}
		c.statuses = append(c.statuses[:0], statuses...)
		return nil
	}
}

// WithSearchLimit caps the number of results returned. Must be in
// [0, MaxSearchLimit]; negative or above-cap values return ErrBadRequest.
func WithSearchLimit(limit int) SearchOption {
	return func(c *searchConfig) error {
		if limit < 0 || limit > MaxSearchLimit {
			return fmt.Errorf("%w: limit must be between 0 and %d", models.ErrBadRequest, MaxSearchLimit)
		}
		c.limit = limit
		return nil
	}
}

// WithSearchOffset skips the first N results (for pagination).
func WithSearchOffset(offset int) SearchOption {
	return func(c *searchConfig) error {
		if offset < 0 {
			return fmt.Errorf("%w: offset cannot be negative", models.ErrBadRequest)
		}
		c.offset = offset
		return nil
	}
}
