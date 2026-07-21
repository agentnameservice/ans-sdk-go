package ans

import (
	"context"
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

// APIVersion selects which Registration Authority API lane the client's
// agent-lifecycle and certificate methods target. The two lanes expose
// the same request/response shapes for those routes; they differ in path
// (`/v1/agents/...` vs `/v2/ans/agents/...`) and in which features the
// server enables — discovery profiles (AgentRegistrationRequest.
// DiscoveryProfiles) only take effect on the V2 lane, where the server
// default is the DNS-AID SVCB family (ANS_DNSAID); the V1 lane is pinned
// to the legacy ANS_TXT family.
type APIVersion string

const (
	// APIVersionV1 targets the original `/v1/agents` lane (default).
	APIVersionV1 APIVersion = "v1"
	// APIVersionV2 targets the `/v2/ans/agents` lane.
	APIVersionV2 APIVersion = "v2"
)

// IsValidAPIVersion reports whether v is a recognised API version.
func IsValidAPIVersion(v APIVersion) bool {
	return v == APIVersionV1 || v == APIVersionV2
}

// TokenSource supplies OAuth 2.0 bearer tokens. Token is called for each
// outgoing request; implementations should cache and refresh proactively
// and must be safe for concurrent use. Token must honor ctx cancellation
// and deadlines — the client's WithTimeout does NOT bound this call.
// Return the raw token without the "Bearer " prefix, and never embed
// credentials or raw token-endpoint responses in returned errors.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// clientConfig holds the configuration for ANS clients.
// Invariant: at most one of authHeader/tokenSource is active — every auth
// option must clear the other field so the last option applied wins.
type clientConfig struct {
	baseURL     string
	httpClient  *http.Client
	authHeader  string // Can be "sso-jwt <token>", "sso-key <key>:<secret>", or "Bearer <token>"
	tokenSource TokenSource
	verbose     bool
	timeout     time.Duration
	apiVersion  APIVersion
}

// authorizationHeader resolves the Authorization value for a single request.
// Static credentials (WithJWT, WithAPIKey, WithBearerToken) return the
// pre-formatted header; a TokenSource is invoked per request so refreshed
// tokens are picked up. Returns "" when no credentials are configured.
func (c *clientConfig) authorizationHeader(ctx context.Context) (string, error) {
	if c.tokenSource == nil {
		return c.authHeader, nil
	}
	token, err := c.tokenSource.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to obtain bearer token: %w", err)
	}
	if token == "" {
		return "", fmt.Errorf("%w: token source returned an empty token", models.ErrBadRequest)
	}
	if !isValidBearerToken(token) {
		return "", fmt.Errorf("%w: token source returned a token containing whitespace or control characters", models.ErrBadRequest)
	}
	return "Bearer " + token, nil
}

// isValidBearerToken rejects tokens containing whitespace or control bytes
// (<= 0x20 or 0x7F) so a malformed or attacker-influenced token can never
// reach the Authorization header, even through a custom transport that skips
// net/http's own header validation.
func isValidBearerToken(token string) bool {
	for i := range len(token) {
		if token[i] <= 0x20 || token[i] == 0x7f {
			return false
		}
	}
	return true
}

// defaultConfig returns the default client configuration
func defaultConfig() *clientConfig {
	return &clientConfig{
		baseURL: "https://api.godaddy.com",
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		verbose:    false,
		timeout:    DefaultTimeout,
		apiVersion: APIVersionV1,
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
		c.tokenSource = nil
		return nil
	}
}

// WithAPIKey sets API key authentication (for public gateway endpoints)
func WithAPIKey(key, secret string) Option {
	return func(c *clientConfig) error {
		c.authHeader = "sso-key " + key + ":" + secret
		c.tokenSource = nil
		return nil
	}
}

// WithBearerToken sets a static OAuth 2.0 access token, sent on every request
// as "Authorization: Bearer <token>". It is an alternative to WithAPIKey and
// WithJWT for deployments that authenticate with OAuth 2.0. Tokens containing
// whitespace or control characters are rejected at construction with
// models.ErrBadRequest; an empty token is sent as "Bearer " — prefer
// WithTokenSource for refreshable resolution. TransparencyClient public
// endpoints never send credentials regardless of this option.
func WithBearerToken(token string) Option {
	return func(c *clientConfig) error {
		if !isValidBearerToken(token) {
			return fmt.Errorf("%w: bearer token contains whitespace or control characters", models.ErrBadRequest)
		}
		c.authHeader = "Bearer " + token
		c.tokenSource = nil
		return nil
	}
}

// WithTokenSource sets a dynamic OAuth 2.0 bearer-token source. The source's
// Token method is called for each outgoing request and the result is sent as
// "Authorization: Bearer <token>", letting callers plug in refreshing
// credentials (see the README for a golang.org/x/oauth2 adapter). A nil
// source is rejected at construction with models.ErrBadRequest. Auth
// options are last-wins: WithTokenSource clears any static credential set by
// WithJWT, WithAPIKey, or WithBearerToken, and vice versa.
func WithTokenSource(ts TokenSource) Option {
	return func(c *clientConfig) error {
		if ts == nil {
			return fmt.Errorf("%w: token source cannot be nil", models.ErrBadRequest)
		}
		c.tokenSource = ts
		c.authHeader = ""
		return nil
	}
}

// WithAPIVersion selects the RA API lane for the agent-lifecycle and
// certificate methods: RegisterAgent, GetAgentDetails, VerifyACME,
// VerifyDNS, GetIdentityCertificates, GetServerCertificates,
// SubmitIdentityCSR, SubmitServerCSR, GetCSRStatus, and RevokeAgent.
// Defaults to APIVersionV1. Methods without a V2 twin on the server
// (GetChallengeDetails, SearchAgents, GetAgentEvents, ResolveAgent)
// keep their existing paths regardless of this option, so enabling V2
// never changes the behavior of a route that only exists on V1. An
// unrecognised version is rejected at construction with
// models.ErrBadRequest.
func WithAPIVersion(v APIVersion) Option {
	return func(c *clientConfig) error {
		if !IsValidAPIVersion(v) {
			return fmt.Errorf("%w: invalid API version %q (want %q or %q)",
				models.ErrBadRequest, v, APIVersionV1, APIVersionV2)
		}
		c.apiVersion = v
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
