package ans

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/internal/httputility"
	"github.com/agentnameservice/ans-sdk-go/models"
)

// Client represents an ANS Registry Authority API client
type Client struct {
	config *clientConfig
}

// NewClient creates a new ANS API client with functional options
func NewClient(opts ...Option) (*Client, error) {
	cfg := defaultConfig()

	// Apply options
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	return &Client{
		config: cfg,
	}, nil
}

// doRequest performs an HTTP request with authentication and context
func (c *Client) doRequest(ctx context.Context, method, path string, body any, result any) error {
	authHeader, err := c.config.authorizationHeader(ctx)
	if err != nil {
		return err
	}
	httpCfg := &httputility.ClientConfig{
		BaseURL:    c.config.baseURL,
		HTTPClient: c.config.httpClient,
		AuthHeader: authHeader,
	}
	return httputility.DoRequest(ctx, httpCfg, method, path, body, result)
}

// agentsCollectionPath returns the lane-specific agents collection path:
// "/v1/agents" on the default V1 lane, "/v2/ans/agents" when the client
// was built WithAPIVersion(APIVersionV2). The client decodes the shared
// subset of both lanes' response shapes; V2-only response fields (e.g.
// the detail response's identities[]) are ignored until modeled here.
func (c *Client) agentsCollectionPath() string {
	if c.config.apiVersion == APIVersionV2 {
		return "/v2/ans/agents"
	}
	return "/v1/agents"
}

// registerPath returns the lane-specific registration route: the V1 lane
// registers at POST /v1/agents/register, the V2 lane at the collection
// itself (POST /v2/ans/agents).
func (c *Client) registerPath() string {
	if c.config.apiVersion == APIVersionV2 {
		return "/v2/ans/agents"
	}
	return "/v1/agents/register"
}

// agentPath returns the lane-specific path for one agent with optional
// trailing segments. agentID is URL-escaped here; callers escape any
// segment that carries user input (e.g. a csrID).
func (c *Client) agentPath(agentID string, segments ...string) string {
	parts := append([]string{c.agentsCollectionPath(), url.PathEscape(agentID)}, segments...)
	return strings.Join(parts, "/")
}

// RegisterAgent registers a new agent. On the V2 lane the request's
// DiscoveryProfiles field selects which DNS record families the RA asks
// the operator to publish (omitted → the server default, ANS_DNSAID).
// Setting DiscoveryProfiles on the V1 lane is rejected with
// models.ErrBadRequest: the V1 lane ignores the field server-side and
// always emits the ANS_TXT family, so forwarding it would silently
// drop an explicit choice — the registration would succeed with TXT
// records and no signal anywhere.
func (c *Client) RegisterAgent(ctx context.Context, req *models.AgentRegistrationRequest) (*models.RegistrationPending, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: request cannot be nil", models.ErrBadRequest)
	}
	if len(req.DiscoveryProfiles) > 0 && c.config.apiVersion != APIVersionV2 {
		return nil, fmt.Errorf("%w: DiscoveryProfiles requires WithAPIVersion(APIVersionV2); the V1 lane ignores the field", models.ErrBadRequest)
	}
	var result models.RegistrationPending
	err := c.doRequest(ctx, http.MethodPost, c.registerPath(), req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetAgentDetails retrieves agent details by ID
func (c *Client) GetAgentDetails(ctx context.Context, agentID string) (*models.AgentDetails, error) {
	if err := validateRequired("agentID", agentID); err != nil {
		return nil, err
	}
	var result models.AgentDetails
	err := c.doRequest(ctx, http.MethodGet, c.agentPath(agentID), nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetChallengeDetails retrieves challenge details for an agent.
// This route only exists on the V1 surface, so the path is not affected
// by WithAPIVersion; on either lane the pending challenges are also
// available via GetAgentDetails' RegistrationPending.Challenges.
func (c *Client) GetChallengeDetails(ctx context.Context, agentID string) (*models.ChallengeDetails, error) {
	if err := validateRequired("agentID", agentID); err != nil {
		return nil, err
	}
	var result models.ChallengeDetails
	path := fmt.Sprintf("/v1/agents/%s/challenge", url.PathEscape(agentID))
	err := c.doRequest(ctx, http.MethodGet, path, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// VerifyACME triggers ACME validation
func (c *Client) VerifyACME(ctx context.Context, agentID string) (*models.AgentStatus, error) {
	if err := validateRequired("agentID", agentID); err != nil {
		return nil, err
	}
	var result models.AgentStatus
	err := c.doRequest(ctx, http.MethodPost, c.agentPath(agentID, "verify-acme"), nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// VerifyDNS verifies DNS records are configured.
// On HTTP 422, the API returns a structured payload listing missing/incorrect
// DNS records. VerifyDNS upgrades that response to a *models.DNSVerificationError
// (which wraps the underlying *ResponseError, so errors.As(err, &respErr) keeps
// working). Other non-2xx statuses pass through as *models.ResponseError.
func (c *Client) VerifyDNS(ctx context.Context, agentID string) (*models.AgentStatus, error) {
	if err := validateRequired("agentID", agentID); err != nil {
		return nil, err
	}
	var result models.AgentStatus
	err := c.doRequest(ctx, http.MethodPost, c.agentPath(agentID, "verify-dns"), nil, &result)
	if err != nil {
		return nil, asDNSVerificationError(err)
	}
	return &result, nil
}

// asDNSVerificationError upgrades a 422 *models.ResponseError into a
// *models.DNSVerificationError when the raw body parses cleanly. All other
// errors pass through unchanged.
func asDNSVerificationError(err error) error {
	var respErr *models.ResponseError
	if !errors.As(err, &respErr) {
		return err
	}
	if respErr.StatusCode != http.StatusUnprocessableEntity || len(respErr.RawBody) == 0 {
		return err
	}
	var dnsErr models.DNSVerificationError
	if jsonErr := json.Unmarshal(respErr.RawBody, &dnsErr); jsonErr != nil {
		return err
	}
	dnsErr.ResponseError = respErr
	return &dnsErr
}

// SearchAgents searches for agents using safe URL encoding. Pass filters via
// functional options (WithSearchName, WithSearchHost, WithSearchVersion,
// WithSearchProtocol, WithSearchStatus, WithSearchLimit, WithSearchOffset).
//
// By default the API returns only ACTIVE agents; use WithSearchStatus to
// include other lifecycle states (for example, AgentStatusPendingDNS to list
// registrations still completing DNS validation).
//
// This search surface (its filter set and response shape) only exists on
// the V1 lane, so the path is not affected by WithAPIVersion.
func (c *Client) SearchAgents(ctx context.Context, opts ...SearchOption) (*models.AgentSearchResponse, error) {
	cfg := &searchConfig{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	params := url.Values{}
	if cfg.name != "" {
		params.Set("agentDisplayName", cfg.name)
	}
	if cfg.host != "" {
		params.Set("agentHost", cfg.host)
	}
	if cfg.version != "" {
		params.Set("version", cfg.version)
	}
	if cfg.protocol != "" {
		params.Set("protocol", string(cfg.protocol))
	}
	for _, s := range cfg.statuses {
		params.Add("status", string(s))
	}
	if cfg.limit > 0 {
		params.Set("limit", strconv.Itoa(cfg.limit))
	}
	if cfg.offset > 0 {
		params.Set("offset", strconv.Itoa(cfg.offset))
	}

	path := "/v1/agents"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var result models.AgentSearchResponse
	err := c.doRequest(ctx, http.MethodGet, path, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetIdentityCertificates retrieves identity certificates for an agent
func (c *Client) GetIdentityCertificates(ctx context.Context, agentID string) ([]models.CertificateResponse, error) {
	if err := validateRequired("agentID", agentID); err != nil {
		return nil, err
	}
	var result []models.CertificateResponse
	err := c.doRequest(ctx, http.MethodGet, c.agentPath(agentID, "certificates", "identity"), nil, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetServerCertificates retrieves server certificates for an agent
func (c *Client) GetServerCertificates(ctx context.Context, agentID string) ([]models.CertificateResponse, error) {
	if err := validateRequired("agentID", agentID); err != nil {
		return nil, err
	}
	var result []models.CertificateResponse
	err := c.doRequest(ctx, http.MethodGet, c.agentPath(agentID, "certificates", "server"), nil, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// SubmitIdentityCSR submits an identity CSR for an agent
func (c *Client) SubmitIdentityCSR(ctx context.Context, agentID, csrPEM string) (*models.CsrSubmissionResponse, error) {
	if err := validateRequired("agentID", agentID); err != nil {
		return nil, err
	}
	if err := validateRequired("csrPEM", csrPEM); err != nil {
		return nil, err
	}
	req := &models.CsrSubmissionRequest{CsrPEM: csrPEM}
	var result models.CsrSubmissionResponse
	err := c.doRequest(ctx, http.MethodPost, c.agentPath(agentID, "certificates", "identity"), req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// SubmitServerCSR submits a server CSR for an agent
func (c *Client) SubmitServerCSR(ctx context.Context, agentID, csrPEM string) (*models.CsrSubmissionResponse, error) {
	if err := validateRequired("agentID", agentID); err != nil {
		return nil, err
	}
	if err := validateRequired("csrPEM", csrPEM); err != nil {
		return nil, err
	}
	req := &models.CsrSubmissionRequest{CsrPEM: csrPEM}
	var result models.CsrSubmissionResponse
	err := c.doRequest(ctx, http.MethodPost, c.agentPath(agentID, "certificates", "server"), req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetCSRStatus retrieves the status of a CSR
func (c *Client) GetCSRStatus(ctx context.Context, agentID, csrID string) (*models.CsrStatusResponse, error) {
	if err := validateRequired("agentID", agentID); err != nil {
		return nil, err
	}
	if err := validateRequired("csrID", csrID); err != nil {
		return nil, err
	}
	var result models.CsrStatusResponse
	err := c.doRequest(ctx, http.MethodGet, c.agentPath(agentID, "csrs", url.PathEscape(csrID), "status"), nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetAgentEvents retrieves paginated events using safe URL encoding.
// The events feed is a lane-neutral route served at /v1/agents/events
// regardless of WithAPIVersion.
func (c *Client) GetAgentEvents(ctx context.Context, limit int, providerID, lastLogID string) (*models.EventPageResponse, error) {
	params := url.Values{}

	if limit > 0 {
		params.Set("limit", strconv.Itoa(limit))
	}
	if providerID != "" {
		params.Set("providerId", providerID)
	}
	if lastLogID != "" {
		params.Set("lastLogId", lastLogID)
	}

	path := "/v1/agents/events"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var result models.EventPageResponse
	err := c.doRequest(ctx, http.MethodGet, path, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// ResolveAgent resolves an agent by host and version pattern
// The version parameter supports semver patterns: "*" (any), "^1.0.0" (compatible), "~1.2.3" (patch), or exact "1.0.0".
// This route only exists on the V1 surface, so the path is not affected
// by WithAPIVersion.
func (c *Client) ResolveAgent(ctx context.Context, host, version string) (*models.AgentCapabilityResponse, error) {
	if err := validateRequired("host", host); err != nil {
		return nil, err
	}
	req := &models.AgentCapabilityRequest{
		AgentHost: host,
		Version:   version,
	}
	var result models.AgentCapabilityResponse
	err := c.doRequest(ctx, http.MethodPost, "/v1/agents/resolution", req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// RevokeAgent revokes an agent registration
func (c *Client) RevokeAgent(ctx context.Context, agentID string, reason models.RevocationReason, comments string) (*models.AgentRevocationResponse, error) {
	if err := validateRequired("agentID", agentID); err != nil {
		return nil, err
	}
	req := &models.AgentRevocationRequest{
		Reason:   reason,
		Comments: comments,
	}
	var result models.AgentRevocationResponse
	err := c.doRequest(ctx, http.MethodPost, c.agentPath(agentID, "revoke"), req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
