package ans

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/godaddy/ans-sdk-go/internal/httputility"
	"github.com/godaddy/ans-sdk-go/models"
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
	httpCfg := &httputility.ClientConfig{
		BaseURL:    c.config.baseURL,
		HTTPClient: c.config.httpClient,
		AuthHeader: c.config.authHeader,
	}
	return httputility.DoRequest(ctx, httpCfg, method, path, body, result)
}

// RegisterAgent registers a new agent
func (c *Client) RegisterAgent(ctx context.Context, req *models.AgentRegistrationRequest) (*models.RegistrationPending, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: request cannot be nil", models.ErrBadRequest)
	}
	var result models.RegistrationPending
	err := c.doRequest(ctx, http.MethodPost, "/v1/agents/register", req, &result)
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
	path := fmt.Sprintf("/v1/agents/%s", url.PathEscape(agentID))
	err := c.doRequest(ctx, http.MethodGet, path, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetChallengeDetails retrieves challenge details for an agent
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
	path := fmt.Sprintf("/v1/agents/%s/verify-acme", url.PathEscape(agentID))
	err := c.doRequest(ctx, http.MethodPost, path, nil, &result)
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
	path := fmt.Sprintf("/v1/agents/%s/verify-dns", url.PathEscape(agentID))
	err := c.doRequest(ctx, http.MethodPost, path, nil, &result)
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

// SearchAgents searches for agents using safe URL encoding
func (c *Client) SearchAgents(ctx context.Context, name, host, version string, limit, offset int) (*models.AgentSearchResponse, error) {
	if limit < 0 || limit > 1000 {
		return nil, fmt.Errorf("%w: limit must be between 0 and 1000", models.ErrBadRequest)
	}
	if offset < 0 {
		return nil, fmt.Errorf("%w: offset cannot be negative", models.ErrBadRequest)
	}
	params := url.Values{}

	if name != "" {
		params.Set("agentDisplayName", name)
	}
	if host != "" {
		params.Set("agentHost", host)
	}
	if version != "" {
		params.Set("version", version)
	}
	if limit > 0 {
		params.Set("limit", strconv.Itoa(limit))
	}
	if offset > 0 {
		params.Set("offset", strconv.Itoa(offset))
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
	path := fmt.Sprintf("/v1/agents/%s/certificates/identity", url.PathEscape(agentID))
	err := c.doRequest(ctx, http.MethodGet, path, nil, &result)
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
	path := fmt.Sprintf("/v1/agents/%s/certificates/server", url.PathEscape(agentID))
	err := c.doRequest(ctx, http.MethodGet, path, nil, &result)
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
	path := fmt.Sprintf("/v1/agents/%s/certificates/identity", url.PathEscape(agentID))
	err := c.doRequest(ctx, http.MethodPost, path, req, &result)
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
	path := fmt.Sprintf("/v1/agents/%s/certificates/server", url.PathEscape(agentID))
	err := c.doRequest(ctx, http.MethodPost, path, req, &result)
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
	path := fmt.Sprintf("/v1/agents/%s/csrs/%s/status", url.PathEscape(agentID), url.PathEscape(csrID))
	err := c.doRequest(ctx, http.MethodGet, path, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetAgentEvents retrieves paginated events using safe URL encoding
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
// The version parameter supports semver patterns: "*" (any), "^1.0.0" (compatible), "~1.2.3" (patch), or exact "1.0.0"
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
	path := fmt.Sprintf("/v1/agents/%s/revoke", url.PathEscape(agentID))
	err := c.doRequest(ctx, http.MethodPost, path, req, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
