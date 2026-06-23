package ans

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify"
)

// AgentClient is an HTTP client that verifies ANS agent certificates before requests.
// It wraps a standard HTTP client and adds badge verification for secure agent-to-agent communication.
type AgentClient struct {
	httpClient *http.Client
	verifier   *verify.AnsVerifier
	config     *agentClientConfig
}

// agentClientConfig holds the configuration for the agent client.
type agentClientConfig struct {
	timeout         time.Duration
	verifyServer    bool
	tlsConfig       *tls.Config
	failurePolicy   verify.FailurePolicy
	verifierOptions []verify.Option
}

// AgentClientOption configures an AgentClient.
type AgentClientOption func(*agentClientConfig)

// Default agent client timeout.
const defaultAgentClientTimeout = 30 * time.Second

// defaultAgentClientConfig returns the default agent client configuration.
func defaultAgentClientConfig() *agentClientConfig {
	return &agentClientConfig{
		timeout:       defaultAgentClientTimeout,
		verifyServer:  true,
		failurePolicy: verify.FailClosed,
	}
}

// WithAgentClientTimeout sets the HTTP client timeout.
func WithAgentClientTimeout(d time.Duration) AgentClientOption {
	return func(c *agentClientConfig) {
		c.timeout = d
	}
}

// WithAgentClientTLS sets a custom TLS configuration.
func WithAgentClientTLS(cfg *tls.Config) AgentClientOption {
	return func(c *agentClientConfig) {
		c.tlsConfig = cfg
	}
}

// WithAgentClientVerifyServer enables or disables server certificate verification.
func WithAgentClientVerifyServer(verify bool) AgentClientOption {
	return func(c *agentClientConfig) {
		c.verifyServer = verify
	}
}

// WithAgentClientFailurePolicy sets the failure policy for verification failures.
func WithAgentClientFailurePolicy(p verify.FailurePolicy) AgentClientOption {
	return func(c *agentClientConfig) {
		c.failurePolicy = p
	}
}

// WithAgentClientVerifierOptions sets custom options for the verifier.
func WithAgentClientVerifierOptions(opts ...verify.Option) AgentClientOption {
	return func(c *agentClientConfig) {
		c.verifierOptions = opts
	}
}

// NewAgentClient creates a new agent-to-agent HTTP client.
func NewAgentClient(opts ...AgentClientOption) *AgentClient {
	cfg := defaultAgentClientConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	// Build verifier options
	verifierOpts := cfg.verifierOptions

	// Clone http.DefaultTransport to preserve defaults (proxy, connection pooling, etc.)
	// and only override TLS config if provided
	var transport *http.Transport
	if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = defaultTransport.Clone()
	} else {
		transport = &http.Transport{}
	}
	if cfg.tlsConfig != nil {
		transport.TLSClientConfig = cfg.tlsConfig
	}

	return &AgentClient{
		httpClient: &http.Client{
			Timeout:   cfg.timeout,
			Transport: transport,
		},
		verifier: verify.NewAnsVerifier(verifierOpts...),
		config:   cfg,
	}
}

// Response wraps an HTTP response with additional verification information.
type Response struct {
	*http.Response
	VerificationOutcome *verify.VerificationOutcome
}

// Get performs a GET request to the specified URL with badge verification.
func (c *AgentClient) Get(ctx context.Context, urlStr string) (*Response, error) {
	return c.Do(ctx, http.MethodGet, urlStr, nil)
}

// Post performs a POST request to the specified URL with badge verification.
func (c *AgentClient) Post(ctx context.Context, urlStr string, body any) (*Response, error) {
	return c.Do(ctx, http.MethodPost, urlStr, body)
}

// Put performs a PUT request to the specified URL with badge verification.
func (c *AgentClient) Put(ctx context.Context, urlStr string, body any) (*Response, error) {
	return c.Do(ctx, http.MethodPut, urlStr, body)
}

// Delete performs a DELETE request to the specified URL with badge verification.
func (c *AgentClient) Delete(ctx context.Context, urlStr string) (*Response, error) {
	return c.Do(ctx, http.MethodDelete, urlStr, nil)
}

// Do performs an HTTP request with badge verification.
func (c *AgentClient) Do(ctx context.Context, method, urlStr string, body any) (*Response, error) {
	// Parse and validate URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	host := parsedURL.Hostname()
	if host == "" {
		return nil, fmt.Errorf("invalid URL: missing hostname: %s", urlStr)
	}

	if c.config.verifyServer && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("server verification requires HTTPS, got scheme %q for %s", parsedURL.Scheme, urlStr)
	}

	// Verify server badge before making request (if enabled)
	if err := c.prefetchBadge(ctx, host); err != nil {
		return nil, err
	}

	// Build and execute request
	resp, err := c.executeRequest(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}

	// Verify TLS certificate
	outcome, err := c.verifyTLSCert(ctx, host, resp)
	if err != nil {
		return nil, err
	}

	return &Response{
		Response:            resp,
		VerificationOutcome: outcome,
	}, nil
}

// prefetchBadge pre-fetches the badge if server verification is enabled.
// On error:
//   - FailClosed: returns error immediately
//   - FailOpenWithCache: continues — the verifier checks stale cache during VerifyServer
//   - FailOpen: continues without verification (not recommended)
func (c *AgentClient) prefetchBadge(ctx context.Context, host string) error {
	if !c.config.verifyServer {
		return nil
	}

	_, err := c.verifier.Prefetch(ctx, host)
	if err != nil {
		switch c.config.failurePolicy {
		case verify.FailClosed:
			return fmt.Errorf("badge verification failed for %s: %w", host, err)
		case verify.FailOpenWithCache, verify.FailOpen:
			// FailOpenWithCache: the verifier's VerifyServer will check stale cache internally
			// FailOpen: continue without verification (not recommended for production)
			return nil
		}
	}
	return nil
}

// executeRequest builds and executes the HTTP request.
func (c *AgentClient) executeRequest(ctx context.Context, method, urlStr string, body any) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBytes, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", marshalErr)
		}
		bodyReader = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, urlStr, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req) //nolint:gosec // G704 - URL parsed and validated above (lines 145-157)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// verifyTLSCert verifies the TLS certificate if server verification is enabled.
// Returns nil outcome if verification is disabled.
// On verification failure:
//   - FailClosed: returns error
//   - FailOpenWithCache: returns error (cache fallback handled by verifier)
//   - FailOpen: returns outcome without error (not recommended)
func (c *AgentClient) verifyTLSCert(ctx context.Context, host string, resp *http.Response) (*verify.VerificationOutcome, error) {
	if !c.config.verifyServer {
		return nil, nil //nolint:nilnil // nil outcome indicates verification is disabled
	}

	// When verification is enabled, missing TLS or peer certs is a failure
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		switch c.config.failurePolicy {
		case verify.FailClosed, verify.FailOpenWithCache:
			_ = resp.Body.Close()
			return nil, fmt.Errorf("certificate verification failed for %s: no TLS peer certificates", host)
		case verify.FailOpen:
			return nil, nil //nolint:nilnil // fail-open: proceed without verification
		}
	}

	certIdentity := verify.CertIdentityFromX509(resp.TLS.PeerCertificates[0])
	outcome := c.verifier.VerifyServer(ctx, host, certIdentity)

	if !outcome.IsSuccess() {
		switch c.config.failurePolicy {
		case verify.FailClosed, verify.FailOpenWithCache:
			_ = resp.Body.Close()
			if verifyErr := outcome.ToError(); verifyErr != nil {
				return nil, fmt.Errorf("certificate verification failed for %s: %w", host, verifyErr)
			}
			return nil, fmt.Errorf("certificate verification failed for %s", host)
		case verify.FailOpen:
			// Return outcome but don't fail (not recommended for production)
			return outcome, nil
		}
	}

	return outcome, nil
}

// GetJSON performs a GET request and unmarshals the JSON response.
func (c *AgentClient) GetJSON(ctx context.Context, urlStr string, result any) (*Response, error) {
	resp, err := c.Get(ctx, urlStr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return resp, nil
}

// PostJSON performs a POST request with JSON body and unmarshals the JSON response.
func (c *AgentClient) PostJSON(ctx context.Context, urlStr string, body any, result any) (*Response, error) {
	resp, err := c.Post(ctx, urlStr, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return resp, nil
}

// PutJSON performs a PUT request with JSON body and unmarshals the JSON response.
func (c *AgentClient) PutJSON(ctx context.Context, urlStr string, body any, result any) (*Response, error) {
	resp, err := c.Put(ctx, urlStr, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return resp, nil
}

// Prefetch preemptively fetches and caches the badge for a host.
// This is useful for warming the cache before making requests.
func (c *AgentClient) Prefetch(ctx context.Context, host string) error {
	if err := validateRequired("host", host); err != nil {
		return err
	}
	_, err := c.verifier.Prefetch(ctx, host)
	return err
}
