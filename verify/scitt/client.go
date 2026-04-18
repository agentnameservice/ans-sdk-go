package scitt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client defines the interface for fetching SCITT artifacts.
type Client interface {
	FetchReceipt(ctx context.Context, agentID string) ([]byte, error)
	FetchStatusToken(ctx context.Context, agentID string) ([]byte, error)
	FetchRootKeys(ctx context.Context) ([]string, error)
}

const (
	defaultTimeout   = 30 * time.Second
	maxResponseBytes = 2 << 20 // 2 MiB
)

// HTTPClient is an HTTP-based implementation of Client.
type HTTPClient struct {
	baseURL         string
	httpClient      *http.Client
	headers         http.Header
	allowInsecure   bool
	timeoutOverride *time.Duration
	explicitHTTP    *http.Client
}

// HTTPClientOption configures an HTTPClient.
type HTTPClientOption func(*HTTPClient)

// NewHTTPClient creates a new HTTPClient. baseURL must use the https scheme
// unless WithAllowInsecureTransport is supplied. Returns an error if baseURL
// is malformed or uses a non-https scheme without the insecure opt-in.
func NewHTTPClient(baseURL string, opts ...HTTPClientOption) (*HTTPClient, error) {
	c := &HTTPClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		headers: make(http.Header),
	}
	for _, opt := range opts {
		opt(c)
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid baseURL: %w", err)
	}
	if u.Scheme != "https" && !c.allowInsecure {
		return nil, fmt.Errorf("baseURL must use https scheme (got %q); use WithAllowInsecureTransport for non-https endpoints", u.Scheme)
	}

	switch {
	case c.explicitHTTP != nil:
		c.httpClient = c.explicitHTTP
		if c.httpClient.Timeout == 0 {
			c.httpClient.Timeout = defaultTimeout
		}
		if c.timeoutOverride != nil {
			c.httpClient.Timeout = *c.timeoutOverride
		}
	default:
		timeout := defaultTimeout
		if c.timeoutOverride != nil {
			timeout = *c.timeoutOverride
		}
		c.httpClient = &http.Client{Timeout: timeout}
	}

	return c, nil
}

// WithHTTPClient returns an option that supplies a custom *http.Client.
// If the client has zero Timeout, defaultTimeout (30s) is applied.
func WithHTTPClient(client *http.Client) HTTPClientOption {
	return func(c *HTTPClient) {
		c.explicitHTTP = client
	}
}

// WithTimeout returns an option that overrides the request timeout.
// Takes precedence over any timeout set on a WithHTTPClient client.
func WithTimeout(d time.Duration) HTTPClientOption {
	return func(c *HTTPClient) {
		d := d
		c.timeoutOverride = &d
	}
}

// WithAllowInsecureTransport returns an option that permits a non-https baseURL.
// Use only for tests or loopback development — production must use https.
func WithAllowInsecureTransport() HTTPClientOption {
	return func(c *HTTPClient) {
		c.allowInsecure = true
	}
}

// WithHeader returns an option that sets a single header (overwrites existing values for that name).
func WithHeader(name, value string) HTTPClientOption {
	return func(c *HTTPClient) {
		c.headers.Set(name, value)
	}
}

// WithHeaders returns an option that merges the given headers (appends values).
func WithHeaders(headers http.Header) HTTPClientOption {
	return func(c *HTTPClient) {
		for name, values := range headers {
			for _, v := range values {
				c.headers.Add(name, v)
			}
		}
	}
}

// FetchReceipt retrieves the SCITT receipt for the given agent.
func (c *HTTPClient) FetchReceipt(ctx context.Context, agentID string) ([]byte, error) {
	u := fmt.Sprintf("%s/v1/agents/%s/receipt", c.baseURL, url.PathEscape(agentID))
	return c.fetchBytes(ctx, u)
}

// FetchStatusToken retrieves the status token for the given agent.
func (c *HTTPClient) FetchStatusToken(ctx context.Context, agentID string) ([]byte, error) {
	u := fmt.Sprintf("%s/v1/agents/%s/status-token", c.baseURL, url.PathEscape(agentID))
	return c.fetchBytes(ctx, u)
}

// FetchRootKeys retrieves the SCITT root signing keys (newline-delimited C2SP key strings).
func (c *HTTPClient) FetchRootKeys(ctx context.Context) ([]string, error) {
	u := fmt.Sprintf("%s/root-keys", c.baseURL)

	body, err := c.fetchBytes(ctx, u)
	if err != nil {
		return nil, err
	}

	var keys []string
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			keys = append(keys, line)
		}
	}
	if len(keys) == 0 {
		return nil, &TransportError{
			Type:    TransportErrHTTPError,
			Message: "no valid keys found in root keys response",
		}
	}
	return keys, nil
}

func (c *HTTPClient) fetchBytes(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, &TransportError{
			Type:    TransportErrHTTPError,
			Message: "failed to create request",
			Cause:   err,
		}
	}

	for name, values := range c.headers {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}

	resp, err := c.httpClient.Do(req) //nolint:gosec // G704: URL constructed from caller-provided baseURL, not user input
	if err != nil {
		return nil, &TransportError{
			Type:    TransportErrHTTPError,
			Message: "request failed",
			Cause:   err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, mapStatusCodeToError(resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, &TransportError{
			Type:    TransportErrHTTPError,
			Message: "failed to read response body",
			Cause:   err,
		}
	}

	if int64(len(body)) > maxResponseBytes {
		return nil, &TransportError{
			Type:    TransportErrHTTPError,
			Message: fmt.Sprintf("response body exceeds maximum size (%d bytes)", maxResponseBytes),
		}
	}

	return body, nil
}

func mapStatusCodeToError(code int) *TransportError {
	switch code {
	case http.StatusNotFound:
		return &TransportError{
			Type:       TransportErrNotFound,
			StatusCode: http.StatusNotFound,
			Message:    "resource not found",
		}
	case http.StatusGone:
		return &TransportError{
			Type:       TransportErrAgentTerminal,
			StatusCode: http.StatusGone,
			Message:    "agent is in terminal state",
		}
	case http.StatusNotImplemented:
		return &TransportError{
			Type:       TransportErrNotSupported,
			StatusCode: http.StatusNotImplemented,
			Message:    "SCITT not supported",
		}
	default:
		return &TransportError{
			Type:       TransportErrHTTPError,
			StatusCode: code,
			Message:    fmt.Sprintf("unexpected status code %d", code),
		}
	}
}
