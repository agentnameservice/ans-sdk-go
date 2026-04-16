package scitt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	baseURL    string
	httpClient *http.Client
}

// NewHTTPClient creates a new HTTPClient with default settings.
func NewHTTPClient(baseURL string) *HTTPClient {
	return &HTTPClient{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}
}

// NewHTTPClientWithHTTPClient creates a new HTTPClient with a custom http.Client.
func NewHTTPClientWithHTTPClient(baseURL string, client *http.Client) *HTTPClient {
	return &HTTPClient{
		baseURL:    baseURL,
		httpClient: client,
	}
}

// FetchReceipt retrieves the SCITT receipt for the given agent.
func (c *HTTPClient) FetchReceipt(ctx context.Context, agentID string) ([]byte, error) {
	u := fmt.Sprintf("%s/v1/receipts/%s", c.baseURL, url.PathEscape(agentID))
	return c.fetchBytes(ctx, u)
}

// FetchStatusToken retrieves the status token for the given agent.
func (c *HTTPClient) FetchStatusToken(ctx context.Context, agentID string) ([]byte, error) {
	u := fmt.Sprintf("%s/v1/status/%s", c.baseURL, url.PathEscape(agentID))
	return c.fetchBytes(ctx, u)
}

// FetchRootKeys retrieves the SCITT root signing keys.
func (c *HTTPClient) FetchRootKeys(ctx context.Context) ([]string, error) {
	u := fmt.Sprintf("%s/v1/root-keys", c.baseURL)

	body, err := c.fetchBytes(ctx, u)
	if err != nil {
		return nil, err
	}

	var keys []string
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, &TransportError{
			Type:    TransportErrHTTPError,
			Message: "failed to decode root keys response",
			Cause:   err,
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
