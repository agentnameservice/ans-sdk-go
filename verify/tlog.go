package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
)

// Default HTTP client configuration values.
const (
	defaultHTTPTimeoutSeconds = 30
	maxErrorResponseBodyBytes = 1024
	maxBadgeResponseBodyBytes = 1 << 20 // 1 MB
)

// TransparencyLogClient is the interface for fetching badges from the transparency log.
type TransparencyLogClient interface {
	// FetchBadge fetches a badge from the given URL.
	FetchBadge(ctx context.Context, url string) (*models.Badge, error)
}

// HTTPTransparencyLogClient is an HTTP-based implementation of TransparencyLogClient.
type HTTPTransparencyLogClient struct {
	httpClient *http.Client
}

// NewHTTPTransparencyLogClient creates a new HTTP-based transparency log client.
func NewHTTPTransparencyLogClient() *HTTPTransparencyLogClient {
	return &HTTPTransparencyLogClient{
		httpClient: &http.Client{
			Timeout: defaultHTTPTimeoutSeconds * time.Second,
		},
	}
}

// WithHTTPClient sets a custom HTTP client.
func (c *HTTPTransparencyLogClient) WithHTTPClient(client *http.Client) *HTTPTransparencyLogClient {
	c.httpClient = client
	return c
}

// WithTimeout sets the request timeout.
func (c *HTTPTransparencyLogClient) WithTimeout(timeout time.Duration) *HTTPTransparencyLogClient {
	c.httpClient.Timeout = timeout
	return c
}

// FetchBadge fetches a badge from the given URL.
func (c *HTTPTransparencyLogClient) FetchBadge(ctx context.Context, url string) (*models.Badge, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, &TlogError{
			Type:   TlogErrorInvalidResponse,
			URL:    url,
			Reason: fmt.Sprintf("failed to create request: %v", err),
		}
	}

	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req) //nolint:gosec // G704 - badge URL from ANS transparency log
	if err != nil {
		return nil, &TlogError{
			Type:   TlogErrorServiceUnavailable,
			URL:    url,
			Reason: err.Error(),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Drain response body to enable HTTP connection reuse
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, &TlogError{
			Type:     TlogErrorNotFound,
			URL:      url,
			HTTPCode: resp.StatusCode,
		}
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		// Drain response body to enable HTTP connection reuse
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, &TlogError{
			Type:     TlogErrorServiceUnavailable,
			URL:      url,
			HTTPCode: resp.StatusCode,
		}
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorResponseBodyBytes))
		// Drain remaining body to enable HTTP connection reuse
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, &TlogError{
			Type:     TlogErrorInvalidResponse,
			URL:      url,
			HTTPCode: resp.StatusCode,
			Reason:   fmt.Sprintf("unexpected status %d: %s", resp.StatusCode, string(body)),
		}
	}

	var badge models.Badge
	limitedReader := io.LimitReader(resp.Body, maxBadgeResponseBodyBytes)
	if err := json.NewDecoder(limitedReader).Decode(&badge); err != nil {
		return nil, &TlogError{
			Type:   TlogErrorInvalidResponse,
			URL:    url,
			Reason: fmt.Sprintf("failed to decode response: %v", err),
		}
	}

	return &badge, nil
}
