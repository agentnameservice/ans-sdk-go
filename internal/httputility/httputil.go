// Package httputility provides HTTP client utilities for the ANS SDK.
package httputility

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/agentnameservice/ans-sdk-go/models"
)

const (
	// maxResponseBodyBytes limits response body reads to prevent memory exhaustion (10MB)
	maxResponseBodyBytes = 10 << 20
)

// ClientConfig holds HTTP client configuration
type ClientConfig struct {
	BaseURL    string
	HTTPClient *http.Client
	AuthHeader string
}

// DoRequest performs an HTTP request with context
func DoRequest(ctx context.Context, cfg *ClientConfig, method, path string, body any, result any) error {
	reqBody, err := prepareRequestBody(body)
	if err != nil {
		return err
	}

	reqURL := cfg.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	setRequestHeaders(req, cfg.AuthHeader)

	resp, err := cfg.HTTPClient.Do(req) //nolint:gosec // G704 - internal utility, URL from trusted client config
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for client/server errors (status >= 400)
	if resp.StatusCode >= http.StatusBadRequest {
		return HandleErrorResponse(resp.StatusCode, respBody)
	}

	return parseSuccessResponse(respBody, result)
}

// prepareRequestBody marshals the request body to JSON
func prepareRequestBody(body any) (io.Reader, error) {
	if body == nil {
		return http.NoBody, nil
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	return bytes.NewBuffer(jsonData), nil
}

// setRequestHeaders sets common HTTP headers on the request
func setRequestHeaders(req *http.Request, authHeader string) {
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
}

// HandleErrorResponse processes error responses from the API.
// It returns a *models.ResponseError for the given status code, with the verbatim
// response body preserved on the RawBody field so callers can re-parse non-standard
// error shapes (e.g., verify-dns 422 with missingRecords/incorrectRecords).
func HandleErrorResponse(statusCode int, respBody []byte) error {
	var apiErr models.APIError
	var re *models.ResponseError
	if err := json.Unmarshal(respBody, &apiErr); err != nil {
		// Non-JSON error body — preserve raw body as message
		re = models.NewResponseError(statusCode, &models.APIError{
			Message: string(respBody),
		})
	} else {
		re = models.NewResponseError(statusCode, &apiErr)
	}
	re.RawBody = respBody
	return re
}

// parseSuccessResponse unmarshals a successful response
func parseSuccessResponse(respBody []byte, result any) error {
	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}
	return nil
}
