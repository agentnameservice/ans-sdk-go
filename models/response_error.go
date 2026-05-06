package models

import (
	"fmt"
	"net/http"
)

// ResponseError represents a structured API error response.
// Callers extract structured data with errors.As() and check StatusCode directly.
// RawBody preserves the verbatim response body so callers can re-parse non-standard
// error shapes (e.g., the verify-dns 422 payload with missingRecords/incorrectRecords).
type ResponseError struct {
	StatusCode int            // HTTP status code (e.g., 400, 404, 500)
	Code       string         // API error code (e.g., "INVALID_AGENT_HOST")
	Message    string         // Human-readable error message from server
	Details    map[string]any // Additional error details (optional)
	RawBody    []byte         // Verbatim response body, preserved for re-parsing
}

// NewResponseError creates a ResponseError for the given HTTP status code.
// If apiErr is non-nil, its Code, Message, and Details are copied.
func NewResponseError(statusCode int, apiErr *APIError) *ResponseError {
	re := &ResponseError{
		StatusCode: statusCode,
	}
	if apiErr != nil {
		re.Code = apiErr.Code
		re.Message = apiErr.Message
		re.Details = apiErr.Details
	}
	return re
}

// Error returns a human-readable error string.
func (e *ResponseError) Error() string {
	prefix := http.StatusText(e.StatusCode)
	if prefix == "" {
		prefix = fmt.Sprintf("HTTP %d", e.StatusCode)
	}
	if e.Message != "" {
		return prefix + ": " + e.Message
	}
	return prefix
}
