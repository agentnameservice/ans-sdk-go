package models

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestResponseError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ResponseError
		expected string
	}{
		{
			name: "with message",
			err: NewResponseError(http.StatusNotFound, &APIError{
				Code:    "NOT_FOUND",
				Message: "Agent not found",
			}),
			expected: "Not Found: Agent not found",
		},
		{
			name:     "without message (empty apiErr)",
			err:      NewResponseError(http.StatusBadRequest, &APIError{}),
			expected: "Bad Request",
		},
		{
			name:     "nil apiErr",
			err:      NewResponseError(http.StatusInternalServerError, nil),
			expected: "Internal Server Error",
		},
		{
			name:     "known but non-sentinel status code",
			err:      NewResponseError(http.StatusBadGateway, &APIError{Message: "bad gateway"}),
			expected: "Bad Gateway: bad gateway",
		},
		{
			name:     "unknown status code",
			err:      NewResponseError(999, &APIError{Message: "something broke"}),
			expected: "HTTP 999: something broke",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestResponseError_ErrorsAs(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
		wantMsg    string
	}{
		{
			name: "extracts all fields",
			err: NewResponseError(http.StatusNotFound, &APIError{
				Code:    "NOT_FOUND",
				Message: "Agent not found",
				Details: map[string]any{"agentId": "abc"},
			}),
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
			wantMsg:    "Agent not found",
		},
		{
			name:       "nil apiErr yields zero fields",
			err:        NewResponseError(http.StatusInternalServerError, nil),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "",
			wantMsg:    "",
		},
		{
			name: "wrapped in another error",
			err: fmt.Errorf("outer: %w", NewResponseError(http.StatusTooManyRequests, &APIError{
				Code:    "RATE_LIMIT",
				Message: "slow down",
			})),
			wantStatus: http.StatusTooManyRequests,
			wantCode:   "RATE_LIMIT",
			wantMsg:    "slow down",
		},
		{
			name:       "unmapped status code",
			err:        NewResponseError(http.StatusBadGateway, &APIError{Message: "bad gateway"}),
			wantStatus: http.StatusBadGateway,
			wantCode:   "",
			wantMsg:    "bad gateway",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var re *ResponseError
			if !errors.As(tt.err, &re) {
				t.Fatal("errors.As() = false, want true")
			}
			if re.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %d, want %d", re.StatusCode, tt.wantStatus)
			}
			if re.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", re.Code, tt.wantCode)
			}
			if re.Message != tt.wantMsg {
				t.Errorf("Message = %q, want %q", re.Message, tt.wantMsg)
			}
		})
	}
}

func TestResponseError_RawBody(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{name: "nil body", body: nil},
		{name: "empty body", body: []byte{}},
		{name: "json body", body: []byte(`{"status":"ERROR","missingRecords":[]}`)},
		{name: "non-utf8 body", body: []byte{0xff, 0xfe, 0xfd}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re := NewResponseError(http.StatusUnprocessableEntity, nil)
			re.RawBody = tt.body

			var got *ResponseError
			if !errors.As(re, &got) {
				t.Fatal("errors.As failed")
			}
			if string(got.RawBody) != string(tt.body) {
				t.Errorf("RawBody = %v, want %v", got.RawBody, tt.body)
			}
		})
	}
}

func TestResponseError_Details(t *testing.T) {
	details := map[string]any{
		"field":  "agentHost",
		"reason": "invalid format",
	}
	re := NewResponseError(http.StatusBadRequest, &APIError{
		Code:    "INVALID_AGENT_HOST",
		Message: "bad host",
		Details: details,
	})

	if re.Details == nil {
		t.Fatal("Details is nil")
	}
	if re.Details["field"] != "agentHost" {
		t.Errorf("Details[field] = %v, want agentHost", re.Details["field"])
	}
	if re.Details["reason"] != "invalid format" {
		t.Errorf("Details[reason] = %v, want 'invalid format'", re.Details["reason"])
	}
}
