package scitt

import (
	"context"
	"net/http"
)

// MockClient is a mock implementation of Client for testing.
type MockClient struct {
	receipts     map[string][]byte
	statusTokens map[string][]byte
	rootKeys     []string
	errors       map[string]error
}

// NewMockClient creates a new MockClient.
func NewMockClient() *MockClient {
	return &MockClient{
		receipts:     make(map[string][]byte),
		statusTokens: make(map[string][]byte),
		errors:       make(map[string]error),
	}
}

// WithReceipt configures a receipt for the given agent ID.
func (m *MockClient) WithReceipt(agentID string, receipt []byte) *MockClient {
	m.receipts[agentID] = receipt
	return m
}

// WithStatusToken configures a status token for the given agent ID.
func (m *MockClient) WithStatusToken(agentID string, token []byte) *MockClient {
	m.statusTokens[agentID] = token
	return m
}

// WithRootKeys configures the root keys response.
func (m *MockClient) WithRootKeys(keys []string) *MockClient {
	m.rootKeys = keys
	return m
}

// WithError configures an error for the given key.
// Use agentID for receipt/token errors, "root-keys" for root key errors.
func (m *MockClient) WithError(key string, err error) *MockClient {
	m.errors[key] = err
	return m
}

// FetchReceipt returns the configured receipt or error for the given agent.
func (m *MockClient) FetchReceipt(_ context.Context, agentID string) ([]byte, error) {
	if err, ok := m.errors[agentID]; ok {
		return nil, err
	}
	if receipt, ok := m.receipts[agentID]; ok {
		return receipt, nil
	}
	return nil, &TransportError{
		Type:       TransportErrNotFound,
		StatusCode: http.StatusNotFound,
		Message:    "receipt not found for " + agentID,
	}
}

// FetchStatusToken returns the configured status token or error for the given agent.
func (m *MockClient) FetchStatusToken(_ context.Context, agentID string) ([]byte, error) {
	if err, ok := m.errors[agentID]; ok {
		return nil, err
	}
	if token, ok := m.statusTokens[agentID]; ok {
		return token, nil
	}
	return nil, &TransportError{
		Type:       TransportErrNotFound,
		StatusCode: http.StatusNotFound,
		Message:    "status token not found for " + agentID,
	}
}

// FetchRootKeys returns the configured root keys or error.
func (m *MockClient) FetchRootKeys(_ context.Context) ([]string, error) {
	if err, ok := m.errors["root-keys"]; ok {
		return nil, err
	}
	if m.rootKeys != nil {
		return m.rootKeys, nil
	}
	return nil, &TransportError{
		Type:       TransportErrNotFound,
		StatusCode: http.StatusNotFound,
		Message:    "root keys not found",
	}
}
