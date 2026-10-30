package verify

import (
	"context"

	"github.com/agentnameservice/ans-sdk-go/models"
)

// MockTransparencyLogClient is a mock implementation of TransparencyLogClient for testing.
type MockTransparencyLogClient struct {
	badges map[string]*models.Badge
	errors map[string]error
}

// NewMockTransparencyLogClient creates a new mock transparency log client.
func NewMockTransparencyLogClient() *MockTransparencyLogClient {
	return &MockTransparencyLogClient{
		badges: make(map[string]*models.Badge),
		errors: make(map[string]error),
	}
}

// WithBadge adds a badge for a URL.
func (c *MockTransparencyLogClient) WithBadge(url string, badge *models.Badge) *MockTransparencyLogClient {
	c.badges[url] = badge
	return c
}

// WithError configures an error for a URL.
func (c *MockTransparencyLogClient) WithError(url string, err error) *MockTransparencyLogClient {
	c.errors[url] = err
	return c
}

// FetchBadge fetches a badge from the given URL.
func (c *MockTransparencyLogClient) FetchBadge(_ context.Context, url string) (*models.Badge, error) {
	// Check for configured error first
	if err, ok := c.errors[url]; ok {
		return nil, err
	}

	// Return configured badge or NotFound
	if badge, ok := c.badges[url]; ok {
		return badge, nil
	}

	return nil, &TlogError{
		Type: TlogErrorNotFound,
		URL:  url,
	}
}
