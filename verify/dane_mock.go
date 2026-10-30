package verify

import (
	"context"
	"fmt"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/models"
)

// MockDANEResolver is a mock DANE resolver for testing.
type MockDANEResolver struct {
	results map[string]TLSALookupResult
	errors  map[string]error
}

// NewMockDANEResolver creates a new MockDANEResolver.
func NewMockDANEResolver() *MockDANEResolver {
	return &MockDANEResolver{
		results: make(map[string]TLSALookupResult),
		errors:  make(map[string]error),
	}
}

// daneKey generates a map key for the given FQDN and port.
func daneKey(fqdn string, port uint16) string {
	return fmt.Sprintf("_%d._tcp.%s", port, strings.ToLower(fqdn))
}

// WithTLSA configures a TLSA lookup result for the given FQDN and port.
func (r *MockDANEResolver) WithTLSA(fqdn string, port uint16, result TLSALookupResult) *MockDANEResolver {
	r.results[daneKey(fqdn, port)] = result
	return r
}

// WithError configures an error for the given FQDN and port.
func (r *MockDANEResolver) WithError(fqdn string, port uint16, err error) *MockDANEResolver {
	r.errors[daneKey(fqdn, port)] = err
	return r
}

// LookupTLSA returns the configured TLSA result or error for the given FQDN and port.
func (r *MockDANEResolver) LookupTLSA(_ context.Context, fqdn models.Fqdn, port uint16) (TLSALookupResult, error) {
	key := daneKey(fqdn.String(), port)

	if err, ok := r.errors[key]; ok {
		return TLSALookupResult{}, err
	}

	if result, ok := r.results[key]; ok {
		return result, nil
	}

	return TLSALookupResult{Found: false}, nil
}
