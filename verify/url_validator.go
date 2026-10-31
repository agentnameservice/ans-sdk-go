package verify

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// ErrNoTrustedDomains is returned, wrapped in a URLValidationError of type
// URLErrorUntrustedDomain, when a badge URL is validated against an empty
// trusted-domain list. The SDK ships no default trust anchors; configure the
// transparency logs you trust with WithTrustedRADomains. The public registries
// and their log hosts are listed in the ANS specification repository
// (agentnameservice/ans-spec, registries/known-registries.json).
var ErrNoTrustedDomains = errors.New("no trusted transparency log domains configured; use WithTrustedRADomains")

// URLErrorType represents the type of URL validation failure.
type URLErrorType int

const (
	// URLErrorHTTPScheme indicates the URL uses HTTP instead of HTTPS.
	URLErrorHTTPScheme URLErrorType = iota
	// URLErrorUntrustedDomain indicates the URL domain is not a trusted RA.
	URLErrorUntrustedDomain
	// URLErrorNonStandardPort indicates the URL uses a non-standard port.
	URLErrorNonStandardPort
	// URLErrorPathTraversal indicates the URL contains path traversal or query injection.
	URLErrorPathTraversal
)

// URLValidationError represents a badge URL validation failure.
type URLValidationError struct {
	Type   URLErrorType
	URL    string
	Reason string
	err    error
}

// Unwrap returns the underlying cause, when one is recorded, so callers can
// use errors.Is(err, ErrNoTrustedDomains).
func (e *URLValidationError) Unwrap() error { return e.err }

// Error implements the error interface.
func (e *URLValidationError) Error() string {
	switch e.Type {
	case URLErrorHTTPScheme:
		return fmt.Sprintf("badge URL must use HTTPS: %s", e.URL)
	case URLErrorUntrustedDomain:
		return fmt.Sprintf("badge URL domain not trusted: %s", e.URL)
	case URLErrorNonStandardPort:
		return fmt.Sprintf("badge URL uses non-standard port: %s", e.URL)
	case URLErrorPathTraversal:
		return fmt.Sprintf("badge URL contains path traversal or query params: %s", e.URL)
	default:
		return fmt.Sprintf("badge URL validation error: %s", e.URL)
	}
}

// URLValidator validates badge URLs against trusted RA domains.
type URLValidator struct {
	trustedDomains []string
}

// NewURLValidator creates a new URLValidator with the given trusted domains.
func NewURLValidator(trustedDomains []string) *URLValidator {
	lower := make([]string, len(trustedDomains))
	for i, d := range trustedDomains {
		lower[i] = strings.ToLower(d)
	}
	return &URLValidator{trustedDomains: lower}
}

// Validate checks a badge URL against security requirements:
// 1. HTTPS required
// 2. Domain must be in trusted list (case-insensitive)
// 3. No non-standard port (only 443 or empty)
// 4. No path traversal (..) or query params
func (v *URLValidator) Validate(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return &URLValidationError{
			Type:   URLErrorHTTPScheme,
			URL:    rawURL,
			Reason: err.Error(),
		}
	}

	// 1. HTTPS required
	if parsed.Scheme != "https" {
		return &URLValidationError{
			Type: URLErrorHTTPScheme,
			URL:  rawURL,
		}
	}

	// 2. Trusted domain check (case-insensitive). An empty list is a
	// configuration error, not an untrusted host, so name it.
	if len(v.trustedDomains) == 0 {
		return &URLValidationError{
			Type:   URLErrorUntrustedDomain,
			URL:    rawURL,
			Reason: ErrNoTrustedDomains.Error(),
			err:    ErrNoTrustedDomains,
		}
	}
	hostname := strings.ToLower(parsed.Hostname())
	if !v.isDomainTrusted(hostname) {
		return &URLValidationError{
			Type: URLErrorUntrustedDomain,
			URL:  rawURL,
		}
	}

	// 3. No non-standard port
	port := parsed.Port()
	if port != "" && port != "443" {
		return &URLValidationError{
			Type: URLErrorNonStandardPort,
			URL:  rawURL,
		}
	}

	// 4. No path traversal or query injection
	if strings.Contains(parsed.Path, "..") {
		return &URLValidationError{
			Type: URLErrorPathTraversal,
			URL:  rawURL,
		}
	}
	if parsed.RawQuery != "" {
		return &URLValidationError{
			Type: URLErrorPathTraversal,
			URL:  rawURL,
		}
	}

	return nil
}

// isDomainTrusted checks if the hostname matches any trusted domain.
func (v *URLValidator) isDomainTrusted(hostname string) bool {
	return slices.Contains(v.trustedDomains, hostname)
}
