package verify

import "fmt"

// DNSErrorType represents the type of DNS error.
type DNSErrorType int

const (
	// DNSErrorNotFound indicates the record does not exist (NXDOMAIN).
	DNSErrorNotFound DNSErrorType = iota
	// DNSErrorLookupFailed indicates the DNS lookup failed.
	DNSErrorLookupFailed
	// DNSErrorTimeout indicates the DNS lookup timed out.
	DNSErrorTimeout
)

// DNSError represents a DNS resolution error.
type DNSError struct {
	Type   DNSErrorType
	Fqdn   string
	Reason string
}

// Error implements the error interface.
func (e *DNSError) Error() string {
	switch e.Type {
	case DNSErrorNotFound:
		return fmt.Sprintf("DNS record not found for %s", e.Fqdn)
	case DNSErrorTimeout:
		return fmt.Sprintf("DNS timeout for %s", e.Fqdn)
	case DNSErrorLookupFailed:
		if e.Reason != "" {
			return fmt.Sprintf("DNS lookup failed for %s: %s", e.Fqdn, e.Reason)
		}
		return fmt.Sprintf("DNS lookup failed for %s", e.Fqdn)
	default:
		return fmt.Sprintf("DNS error for %s", e.Fqdn)
	}
}

// TlogErrorType represents the type of transparency log error.
type TlogErrorType int

const (
	// TlogErrorNotFound indicates the badge was not found.
	TlogErrorNotFound TlogErrorType = iota
	// TlogErrorServiceUnavailable indicates the service is unavailable.
	TlogErrorServiceUnavailable
	// TlogErrorInvalidResponse indicates an invalid response was received.
	TlogErrorInvalidResponse
)

// TlogError represents a transparency log error.
type TlogError struct {
	Type     TlogErrorType
	URL      string
	Reason   string
	HTTPCode int
}

// Error implements the error interface.
func (e *TlogError) Error() string {
	switch e.Type {
	case TlogErrorNotFound:
		return fmt.Sprintf("badge not found at %s", e.URL)
	case TlogErrorServiceUnavailable:
		return fmt.Sprintf("transparency log unavailable at %s", e.URL)
	case TlogErrorInvalidResponse:
		if e.Reason != "" {
			return fmt.Sprintf("invalid response from transparency log: %s", e.Reason)
		}
		return "invalid response from transparency log"
	default:
		return fmt.Sprintf("transparency log error for %s", e.URL)
	}
}

// DANEErrorType represents the type of DANE verification error.
type DANEErrorType int

const (
	// DANEErrorDNSSECFailed indicates DNSSEC validation failed.
	DANEErrorDNSSECFailed DANEErrorType = iota
	// DANEErrorLookupFailed indicates the TLSA DNS lookup failed.
	DANEErrorLookupFailed
)

// DANEError represents a DANE/TLSA verification error.
type DANEError struct {
	Type   DANEErrorType
	Fqdn   string
	Reason string
}

// Error implements the error interface.
func (e *DANEError) Error() string {
	switch e.Type {
	case DANEErrorDNSSECFailed:
		if e.Reason != "" {
			return fmt.Sprintf("DNSSEC validation failed for %s: %s", e.Fqdn, e.Reason)
		}
		return fmt.Sprintf("DNSSEC validation failed for %s", e.Fqdn)
	case DANEErrorLookupFailed:
		if e.Reason != "" {
			return fmt.Sprintf("DANE TLSA lookup failed for %s: %s", e.Fqdn, e.Reason)
		}
		return fmt.Sprintf("DANE TLSA lookup failed for %s", e.Fqdn)
	default:
		return fmt.Sprintf("DANE error for %s", e.Fqdn)
	}
}

// VerificationErrorType represents the type of verification error.
type VerificationErrorType int

const (
	// VerificationErrorInvalidStatus indicates the badge status is invalid.
	VerificationErrorInvalidStatus VerificationErrorType = iota
	// VerificationErrorFingerprintMismatch indicates fingerprint mismatch.
	VerificationErrorFingerprintMismatch
	// VerificationErrorHostnameMismatch indicates hostname mismatch.
	VerificationErrorHostnameMismatch
	// VerificationErrorAnsNameMismatch indicates ANS name mismatch.
	VerificationErrorAnsNameMismatch
	// VerificationErrorNoCN indicates no CN in certificate.
	// Retained for backward compatibility; the verifiers no longer produce it and report VerificationErrorNoURISAN when a certificate lacks an ANS identity.
	VerificationErrorNoCN
	// VerificationErrorNoURISAN indicates no URI SAN in certificate.
	VerificationErrorNoURISAN
)

// VerificationError represents a verification error.
type VerificationError struct {
	Type     VerificationErrorType
	Expected string
	Actual   string
	Message  string
}

// Error implements the error interface.
func (e *VerificationError) Error() string {
	switch e.Type {
	case VerificationErrorInvalidStatus:
		return fmt.Sprintf("invalid badge status: %s", e.Actual)
	case VerificationErrorFingerprintMismatch:
		return fmt.Sprintf("certificate fingerprint mismatch: expected %s, got %s", e.Expected, e.Actual)
	case VerificationErrorHostnameMismatch:
		return fmt.Sprintf("hostname mismatch: expected %s, got %s", e.Expected, e.Actual)
	case VerificationErrorAnsNameMismatch:
		return fmt.Sprintf("ANS name mismatch: expected %s, got %s", e.Expected, e.Actual)
	case VerificationErrorNoCN:
		return "no CN or DNS SAN found in certificate"
	case VerificationErrorNoURISAN:
		return "no ANS name (ans://) found in URI SANs"
	default:
		if e.Message != "" {
			return e.Message
		}
		return "verification error"
	}
}
