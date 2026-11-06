package verify

import (
	"strings"
	"testing"
)

func TestDNSError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *DNSError
		contains string
	}{
		{
			name:     "not found",
			err:      &DNSError{Type: DNSErrorNotFound, Fqdn: "test.example.com"},
			contains: "DNS record not found for test.example.com",
		},
		{
			name:     "timeout",
			err:      &DNSError{Type: DNSErrorTimeout, Fqdn: "test.example.com"},
			contains: "DNS timeout for test.example.com",
		},
		{
			name:     "lookup failed with reason",
			err:      &DNSError{Type: DNSErrorLookupFailed, Fqdn: "test.example.com", Reason: "network error"},
			contains: "DNS lookup failed for test.example.com: network error",
		},
		{
			name:     "lookup failed without reason",
			err:      &DNSError{Type: DNSErrorLookupFailed, Fqdn: "test.example.com"},
			contains: "DNS lookup failed for test.example.com",
		},
		{
			name:     "unknown type",
			err:      &DNSError{Type: DNSErrorType(99), Fqdn: "test.example.com"},
			contains: "DNS error for test.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if !strings.Contains(got, tt.contains) {
				t.Errorf("Error() = %q, want containing %q", got, tt.contains)
			}
		})
	}
}

func TestTlogError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *TlogError
		contains string
	}{
		{
			name:     "not found",
			err:      &TlogError{Type: TlogErrorNotFound, URL: "https://tlog.example.com/badge/123"},
			contains: "badge not found",
		},
		{
			name:     "service unavailable",
			err:      &TlogError{Type: TlogErrorServiceUnavailable, URL: "https://tlog.example.com"},
			contains: "transparency log unavailable",
		},
		{
			name:     "invalid response with reason",
			err:      &TlogError{Type: TlogErrorInvalidResponse, Reason: "bad JSON"},
			contains: "invalid response from transparency log: bad JSON",
		},
		{
			name:     "invalid response without reason",
			err:      &TlogError{Type: TlogErrorInvalidResponse},
			contains: "invalid response from transparency log",
		},
		{
			name:     "unknown type",
			err:      &TlogError{Type: TlogErrorType(99), URL: "https://tlog.example.com"},
			contains: "transparency log error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if !strings.Contains(got, tt.contains) {
				t.Errorf("Error() = %q, want containing %q", got, tt.contains)
			}
		})
	}
}

func TestDANEError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *DANEError
		contains string
	}{
		{
			name:     "DNSSEC failed with reason",
			err:      &DANEError{Type: DANEErrorDNSSECFailed, Fqdn: "test.example.com", Reason: "expired signature"},
			contains: "DNSSEC validation failed for test.example.com: expired signature",
		},
		{
			name:     "DNSSEC failed without reason",
			err:      &DANEError{Type: DANEErrorDNSSECFailed, Fqdn: "test.example.com"},
			contains: "DNSSEC validation failed for test.example.com",
		},
		{
			name:     "lookup failed with reason",
			err:      &DANEError{Type: DANEErrorLookupFailed, Fqdn: "test.example.com", Reason: "timeout"},
			contains: "DANE TLSA lookup failed for test.example.com: timeout",
		},
		{
			name:     "lookup failed without reason",
			err:      &DANEError{Type: DANEErrorLookupFailed, Fqdn: "test.example.com"},
			contains: "DANE TLSA lookup failed for test.example.com",
		},
		{
			name:     "unknown type",
			err:      &DANEError{Type: DANEErrorType(99), Fqdn: "test.example.com"},
			contains: "DANE error for test.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if !strings.Contains(got, tt.contains) {
				t.Errorf("Error() = %q, want containing %q", got, tt.contains)
			}
		})
	}
}

func TestVerificationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *VerificationError
		contains string
	}{
		{
			name:     "invalid status",
			err:      &VerificationError{Type: VerificationErrorInvalidStatus, Actual: "REVOKED"},
			contains: "invalid badge status: REVOKED",
		},
		{
			name:     "fingerprint mismatch",
			err:      &VerificationError{Type: VerificationErrorFingerprintMismatch, Expected: "SHA256:abc", Actual: "SHA256:def"},
			contains: "certificate fingerprint mismatch",
		},
		{
			name:     "hostname mismatch",
			err:      &VerificationError{Type: VerificationErrorHostnameMismatch, Expected: "foo.com", Actual: "bar.com"},
			contains: "hostname mismatch",
		},
		{
			name:     "ANS name mismatch",
			err:      &VerificationError{Type: VerificationErrorAnsNameMismatch, Expected: "ans://v1.0.0.foo.com", Actual: "ans://v2.0.0.foo.com"},
			contains: "ANS name mismatch",
		},
		{
			name:     "no CN",
			err:      &VerificationError{Type: VerificationErrorNoCN},
			contains: "no CN or DNS SAN",
		},
		{
			name:     "no URI SAN",
			err:      &VerificationError{Type: VerificationErrorNoURISAN},
			contains: "no ANS name",
		},
		{
			name:     "identity DNS mismatch",
			err:      &VerificationError{Type: VerificationErrorIdentityDNSMismatch, Expected: "agent.example.com", Actual: "other.example.com"},
			contains: "identity certificate name mismatch",
		},
		{
			name:     "unknown type with message",
			err:      &VerificationError{Type: VerificationErrorType(99), Message: "custom error"},
			contains: "custom error",
		},
		{
			name:     "unknown type without message",
			err:      &VerificationError{Type: VerificationErrorType(99)},
			contains: "verification error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if !strings.Contains(got, tt.contains) {
				t.Errorf("Error() = %q, want containing %q", got, tt.contains)
			}
		})
	}
}
