package models

import "fmt"

// DNSVerificationError is the typed error returned by Client.VerifyDNS when the
// API responds with HTTP 422 carrying structured missingRecords/incorrectRecords
// arrays. It wraps the underlying *ResponseError so callers that previously did
// errors.As(err, &respErr) continue to succeed.
type DNSVerificationError struct {
	// ResponseError is the underlying transport error. Always populated for errors
	// produced by the SDK; may be nil if the type is constructed in tests directly.
	*ResponseError `json:"-"`

	MissingRecords   []DNSRecord          `json:"missingRecords,omitempty"`
	IncorrectRecords []IncorrectDNSRecord `json:"incorrectRecords,omitempty"`
}

// IncorrectDNSRecord describes a DNS record that is published but whose value
// does not match what the registry expects. Returned in the incorrectRecords
// array of an HTTP 422 verify-dns response.
//
// Expected and Found are flat strings populated by the registry for display.
// Record carries the full DNS record metadata (name, type, purpose, ttl).
// All three fields are independent — do not assume Expected equals Record.Value.
type IncorrectDNSRecord struct {
	// Record is the DNS record metadata the registry expected to find.
	Record DNSRecord `json:"record"`

	// Expected is the value the registry expects.
	Expected string `json:"expected,omitempty"`

	// Found is the value actually observed in DNS at verification time.
	Found string `json:"found,omitempty"`
}

// Error returns a human-readable summary of the verification failure.
func (e *DNSVerificationError) Error() string {
	missing := len(e.MissingRecords)
	incorrect := len(e.IncorrectRecords)
	switch {
	case missing > 0 && incorrect > 0:
		return fmt.Sprintf("DNS verification failed: %d missing record(s), %d incorrect record(s)", missing, incorrect)
	case missing > 0:
		return fmt.Sprintf("DNS verification failed: %d missing record(s)", missing)
	case incorrect > 0:
		return fmt.Sprintf("DNS verification failed: %d incorrect record(s)", incorrect)
	default:
		return "DNS verification failed"
	}
}

// Unwrap exposes the embedded *ResponseError so errors.As(err, &respErr) keeps
// working for callers that haven't migrated to the typed error.
func (e *DNSVerificationError) Unwrap() error {
	if e.ResponseError == nil {
		return nil
	}
	return e.ResponseError
}
