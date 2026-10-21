package models

import (
	"fmt"
	"strings"
)

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
	var parts []string
	if n := len(e.MissingRecords); n > 0 {
		required := 0
		for _, r := range e.MissingRecords {
			if r.Required {
				required++
			}
		}
		parts = append(parts, recordCount("missing", n, required))
	}
	if n := len(e.IncorrectRecords); n > 0 {
		required := 0
		for _, r := range e.IncorrectRecords {
			if r.Record.Required {
				required++
			}
		}
		parts = append(parts, recordCount("incorrect", n, required))
	}

	const prefix = "DNS verification failed"
	if len(parts) == 0 {
		return prefix
	}
	return prefix + ": " + strings.Join(parts, ", ")
}

// Unwrap exposes the embedded *ResponseError so errors.As(err, &respErr) keeps
// working for callers that haven't migrated to the typed error.
func (e *DNSVerificationError) Unwrap() error {
	if e.ResponseError == nil {
		return nil
	}
	return e.ResponseError
}

// recordCount qualifies a category only when it mixes required and optional
// records. A category with none marked is indistinguishable from a registry
// whose wire format omits the flag, as the V1 mismatch records do, so it is
// never annotated from the other category's flags.
func recordCount(category string, total, required int) string {
	s := fmt.Sprintf("%d %s record(s)", total, category)
	if required > 0 && required < total {
		s += fmt.Sprintf(" (%d required)", required)
	}
	return s
}
