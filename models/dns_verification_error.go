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
	missingRequired, incorrectRequired := 0, 0
	for _, r := range e.MissingRecords {
		if r.Required {
			missingRequired++
		}
	}
	for _, r := range e.IncorrectRecords {
		if r.Record.Required {
			incorrectRequired++
		}
	}
	// A response that marks no record required is indistinguishable from one sent by
	// a registry that never emits the flag, so only a marked response gets qualified.
	serverDistinguishesRequired := missingRequired > 0 || incorrectRequired > 0

	var parts []string
	if n := len(e.MissingRecords); n > 0 {
		parts = append(parts, recordCount("missing", n, missingRequired, serverDistinguishesRequired))
	}
	if n := len(e.IncorrectRecords); n > 0 {
		parts = append(parts, recordCount("incorrect", n, incorrectRequired, serverDistinguishesRequired))
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

func recordCount(category string, total, required int, showRequired bool) string {
	s := fmt.Sprintf("%d %s record(s)", total, category)
	if showRequired && required < total {
		s += fmt.Sprintf(" (%d required)", required)
	}
	return s
}
