package models

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// The exact 422 body shape from issue #14.
const dnsVerificationErrorBody = `{
  "status": "ERROR",
  "missingRecords": [
    {
      "name": "_ans.example.com",
      "type": "TXT",
      "value": "v=ans1; version=v1.0.0; p=mcp; mode=direct; url=https://example.com/invoke",
      "priority": null,
      "ttl": 3600,
      "purpose": "TRUST",
      "required": true
    },
    {
      "name": "example.com",
      "type": "HTTPS",
      "value": "1 . alpn=h2",
      "priority": 1,
      "ttl": 3600,
      "purpose": "DISCOVERY",
      "required": false
    }
  ],
  "incorrectRecords": []
}`

// realWorldMismatchBody mirrors the structure of the 2026-05-13 incident: an
// `_ans` record and an `_ans-badge` record whose values are stale (older
// version string still published in DNS). Identifiers are synthetic — no
// real customer data is committed to the public OSS repo.
const realWorldMismatchBody = `{
  "status": "ERROR",
  "missingRecords": [],
  "incorrectRecords": [
    {
      "record": {
        "name": "_ans.example.com",
        "type": "TXT",
        "value": "v=ans1; version=v0.1.36; p=mcp; mode=direct; url=https://example.com/api/mcp/v0.1.36",
        "ttl": 3600,
        "purpose": "TRUST",
        "required": true
      },
      "expected": "v=ans1; version=v0.1.36; p=mcp; mode=direct; url=https://example.com/api/mcp/v0.1.36",
      "found": "v=ans1; version=v0.1.35; p=mcp; mode=direct; url=https://example.com/api/mcp/v0.1.35"
    },
    {
      "record": {
        "name": "_ans-badge.example.com",
        "type": "TXT",
        "value": "v=ans-badge1; version=v0.1.36; url=https://transparency.example.com/v1/agents/00000000-0000-0000-0000-000000000001",
        "purpose": "BADGE"
      },
      "expected": "v=ans-badge1; version=v0.1.36; url=https://transparency.example.com/v1/agents/00000000-0000-0000-0000-000000000001",
      "found": "v=ans-badge1; version=v0.1.35; url=https://transparency.example.com/v1/agents/00000000-0000-0000-0000-000000000002"
    }
  ]
}`

func TestDNSVerificationError_Unmarshal_Missing(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		wantMissingCount int
		wantIncorrCount  int
		wantFirstName    string
		wantFirstType    string
	}{
		{
			name:             "issue #14 example body",
			body:             dnsVerificationErrorBody,
			wantMissingCount: 2,
			wantIncorrCount:  0,
			wantFirstName:    "_ans.example.com",
			wantFirstType:    "TXT",
		},
		{
			name:             "both empty",
			body:             `{"status":"ERROR","missingRecords":[],"incorrectRecords":[]}`,
			wantMissingCount: 0,
			wantIncorrCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got DNSVerificationError
			if err := json.Unmarshal([]byte(tt.body), &got); err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}
			if len(got.MissingRecords) != tt.wantMissingCount {
				t.Errorf("MissingRecords len = %d, want %d", len(got.MissingRecords), tt.wantMissingCount)
			}
			if len(got.IncorrectRecords) != tt.wantIncorrCount {
				t.Errorf("IncorrectRecords len = %d, want %d", len(got.IncorrectRecords), tt.wantIncorrCount)
			}
			if tt.wantFirstName != "" {
				if got.MissingRecords[0].Name != tt.wantFirstName {
					t.Errorf("first record Name = %q, want %q", got.MissingRecords[0].Name, tt.wantFirstName)
				}
				if got.MissingRecords[0].Type != tt.wantFirstType {
					t.Errorf("first record Type = %q, want %q", got.MissingRecords[0].Type, tt.wantFirstType)
				}
			}
		})
	}
}

func TestDNSVerificationError_Unmarshal_Incorrect(t *testing.T) {
	tests := []struct {
		name              string
		body              string
		wantIncorrCount   int
		wantFirstName     string
		wantFirstType     string
		wantFirstExpected string
		wantFirstFound    string
		wantFirstRequired bool
	}{
		{
			name: "single incorrect record",
			body: `{"status":"ERROR","incorrectRecords":[
				{"record":{"name":"a.b","type":"TXT","value":"expected-val"},
				 "expected":"expected-val","found":"actual-val"}]}`,
			wantIncorrCount:   1,
			wantFirstName:     "a.b",
			wantFirstType:     "TXT",
			wantFirstExpected: "expected-val",
			wantFirstFound:    "actual-val",
		},
		{
			name:              "real-world _ans / _ans-badge mismatch (regression for 2026-05-13 incident)",
			body:              realWorldMismatchBody,
			wantIncorrCount:   2,
			wantFirstName:     "_ans.example.com",
			wantFirstType:     "TXT",
			wantFirstExpected: "v=ans1; version=v0.1.36; p=mcp; mode=direct; url=https://example.com/api/mcp/v0.1.36",
			wantFirstFound:    "v=ans1; version=v0.1.35; p=mcp; mode=direct; url=https://example.com/api/mcp/v0.1.35",
			wantFirstRequired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got DNSVerificationError
			if err := json.Unmarshal([]byte(tt.body), &got); err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}
			if len(got.IncorrectRecords) != tt.wantIncorrCount {
				t.Fatalf("IncorrectRecords len = %d, want %d", len(got.IncorrectRecords), tt.wantIncorrCount)
			}
			first := got.IncorrectRecords[0]
			if first.Record.Name != tt.wantFirstName {
				t.Errorf("Record.Name = %q, want %q", first.Record.Name, tt.wantFirstName)
			}
			if first.Record.Type != tt.wantFirstType {
				t.Errorf("Record.Type = %q, want %q", first.Record.Type, tt.wantFirstType)
			}
			if first.Expected != tt.wantFirstExpected {
				t.Errorf("Expected = %q, want %q", first.Expected, tt.wantFirstExpected)
			}
			if first.Found != tt.wantFirstFound {
				t.Errorf("Found = %q, want %q", first.Found, tt.wantFirstFound)
			}
			if first.Record.Required != tt.wantFirstRequired {
				t.Errorf("Record.Required = %v, want %v", first.Record.Required, tt.wantFirstRequired)
			}
		})
	}
}

func TestDNSVerificationError_Error(t *testing.T) {
	tests := []struct {
		name        string
		err         *DNSVerificationError
		wantSubstr  []string
		wantNoEmpty bool
	}{
		{
			name: "missing only",
			err: &DNSVerificationError{
				MissingRecords: []DNSRecord{{Name: "a"}, {Name: "b"}},
			},
			wantSubstr: []string{"DNS verification failed", "2 missing"},
		},
		{
			name: "incorrect only",
			err: &DNSVerificationError{
				IncorrectRecords: []IncorrectDNSRecord{{Record: DNSRecord{Name: "a"}}},
			},
			wantSubstr: []string{"DNS verification failed", "1 incorrect"},
		},
		{
			name: "both",
			err: &DNSVerificationError{
				MissingRecords: []DNSRecord{{Name: "a"}},
				IncorrectRecords: []IncorrectDNSRecord{
					{Record: DNSRecord{Name: "b"}},
					{Record: DNSRecord{Name: "c"}},
				},
			},
			wantSubstr: []string{"DNS verification failed", "1 missing", "2 incorrect"},
		},
		{
			name:        "empty (degenerate)",
			err:         &DNSVerificationError{},
			wantNoEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got == "" {
				t.Fatal("Error() returned empty string")
			}
			if tt.wantNoEmpty {
				return
			}
			for _, sub := range tt.wantSubstr {
				if !strings.Contains(got, sub) {
					t.Errorf("Error() = %q, missing substring %q", got, sub)
				}
			}
		})
	}
}

func TestDNSVerificationError_Unwrap(t *testing.T) {
	tests := []struct {
		name     string
		err      *DNSVerificationError
		wantNil  bool
		wantWrap *ResponseError
	}{
		{
			name:    "nil ResponseError unwraps to nil",
			err:     &DNSVerificationError{},
			wantNil: true,
		},
		{
			name:     "non-nil ResponseError unwraps to it",
			err:      &DNSVerificationError{ResponseError: NewResponseError(http.StatusUnprocessableEntity, nil)},
			wantWrap: NewResponseError(http.StatusUnprocessableEntity, nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Unwrap()
			if tt.wantNil {
				if got != nil {
					t.Errorf("Unwrap() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("Unwrap() = nil, want non-nil")
			}
			var re *ResponseError
			if !errors.As(got, &re) {
				t.Fatal("unwrapped error is not *ResponseError")
			}
			if re.StatusCode != tt.wantWrap.StatusCode {
				t.Errorf("StatusCode = %d, want %d", re.StatusCode, tt.wantWrap.StatusCode)
			}
		})
	}
}

func TestDNSVerificationError_ErrorsAs(t *testing.T) {
	// Build the wrapped chain: a *DNSVerificationError that wraps a *ResponseError.
	wrapped := NewResponseError(http.StatusUnprocessableEntity, &APIError{Status: "ERROR"})
	wrapped.RawBody = []byte(dnsVerificationErrorBody)

	dnsErr := &DNSVerificationError{
		ResponseError:    wrapped,
		MissingRecords:   []DNSRecord{{Name: "a"}},
		IncorrectRecords: []IncorrectDNSRecord{},
	}

	var err error = dnsErr

	tests := []struct {
		name    string
		assertF func(t *testing.T, err error)
	}{
		{
			name: "extracts *DNSVerificationError",
			assertF: func(t *testing.T, err error) {
				var target *DNSVerificationError
				if !errors.As(err, &target) {
					t.Fatal("errors.As(*DNSVerificationError) = false, want true")
				}
				if len(target.MissingRecords) != 1 {
					t.Errorf("MissingRecords len = %d, want 1", len(target.MissingRecords))
				}
			},
		},
		{
			name: "extracts wrapped *ResponseError (backwards compat)",
			assertF: func(t *testing.T, err error) {
				var target *ResponseError
				if !errors.As(err, &target) {
					t.Fatal("errors.As(*ResponseError) = false, want true")
				}
				if target.StatusCode != http.StatusUnprocessableEntity {
					t.Errorf("StatusCode = %d, want 422", target.StatusCode)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertF(t, err)
		})
	}
}
