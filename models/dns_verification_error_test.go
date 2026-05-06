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

func TestDNSVerificationError_Unmarshal(t *testing.T) {
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
			name:             "only incorrectRecords populated",
			body:             `{"status":"ERROR","incorrectRecords":[{"name":"a.b","type":"TXT","value":"x"}]}`,
			wantMissingCount: 0,
			wantIncorrCount:  1,
			wantFirstName:    "a.b",
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
				records := got.MissingRecords
				if len(records) == 0 {
					records = got.IncorrectRecords
				}
				if records[0].Name != tt.wantFirstName {
					t.Errorf("first record Name = %q, want %q", records[0].Name, tt.wantFirstName)
				}
				if records[0].Type != tt.wantFirstType {
					t.Errorf("first record Type = %q, want %q", records[0].Type, tt.wantFirstType)
				}
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
				IncorrectRecords: []DNSRecord{{Name: "a"}},
			},
			wantSubstr: []string{"DNS verification failed", "1 incorrect"},
		},
		{
			name: "both",
			err: &DNSVerificationError{
				MissingRecords:   []DNSRecord{{Name: "a"}},
				IncorrectRecords: []DNSRecord{{Name: "b"}, {Name: "c"}},
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
		IncorrectRecords: []DNSRecord{},
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
