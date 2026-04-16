package scitt

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// makeHeaders builds an http.Header using Set() so keys are canonical.
func makeHeaders(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i < len(pairs); i += 2 {
		h.Set(pairs[i], pairs[i+1])
	}
	return h
}

func TestExtractHeaders(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		wantReceipt   []byte
		wantToken     []byte
		wantEmpty     bool
		wantHasBoth   bool
		wantErr       bool
		wantErrType   TransportErrorType
		wantErrSubstr string
	}{
		{
			name: "both headers present",
			headers: makeHeaders(
				HeaderReceipt, base64.StdEncoding.EncodeToString([]byte("receipt-data")),
				HeaderStatusToken, base64.StdEncoding.EncodeToString([]byte("token-data")),
			),
			wantReceipt: []byte("receipt-data"),
			wantToken:   []byte("token-data"),
			wantEmpty:   false,
			wantHasBoth: true,
		},
		{
			name:        "neither header present",
			headers:     http.Header{},
			wantEmpty:   true,
			wantHasBoth: false,
		},
		{
			name: "only receipt header",
			headers: makeHeaders(
				HeaderReceipt, base64.StdEncoding.EncodeToString([]byte("receipt-only")),
			),
			wantReceipt: []byte("receipt-only"),
			wantEmpty:   false,
			wantHasBoth: false,
		},
		{
			name: "only status token header",
			headers: makeHeaders(
				HeaderStatusToken, base64.StdEncoding.EncodeToString([]byte("token-only")),
			),
			wantToken:   []byte("token-only"),
			wantEmpty:   false,
			wantHasBoth: false,
		},
		{
			name: "invalid base64 in receipt",
			headers: makeHeaders(
				HeaderReceipt, "!!!not-base64!!!",
			),
			wantErr:       true,
			wantErrType:   TransportErrBase64Decode,
			wantErrSubstr: "base64 decode failed",
		},
		{
			name: "invalid base64 in status token",
			headers: makeHeaders(
				HeaderStatusToken, "???invalid???",
			),
			wantErr:       true,
			wantErrType:   TransportErrBase64Decode,
			wantErrSubstr: "base64 decode failed",
		},
		{
			name: "case-insensitive header names",
			headers: makeHeaders(
				"x-scitt-receipt", base64.StdEncoding.EncodeToString([]byte("case-test")),
				"x-ans-status-token", base64.StdEncoding.EncodeToString([]byte("case-token")),
			),
			wantReceipt: []byte("case-test"),
			wantToken:   []byte("case-token"),
			wantEmpty:   false,
			wantHasBoth: true,
		},
		{
			name: "oversized receipt header",
			headers: makeHeaders(
				HeaderReceipt, strings.Repeat("A", MaxBase64HeaderSize+1),
			),
			wantErr:       true,
			wantErrType:   TransportErrBase64Decode,
			wantErrSubstr: "exceeds size limit",
		},
		{
			name: "oversized status token header",
			headers: makeHeaders(
				HeaderStatusToken, strings.Repeat("A", MaxBase64HeaderSize+1),
			),
			wantErr:       true,
			wantErrType:   TransportErrBase64Decode,
			wantErrSubstr: "exceeds size limit",
		},
		{
			name: "valid base64 with padding",
			headers: makeHeaders(
				HeaderReceipt, base64.StdEncoding.EncodeToString([]byte("ab")),
			),
			wantReceipt: []byte("ab"),
			wantEmpty:   false,
			wantHasBoth: false,
		},
		{
			name: "round-trip encode and extract",
			headers: func() http.Header {
				data := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}
				h := http.Header{}
				h.Set(HeaderReceipt, base64.StdEncoding.EncodeToString(data))     //nolint:canonicalheader // spec-defined header names
				h.Set(HeaderStatusToken, base64.StdEncoding.EncodeToString(data)) //nolint:canonicalheader // spec-defined header names
				return h
			}(),
			wantReceipt: []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd},
			wantToken:   []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd},
			wantEmpty:   false,
			wantHasBoth: true,
		},
		{
			name: "exactly at max size limit is accepted",
			headers: makeHeaders(
				HeaderReceipt, base64.StdEncoding.EncodeToString(make([]byte, MaxCoseInputSize)),
			),
			wantReceipt: make([]byte, MaxCoseInputSize),
			wantEmpty:   false,
			wantHasBoth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExtractHeaders(tt.headers)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				var transportErr *TransportError
				if !errors.As(err, &transportErr) {
					t.Fatalf("expected TransportError, got %T: %v", err, err)
				}
				if transportErr.Type != tt.wantErrType {
					t.Errorf("error type = %v, want %v", transportErr.Type, tt.wantErrType)
				}
				if tt.wantErrSubstr != "" && !strings.Contains(transportErr.Message, tt.wantErrSubstr) {
					t.Errorf("error message %q does not contain %q", transportErr.Message, tt.wantErrSubstr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if string(result.Receipt) != string(tt.wantReceipt) {
				t.Errorf("Receipt = %v, want %v", result.Receipt, tt.wantReceipt)
			}
			if string(result.StatusToken) != string(tt.wantToken) {
				t.Errorf("StatusToken = %v, want %v", result.StatusToken, tt.wantToken)
			}
			if result.IsEmpty() != tt.wantEmpty {
				t.Errorf("IsEmpty() = %v, want %v", result.IsEmpty(), tt.wantEmpty)
			}
			if result.HasBoth() != tt.wantHasBoth {
				t.Errorf("HasBoth() = %v, want %v", result.HasBoth(), tt.wantHasBoth)
			}
		})
	}
}
