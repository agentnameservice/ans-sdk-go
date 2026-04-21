package scitt

import (
	"encoding/base64"
	"net/http"
	"testing"
)

func TestGenerateHeaders(t *testing.T) {
	tests := []struct {
		name        string
		receipt     []byte
		statusToken []byte
		wantReceipt string // expected base64 value, empty means header absent
		wantToken   string // expected base64 value, empty means header absent
	}{
		{
			name:        "both present",
			receipt:     []byte("receipt-data"),
			statusToken: []byte("token-data"),
			wantReceipt: base64.StdEncoding.EncodeToString([]byte("receipt-data")),
			wantToken:   base64.StdEncoding.EncodeToString([]byte("token-data")),
		},
		{
			name:        "nil receipt",
			receipt:     nil,
			statusToken: []byte("token-only"),
			wantReceipt: "",
			wantToken:   base64.StdEncoding.EncodeToString([]byte("token-only")),
		},
		{
			name:        "nil status token",
			receipt:     []byte("receipt-only"),
			statusToken: nil,
			wantReceipt: base64.StdEncoding.EncodeToString([]byte("receipt-only")),
			wantToken:   "",
		},
		{
			name:        "both nil",
			receipt:     nil,
			statusToken: nil,
			wantReceipt: "",
			wantToken:   "",
		},
		{
			name:        "empty receipt slice",
			receipt:     []byte{},
			statusToken: []byte("token"),
			wantReceipt: "",
			wantToken:   base64.StdEncoding.EncodeToString([]byte("token")),
		},
		{
			name:        "empty status token slice",
			receipt:     []byte("receipt"),
			statusToken: []byte{},
			wantReceipt: base64.StdEncoding.EncodeToString([]byte("receipt")),
			wantToken:   "",
		},
		{
			name:        "binary data",
			receipt:     []byte{0x00, 0x01, 0xFF, 0xFE},
			statusToken: []byte{0xDE, 0xAD, 0xBE, 0xEF},
			wantReceipt: base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0xFF, 0xFE}),
			wantToken:   base64.StdEncoding.EncodeToString([]byte{0xDE, 0xAD, 0xBE, 0xEF}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := GenerateHeaders(tt.receipt, tt.statusToken)

			gotReceipt := h.Get(HeaderReceipt)   //nolint:canonicalheader // spec-defined header names
			gotToken := h.Get(HeaderStatusToken) //nolint:canonicalheader // spec-defined header names

			if gotReceipt != tt.wantReceipt {
				t.Errorf("receipt header = %q, want %q", gotReceipt, tt.wantReceipt)
			}
			if gotToken != tt.wantToken {
				t.Errorf("token header = %q, want %q", gotToken, tt.wantToken)
			}

			// Verify absent headers are truly absent (not set to empty string)
			if tt.wantReceipt == "" {
				if _, ok := h[http.CanonicalHeaderKey(HeaderReceipt)]; ok {
					t.Error("receipt header should be absent, not empty")
				}
			}
			if tt.wantToken == "" {
				if _, ok := h[http.CanonicalHeaderKey(HeaderStatusToken)]; ok {
					t.Error("token header should be absent, not empty")
				}
			}
		})
	}
}

func TestGenerateHeadersRoundTrip(t *testing.T) {
	receipt := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
	token := []byte("status-token-payload")

	generated := GenerateHeaders(receipt, token)
	extracted, err := ExtractHeaders(generated)
	if err != nil {
		t.Fatalf("ExtractHeaders failed: %v", err)
	}

	if string(extracted.Receipt) != string(receipt) {
		t.Errorf("round-trip receipt = %x, want %x", extracted.Receipt, receipt)
	}
	if string(extracted.StatusToken) != string(token) {
		t.Errorf("round-trip token = %q, want %q", extracted.StatusToken, token)
	}
	if !extracted.HasBoth() {
		t.Error("expected HasBoth() true after round-trip")
	}
}
