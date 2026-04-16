package scitt

import (
	"encoding/base64"
	"net/http"
)

const (
	// HeaderReceipt is the HTTP header for SCITT receipts.
	HeaderReceipt = "X-SCITT-Receipt"
	// HeaderStatusToken is the HTTP header for ANS status tokens.
	HeaderStatusToken = "X-ANS-Status-Token" //nolint:gosec // G101: not credentials, this is a header name constant

	// MaxBase64HeaderSize is the maximum allowed Base64-encoded header size.
	// Derived from MaxCoseInputSize defined in cose.go.
	MaxBase64HeaderSize = (MaxCoseInputSize + 2) / 3 * 4 //nolint:mnd // standard base64 encoding formula: ceil(n/3)*4
)

// Headers holds the decoded SCITT-related HTTP headers.
type Headers struct {
	Receipt     []byte
	StatusToken []byte
}

// ExtractHeaders decodes SCITT-related headers from an HTTP response.
// Returns an empty Headers (not an error) when neither header is present.
func ExtractHeaders(h http.Header) (*Headers, error) {
	rawReceipt := h.Get(HeaderReceipt)         //nolint:canonicalheader // spec-defined header names
	rawStatusToken := h.Get(HeaderStatusToken) //nolint:canonicalheader // spec-defined header names

	if rawReceipt == "" && rawStatusToken == "" {
		return &Headers{}, nil
	}

	var receipt, statusToken []byte
	var err error

	if rawReceipt != "" {
		receipt, err = decodeHeaderValue(rawReceipt, HeaderReceipt)
		if err != nil {
			return nil, err
		}
	}

	if rawStatusToken != "" {
		statusToken, err = decodeHeaderValue(rawStatusToken, HeaderStatusToken)
		if err != nil {
			return nil, err
		}
	}

	return &Headers{
		Receipt:     receipt,
		StatusToken: statusToken,
	}, nil
}

// IsEmpty returns true when both Receipt and StatusToken are nil or empty.
func (s *Headers) IsEmpty() bool {
	return len(s.Receipt) == 0 && len(s.StatusToken) == 0
}

// HasBoth returns true when both Receipt and StatusToken are non-nil and non-empty.
func (s *Headers) HasBoth() bool {
	return len(s.Receipt) > 0 && len(s.StatusToken) > 0
}

func decodeHeaderValue(encoded, headerName string) ([]byte, error) {
	if len(encoded) > MaxBase64HeaderSize {
		return nil, &TransportError{
			Type:    TransportErrBase64Decode,
			Message: headerName + " header exceeds size limit",
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, &TransportError{
			Type:    TransportErrBase64Decode,
			Message: headerName + " base64 decode failed",
			Cause:   err,
		}
	}

	return decoded, nil
}
