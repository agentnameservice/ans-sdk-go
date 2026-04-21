package scitt

import (
	"encoding/base64"
	"net/http"
)

// GenerateHeaders encodes receipt and statusToken as Base64 and returns
// them as HTTP headers. Nil or empty slices are omitted from the result.
func GenerateHeaders(receipt, statusToken []byte) http.Header {
	h := http.Header{}

	if len(receipt) > 0 {
		h.Set(HeaderReceipt, base64.StdEncoding.EncodeToString(receipt)) //nolint:canonicalheader // spec-defined header names
	}

	if len(statusToken) > 0 {
		h.Set(HeaderStatusToken, base64.StdEncoding.EncodeToString(statusToken)) //nolint:canonicalheader // spec-defined header names
	}

	return h
}
