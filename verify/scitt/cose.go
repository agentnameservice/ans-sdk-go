package scitt

import (
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// MaxCoseInputSize is the maximum allowed size for COSE_Sign1 input (1 MiB).
const MaxCoseInputSize = 1 << 20

// coseAlgES256 is the COSE algorithm identifier for ECDSA w/ SHA-256 (P-256).
const coseAlgES256 int64 = -7

// p1363SignatureLen is the expected signature length for P-256 in IEEE P1363 format.
const p1363SignatureLen = 64

// COSE_Sign1 structure constants.
const (
	coseSign1ArrayLen     = 4    // number of elements in a COSE_Sign1 array
	kidLen                = 4    // key ID length in bytes
	cborMaxNestedLevels   = 16   // max CBOR nesting depth
	cborMaxArrayElements  = 1024 // max CBOR array elements
	cborMaxMapPairs       = 256  // max CBOR map pairs
	coseHeaderAlg         = 1    // COSE header key: algorithm
	coseHeaderContentType = 3    // COSE header key: content type
	coseHeaderKid         = 4    // COSE header key: key ID
	coseHeaderCWTClaims   = 15   // COSE header key: CWT claims
	coseHeaderVDS         = 395  // COSE header key: verifiable data structure
	cwtClaimIss           = 1    // CWT claim key: issuer
	cwtClaimIat           = 6    // CWT claim key: issued-at
)

// ParsedCoseSign1 holds the decoded fields of a COSE_Sign1 structure.
type ParsedCoseSign1 struct {
	ProtectedBytes []byte // verbatim, never re-encoded
	Protected      ProtectedHeader
	Unprotected    cbor.RawMessage
	Payload        []byte
	Signature      []byte // exactly 64 bytes P1363
}

// ProtectedHeader holds the decoded COSE protected header fields.
type ProtectedHeader struct {
	Alg         int64
	Kid         [4]byte
	Vds         *int64
	ContentType *string
	CwtIss      *string
	CwtIat      *int64
}

// newDecMode creates a safe CBOR decode mode with restricted limits.
func newDecMode() (cbor.DecMode, error) {
	opts := cbor.DecOptions{
		MaxNestedLevels:  cborMaxNestedLevels,
		MaxArrayElements: cborMaxArrayElements,
		MaxMapPairs:      cborMaxMapPairs,
	}
	return opts.DecMode()
}

// ParseCoseSign1 parses a CBOR-encoded COSE_Sign1 structure.
//
// This is a hand-rolled parser rather than using veraison/go-cose because:
//   - go-cose does not expose custom CBOR decode options (MaxNestedLevels,
//     MaxArrayElements, MaxMapPairs) needed for DoS protection on untrusted input.
//   - Custom header fields (vds=395, CWT claims) require manual parsing of
//     RawProtected regardless, negating most of go-cose's value.
//   - Verbatim ProtectedBytes must be preserved without re-encoding for correct
//     ECDSA signature verification over the exact signed bytes.
func ParseCoseSign1(data []byte) (*ParsedCoseSign1, error) {
	if len(data) > MaxCoseInputSize {
		return nil, &CoseError{
			Type:    CoseErrOversizedInput,
			Message: fmt.Sprintf("input size %d exceeds maximum %d", len(data), MaxCoseInputSize),
		}
	}

	dm, err := newDecMode()
	if err != nil {
		return nil, &CoseError{
			Type:    CoseErrCborDecode,
			Message: "failed to create CBOR decode mode",
			Cause:   err,
		}
	}

	// First decode into RawMessage to handle both tagged (Tag 18) and untagged input.
	var rawOuter cbor.RawMessage
	if err := dm.Unmarshal(data, &rawOuter); err != nil {
		return nil, &CoseError{
			Type:    CoseErrCborDecode,
			Message: "failed to decode CBOR input",
			Cause:   err,
		}
	}

	// Try to unwrap Tag 18 if present.
	arrayBytes := unwrapTag18(rawOuter)

	// Decode the array elements.
	var elements []cbor.RawMessage
	if err := dm.Unmarshal(arrayBytes, &elements); err != nil {
		return nil, &CoseError{
			Type:    CoseErrNotACoseSign1,
			Message: "failed to decode COSE_Sign1 array",
			Cause:   err,
		}
	}

	if len(elements) != coseSign1ArrayLen {
		return nil, &CoseError{
			Type:    CoseErrInvalidArrayLength,
			Message: fmt.Sprintf("expected %d elements, got %d", coseSign1ArrayLen, len(elements)),
		}
	}

	// Element 0: protected header bytes (bstr).
	var protectedBytes []byte
	if err := dm.Unmarshal(elements[0], &protectedBytes); err != nil {
		return nil, &CoseError{
			Type:    CoseErrInvalidProtectedHeader,
			Message: "failed to decode protected header bytes",
			Cause:   err,
		}
	}

	// Parse the protected header map.
	header, err := parseProtectedHeader(dm, protectedBytes)
	if err != nil {
		return nil, err
	}

	// Element 1: unprotected header (keep as raw).
	unprotected := elements[1]

	// Element 2: payload (bstr, must not be nil/empty).
	var payload []byte
	if err := dm.Unmarshal(elements[2], &payload); err != nil {
		return nil, &CoseError{
			Type:    CoseErrNotACoseSign1,
			Message: "failed to decode payload",
			Cause:   err,
		}
	}
	if len(payload) == 0 {
		return nil, &CoseError{
			Type:    CoseErrNotACoseSign1,
			Message: "payload must not be nil or empty",
		}
	}

	// Element 3: signature (bstr, must be exactly 64 bytes).
	var signature []byte
	if err := dm.Unmarshal(elements[3], &signature); err != nil {
		return nil, &CoseError{
			Type:    CoseErrInvalidSignatureLength,
			Message: "failed to decode signature",
			Cause:   err,
		}
	}
	if len(signature) != p1363SignatureLen {
		return nil, &CoseError{
			Type:    CoseErrInvalidSignatureLength,
			Message: fmt.Sprintf("expected %d bytes, got %d", p1363SignatureLen, len(signature)),
		}
	}

	return &ParsedCoseSign1{
		ProtectedBytes: protectedBytes,
		Protected:      *header,
		Unprotected:    unprotected,
		Payload:        payload,
		Signature:      signature,
	}, nil
}

// unwrapTag18 strips CBOR Tag 18 from the raw bytes if present, returning the inner content.
func unwrapTag18(raw cbor.RawMessage) []byte {
	var tag cbor.RawTag
	if err := tag.UnmarshalCBOR(raw); err == nil && tag.Number == 18 { //nolint:staticcheck // SA1019: no replacement API available in fxamacker/cbor for raw tag unwrapping
		return tag.Content
	}
	return raw
}

// parseCWTClaims extracts issuer and issued-at from a CBOR-encoded CWT claims map.
func parseCWTClaims(dm cbor.DecMode, cwtRaw cbor.RawMessage) (*string, *int64) {
	var cwtMap map[int64]cbor.RawMessage
	if err := dm.Unmarshal(cwtRaw, &cwtMap); err != nil {
		return nil, nil
	}

	var iss *string
	if issRaw, issFound := cwtMap[cwtClaimIss]; issFound {
		var issVal string
		if err := dm.Unmarshal(issRaw, &issVal); err == nil {
			iss = &issVal
		}
	}

	var iat *int64
	if iatRaw, iatFound := cwtMap[cwtClaimIat]; iatFound {
		var iatVal int64
		if err := dm.Unmarshal(iatRaw, &iatVal); err == nil {
			iat = &iatVal
		}
	}

	return iss, iat
}

// parseProtectedHeader decodes the CBOR-encoded protected header map.
func parseProtectedHeader(dm cbor.DecMode, protectedBytes []byte) (*ProtectedHeader, error) {
	var headerMap map[int64]cbor.RawMessage
	if err := dm.Unmarshal(protectedBytes, &headerMap); err != nil {
		return nil, &CoseError{
			Type:    CoseErrInvalidProtectedHeader,
			Message: "failed to decode protected header map",
			Cause:   err,
		}
	}

	header := &ProtectedHeader{}

	// Key 1: alg (required, must be -7 for ES256).
	algRaw, ok := headerMap[coseHeaderAlg]
	if !ok {
		return nil, &CoseError{
			Type:    CoseErrUnsupportedAlgorithm,
			Message: "missing algorithm in protected header",
		}
	}
	if err := dm.Unmarshal(algRaw, &header.Alg); err != nil {
		return nil, &CoseError{
			Type:    CoseErrUnsupportedAlgorithm,
			Message: "failed to decode algorithm",
			Cause:   err,
		}
	}
	if header.Alg != coseAlgES256 {
		return nil, &CoseError{
			Type:    CoseErrUnsupportedAlgorithm,
			Message: fmt.Sprintf("expected algorithm %d (ES256), got %d", coseAlgES256, header.Alg),
		}
	}

	// Key 3: content_type (optional string).
	if ctRaw, ctOk := headerMap[coseHeaderContentType]; ctOk {
		var ct string
		if err := dm.Unmarshal(ctRaw, &ct); err == nil {
			header.ContentType = &ct
		}
	}

	// Key 4: kid (required, must be exactly 4 bytes).
	kidRaw, ok := headerMap[coseHeaderKid]
	if !ok {
		return nil, &CoseError{
			Type:    CoseErrMissingKid,
			Message: "key ID (kid) not present in protected header",
		}
	}
	var kidBytes []byte
	if err := dm.Unmarshal(kidRaw, &kidBytes); err != nil {
		return nil, &CoseError{
			Type:    CoseErrMissingKid,
			Message: "failed to decode kid",
			Cause:   err,
		}
	}
	if len(kidBytes) != kidLen {
		return nil, &CoseError{
			Type:    CoseErrMissingKid,
			Message: fmt.Sprintf("kid must be exactly %d bytes, got %d", kidLen, len(kidBytes)),
		}
	}
	copy(header.Kid[:], kidBytes)

	// Key 15: cwt-claims map (optional).
	if cwtRaw, cwtOk := headerMap[coseHeaderCWTClaims]; cwtOk {
		header.CwtIss, header.CwtIat = parseCWTClaims(dm, cwtRaw)
	}

	// Key 395: vds (optional int64).
	if vdsRaw, vdsOk := headerMap[coseHeaderVDS]; vdsOk {
		var vds int64
		if err := dm.Unmarshal(vdsRaw, &vds); err == nil {
			header.Vds = &vds
		}
	}

	return header, nil
}

// BuildSigStructure constructs the COSE Sig_structure1 for signing/verification.
// The structure is: ["Signature1", protectedBytes, externalAad, payload]
func BuildSigStructure(protectedBytes, payload []byte) ([]byte, error) {
	sigStructure := []interface{}{
		"Signature1",
		protectedBytes,
		[]byte{}, // external AAD (empty)
		payload,
	}
	encoded, err := cbor.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Sig_structure1: %w", err)
	}
	return encoded, nil
}

// ComputeSigStructureDigest builds the Sig_structure1 and returns its SHA-256 digest.
func ComputeSigStructureDigest(protectedBytes, payload []byte) ([32]byte, error) {
	sigBytes, err := BuildSigStructure(protectedBytes, payload)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(sigBytes), nil
}
