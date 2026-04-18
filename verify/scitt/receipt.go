package scitt

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// vdsRFC9162 is the Verifiable Data Structure identifier for RFC 9162 Merkle trees.
const vdsRFC9162 int64 = 1

// vdpCBORKey is the CBOR map key for Verifiable Data Proofs in the unprotected header.
const vdpCBORKey int64 = 396

// VDP map keys (negative integers per SCITT COSE profile).
const (
	vdpKeyTreeSize      int64 = -1
	vdpKeyLeafIndex     int64 = -2
	vdpKeyInclusionPath int64 = -3
	hashLen                   = 32 // SHA-256 hash length in bytes
)

// VerifiedReceipt holds the verified fields extracted from a SCITT receipt.
type VerifiedReceipt struct {
	TreeSize  uint64
	LeafIndex uint64
	// RootHash is the Merkle tree root computed from walking the inclusion path.
	// IMPORTANT: This value is NOT verified against any trusted tree head.
	// Callers requiring tree-head attestation MUST compare this hash to a root
	// obtained out-of-band (e.g., from a witness or monitor). The ECDSA signature
	// over the leaf is authoritative for leaf-level trust; the walked root alone
	// does not prove inclusion in any particular published tree.
	RootHash   [32]byte
	EventBytes []byte
	KeyID      [4]byte
	Iss        *string
	Iat        *int64
}

// VerifyReceipt parses and verifies a COSE_Sign1 SCITT receipt.
//
// Verification order:
//  1. Parse COSE_Sign1 structure
//  2. Validate vds == 1 (RFC 9162)
//  3. Look up signing key by kid
//  4. Verify ECDSA signature (before any issuer check)
//  5. Verify issuer binding (after signature verification)
//  6. Extract VDP (Verifiable Data Proofs) from unprotected header
//  7. Walk Merkle inclusion path
func VerifyReceipt(receiptBytes []byte, keys KeyLookup) (*VerifiedReceipt, error) {
	parsed, err := ParseCoseSign1(receiptBytes)
	if err != nil {
		return nil, err
	}

	if err := validateVDS(parsed.Protected.Vds); err != nil {
		return nil, err
	}

	trustedKey, err := keys.Get(parsed.Protected.Kid)
	if err != nil {
		return nil, err
	}

	if err := verifyECDSA(trustedKey.Key, parsed.ProtectedBytes, parsed.Payload, parsed.Signature, parsed.Protected.Kid); err != nil {
		return nil, err
	}

	if err := verifyIssuerBinding(parsed.Protected.CwtIss, trustedKey); err != nil {
		return nil, err
	}

	treeSize, leafIndex, rootHash, err := verifyInclusionProof(parsed)
	if err != nil {
		return nil, err
	}

	return &VerifiedReceipt{
		TreeSize:   treeSize,
		LeafIndex:  leafIndex,
		RootHash:   rootHash,
		EventBytes: parsed.Payload,
		KeyID:      parsed.Protected.Kid,
		Iss:        parsed.Protected.CwtIss,
		Iat:        parsed.Protected.CwtIat,
	}, nil
}

// validateVDS checks that the Verifiable Data Structure identifier is present and equals 1.
func validateVDS(vds *int64) error {
	if vds == nil {
		return &CoseError{
			Type:    CoseErrInvalidProtectedHeader,
			Message: "missing vds (key 395) in protected header",
		}
	}
	if *vds != vdsRFC9162 {
		return &CoseError{
			Type:    CoseErrInvalidProtectedHeader,
			Message: fmt.Sprintf("expected vds=%d (RFC 9162), got %d", vdsRFC9162, *vds),
		}
	}
	return nil
}

// verifyIssuerBinding checks that the CWT issuer claim matches the key name.
// This MUST be called after signature verification to prevent key store enumeration.
func verifyIssuerBinding(iss *string, key *TrustedKey) error {
	if iss == nil {
		return nil
	}
	if *iss != key.Name {
		return &SignatureError{
			Type:    SigErrIssuerMismatch,
			Kid:     key.Kid,
			Message: fmt.Sprintf("issuer %q does not match key name %q", *iss, key.Name),
		}
	}
	return nil
}

// verifyInclusionProof extracts VDP from the unprotected header and walks the Merkle path.
func verifyInclusionProof(parsed *ParsedCoseSign1) (uint64, uint64, [32]byte, error) {
	dm, err := newDecMode()
	if err != nil {
		return 0, 0, [32]byte{}, fmt.Errorf("failed to create CBOR decode mode: %w", err)
	}

	treeSize, leafIndex, hashPath, err := extractVDP(dm, parsed.Unprotected)
	if err != nil {
		return 0, 0, [32]byte{}, err
	}

	rootHash, err := WalkInclusionPath(parsed.Payload, leafIndex, treeSize, hashPath)
	if err != nil {
		return 0, 0, [32]byte{}, err
	}

	return treeSize, leafIndex, rootHash, nil
}

// extractVDP decodes the Verifiable Data Proof from the unprotected header.
// VDP is a CBOR map at key 396 with negative-integer keys:
//
//	-1: tree_size (uint64)
//	-2: leaf_index (uint64)
//	-3: inclusion_path (array of 32-byte bstr)
func extractVDP(dm cbor.DecMode, unprotected cbor.RawMessage) (uint64, uint64, [][32]byte, error) {
	var unprotectedMap map[int64]cbor.RawMessage
	if err := dm.Unmarshal(unprotected, &unprotectedMap); err != nil {
		return 0, 0, nil, &CoseError{
			Type:    CoseErrInvalidUnprotectedHeader,
			Message: "failed to decode unprotected header map",
			Cause:   err,
		}
	}

	vdpRaw, ok := unprotectedMap[vdpCBORKey]
	if !ok {
		return 0, 0, nil, &CoseError{
			Type:    CoseErrInvalidUnprotectedHeader,
			Message: "missing VDP (key 396) in unprotected header",
		}
	}

	var vdpMap map[int64]cbor.RawMessage
	if err := dm.Unmarshal(vdpRaw, &vdpMap); err != nil {
		return 0, 0, nil, &CoseError{
			Type:    CoseErrInvalidUnprotectedHeader,
			Message: "VDP (key 396) must be a CBOR map",
			Cause:   err,
		}
	}

	treeSizeRaw, ok := vdpMap[vdpKeyTreeSize]
	if !ok {
		return 0, 0, nil, &CoseError{
			Type:    CoseErrInvalidUnprotectedHeader,
			Message: "missing tree_size (key -1) in VDP map",
		}
	}
	var treeSize uint64
	if err := dm.Unmarshal(treeSizeRaw, &treeSize); err != nil {
		return 0, 0, nil, &CoseError{
			Type:    CoseErrInvalidUnprotectedHeader,
			Message: "tree_size (key -1) must be an unsigned integer",
			Cause:   err,
		}
	}

	leafIndexRaw, ok := vdpMap[vdpKeyLeafIndex]
	if !ok {
		return 0, 0, nil, &CoseError{
			Type:    CoseErrInvalidUnprotectedHeader,
			Message: "missing leaf_index (key -2) in VDP map",
		}
	}
	var leafIndex uint64
	if err := dm.Unmarshal(leafIndexRaw, &leafIndex); err != nil {
		return 0, 0, nil, &CoseError{
			Type:    CoseErrInvalidUnprotectedHeader,
			Message: "leaf_index (key -2) must be an unsigned integer",
			Cause:   err,
		}
	}

	pathRaw, ok := vdpMap[vdpKeyInclusionPath]
	if !ok {
		return treeSize, leafIndex, nil, nil
	}

	var rawHashes []cbor.RawMessage
	if err := dm.Unmarshal(pathRaw, &rawHashes); err != nil {
		return 0, 0, nil, &CoseError{
			Type:    CoseErrInvalidUnprotectedHeader,
			Message: "inclusion_path (key -3) must be a CBOR array",
			Cause:   err,
		}
	}

	hashPath := make([][32]byte, 0, len(rawHashes))
	for i, raw := range rawHashes {
		var hashBytes []byte
		if err := dm.Unmarshal(raw, &hashBytes); err != nil {
			return 0, 0, nil, &CoseError{
				Type:    CoseErrInvalidUnprotectedHeader,
				Message: fmt.Sprintf("failed to decode inclusion_path element %d", i),
				Cause:   err,
			}
		}
		if len(hashBytes) != hashLen {
			return 0, 0, nil, &CoseError{
				Type:    CoseErrInvalidUnprotectedHeader,
				Message: fmt.Sprintf("inclusion_path element %d is %d bytes, expected %d", i, len(hashBytes), hashLen),
			}
		}
		var h [32]byte
		copy(h[:], hashBytes)
		hashPath = append(hashPath, h)
	}

	return treeSize, leafIndex, hashPath, nil
}
