package scitt

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// vdsRFC9162 is the Verifiable Data Structure identifier for RFC 9162 Merkle trees.
const vdsRFC9162 int64 = 1

// vdpCBORKey is the CBOR map key for Verifiable Data Proofs in the unprotected header.
const vdpCBORKey int64 = 396

// Inclusion proof structure constants.
const (
	minProofElements = 2  // minimum elements in an inclusion proof (treeSize + leafIndex)
	hashLen          = 32 // SHA-256 hash length in bytes
	vdpProofStartIdx = 2  // index where hash path elements begin in the proof array
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

// extractVDP decodes the Verifiable Data Proofs from the unprotected header.
// VDP is stored at key 396 as an array of inclusion proofs.
// Each proof is: [treeSize, leafIndex, hashNode1, hashNode2, ...]
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

	// VDP is an array of proofs; we use the first one.
	var proofs []cbor.RawMessage
	if err := dm.Unmarshal(vdpRaw, &proofs); err != nil {
		return 0, 0, nil, &CoseError{
			Type:    CoseErrInvalidUnprotectedHeader,
			Message: "failed to decode VDP array",
			Cause:   err,
		}
	}

	if len(proofs) == 0 {
		return 0, 0, nil, &CoseError{
			Type:    CoseErrInvalidUnprotectedHeader,
			Message: "VDP array is empty",
		}
	}

	// Decode the first proof: [treeSize, leafIndex, hash1, hash2, ...]
	var proofElements []cbor.RawMessage
	if err := dm.Unmarshal(proofs[0], &proofElements); err != nil {
		return 0, 0, nil, &CoseError{
			Type:    CoseErrInvalidUnprotectedHeader,
			Message: "failed to decode inclusion proof array",
			Cause:   err,
		}
	}

	if len(proofElements) < minProofElements {
		return 0, 0, nil, &CoseError{
			Type:    CoseErrInvalidUnprotectedHeader,
			Message: fmt.Sprintf("inclusion proof needs at least %d elements, got %d", minProofElements, len(proofElements)),
		}
	}

	var treeSize uint64
	if err := dm.Unmarshal(proofElements[0], &treeSize); err != nil {
		return 0, 0, nil, &CoseError{
			Type:    CoseErrInvalidUnprotectedHeader,
			Message: "failed to decode tree size",
			Cause:   err,
		}
	}

	var leafIndex uint64
	if err := dm.Unmarshal(proofElements[1], &leafIndex); err != nil {
		return 0, 0, nil, &CoseError{
			Type:    CoseErrInvalidUnprotectedHeader,
			Message: "failed to decode leaf index",
			Cause:   err,
		}
	}

	hashPath := make([][32]byte, 0, len(proofElements)-vdpProofStartIdx)
	for i := vdpProofStartIdx; i < len(proofElements); i++ {
		var hashBytes []byte
		if err := dm.Unmarshal(proofElements[i], &hashBytes); err != nil {
			return 0, 0, nil, &CoseError{
				Type:    CoseErrInvalidUnprotectedHeader,
				Message: fmt.Sprintf("failed to decode hash path element %d", i-vdpProofStartIdx),
				Cause:   err,
			}
		}
		if len(hashBytes) != hashLen {
			return 0, 0, nil, &CoseError{
				Type:    CoseErrInvalidUnprotectedHeader,
				Message: fmt.Sprintf("hash path element %d is %d bytes, expected %d", i-vdpProofStartIdx, len(hashBytes), hashLen),
			}
		}
		var h [32]byte
		copy(h[:], hashBytes)
		hashPath = append(hashPath, h)
	}

	return treeSize, leafIndex, hashPath, nil
}
