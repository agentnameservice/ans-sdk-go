package scitt

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// MaxHashPathLen is the maximum number of elements in a Merkle inclusion proof path.
// A SHA-256 Merkle tree can have at most 2^63 leaves, requiring at most 63 path nodes.
const MaxHashPathLen = 63

// ComputeLeafHash computes SHA-256(0x00 || data) per RFC 9162 section 2.1.
func ComputeLeafHash(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ComputeNodeHash computes SHA-256(0x01 || left || right) per RFC 9162 section 2.1.
func ComputeNodeHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// WalkInclusionPath walks an RFC 9162 inclusion proof, computing the root hash
// from the event data, leaf index, tree size, and hash path.
func WalkInclusionPath(eventBytes []byte, leafIndex, treeSize uint64, hashPath [][32]byte) ([32]byte, error) {
	if treeSize == 0 {
		return [32]byte{}, &MerkleError{Type: MerkleErrInvalidProof, Message: "tree size is zero"}
	}
	if leafIndex >= treeSize {
		return [32]byte{}, &MerkleError{
			Type:    MerkleErrInvalidProof,
			Message: fmt.Sprintf("leaf index %d >= tree size %d", leafIndex, treeSize),
		}
	}
	if len(hashPath) > MaxHashPathLen {
		return [32]byte{}, &MerkleError{
			Type:    MerkleErrInvalidProof,
			Message: fmt.Sprintf("path length %d exceeds maximum %d", len(hashPath), MaxHashPathLen),
		}
	}

	fn := leafIndex
	sn := treeSize - 1
	r := ComputeLeafHash(eventBytes)

	for _, p := range hashPath {
		if sn == 0 {
			return [32]byte{}, &MerkleError{Type: MerkleErrInvalidProof, Message: "excess path elements"}
		}
		if fn&1 == 1 || fn == sn {
			r = ComputeNodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = ComputeNodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}

	if sn != 0 {
		return [32]byte{}, &MerkleError{Type: MerkleErrInvalidProof, Message: "insufficient path elements"}
	}

	return r, nil
}

// VerifyMerkleInclusion verifies an RFC 9162 Merkle inclusion proof by walking
// the path and comparing the computed root against the expected root using
// constant-time comparison.
func VerifyMerkleInclusion(eventBytes []byte, leafIndex, treeSize uint64, hashPath [][32]byte, expectedRoot [32]byte) error {
	computedRoot, err := WalkInclusionPath(eventBytes, leafIndex, treeSize, hashPath)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(computedRoot[:], expectedRoot[:]) != 1 {
		return &MerkleError{
			Type:    MerkleErrRootMismatch,
			Message: "computed root does not match expected root",
		}
	}

	return nil
}
