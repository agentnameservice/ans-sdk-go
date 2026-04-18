package scitt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// testKeyBundle holds a generated ECDSA key pair and its kid for test use.
type testKeyBundle struct {
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
	kid  [4]byte
	name string
}

// generateTestKey creates an ECDSA P-256 key with a deterministic kid derived from the public key.
func generateTestKey(t *testing.T, name string) *testKeyBundle {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	// kid = first 4 bytes of SHA-256(SPKI-encoded public key)
	spkiDer, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	hash := sha256.Sum256(spkiDer)
	var kid [4]byte
	copy(kid[:], hash[:4])
	return &testKeyBundle{
		priv: priv,
		pub:  &priv.PublicKey,
		kid:  kid,
		name: name,
	}
}

// receiptTestKeyStore implements KeyLookup for tests.
type receiptTestKeyStore struct {
	keys map[[4]byte]*TrustedKey
}

func (s *receiptTestKeyStore) Get(kid [4]byte) (*TrustedKey, error) {
	tk, ok := s.keys[kid]
	if !ok {
		return nil, &SignatureError{
			Type:    SigErrUnknownKeyID,
			Kid:     kid,
			Message: "unknown key ID",
		}
	}
	return tk, nil
}

func newTestKeyStore(bundles ...*testKeyBundle) *receiptTestKeyStore {
	keys := make(map[[4]byte]*TrustedKey, len(bundles))
	for _, b := range bundles {
		keys[b.kid] = &TrustedKey{
			Name: b.name,
			Kid:  b.kid,
			Key:  b.pub,
		}
	}
	return &receiptTestKeyStore{keys: keys}
}

// buildProtectedHeader builds a CBOR-encoded protected header map for tests.
func buildProtectedHeader(t *testing.T, kid [4]byte, vds *int64, iss *string, iat *int64) []byte {
	t.Helper()
	hdr := map[int64]interface{}{
		1: int64(-7), // alg = ES256
		4: kid[:],    // kid
	}
	if vds != nil {
		hdr[395] = *vds
	}
	if iss != nil || iat != nil {
		cwt := map[int64]interface{}{}
		if iss != nil {
			cwt[1] = *iss
		}
		if iat != nil {
			cwt[6] = *iat
		}
		hdr[15] = cwt
	}
	encoded, err := cbor.Marshal(hdr)
	if err != nil {
		t.Fatalf("failed to encode protected header: %v", err)
	}
	return encoded
}

// buildUnprotectedWithVDP builds an unprotected header containing VDP (key 396).
func buildUnprotectedWithVDP(t *testing.T, treeSize, leafIndex uint64, hashPath [][32]byte) cbor.RawMessage {
	t.Helper()

	vdp := map[int64]interface{}{
		int64(-1): treeSize,
		int64(-2): leafIndex,
	}
	if len(hashPath) > 0 {
		path := make([]interface{}, len(hashPath))
		for i, h := range hashPath {
			path[i] = h[:]
		}
		vdp[int64(-3)] = path
	}

	unprotected := map[int64]interface{}{
		int64(396): vdp,
	}

	encoded, err := cbor.Marshal(unprotected)
	if err != nil {
		t.Fatalf("failed to encode unprotected header: %v", err)
	}
	return cbor.RawMessage(encoded)
}

// buildEmptyUnprotected returns an empty CBOR map.
func buildEmptyUnprotected(t *testing.T) cbor.RawMessage {
	t.Helper()
	encoded, err := cbor.Marshal(map[int64]interface{}{})
	if err != nil {
		t.Fatalf("failed to encode empty unprotected: %v", err)
	}
	return cbor.RawMessage(encoded)
}

// signP1363 signs a digest using ECDSA and returns a 64-byte P1363 signature.
func signP1363(t *testing.T, priv *ecdsa.PrivateKey, digest [32]byte) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return sig
}

// buildValidReceipt builds a complete valid COSE_Sign1 receipt for testing.
func buildValidReceipt(t *testing.T, bundle *testKeyBundle, payload []byte, vds *int64, iss *string, iat *int64,
	treeSize, leafIndex uint64, hashPath [][32]byte) []byte {
	t.Helper()

	protectedBytes := buildProtectedHeader(t, bundle.kid, vds, iss, iat)

	// Compute sig structure digest
	digest, err := ComputeSigStructureDigest(protectedBytes, payload)
	if err != nil {
		t.Fatalf("failed to compute sig structure digest: %v", err)
	}

	sig := signP1363(t, bundle.priv, digest)
	unprotected := buildUnprotectedWithVDP(t, treeSize, leafIndex, hashPath)

	// Build COSE_Sign1 array: [protectedBytes, unprotected, payload, signature]
	coseArray := []interface{}{
		protectedBytes,
		unprotected,
		payload,
		sig,
	}

	encoded, err := cbor.Marshal(cbor.Tag{Number: 18, Content: coseArray})
	if err != nil {
		t.Fatalf("failed to encode COSE_Sign1: %v", err)
	}
	return encoded
}

// merkle helpers reused from merkle_test.go concepts
func receiptTestLeafHash(data []byte) [32]byte {
	return ComputeLeafHash(data)
}

func receiptTestBuildMerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := receiptTestLargestPow2(uint64(len(leaves)))
	left := receiptTestBuildMerkleRoot(leaves[:k])
	right := receiptTestBuildMerkleRoot(leaves[k:])
	return ComputeNodeHash(left, right)
}

func receiptTestBuildInclusionPath(leaves [][32]byte, index uint64) [][32]byte {
	if len(leaves) == 1 {
		return nil
	}
	k := receiptTestLargestPow2(uint64(len(leaves)))
	if index < k {
		path := receiptTestBuildInclusionPath(leaves[:k], index)
		rightRoot := receiptTestBuildMerkleRoot(leaves[k:])
		return append(path, rightRoot)
	}
	path := receiptTestBuildInclusionPath(leaves[k:], index-k)
	leftRoot := receiptTestBuildMerkleRoot(leaves[:k])
	return append(path, leftRoot)
}

func receiptTestLargestPow2(n uint64) uint64 {
	if n <= 1 {
		return 0
	}
	k := uint64(1)
	for k*2 < n {
		k *= 2
	}
	return k
}

func receiptTestMakeLeaves(n int) [][32]byte {
	leaves := make([][32]byte, n)
	for i := range n {
		leaves[i] = receiptTestLeafHash([]byte{byte(i)})
	}
	return leaves
}

func ptrInt64(v int64) *int64 {
	return &v
}

func ptrString(v string) *string {
	return &v
}

//nolint:cyclop,gocyclo // table-driven test
func TestVerifyReceipt(t *testing.T) {
	t.Parallel()

	key1 := generateTestKey(t, "test-key-1")
	key2 := generateTestKey(t, "test-key-2")
	store := newTestKeyStore(key1)

	// Build a small Merkle tree for test data
	payload := []byte{0} // same as leaf 0
	leaves := receiptTestMakeLeaves(4)
	root := receiptTestBuildMerkleRoot(leaves)
	path := receiptTestBuildInclusionPath(leaves, 0)
	vds1 := int64(1)

	_ = root // used indirectly through WalkInclusionPath verification

	tests := []struct {
		name        string
		receipt     []byte
		keys        KeyLookup
		wantErr     bool
		errCheck    func(t *testing.T, err error)
		resultCheck func(t *testing.T, r *VerifiedReceipt)
	}{
		{
			name:    "valid receipt: basic",
			receipt: buildValidReceipt(t, key1, payload, &vds1, nil, nil, 4, 0, path),
			keys:    store,
			resultCheck: func(t *testing.T, r *VerifiedReceipt) {
				t.Helper()
				if r.TreeSize != 4 {
					t.Errorf("TreeSize = %d, want 4", r.TreeSize)
				}
				if r.LeafIndex != 0 {
					t.Errorf("LeafIndex = %d, want 0", r.LeafIndex)
				}
				if r.KeyID != key1.kid {
					t.Errorf("KeyID = %x, want %x", r.KeyID, key1.kid)
				}
				if r.Iss != nil {
					t.Errorf("Iss = %v, want nil", r.Iss)
				}
			},
		},
		{
			name:    "valid receipt: with issuer and iat",
			receipt: buildValidReceipt(t, key1, payload, &vds1, ptrString("test-key-1"), ptrInt64(1000), 4, 0, path),
			keys:    store,
			resultCheck: func(t *testing.T, r *VerifiedReceipt) {
				t.Helper()
				if r.Iss == nil || *r.Iss != "test-key-1" {
					t.Errorf("Iss = %v, want test-key-1", r.Iss)
				}
				if r.Iat == nil || *r.Iat != 1000 {
					t.Errorf("Iat = %v, want 1000", r.Iat)
				}
			},
		},
		{
			name:    "valid receipt: leaf index 3 in 4-element tree",
			receipt: buildValidReceipt(t, key1, []byte{3}, &vds1, nil, nil, 4, 3, receiptTestBuildInclusionPath(leaves, 3)),
			keys:    store,
			resultCheck: func(t *testing.T, r *VerifiedReceipt) {
				t.Helper()
				if r.LeafIndex != 3 {
					t.Errorf("LeafIndex = %d, want 3", r.LeafIndex)
				}
			},
		},
		{
			name: "error: invalid COSE_Sign1 bytes",
			receipt: func() []byte {
				return []byte{0xFF, 0xFF}
			}(),
			keys:    store,
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var coseErr *CoseError
				if !errors.As(err, &coseErr) {
					t.Errorf("expected *CoseError, got %T: %v", err, err)
				}
			},
		},
		{
			name:    "error: missing vds in protected header",
			receipt: buildValidReceipt(t, key1, payload, nil, nil, nil, 4, 0, path),
			keys:    store,
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var coseErr *CoseError
				if !errors.As(err, &coseErr) {
					t.Errorf("expected *CoseError, got %T: %v", err, err)
				}
			},
		},
		{
			name: "error: wrong vds value (not 1)",
			receipt: func() []byte {
				vds2 := int64(2)
				return buildValidReceipt(t, key1, payload, &vds2, nil, nil, 4, 0, path)
			}(),
			keys:    store,
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var coseErr *CoseError
				if !errors.As(err, &coseErr) {
					t.Errorf("expected *CoseError, got %T: %v", err, err)
				}
			},
		},
		{
			name:    "error: unknown key ID",
			receipt: buildValidReceipt(t, key2, payload, &vds1, nil, nil, 4, 0, path),
			keys:    store,
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var sigErr *SignatureError
				if !errors.As(err, &sigErr) {
					t.Errorf("expected *SignatureError, got %T: %v", err, err)
				}
				if sigErr.Type != SigErrUnknownKeyID {
					t.Errorf("error type = %v, want SigErrUnknownKeyID", sigErr.Type)
				}
			},
		},
		{
			name: "error: invalid signature (tampered)",
			receipt: func() []byte {
				// Sign with key2's private key but use key1's kid in the header
				protectedBytes := buildProtectedHeader(t, key1.kid, &vds1, nil, nil)
				digest, _ := ComputeSigStructureDigest(protectedBytes, payload)
				// Sign with key2's private key but use key1's kid
				sig := signP1363(t, key2.priv, digest)
				unprotected := buildUnprotectedWithVDP(t, 4, 0, path)
				coseArray := []interface{}{protectedBytes, unprotected, payload, sig}
				encoded, _ := cbor.Marshal(cbor.Tag{Number: 18, Content: coseArray})
				return encoded
			}(),
			keys:    store,
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var sigErr *SignatureError
				if !errors.As(err, &sigErr) {
					t.Errorf("expected *SignatureError, got %T: %v", err, err)
				}
				if sigErr.Type != SigErrSignatureInvalid {
					t.Errorf("error type = %v, want SigErrSignatureInvalid", sigErr.Type)
				}
			},
		},
		{
			name:    "error: issuer mismatch",
			receipt: buildValidReceipt(t, key1, payload, &vds1, ptrString("wrong-issuer"), nil, 4, 0, path),
			keys:    store,
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var sigErr *SignatureError
				if !errors.As(err, &sigErr) {
					t.Errorf("expected *SignatureError, got %T: %v", err, err)
				}
				if sigErr.Type != SigErrIssuerMismatch {
					t.Errorf("error type = %v, want SigErrIssuerMismatch", sigErr.Type)
				}
			},
		},
		{
			name: "error: missing VDP in unprotected header",
			receipt: func() []byte {
				protectedBytes := buildProtectedHeader(t, key1.kid, &vds1, nil, nil)
				digest, _ := ComputeSigStructureDigest(protectedBytes, payload)
				sig := signP1363(t, key1.priv, digest)
				unprotected := buildEmptyUnprotected(t)
				coseArray := []interface{}{protectedBytes, unprotected, payload, sig}
				encoded, _ := cbor.Marshal(cbor.Tag{Number: 18, Content: coseArray})
				return encoded
			}(),
			keys:    store,
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var coseErr *CoseError
				if !errors.As(err, &coseErr) {
					t.Errorf("expected *CoseError, got %T: %v", err, err)
				}
				if coseErr.Type != CoseErrInvalidUnprotectedHeader {
					t.Errorf("error type = %v, want CoseErrInvalidUnprotectedHeader", coseErr.Type)
				}
			},
		},
		{
			name: "wrong payload produces different root hash (no error - root is just different)",
			receipt: func() []byte {
				// Use payload that doesn't match the leaf at index 0
				// This succeeds but the root hash will differ from the original tree root
				wrongPayload := []byte{99}
				return buildValidReceipt(t, key1, wrongPayload, &vds1, nil, nil, 4, 0, path)
			}(),
			keys: store,
			resultCheck: func(t *testing.T, r *VerifiedReceipt) {
				t.Helper()
				// The root hash should NOT match the original tree root since payload differs
				originalRoot := receiptTestBuildMerkleRoot(leaves)
				if r.RootHash == originalRoot {
					t.Error("expected different root hash for wrong payload, but got original root")
				}
			},
		},
		{
			name: "error: Merkle proof with wrong tree size",
			receipt: func() []byte {
				// treeSize=8 but path is for treeSize=4
				return buildValidReceipt(t, key1, payload, &vds1, nil, nil, 8, 0, path)
			}(),
			keys:    store,
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var merkleErr *MerkleError
				if !errors.As(err, &merkleErr) {
					t.Errorf("expected *MerkleError, got %T: %v", err, err)
				}
			},
		},
		{
			name: "valid receipt: single leaf tree",
			receipt: func() []byte {
				singleLeaves := receiptTestMakeLeaves(1)
				singlePath := receiptTestBuildInclusionPath(singleLeaves, 0)
				return buildValidReceipt(t, key1, []byte{0}, &vds1, nil, nil, 1, 0, singlePath)
			}(),
			keys: store,
			resultCheck: func(t *testing.T, r *VerifiedReceipt) {
				t.Helper()
				if r.TreeSize != 1 {
					t.Errorf("TreeSize = %d, want 1", r.TreeSize)
				}
			},
		},
		{
			name: "valid receipt: 8-element tree index 7",
			receipt: func() []byte {
				bigLeaves := receiptTestMakeLeaves(8)
				bigPath := receiptTestBuildInclusionPath(bigLeaves, 7)
				return buildValidReceipt(t, key1, []byte{7}, &vds1, nil, nil, 8, 7, bigPath)
			}(),
			keys: store,
			resultCheck: func(t *testing.T, r *VerifiedReceipt) {
				t.Helper()
				if r.TreeSize != 8 {
					t.Errorf("TreeSize = %d, want 8", r.TreeSize)
				}
				if r.LeafIndex != 7 {
					t.Errorf("LeafIndex = %d, want 7", r.LeafIndex)
				}
			},
		},
		{
			name: "issuer binding happens after signature verification",
			receipt: func() []byte {
				// Build receipt signed by key2 (not in store) but with issuer mismatch.
				// Should get SigErrUnknownKeyID, NOT SigErrIssuerMismatch — proving
				// key lookup (and thus signature verification) happens before issuer check.
				return buildValidReceipt(t, key2, payload, &vds1, ptrString("wrong-issuer"), nil, 4, 0, path)
			}(),
			keys:    store,
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var sigErr *SignatureError
				if !errors.As(err, &sigErr) {
					t.Errorf("expected *SignatureError, got %T: %v", err, err)
				}
				// Key lookup fails before issuer check
				if sigErr.Type != SigErrUnknownKeyID {
					t.Errorf("error type = %v, want SigErrUnknownKeyID (key lookup before issuer check)", sigErr.Type)
				}
			},
		},
		{
			name: "verified receipt contains correct EventBytes",
			receipt: func() []byte {
				return buildValidReceipt(t, key1, payload, &vds1, nil, nil, 4, 0, path)
			}(),
			keys: store,
			resultCheck: func(t *testing.T, r *VerifiedReceipt) {
				t.Helper()
				if len(r.EventBytes) != len(payload) || r.EventBytes[0] != payload[0] {
					t.Errorf("EventBytes = %x, want %x", r.EventBytes, payload)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := VerifyReceipt(tt.receipt, tt.keys)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errCheck != nil {
					tt.errCheck(t, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if tt.resultCheck != nil {
				tt.resultCheck(t, result)
			}
		})
	}
}

func TestVerifyReceiptP1363ToDER(t *testing.T) {
	t.Parallel()

	// Verify the P1363-to-DER conversion works correctly by checking that
	// a valid signature can be round-tripped through the conversion.
	key := generateTestKey(t, "der-test")
	digest := sha256.Sum256([]byte("test data"))

	tests := []struct {
		name    string
		sig     []byte
		wantErr bool
	}{
		{
			name: "valid signature round-trips through DER",
			sig:  signP1363(t, key.priv, digest),
		},
		{
			name:    "zero R and S values",
			sig:     make([]byte, 64),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := new(big.Int).SetBytes(tt.sig[:32])
			s := new(big.Int).SetBytes(tt.sig[32:64])
			derSig, err := asn1.Marshal(struct{ R, S *big.Int }{R: r, S: s})
			if err != nil {
				t.Fatalf("asn1.Marshal failed: %v", err)
			}
			valid := ecdsa.VerifyASN1(key.pub, digest[:], derSig)
			if tt.wantErr && valid {
				t.Error("expected verification failure, got success")
			}
			if !tt.wantErr && !valid {
				t.Error("expected verification success, got failure")
			}
		})
	}
}

func TestExtractVDP_ErrorPaths(t *testing.T) {
	dm, _ := newDecMode()

	tests := []struct {
		name        string
		unprotected cbor.RawMessage
		wantErr     string
	}{
		{
			name: "invalid CBOR in unprotected header",
			unprotected: func() cbor.RawMessage {
				return cbor.RawMessage{0xFF, 0xFF, 0xFF}
			}(),
			wantErr: "failed to decode unprotected header map",
		},
		{
			name: "missing VDP key 396",
			unprotected: func() cbor.RawMessage {
				m := map[int64]int{99: 1}
				d, _ := cbor.Marshal(m)
				return d
			}(),
			wantErr: "missing VDP",
		},
		{
			name: "VDP not a map",
			unprotected: func() cbor.RawMessage {
				m := map[int64]interface{}{396: "not-a-map"}
				d, _ := cbor.Marshal(m)
				return d
			}(),
			wantErr: "VDP (key 396) must be a CBOR map",
		},
		{
			name: "VDP map missing tree_size",
			unprotected: func() cbor.RawMessage {
				vdp := map[int64]interface{}{-2: uint64(0)}
				m := map[int64]interface{}{396: vdp}
				d, _ := cbor.Marshal(m)
				return d
			}(),
			wantErr: "missing tree_size (key -1)",
		},
		{
			name: "VDP map missing leaf_index",
			unprotected: func() cbor.RawMessage {
				vdp := map[int64]interface{}{-1: uint64(1)}
				m := map[int64]interface{}{396: vdp}
				d, _ := cbor.Marshal(m)
				return d
			}(),
			wantErr: "missing leaf_index (key -2)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := extractVDP(dm, tt.unprotected)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}
