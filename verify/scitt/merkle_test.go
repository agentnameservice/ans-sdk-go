package scitt

import (
	"crypto/sha256"
	"errors"
	"testing"
)

// testLeafHash computes SHA-256(0x00 || data) per RFC 9162.
func testLeafHash(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// testNodeHash computes SHA-256(0x01 || left || right) per RFC 9162.
func testNodeHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// buildMerkleRoot builds a complete Merkle tree root from leaves for test data generation.
// This follows RFC 9162 section 2.1: the tree is built left-complete.
func buildMerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	// Split: left subtree is the largest power of 2 less than n
	k := largestPowerOf2LessThan(uint64(len(leaves)))
	left := buildMerkleRoot(leaves[:k])
	right := buildMerkleRoot(leaves[k:])
	return testNodeHash(left, right)
}

// buildInclusionPath builds the inclusion proof path for a given leaf index.
func buildInclusionPath(leaves [][32]byte, index uint64) [][32]byte {
	if len(leaves) == 1 {
		return nil
	}
	k := largestPowerOf2LessThan(uint64(len(leaves)))
	if index < k {
		path := buildInclusionPath(leaves[:k], index)
		rightRoot := buildMerkleRoot(leaves[k:])
		return append(path, rightRoot)
	}
	path := buildInclusionPath(leaves[k:], index-k)
	leftRoot := buildMerkleRoot(leaves[:k])
	return append(path, leftRoot)
}

// largestPowerOf2LessThan returns the largest power of 2 strictly less than n.
func largestPowerOf2LessThan(n uint64) uint64 {
	if n <= 1 {
		return 0
	}
	k := uint64(1)
	for k*2 < n {
		k *= 2
	}
	return k
}

// makeLeaves generates leaf hashes from byte slices labeled 0..n-1.
func makeLeaves(n int) [][32]byte {
	leaves := make([][32]byte, n)
	for i := range n {
		leaves[i] = testLeafHash([]byte{byte(i)})
	}
	return leaves
}

func TestComputeLeafHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
		want [32]byte
	}{
		{
			name: "deterministic: same input same output",
			data: []byte("hello"),
			want: testLeafHash([]byte("hello")),
		},
		{
			name: "empty input",
			data: []byte{},
			want: testLeafHash([]byte{}),
		},
		{
			name: "different input produces different hash",
			data: []byte("world"),
			want: testLeafHash([]byte("world")),
		},
		{
			name: "single byte",
			data: []byte{0x42},
			want: testLeafHash([]byte{0x42}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ComputeLeafHash(tt.data)
			if got != tt.want {
				t.Errorf("ComputeLeafHash(%x) = %x, want %x", tt.data, got, tt.want)
			}
		})
	}
}

func TestComputeLeafHashDeterministic(t *testing.T) {
	t.Parallel()

	data := []byte("determinism check")
	first := ComputeLeafHash(data)
	for i := range 100 {
		if got := ComputeLeafHash(data); got != first {
			t.Fatalf("ComputeLeafHash not deterministic on iteration %d: got %x, want %x", i, got, first)
		}
	}
}

func TestComputeNodeHash(t *testing.T) {
	t.Parallel()

	left := testLeafHash([]byte("A"))
	right := testLeafHash([]byte("B"))

	tests := []struct {
		name  string
		left  [32]byte
		right [32]byte
		want  [32]byte
	}{
		{
			name:  "deterministic: same inputs same output",
			left:  left,
			right: right,
			want:  testNodeHash(left, right),
		},
		{
			name:  "same left and right",
			left:  left,
			right: left,
			want:  testNodeHash(left, left),
		},
		{
			name:  "zero hashes",
			left:  [32]byte{},
			right: [32]byte{},
			want:  testNodeHash([32]byte{}, [32]byte{}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ComputeNodeHash(tt.left, tt.right)
			if got != tt.want {
				t.Errorf("ComputeNodeHash(%x, %x) = %x, want %x", tt.left, tt.right, got, tt.want)
			}
		})
	}
}

func TestComputeNodeHashNotCommutative(t *testing.T) {
	t.Parallel()

	a := testLeafHash([]byte("A"))
	b := testLeafHash([]byte("B"))

	ab := ComputeNodeHash(a, b)
	ba := ComputeNodeHash(b, a)

	if ab == ba {
		t.Error("ComputeNodeHash should NOT be commutative: H(A||B) == H(B||A)")
	}
}

func TestComputeNodeHashDeterministic(t *testing.T) {
	t.Parallel()

	left := testLeafHash([]byte("left"))
	right := testLeafHash([]byte("right"))
	first := ComputeNodeHash(left, right)
	for i := range 100 {
		if got := ComputeNodeHash(left, right); got != first {
			t.Fatalf("ComputeNodeHash not deterministic on iteration %d", i)
		}
	}
}

func TestMerkleWalkInclusionPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		data      []byte
		leafIndex uint64
		treeSize  uint64
		hashPath  [][32]byte
		wantRoot  [32]byte
		wantErr   bool
		errType   MerkleErrorType
	}{
		// --- Single-element tree ---
		{
			name:      "single element tree: size=1 index=0 empty path",
			data:      []byte{0},
			leafIndex: 0,
			treeSize:  1,
			hashPath:  nil,
			wantRoot:  buildMerkleRoot(makeLeaves(1)),
		},
		// --- Two-element tree ---
		{
			name:      "two element tree: index=0",
			data:      []byte{0},
			leafIndex: 0,
			treeSize:  2,
			hashPath:  buildInclusionPath(makeLeaves(2), 0),
			wantRoot:  buildMerkleRoot(makeLeaves(2)),
		},
		{
			name:      "two element tree: index=1",
			data:      []byte{1},
			leafIndex: 1,
			treeSize:  2,
			hashPath:  buildInclusionPath(makeLeaves(2), 1),
			wantRoot:  buildMerkleRoot(makeLeaves(2)),
		},
		// --- Three-element tree ---
		{
			name:      "three element tree: index=0",
			data:      []byte{0},
			leafIndex: 0,
			treeSize:  3,
			hashPath:  buildInclusionPath(makeLeaves(3), 0),
			wantRoot:  buildMerkleRoot(makeLeaves(3)),
		},
		{
			name:      "three element tree: index=1",
			data:      []byte{1},
			leafIndex: 1,
			treeSize:  3,
			hashPath:  buildInclusionPath(makeLeaves(3), 1),
			wantRoot:  buildMerkleRoot(makeLeaves(3)),
		},
		{
			name:      "three element tree: index=2",
			data:      []byte{2},
			leafIndex: 2,
			treeSize:  3,
			hashPath:  buildInclusionPath(makeLeaves(3), 2),
			wantRoot:  buildMerkleRoot(makeLeaves(3)),
		},
		// --- Four-element tree ---
		{
			name:      "four element tree: index=0",
			data:      []byte{0},
			leafIndex: 0,
			treeSize:  4,
			hashPath:  buildInclusionPath(makeLeaves(4), 0),
			wantRoot:  buildMerkleRoot(makeLeaves(4)),
		},
		{
			name:      "four element tree: index=2",
			data:      []byte{2},
			leafIndex: 2,
			treeSize:  4,
			hashPath:  buildInclusionPath(makeLeaves(4), 2),
			wantRoot:  buildMerkleRoot(makeLeaves(4)),
		},
		{
			name:      "four element tree: index=3",
			data:      []byte{3},
			leafIndex: 3,
			treeSize:  4,
			hashPath:  buildInclusionPath(makeLeaves(4), 3),
			wantRoot:  buildMerkleRoot(makeLeaves(4)),
		},
		// --- Seven-element tree ---
		{
			name:      "seven element tree: index=0",
			data:      []byte{0},
			leafIndex: 0,
			treeSize:  7,
			hashPath:  buildInclusionPath(makeLeaves(7), 0),
			wantRoot:  buildMerkleRoot(makeLeaves(7)),
		},
		{
			name:      "seven element tree: index=6",
			data:      []byte{6},
			leafIndex: 6,
			treeSize:  7,
			hashPath:  buildInclusionPath(makeLeaves(7), 6),
			wantRoot:  buildMerkleRoot(makeLeaves(7)),
		},
		// --- Eight-element tree (power of 2) ---
		{
			name:      "eight element tree: index=0",
			data:      []byte{0},
			leafIndex: 0,
			treeSize:  8,
			hashPath:  buildInclusionPath(makeLeaves(8), 0),
			wantRoot:  buildMerkleRoot(makeLeaves(8)),
		},
		{
			name:      "eight element tree: index=7",
			data:      []byte{7},
			leafIndex: 7,
			treeSize:  8,
			hashPath:  buildInclusionPath(makeLeaves(8), 7),
			wantRoot:  buildMerkleRoot(makeLeaves(8)),
		},
		// --- Fifteen-element tree ---
		{
			name:      "fifteen element tree: index=0",
			data:      []byte{0},
			leafIndex: 0,
			treeSize:  15,
			hashPath:  buildInclusionPath(makeLeaves(15), 0),
			wantRoot:  buildMerkleRoot(makeLeaves(15)),
		},
		{
			name:      "fifteen element tree: index=14",
			data:      []byte{14},
			leafIndex: 14,
			treeSize:  15,
			hashPath:  buildInclusionPath(makeLeaves(15), 14),
			wantRoot:  buildMerkleRoot(makeLeaves(15)),
		},
		// --- Sixteen-element tree (power of 2) ---
		{
			name:      "sixteen element tree: index=0",
			data:      []byte{0},
			leafIndex: 0,
			treeSize:  16,
			hashPath:  buildInclusionPath(makeLeaves(16), 0),
			wantRoot:  buildMerkleRoot(makeLeaves(16)),
		},
		{
			name:      "sixteen element tree: index=15",
			data:      []byte{15},
			leafIndex: 15,
			treeSize:  16,
			hashPath:  buildInclusionPath(makeLeaves(16), 15),
			wantRoot:  buildMerkleRoot(makeLeaves(16)),
		},
		// --- Error: tree size 0 ---
		{
			name:      "error: tree size zero",
			data:      []byte{0},
			leafIndex: 0,
			treeSize:  0,
			hashPath:  nil,
			wantErr:   true,
			errType:   MerkleErrInvalidProof,
		},
		// --- Error: leaf index >= tree size ---
		{
			name:      "error: leaf index equals tree size",
			data:      []byte{0},
			leafIndex: 5,
			treeSize:  5,
			hashPath:  nil,
			wantErr:   true,
			errType:   MerkleErrInvalidProof,
		},
		{
			name:      "error: leaf index exceeds tree size",
			data:      []byte{0},
			leafIndex: 10,
			treeSize:  5,
			hashPath:  nil,
			wantErr:   true,
			errType:   MerkleErrInvalidProof,
		},
		// --- Error: path too long ---
		{
			name:      "error: path exceeds MaxHashPathLen",
			data:      []byte{0},
			leafIndex: 0,
			treeSize:  2,
			hashPath:  make([][32]byte, MaxHashPathLen+1),
			wantErr:   true,
			errType:   MerkleErrInvalidProof,
		},
		// --- Error: excess path elements ---
		{
			name:      "error: excess path elements for single leaf tree",
			data:      []byte{0},
			leafIndex: 0,
			treeSize:  1,
			hashPath:  [][32]byte{{}},
			wantErr:   true,
			errType:   MerkleErrInvalidProof,
		},
		// --- Error: insufficient path elements ---
		{
			name:      "error: insufficient path elements for two leaf tree",
			data:      []byte{0},
			leafIndex: 0,
			treeSize:  2,
			hashPath:  nil,
			wantErr:   true,
			errType:   MerkleErrInvalidProof,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := WalkInclusionPath(tt.data, tt.leafIndex, tt.treeSize, tt.hashPath)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				var merkleErr *MerkleError
				if !errors.As(err, &merkleErr) {
					t.Fatalf("expected *MerkleError, got %T: %v", err, err)
				}
				if merkleErr.Type != tt.errType {
					t.Errorf("error type = %v, want %v", merkleErr.Type, tt.errType)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantRoot {
				t.Errorf("root = %x, want %x", got, tt.wantRoot)
			}
		})
	}
}

func TestMerkleVerifyInclusion(t *testing.T) {
	t.Parallel()

	leaves := makeLeaves(8)
	root := buildMerkleRoot(leaves)
	wrongRoot := [32]byte{0xFF}

	tests := []struct {
		name         string
		data         []byte
		leafIndex    uint64
		treeSize     uint64
		hashPath     [][32]byte
		expectedRoot [32]byte
		wantErr      bool
		errType      MerkleErrorType
	}{
		{
			name:         "correct root: success",
			data:         []byte{0},
			leafIndex:    0,
			treeSize:     8,
			hashPath:     buildInclusionPath(leaves, 0),
			expectedRoot: root,
		},
		{
			name:         "correct root: last leaf",
			data:         []byte{7},
			leafIndex:    7,
			treeSize:     8,
			hashPath:     buildInclusionPath(leaves, 7),
			expectedRoot: root,
		},
		{
			name:         "wrong root: MerkleErrRootMismatch",
			data:         []byte{0},
			leafIndex:    0,
			treeSize:     8,
			hashPath:     buildInclusionPath(leaves, 0),
			expectedRoot: wrongRoot,
			wantErr:      true,
			errType:      MerkleErrRootMismatch,
		},
		{
			name:         "tampered hash path: wrong root",
			data:         []byte{0},
			leafIndex:    0,
			treeSize:     8,
			hashPath:     func() [][32]byte { p := buildInclusionPath(leaves, 0); p[0] = [32]byte{0xDE}; return p }(),
			expectedRoot: root,
			wantErr:      true,
			errType:      MerkleErrRootMismatch,
		},
		{
			name:         "structural error propagated from WalkInclusionPath",
			data:         []byte{0},
			leafIndex:    0,
			treeSize:     0,
			hashPath:     nil,
			expectedRoot: root,
			wantErr:      true,
			errType:      MerkleErrInvalidProof,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := VerifyMerkleInclusion(tt.data, tt.leafIndex, tt.treeSize, tt.hashPath, tt.expectedRoot)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				var merkleErr *MerkleError
				if !errors.As(err, &merkleErr) {
					t.Fatalf("expected *MerkleError, got %T: %v", err, err)
				}
				if merkleErr.Type != tt.errType {
					t.Errorf("error type = %v, want %v", merkleErr.Type, tt.errType)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestMerkleAllIndicesInTree(t *testing.T) {
	t.Parallel()

	sizes := []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16}

	for _, size := range sizes {
		leaves := makeLeaves(size)
		root := buildMerkleRoot(leaves)

		for idx := range size {
			t.Run("", func(t *testing.T) {
				t.Parallel()
				path := buildInclusionPath(leaves, uint64(idx))
				err := VerifyMerkleInclusion([]byte{byte(idx)}, uint64(idx), uint64(size), path, root)
				if err != nil {
					t.Errorf("size=%d index=%d: unexpected error: %v", size, idx, err)
				}
			})
		}
	}
}
