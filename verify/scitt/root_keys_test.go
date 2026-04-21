package scitt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// mustGenerateTestKey generates a P-256 key and returns the C2SP key parts.
func mustGenerateTestKey(t *testing.T) (string, string, string, *ecdsa.PublicKey) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P-256 key: %v", err)
	}

	spkiDer, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal SPKI: %v", err)
	}

	hash := sha256.Sum256(spkiDer)
	kidHex := hex.EncodeToString(hash[:4])
	spkiB64 := base64.StdEncoding.EncodeToString(spkiDer)
	name := "test-key"

	return name, kidHex, spkiB64, &priv.PublicKey
}

func TestParseC2SPKey(t *testing.T) {
	t.Parallel()

	name, kidHex, spkiB64, _ := mustGenerateTestKey(t)

	// Build a key with 0x02 C2SP type-byte prefix.
	privForPrefix, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key for prefix test: %v", err)
	}
	spkiDerPrefix, err := x509.MarshalPKIXPublicKey(&privForPrefix.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal SPKI for prefix test: %v", err)
	}
	prefixHash := sha256.Sum256(spkiDerPrefix)
	prefixKidHex := hex.EncodeToString(prefixHash[:4])
	prefixSpkiB64 := base64.StdEncoding.EncodeToString(append([]byte{0x02}, spkiDerPrefix...))

	// Build an ed25519 key for non-ECDSA test.
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	edSpkiDer, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatalf("failed to marshal ed25519 SPKI: %v", err)
	}
	edHash := sha256.Sum256(edSpkiDer)
	edKidHex := hex.EncodeToString(edHash[:4])
	edSpkiB64 := base64.StdEncoding.EncodeToString(edSpkiDer)

	// Build a P-384 key for non-P256 test.
	privP384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P-384 key: %v", err)
	}
	p384SpkiDer, err := x509.MarshalPKIXPublicKey(&privP384.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal P-384 SPKI: %v", err)
	}
	p384Hash := sha256.Sum256(p384SpkiDer)
	p384KidHex := hex.EncodeToString(p384Hash[:4])
	p384SpkiB64 := base64.StdEncoding.EncodeToString(p384SpkiDer)

	// Build a kid that doesn't match the hash (swap first byte).
	mismatchKid := make([]byte, 4)
	raw, _ := hex.DecodeString(kidHex)
	copy(mismatchKid, raw)
	mismatchKid[0] ^= 0xFF
	mismatchKidHex := hex.EncodeToString(mismatchKid)

	tests := []struct {
		name    string
		input   string
		wantErr bool
		errType SignatureErrorType
	}{
		{
			name:    "valid key",
			input:   fmt.Sprintf("%s+%s+%s", name, kidHex, spkiB64),
			wantErr: false,
		},
		{
			name:    "wrong number of parts - two parts",
			input:   "name+kid",
			wantErr: true,
			errType: SigErrInvalidKeyFormat,
		},
		{
			name:    "wrong number of parts - one part",
			input:   "nameonly",
			wantErr: true,
			errType: SigErrInvalidKeyFormat,
		},
		{
			name:    "empty name",
			input:   fmt.Sprintf("+%s+%s", kidHex, spkiB64),
			wantErr: true,
			errType: SigErrInvalidKeyFormat,
		},
		{
			name:    "invalid hex in kid",
			input:   fmt.Sprintf("%s+zzzzzzzz+%s", name, spkiB64),
			wantErr: true,
			errType: SigErrInvalidKeyFormat,
		},
		{
			name:    "kid wrong length - 3 bytes",
			input:   fmt.Sprintf("%s+aabbcc+%s", name, spkiB64),
			wantErr: true,
			errType: SigErrInvalidKeyFormat,
		},
		{
			name:    "kid wrong length - 5 bytes",
			input:   fmt.Sprintf("%s+aabbccddee+%s", name, spkiB64),
			wantErr: true,
			errType: SigErrInvalidKeyFormat,
		},
		{
			name:    "invalid base64 in SPKI",
			input:   fmt.Sprintf("%s+%s+!!!invalid!!!", name, kidHex),
			wantErr: true,
			errType: SigErrInvalidKeyFormat,
		},
		{
			name:    "SPKI not a valid public key",
			input:   fmt.Sprintf("%s+%s+%s", name, kidHex, base64.StdEncoding.EncodeToString([]byte("not-a-real-key"))),
			wantErr: true,
			errType: SigErrInvalidPublicKey,
		},
		{
			name:    "with 0x02 C2SP type-byte prefix",
			input:   fmt.Sprintf("prefixed-key+%s+%s", prefixKidHex, prefixSpkiB64),
			wantErr: false,
		},
		{
			name:    "kid hash mismatch",
			input:   fmt.Sprintf("%s+%s+%s", name, mismatchKidHex, spkiB64),
			wantErr: true,
			errType: SigErrKeyHashMismatch,
		},
		{
			name:    "not ECDSA - ed25519 key",
			input:   fmt.Sprintf("ed-key+%s+%s", edKidHex, edSpkiB64),
			wantErr: true,
			errType: SigErrInvalidPublicKey,
		},
		{
			name:    "not P-256 - P-384 key",
			input:   fmt.Sprintf("p384-key+%s+%s", p384KidHex, p384SpkiB64),
			wantErr: true,
			errType: SigErrInvalidPublicKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseC2SPKey(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				var sigErr *SignatureError
				if !errors.As(err, &sigErr) {
					t.Fatalf("expected *SignatureError, got %T: %v", err, err)
				}
				if sigErr.Type != tt.errType {
					t.Errorf("error type = %d, want %d", sigErr.Type, tt.errType)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("expected non-nil TrustedKey")
			}
			if got.Key == nil {
				t.Fatal("expected non-nil Key in TrustedKey")
			}
		})
	}
}

func TestNewKeyStore(t *testing.T) {
	t.Parallel()

	name1, kid1Hex, spki1B64, _ := mustGenerateTestKey(t)
	_, kid2Hex, spki2B64, _ := mustGenerateTestKey(t)

	tests := []struct {
		name       string
		keyStrings []string
		wantLen    int
		wantErr    bool
	}{
		{
			name:       "empty input - valid empty store",
			keyStrings: []string{},
			wantLen:    0,
			wantErr:    false,
		},
		{
			name:       "single valid key",
			keyStrings: []string{fmt.Sprintf("%s+%s+%s", name1, kid1Hex, spki1B64)},
			wantLen:    1,
			wantErr:    false,
		},
		{
			name: "multiple valid keys",
			keyStrings: []string{
				fmt.Sprintf("key-1+%s+%s", kid1Hex, spki1B64),
				fmt.Sprintf("key-2+%s+%s", kid2Hex, spki2B64),
			},
			wantLen: 2,
			wantErr: false,
		},
		{
			name: "duplicate kid - should error",
			keyStrings: []string{
				fmt.Sprintf("key-1+%s+%s", kid1Hex, spki1B64),
				fmt.Sprintf("key-dup+%s+%s", kid1Hex, spki1B64),
			},
			wantErr: true,
		},
		{
			name:       "invalid key string - should error",
			keyStrings: []string{"bad-input"},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store, err := NewKeyStore(tt.keyStrings)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if store.Len() != tt.wantLen {
				t.Errorf("Len() = %d, want %d", store.Len(), tt.wantLen)
			}
		})
	}
}

func TestKeyStoreGet(t *testing.T) {
	t.Parallel()

	_, kidHex, spkiB64, expectedKey := mustGenerateTestKey(t)
	kidBytes, _ := hex.DecodeString(kidHex)
	var kid [4]byte
	copy(kid[:], kidBytes)

	store, err := NewKeyStore([]string{
		fmt.Sprintf("my-key+%s+%s", kidHex, spkiB64),
	})
	if err != nil {
		t.Fatalf("failed to create key store: %v", err)
	}

	tests := []struct {
		name    string
		kid     [4]byte
		wantErr bool
		errType SignatureErrorType
	}{
		{
			name:    "known kid - returns correct key",
			kid:     kid,
			wantErr: false,
		},
		{
			name:    "unknown kid - returns error",
			kid:     [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
			wantErr: true,
			errType: SigErrUnknownKeyID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := store.Get(tt.kid)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				var sigErr *SignatureError
				if !errors.As(err, &sigErr) {
					t.Fatalf("expected *SignatureError, got %T: %v", err, err)
				}
				if sigErr.Type != tt.errType {
					t.Errorf("error type = %d, want %d", sigErr.Type, tt.errType)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("expected non-nil TrustedKey")
			}
			if got.Name != "my-key" {
				t.Errorf("Name = %q, want %q", got.Name, "my-key")
			}
			if got.Kid != kid {
				t.Errorf("Kid = %x, want %x", got.Kid, kid)
			}
			if !got.Key.Equal(expectedKey) {
				t.Error("Key does not match expected key")
			}
		})
	}
}

func TestKeyStoreIsEmpty(t *testing.T) {
	t.Parallel()

	name, kidHex, spkiB64, _ := mustGenerateTestKey(t)

	nonEmptyStore, err := NewKeyStore([]string{
		fmt.Sprintf("%s+%s+%s", name, kidHex, spkiB64),
	})
	if err != nil {
		t.Fatalf("failed to create non-empty store: %v", err)
	}

	emptyStore, err := NewKeyStore([]string{})
	if err != nil {
		t.Fatalf("failed to create empty store: %v", err)
	}

	tests := []struct {
		name  string
		store *KeyStore
		want  bool
	}{
		{
			name:  "empty store returns true",
			store: emptyStore,
			want:  true,
		},
		{
			name:  "non-empty store returns false",
			store: nonEmptyStore,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.store.IsEmpty(); got != tt.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyStoreMergeFrom(t *testing.T) {
	t.Parallel()

	name1, kid1Hex, spki1B64, _ := mustGenerateTestKey(t)
	name2, kid2Hex, spki2B64, _ := mustGenerateTestKey(t)
	name3, kid3Hex, spki3B64, _ := mustGenerateTestKey(t)

	key1Str := fmt.Sprintf("%s+%s+%s", name1, kid1Hex, spki1B64)
	key2Str := fmt.Sprintf("%s+%s+%s", name2, kid2Hex, spki2B64)
	key3Str := fmt.Sprintf("%s+%s+%s", name3, kid3Hex, spki3B64)

	// Build a collision string: same kid as key1 but different name.
	collisionStr := fmt.Sprintf("different-name+%s+%s", kid1Hex, spki1B64)

	// Build a same-kid-same-name duplicate string.
	dupStr := fmt.Sprintf("%s+%s+%s", name1, kid1Hex, spki1B64)

	tests := []struct {
		name                   string
		initialKeys            []string
		mergeKeys              []string
		wantAdded              int
		wantSkipped            int
		wantSkippedUnparseable int
		wantSkippedDuplicate   int
		wantCollisions         int
		wantTotalLen           int
	}{
		{
			name:                   "merge into empty store with no keys",
			initialKeys:            []string{},
			mergeKeys:              []string{},
			wantAdded:              0,
			wantSkipped:            0,
			wantSkippedUnparseable: 0,
			wantSkippedDuplicate:   0,
			wantCollisions:         0,
			wantTotalLen:           0,
		},
		{
			name:                   "merge new keys into empty store",
			initialKeys:            []string{},
			mergeKeys:              []string{key1Str, key2Str},
			wantAdded:              2,
			wantSkipped:            0,
			wantSkippedUnparseable: 0,
			wantSkippedDuplicate:   0,
			wantCollisions:         0,
			wantTotalLen:           2,
		},
		{
			name:                   "merge new key into non-empty store",
			initialKeys:            []string{key1Str},
			mergeKeys:              []string{key2Str},
			wantAdded:              1,
			wantSkipped:            0,
			wantSkippedUnparseable: 0,
			wantSkippedDuplicate:   0,
			wantCollisions:         0,
			wantTotalLen:           2,
		},
		{
			name:                   "merge duplicate kid same name - skipped no collision",
			initialKeys:            []string{key1Str},
			mergeKeys:              []string{dupStr},
			wantAdded:              0,
			wantSkipped:            1,
			wantSkippedUnparseable: 0,
			wantSkippedDuplicate:   1,
			wantCollisions:         0,
			wantTotalLen:           1,
		},
		{
			name:                   "merge duplicate kid different name - collision",
			initialKeys:            []string{key1Str},
			mergeKeys:              []string{collisionStr},
			wantAdded:              0,
			wantSkipped:            1,
			wantSkippedUnparseable: 0,
			wantSkippedDuplicate:   1,
			wantCollisions:         1,
			wantTotalLen:           1,
		},
		{
			name:                   "merge with invalid key string - skipped",
			initialKeys:            []string{key1Str},
			mergeKeys:              []string{"bad-input"},
			wantAdded:              0,
			wantSkipped:            1,
			wantSkippedUnparseable: 1,
			wantSkippedDuplicate:   0,
			wantCollisions:         0,
			wantTotalLen:           1,
		},
		{
			name:                   "merge mix of valid new and invalid keys",
			initialKeys:            []string{key1Str},
			mergeKeys:              []string{key2Str, "bad-input", key3Str},
			wantAdded:              2,
			wantSkipped:            1,
			wantSkippedUnparseable: 1,
			wantSkippedDuplicate:   0,
			wantCollisions:         0,
			wantTotalLen:           3,
		},
		{
			name:                   "merge mix of valid new and collision and invalid",
			initialKeys:            []string{key1Str},
			mergeKeys:              []string{key2Str, collisionStr, "bad-input"},
			wantAdded:              1,
			wantSkipped:            2,
			wantSkippedUnparseable: 1,
			wantSkippedDuplicate:   1,
			wantCollisions:         1,
			wantTotalLen:           2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			original, err := NewKeyStore(tt.initialKeys)
			if err != nil {
				t.Fatalf("failed to create initial store: %v", err)
			}
			originalLen := original.Len()

			merged, result := original.MergeFrom(tt.mergeKeys)

			if result.Added != tt.wantAdded {
				t.Errorf("Added = %d, want %d", result.Added, tt.wantAdded)
			}
			if result.Skipped != tt.wantSkipped {
				t.Errorf("Skipped = %d, want %d", result.Skipped, tt.wantSkipped)
			}
			if result.SkippedUnparseable != tt.wantSkippedUnparseable {
				t.Errorf("SkippedUnparseable = %d, want %d", result.SkippedUnparseable, tt.wantSkippedUnparseable)
			}
			if result.SkippedDuplicate != tt.wantSkippedDuplicate {
				t.Errorf("SkippedDuplicate = %d, want %d", result.SkippedDuplicate, tt.wantSkippedDuplicate)
			}
			if len(result.Collisions) != tt.wantCollisions {
				t.Errorf("Collisions count = %d, want %d", len(result.Collisions), tt.wantCollisions)
			}
			if merged.Len() != tt.wantTotalLen {
				t.Errorf("merged Len() = %d, want %d", merged.Len(), tt.wantTotalLen)
			}
			// Original store must be unchanged (immutability).
			if original.Len() != originalLen {
				t.Errorf("original Len() changed from %d to %d", originalLen, original.Len())
			}
		})
	}
}

func TestKeyStoreMergeFromPreservesOriginalKeys(t *testing.T) {
	t.Parallel()

	_, kid1Hex, spki1B64, expectedKey1 := mustGenerateTestKey(t)
	_, kid2Hex, spki2B64, _ := mustGenerateTestKey(t)

	key1Str := fmt.Sprintf("original-key+%s+%s", kid1Hex, spki1B64)
	key2Str := fmt.Sprintf("new-key+%s+%s", kid2Hex, spki2B64)

	kid1Bytes, _ := hex.DecodeString(kid1Hex)
	var kid1 [4]byte
	copy(kid1[:], kid1Bytes)

	original, err := NewKeyStore([]string{key1Str})
	if err != nil {
		t.Fatalf("failed to create original store: %v", err)
	}

	merged, _ := original.MergeFrom([]string{key2Str})

	// Verify original key is accessible in merged store with correct data.
	got, err := merged.Get(kid1)
	if err != nil {
		t.Fatalf("failed to get original key from merged store: %v", err)
	}
	if got.Name != "original-key" {
		t.Errorf("Name = %q, want %q", got.Name, "original-key")
	}
	if !got.Key.Equal(expectedKey1) {
		t.Error("original key in merged store does not match expected key")
	}
}

func TestKeyStoreImplementsKeyLookup(t *testing.T) {
	t.Parallel()
	var _ KeyLookup = (*KeyStore)(nil)
}

// TestKeyStoreLookupCaching validates that the KeyStore is effectively "cached" — once created,
// repeated Get calls with the same kid return the same key without any external calls.
// The KeyStore is immutable, so "caching" means creating it once and reusing the same store.
func TestKeyStoreLookupCaching(t *testing.T) { //nolint:tparallel // subtests share firstResult state
	t.Parallel()

	_, kidHex, spkiB64, _ := mustGenerateTestKey(t)
	kidBytes, _ := hex.DecodeString(kidHex)
	var kid [4]byte
	copy(kid[:], kidBytes)

	store, err := NewKeyStore([]string{
		fmt.Sprintf("cached-key+%s+%s", kidHex, spkiB64),
	})
	if err != nil {
		t.Fatalf("failed to create key store: %v", err)
	}

	tests := []struct {
		name     string
		callNum  int
		kid      [4]byte
		wantName string
	}{
		{name: "first lookup", callNum: 1, kid: kid, wantName: "cached-key"},
		{name: "second lookup", callNum: 2, kid: kid, wantName: "cached-key"},
		{name: "third lookup", callNum: 3, kid: kid, wantName: "cached-key"},
	}

	var firstResult *TrustedKey

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := store.Get(tt.kid)
			if err != nil {
				t.Fatalf("Get(%x) call %d returned error: %v", tt.kid, tt.callNum, err)
			}
			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if got.Kid != tt.kid {
				t.Errorf("Kid = %x, want %x", got.Kid, tt.kid)
			}
			// Verify the same underlying key is returned each time (pointer equality on the Key field).
			if firstResult == nil {
				firstResult = got
			} else if !got.Key.Equal(firstResult.Key) {
				t.Errorf("call %d returned different key than first call", tt.callNum)
			}
		})
	}
}
