package scitt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// C2SP key format constants.
const (
	c2spKeyParts = 3 // number of '+'-separated parts in a C2SP key string
	c2spKidLen   = 4 // key ID length in bytes
)

// TrustedKey holds a named ECDSA P-256 public key with its 4-byte key ID.
type TrustedKey struct {
	Name string
	Kid  [4]byte
	Key  *ecdsa.PublicKey
}

// KeyLookup retrieves a trusted key by its 4-byte key ID.
type KeyLookup interface {
	Get(kid [4]byte) (*TrustedKey, error)
}

// KeyStore is an immutable store of trusted ECDSA P-256 keys keyed by kid.
type KeyStore struct {
	keys map[[4]byte]TrustedKey
}

// NewKeyStore parses a slice of C2SP key strings and returns an immutable key store.
// Returns an error if any key fails to parse or if duplicate key IDs are found.
func NewKeyStore(keyStrings []string) (*KeyStore, error) {
	keys := make(map[[4]byte]TrustedKey, len(keyStrings))

	for _, s := range keyStrings {
		tk, err := ParseC2SPKey(s)
		if err != nil {
			return nil, err
		}
		if _, exists := keys[tk.Kid]; exists {
			return nil, &SignatureError{
				Type:    SigErrInvalidKeyFormat,
				Kid:     tk.Kid,
				Message: fmt.Sprintf("duplicate key ID %x", tk.Kid),
			}
		}
		keys[tk.Kid] = *tk
	}

	return &KeyStore{keys: keys}, nil
}

// ParseC2SPKey parses a C2SP-formatted key string: "name+hex_kid+base64_spki_der".
func ParseC2SPKey(s string) (*TrustedKey, error) {
	parts := strings.SplitN(s, "+", c2spKeyParts)
	if len(parts) != c2spKeyParts {
		return nil, &SignatureError{
			Type:    SigErrInvalidKeyFormat,
			Message: fmt.Sprintf("expected %d '+'-separated parts, got %d", c2spKeyParts, len(parts)),
		}
	}

	name := parts[0]
	if name == "" {
		return nil, &SignatureError{
			Type:    SigErrInvalidKeyFormat,
			Message: "key name must not be empty",
		}
	}

	kidBytes, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, &SignatureError{
			Type:    SigErrInvalidKeyFormat,
			Message: fmt.Sprintf("invalid hex kid %q", parts[1]),
			Cause:   err,
		}
	}
	if len(kidBytes) != c2spKidLen {
		return nil, &SignatureError{
			Type:    SigErrInvalidKeyFormat,
			Message: fmt.Sprintf("kid must be %d bytes, got %d", c2spKidLen, len(kidBytes)),
		}
	}

	var kid [4]byte
	copy(kid[:], kidBytes)

	spkiRaw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, &SignatureError{
			Type:    SigErrInvalidKeyFormat,
			Message: fmt.Sprintf("invalid base64 SPKI %q", parts[2]),
			Cause:   err,
		}
	}

	// Strip C2SP type-byte prefix (0x02) if present.
	spkiDer := spkiRaw
	if len(spkiDer) > 0 && spkiDer[0] == 0x02 {
		spkiDer = spkiDer[1:]
	}

	pub, err := x509.ParsePKIXPublicKey(spkiDer)
	if err != nil {
		return nil, &SignatureError{
			Type:    SigErrInvalidPublicKey,
			Message: "failed to parse SPKI DER as public key",
			Cause:   err,
		}
	}

	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, &SignatureError{
			Type:    SigErrInvalidPublicKey,
			Message: fmt.Sprintf("expected *ecdsa.PublicKey, got %T", pub),
		}
	}

	if ecKey.Curve != elliptic.P256() {
		return nil, &SignatureError{
			Type:    SigErrInvalidPublicKey,
			Message: fmt.Sprintf("expected P-256 curve, got %s", ecKey.Curve.Params().Name),
		}
	}

	hash := sha256.Sum256(spkiDer)
	var computedKid [4]byte
	copy(computedKid[:], hash[:4])

	if computedKid != kid {
		return nil, &SignatureError{
			Type:    SigErrKeyHashMismatch,
			Kid:     kid,
			Message: fmt.Sprintf("kid %x does not match SHA-256(SPKI) prefix %x", kid, computedKid),
		}
	}

	return &TrustedKey{
		Name: name,
		Kid:  kid,
		Key:  ecKey,
	}, nil
}

// Get looks up a trusted key by its 4-byte key ID.
func (s *KeyStore) Get(kid [4]byte) (*TrustedKey, error) {
	tk, ok := s.keys[kid]
	if !ok {
		return nil, &SignatureError{
			Type:    SigErrUnknownKeyID,
			Kid:     kid,
			Message: "unknown key ID",
		}
	}
	return &tk, nil
}

// Len returns the number of keys in the store.
func (s *KeyStore) Len() int {
	return len(s.keys)
}

// IsEmpty returns true if the store contains no keys.
func (s *KeyStore) IsEmpty() bool {
	return len(s.keys) == 0
}

// MergeResult reports the outcome of a MergeFrom operation.
//
// SkippedUnparseable counts input strings that failed to parse as C2SP keys.
// A non-zero value indicates a potentially malformed key server response and
// warrants operator attention.
//
// SkippedDuplicate counts well-formed keys that collided with an existing kid
// in the store. This is benign during a re-scan of the same key set.
//
// Skipped is the sum of both counters, retained for backward compatibility.
type MergeResult struct {
	Added              int
	Skipped            int      // sum of SkippedUnparseable + SkippedDuplicate
	SkippedUnparseable int      // strings that failed ParseC2SPKey
	SkippedDuplicate   int      // well-formed keys whose kid already existed
	Collisions         []string // kid hex strings that collided with a different name
}

// MergeFrom returns a new KeyStore containing all keys from s plus any
// successfully parsed keys from keyStrings. Existing keys (same kid) are
// preserved; duplicates and unparseable strings are skipped. The original
// store is never modified.
func (s *KeyStore) MergeFrom(keyStrings []string) (*KeyStore, MergeResult) {
	merged := make(map[[4]byte]TrustedKey, len(s.keys)+len(keyStrings))
	for kid, tk := range s.keys {
		merged[kid] = tk
	}

	var result MergeResult

	for _, ks := range keyStrings {
		tk, err := ParseC2SPKey(ks)
		if err != nil {
			result.SkippedUnparseable++
			result.Skipped++
			continue
		}

		if existing, exists := merged[tk.Kid]; exists {
			if existing.Name != tk.Name {
				result.Collisions = append(result.Collisions, fmt.Sprintf("%x", tk.Kid))
			}
			result.SkippedDuplicate++
			result.Skipped++
			continue
		}

		merged[tk.Kid] = *tk
		result.Added++
	}

	return &KeyStore{keys: merged}, result
}
