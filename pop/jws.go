package pop

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// Compact-JWS ES256 mechanics for DPoP proofs.
//
// This is hand-rolled on the standard library rather than a JOSE dependency,
// matching the SDK's deliberate hand-rolled COSE in verify/scitt/cose.go and
// keeping the module dependency-free. JWS ES256 signatures are raw R‖S — the
// same IEEE P1363 form that scitt.verifyECDSA converts to DER for COSE; here we
// skip the DER round-trip and call ecdsa.Verify directly, because JOSE wants
// raw R‖S, not ASN.1. (NOTE: keep the curve/length policy here in sync with
// verify/scitt/status_token.go verifyECDSA and cose.go if either changes.)
const (
	// p256SigLen is the fixed length of a P-256 ES256 signature (R‖S).
	p256SigLen = 64
	// coordLen is the fixed big-endian length of each of R and S for P-256.
	coordLen = 32
	// compactJWSSegments is the number of dot-separated parts in a compact JWS.
	compactJWSSegments = 3
)

// b64urlEncode encodes b with base64url, no padding (RFC 7515 §2 / RFC 4648 §5).
func b64urlEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// b64urlDecode decodes a base64url segment. RawURLEncoding rejects padding and
// the std-base64 '+'/'/' alphabet, so a value encoded any other way fails here
// rather than being silently re-interpreted.
func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// signES256 signs signingInput with an ECDSA P-256 key and returns the
// base64url-encoded fixed-width R‖S signature. R and S are left-padded to
// 32 bytes via FillBytes (a short big-endian integer must not shorten the
// signature, or verifiers that length-check would reject it).
func signES256(key *ecdsa.PrivateKey, signingInput []byte) (string, error) {
	digest := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", wrapErr(ErrSignatureInvalid, "ecdsa sign", err)
	}
	sig := make([]byte, p256SigLen)
	r.FillBytes(sig[:coordLen])
	s.FillBytes(sig[coordLen:])
	return b64urlEncode(sig), nil
}

// verifyES256 verifies a base64url R‖S signature over signingInput under pub.
// It enforces the exact 64-byte length before splitting so a truncated or
// over-long signature cannot reach the big.Int decode.
func verifyES256(pub *ecdsa.PublicKey, signingInput []byte, sigB64 string) error {
	sig, err := b64urlDecode(sigB64)
	if err != nil {
		return wrapErr(ErrMalformedProof, "signature base64url decode", err)
	}
	if len(sig) != p256SigLen {
		return newErr(ErrSignatureInvalid,
			fmt.Sprintf("signature must be %d bytes (R‖S), got %d", p256SigLen, len(sig)))
	}
	r := new(big.Int).SetBytes(sig[:coordLen])
	s := new(big.Int).SetBytes(sig[coordLen:])
	digest := sha256.Sum256(signingInput)
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return newErr(ErrSignatureInvalid, "ECDSA signature verification failed")
	}
	return nil
}

// splitCompactJWS splits "header.payload.signature" into its three non-empty
// base64url segments.
func splitCompactJWS(token string) (string, string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != compactJWSSegments {
		return "", "", "", newErr(ErrMalformedProof,
			fmt.Sprintf("compact JWS must have %d segments, got %d", compactJWSSegments, len(parts)))
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", newErr(ErrMalformedProof, "compact JWS has an empty segment")
	}
	return parts[0], parts[1], parts[2], nil
}

// jwsSigningInput returns the exact ASCII bytes (header.payload) that are
// signed and verified — built from the received segments verbatim, never
// re-serialized, so verification runs over the bytes the signer signed.
func jwsSigningInput(headerB64, payloadB64 string) []byte {
	return []byte(headerB64 + "." + payloadB64)
}
