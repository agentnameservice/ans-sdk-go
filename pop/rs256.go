package pop

// RSA-THROWAWAY(remove when prod supports ES256): this entire file is a THROWAWAY RS256
// opt-in. The profile is ES256-only by design (see doc.go); this exists solely
// so the A2A demo can authenticate against prod (api.godaddy.com), which today
// issues only RSA identity certificates. RS256 is reachable ONLY through
// NewRSASigner (signing) and WithAllowRSA (verification); the default path still
// rejects RS256 as a downgrade. Delete this file and the call sites tagged with
// the same marker once prod issues P-256 identity certs.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
)

const (
	// algRS256 is the JOSE alg for RSASSA-PKCS1-v1_5 with SHA-256.
	algRS256 = "RS256"
	// jwkKtyRSA is the RSA key type (RFC 7518 §6.3).
	jwkKtyRSA = "RSA"
	// minRSABits is the smallest RSA modulus this path accepts, matching the
	// floor prod issues.
	minRSABits = 2048
	// maxRSAExp bounds the public exponent so a malformed jwk cannot force a
	// pathological verification cost.
	maxRSAExp = 1<<31 - 1
)

// signRS256 signs signingInput with an RSA key using RSASSA-PKCS1-v1_5 over
// SHA-256 and returns the base64url-encoded signature (JOSE "RS256"). Unlike
// ES256's R‖S form, an RSA signature is the raw modular exponentiation output.
func signRS256(key *rsa.PrivateKey, signingInput []byte) (string, error) {
	digest := sha256.Sum256(signingInput)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", wrapErr(ErrSignatureInvalid, "rsa sign", err)
	}
	return b64urlEncode(sig), nil
}

// verifyRS256 verifies a base64url RSASSA-PKCS1-v1_5 signature over signingInput
// under pub.
func verifyRS256(pub *rsa.PublicKey, signingInput []byte, sigB64 string) error {
	sig, err := b64urlDecode(sigB64)
	if err != nil {
		return wrapErr(ErrMalformedProof, "signature base64url decode", err)
	}
	digest := sha256.Sum256(signingInput)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return newErr(ErrSignatureInvalid, "RSA signature verification failed")
	}
	return nil
}

// rsaPublicJWK renders pub as an RSA JWK (RFC 7518 §6.3): exactly {kty, n, e}.
func rsaPublicJWK(pub *rsa.PublicKey) *proofJWK {
	e := big.NewInt(int64(pub.E)).Bytes()
	return &proofJWK{Kty: jwkKtyRSA, N: b64urlEncode(pub.N.Bytes()), E: b64urlEncode(e)}
}

// rsaThumbprint is the RFC 7638 §3 thumbprint of an RSA public key: SHA-256 over
// the required members only ({e, kty, n}), lexicographically ordered, no
// whitespace, base64url-encoded. Concatenation is safe because rsaPublicJWK
// guarantees n and e are base64url of raw integers, so neither can contain a
// quote or backslash (same argument as jwkThumbprint).
func rsaThumbprint(pub *rsa.PublicKey) string {
	j := rsaPublicJWK(pub)
	canonical := `{"e":"` + j.E + `","kty":"` + j.Kty + `","n":"` + j.N + `"}`
	h := sha256.Sum256([]byte(canonical))
	return b64urlEncode(h[:])
}

// rsaJWKKey validates j is an RSA JWK carrying exactly {kty, n, e} and returns
// the reconstructed public key. It rejects EC members so a proof cannot present
// a second key shape past the strict header decoder.
func rsaJWKKey(j *proofJWK) (*rsa.PublicKey, error) {
	if j.Kty != jwkKtyRSA {
		return nil, newErr(ErrUnsupportedAlg,
			fmt.Sprintf("jwk must be kty=%q, got kty=%q", jwkKtyRSA, echo(j.Kty)))
	}
	if j.Crv != "" || j.X != "" || j.Y != "" {
		return nil, newErr(ErrMalformedProof, "RSA jwk carries EC members")
	}
	nb, err := b64urlDecode(j.N)
	if err != nil {
		return nil, wrapErr(ErrMalformedProof, "jwk n base64url decode", err)
	}
	eb, err := b64urlDecode(j.E)
	if err != nil {
		return nil, wrapErr(ErrMalformedProof, "jwk e base64url decode", err)
	}
	n := new(big.Int).SetBytes(nb)
	if n.BitLen() < minRSABits {
		return nil, newErr(ErrCertInvalid, "jwk RSA modulus smaller than 2048 bits")
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > maxRSAExp || e.Int64()%2 == 0 {
		return nil, newErr(ErrMalformedProof, "jwk RSA exponent out of range")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// matchRSAJWKToCert enforces the dual-header invariant for RSA: the jwk and the
// x5c[0] certificate must present the same public key.
func matchRSAJWKToCert(j *proofJWK, certPub *rsa.PublicKey) error {
	jwkPub, err := rsaJWKKey(j)
	if err != nil {
		return err
	}
	if jwkPub.N.Cmp(certPub.N) != 0 || jwkPub.E != certPub.E {
		return newErr(ErrKeyMismatch, "jwk public key does not match the x5c[0] certificate key")
	}
	return nil
}

// leafCertRSA decodes x5c[0] (std-base64 DER, RFC 7515 §4.1.6) and asserts an
// RSA leaf of at least 2048 bits. Like leafCert, it performs no chain walk;
// trust comes from the status token, not a CA chain.
func leafCertRSA(h *proofHeader) (*x509.Certificate, *rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(h.X5c[0])
	if err != nil {
		return nil, nil, wrapErr(ErrCertInvalid, "x5c[0] std-base64 decode", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, wrapErr(ErrCertInvalid, "x5c[0] parse", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, newErr(ErrCertInvalid, fmt.Sprintf("x5c[0] key is %T, want RSA", cert.PublicKey))
	}
	if pub.N.BitLen() < minRSABits {
		return nil, nil, newErr(ErrCertInvalid, "x5c[0] RSA key smaller than 2048 bits")
	}
	return cert, pub, nil
}
