package pop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"time"
)

// jtiBytes is the entropy size of a generated jti (128 bits).
const jtiBytes = 16

// Signer mints DPoP proofs for an agent's outbound A2A requests. It holds the
// agent's identity private key and the DER of the matching identity
// certificate — the certificate whose fingerprint the agent's status token
// vouches for. Build one with NewSigner; the zero value is not usable.
type Signer struct {
	key *ecdsa.PrivateKey
	// rsaKey and alg back the throwaway RS256 opt-in (NewRSASigner): when rsaKey
	// is set, key is nil and alg is algRS256. RSA-THROWAWAY(remove when prod supports ES256).
	rsaKey  *rsa.PrivateKey
	alg     string
	certDER []byte
	jwk     *proofJWK
	now     func() time.Time
}

// SignerOption configures a Signer.
type SignerOption func(*Signer)

// NewSigner builds a Signer from a P-256 private key and the DER of the
// identity certificate that binds the matching public key. It verifies the
// certificate's public key equals the private key's public key, so a Signer
// can never emit a proof whose jwk or x5c disagrees with its signing key.
func NewSigner(key *ecdsa.PrivateKey, certDER []byte, opts ...SignerOption) (*Signer, error) {
	if key == nil {
		return nil, newErr(ErrCertInvalid, "signer: nil private key")
	}
	if key.Curve != elliptic.P256() {
		return nil, newErr(ErrCertInvalid, "signer: private key is not P-256")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, wrapErr(ErrCertInvalid, "signer: parse certificate DER", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, newErr(ErrCertInvalid, "signer: certificate public key does not match private key")
	}
	s := &Signer{key: key, alg: dpopAlg, certDER: certDER, jwk: publicJWK(&key.PublicKey), now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// NewRSASigner is a THROWAWAY constructor mirroring NewSigner for an RSA identity
// key. It exists only so the demo can authenticate against prod, which today
// issues RSA identity certificates rather than P-256. The proofs it mints are
// RS256 and are rejected by verifiers unless they opt in with WithAllowRSA.
// RSA-THROWAWAY(remove when prod supports ES256).
func NewRSASigner(key *rsa.PrivateKey, certDER []byte, opts ...SignerOption) (*Signer, error) {
	if key == nil {
		return nil, newErr(ErrCertInvalid, "signer: nil private key")
	}
	if key.N.BitLen() < minRSABits {
		return nil, newErr(ErrCertInvalid, "signer: RSA key smaller than 2048 bits")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, wrapErr(ErrCertInvalid, "signer: parse certificate DER", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, newErr(ErrCertInvalid, "signer: certificate public key does not match private key")
	}
	s := &Signer{rsaKey: key, alg: algRS256, certDER: certDER, jwk: rsaPublicJWK(&key.PublicKey), now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// proofOptions is the resolved per-proof configuration.
type proofOptions struct {
	ath string
}

// ProofOption configures a single Sign call.
type ProofOption func(*proofOptions)

// WithAccessToken binds the proof to an OAuth2 access token: the payload
// gains ath = base64url(SHA-256(token)) per RFC 9449 §4.2. Use it when the
// request presents the token as "Authorization: DPoP <token>" (RFC 9449
// §7.1). Verifiers enforce ath ⟺ presented token in both directions, so a
// proof minted with a token is only accepted alongside that token.
func WithAccessToken(token string) ProofOption {
	return func(o *proofOptions) { o.ath = accessTokenHash(token) }
}

// JKT returns the RFC 7638 thumbprint of the signer's public key — the value an
// authorization server records as an access token's cnf.jkt confirmation claim
// (RFC 9449 §6), and the value a callee compares against
// CallerIdentity.JKT. A client needs it to request a token bound to this key.
func (s *Signer) JKT() string {
	if s.rsaKey != nil { // RSA-THROWAWAY(remove when prod supports ES256)
		return rsaThumbprint(&s.rsaKey.PublicKey)
	}
	return jwkThumbprint(&s.key.PublicKey)
}

// withSignerClock injects a clock for deterministic tests.
func withSignerClock(now func() time.Time) SignerOption {
	return func(s *Signer) { s.now = now }
}

// Sign produces a compact DPoP proof JWS binding the HTTP method and target
// URL, stamped with the current iat and a fresh jti. The header carries both
// the bare public key (jwk) and the identity certificate (x5c). Pass
// WithAccessToken to additionally bind an OAuth2 access token via ath. ctx is
// honored for cancellation though signing is local and fast.
func (s *Signer) Sign(ctx context.Context, method, rawURL string, opts ...ProofOption) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var po proofOptions
	for _, o := range opts {
		o(&po)
	}
	htu, err := normalizeHTU(rawURL)
	if err != nil {
		return "", err
	}
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	hdr := &proofHeader{
		Typ: dpopTyp,
		Alg: s.alg,
		Jwk: s.jwk,
		X5c: []string{base64.StdEncoding.EncodeToString(s.certDER)},
	}
	pl := &proofPayload{
		HTM: method,
		HTU: htu,
		IAT: s.now().Unix(),
		JTI: jti,
		ATH: po.ath,
	}
	headerB64, payloadB64, err := encodeProofParts(hdr, pl)
	if err != nil {
		return "", err
	}
	sigB64, err := s.sign(jwsSigningInput(headerB64, payloadB64))
	if err != nil {
		return "", err
	}
	return headerB64 + "." + payloadB64 + "." + sigB64, nil
}

// sign produces the JWS signature under the signer's configured algorithm.
func (s *Signer) sign(signingInput []byte) (string, error) {
	if s.rsaKey != nil { // RSA-THROWAWAY(remove when prod supports ES256)
		return signRS256(s.rsaKey, signingInput)
	}
	return signES256(s.key, signingInput)
}

// newJTI returns a random 128-bit jti as lowercase hex.
func newJTI() (string, error) {
	var b [jtiBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", wrapErr(ErrMalformedProof, "generate jti", err)
	}
	return hex.EncodeToString(b[:]), nil
}
