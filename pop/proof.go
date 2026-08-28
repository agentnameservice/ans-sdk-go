package pop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// DPoP proof type and algorithm pinned by this profile. ES256 is the only
// algorithm; "dpop+jwt" is the only proof type. These two constants plus the
// jwk and x5c requirements are the entire downgrade policy, enforced in one
// place by acceptES256DPoP — a future WIMSE WPT variant extends here, not in
// scattered literals across sign and verify.
const (
	dpopTyp = "dpop+jwt"
	dpopAlg = "ES256"
)

// The profile's jwk shape: an EC key on P-256 (RFC 7518 §6.2).
const (
	jwkKty = "EC"
	jwkCrv = "P-256"
)

// proofHeader is the protected header of a DPoP proof in this profile. It is
// exactly {typ, alg, jwk, x5c}: jwk is the bare public key RFC 9449 §4.2
// requires, so the proof is wire-conformant DPoP; x5c[0] is the ANS identity
// certificate tying the same key to the agent's ans:// name. The two MUST
// present the same key (matchJWKToCert), so the signature is only ever
// checked under one key. Header parsing rejects unknown fields — any other
// JOSE header parameter fails closed.
type proofHeader struct {
	Typ string    `json:"typ"`
	Alg string    `json:"alg"`
	Jwk *proofJWK `json:"jwk"`
	X5c []string  `json:"x5c"`
}

// proofJWK is the "jwk" header member: the bare P-256 public key in exactly
// the shape {kty, crv, x, y}. Strict decoding rejects any other member — most
// importantly "d" (private key material, forbidden in a DPoP proof by RFC 9449
// §4.2) — and jwkCoords enforces EC/P-256 with full-width coordinates.
type proofJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// proofPayload holds the DPoP claims this profile binds: the HTTP method and
// normalized target URI (htm/htu), the issued-at (iat), a unique id (jti) for
// replay detection, and — only when the request also presents an OAuth2
// access token — that token's hash (ath). Additional claims are tolerated on
// the payload (DPoP permits them); only the header is strictly decoded.
type proofPayload struct {
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	JTI string `json:"jti"`
	ATH string `json:"ath,omitempty"`
}

// acceptES256DPoP is the single predicate deciding which (typ, alg) a proof
// must carry and that both key headers (jwk, x5c) are present. Reject
// alg:"none", RS256, ES384, a missing alg, or a wrong typ here, before any
// signature work.
func acceptES256DPoP(h *proofHeader) error {
	if h.Typ != dpopTyp {
		return newErr(ErrUnsupportedAlg, fmt.Sprintf("typ must be %q, got %q", dpopTyp, echo(h.Typ)))
	}
	if h.Alg != dpopAlg {
		return newErr(ErrUnsupportedAlg, fmt.Sprintf("alg must be %q, got %q", dpopAlg, echo(h.Alg)))
	}
	if h.Jwk == nil {
		return newErr(ErrMalformedProof, "proof header has no jwk (required by RFC 9449)")
	}
	// Exactly one entry: the identity certificate. Trust comes from the status
	// token, not a chain, so extra entries are never consulted — accepting them
	// silently would let a chain-walking verifier reach a different conclusion
	// from this one over the same bytes.
	if len(h.X5c) != 1 {
		return newErr(ErrCertInvalid, "proof header x5c must carry exactly one certificate")
	}
	return nil
}

// publicJWK renders pub as the profile's bare JWK.
func publicJWK(pub *ecdsa.PublicKey) *proofJWK {
	x := make([]byte, coordLen)
	y := make([]byte, coordLen)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return &proofJWK{Kty: jwkKty, Crv: jwkCrv, X: b64urlEncode(x), Y: b64urlEncode(y)}
}

// jwkCoords validates j is the profile's EC/P-256 shape and returns its raw
// 32-byte X and Y coordinates.
func jwkCoords(j *proofJWK) ([]byte, []byte, error) {
	if j.Kty != jwkKty || j.Crv != jwkCrv {
		return nil, nil, newErr(ErrUnsupportedAlg,
			fmt.Sprintf("jwk must be kty=%q crv=%q, got kty=%q crv=%q",
				jwkKty, jwkCrv, echo(j.Kty), echo(j.Crv)))
	}
	x, err := b64urlDecode(j.X)
	if err != nil {
		return nil, nil, wrapErr(ErrMalformedProof, "jwk x coordinate base64url decode", err)
	}
	y, err := b64urlDecode(j.Y)
	if err != nil {
		return nil, nil, wrapErr(ErrMalformedProof, "jwk y coordinate base64url decode", err)
	}
	if len(x) != coordLen || len(y) != coordLen {
		return nil, nil, newErr(ErrMalformedProof,
			fmt.Sprintf("jwk coordinates must be %d bytes each", coordLen))
	}
	return x, y, nil
}

// matchJWKToCert enforces the dual-header invariant: the jwk and the x5c[0]
// certificate must present the same public key. The jwk's point is not
// validated independently — byte-equality with the x509-parsed certificate
// key IS the validation, and verifying the signature under the certificate
// key is then also verifying it under the jwk key (RFC 9449 §4.3).
func matchJWKToCert(j *proofJWK, pub *ecdsa.PublicKey) error {
	jx, jy, err := jwkCoords(j)
	if err != nil {
		return err
	}
	cx := make([]byte, coordLen)
	cy := make([]byte, coordLen)
	pub.X.FillBytes(cx)
	pub.Y.FillBytes(cy)
	if !bytes.Equal(jx, cx) || !bytes.Equal(jy, cy) {
		return newErr(ErrKeyMismatch, "jwk public key does not match the x5c[0] certificate key")
	}
	return nil
}

// accessTokenHash is the RFC 9449 §4.2 ath value for an access token:
// base64url(SHA-256(token)).
func accessTokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return b64urlEncode(h[:])
}

// jwkThumbprint is the RFC 7638 §3 thumbprint of an EC P-256 public key: the
// SHA-256 of the JWK's required members only ({crv, kty, x, y}), lexicographically
// ordered with no whitespace, base64url-encoded. This is the value an OAuth2
// access token's cnf.jkt confirmation claim carries (RFC 9449 §6), so a resource
// server compares it to complete token binding.
//
// The canonical form is concatenated rather than marshalled because
// encoding/json escapes &, < and > — which would corrupt the hash input — and
// because member order here must be lexicographic, not struct order. That is
// safe only because publicJWK guarantees X and Y are base64url of exactly 32
// bytes, so neither can contain a quote or backslash: pass only its output.
func jwkThumbprint(pub *ecdsa.PublicKey) string {
	j := publicJWK(pub)
	canonical := `{"crv":"` + j.Crv + `","kty":"` + j.Kty + `","x":"` + j.X + `","y":"` + j.Y + `"}`
	h := sha256.Sum256([]byte(canonical))
	return b64urlEncode(h[:])
}

// leafCert decodes and validates x5c[0] — the caller's identity certificate.
// x5c entries are std-base64 DER per RFC 7515 §4.1.6 (a different alphabet from
// the RawURL compact-JWS segments). Only the leaf is consulted; there is no
// chain walk (trust comes from the status token, not a CA chain). The leaf key
// must be ECDSA P-256.
func leafCert(h *proofHeader) (*x509.Certificate, *ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(h.X5c[0])
	if err != nil {
		return nil, nil, wrapErr(ErrCertInvalid, "x5c[0] std-base64 decode", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, wrapErr(ErrCertInvalid, "x5c[0] parse", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, newErr(ErrCertInvalid, fmt.Sprintf("x5c[0] key is %T, want ECDSA P-256", cert.PublicKey))
	}
	if pub.Curve != elliptic.P256() {
		return nil, nil, newErr(ErrCertInvalid, "x5c[0] key curve is not P-256")
	}
	return cert, pub, nil
}

// normalizeHTU returns the RFC 9449 §4.3 htu form of rawURL: scheme and host
// lowercased, the default port (:443 for https, :80 for http) dropped, query
// and fragment removed, and an empty path normalized to "/" (RFC 3986 §6.2.3 —
// without this, a bare-origin target signs "https://h.example" while the wire
// request carries "/", and every such request fails the htu comparison). The
// path is otherwise preserved as-is: it is case-sensitive, and no dot-segment
// or percent-encoding canonicalization is performed, so a path-rewriting hop
// between caller and callee breaks the binding. Both signer and verifier run
// this so the comparison is normalized-vs-normalized.
func normalizeHTU(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", wrapErr(ErrMalformedProof, "parse URL for htu", err)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme == "" || host == "" {
		return "", newErr(ErrMalformedProof, "htu requires an absolute URL with scheme and host")
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	hostport := host
	if port != "" {
		hostport = host + ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + hostport + path, nil
}

// encodeProofParts marshals the header and payload and returns their base64url
// (RawURL) segments, ready to sign.
func encodeProofParts(h *proofHeader, p *proofPayload) (string, string, error) {
	hb, err := json.Marshal(h)
	if err != nil {
		return "", "", wrapErr(ErrMalformedProof, "marshal proof header", err)
	}
	pb, err := json.Marshal(p)
	if err != nil {
		return "", "", wrapErr(ErrMalformedProof, "marshal proof payload", err)
	}
	return b64urlEncode(hb), b64urlEncode(pb), nil
}

// decodeProofHeader strictly decodes a base64url header segment. Unknown
// fields are rejected — at the top level (e.g. a smuggled "kid" or "crit")
// and inside the jwk (e.g. a private-key "d"), since DisallowUnknownFields
// applies to nested structs too.
func decodeProofHeader(headerB64 string) (*proofHeader, error) {
	raw, err := b64urlDecode(headerB64)
	if err != nil {
		return nil, wrapErr(ErrMalformedProof, "header base64url decode", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var h proofHeader
	if err := dec.Decode(&h); err != nil {
		return nil, wrapErr(ErrMalformedProof, "decode proof header (unknown fields rejected)", err)
	}
	return &h, nil
}

// decodeProofPayload decodes a base64url payload segment. Unknown claims are
// tolerated (DPoP permits additional claims); only the bound claims are read.
func decodeProofPayload(payloadB64 string) (*proofPayload, error) {
	raw, err := b64urlDecode(payloadB64)
	if err != nil {
		return nil, wrapErr(ErrMalformedProof, "payload base64url decode", err)
	}
	var p proofPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, wrapErr(ErrMalformedProof, "decode proof payload", err)
	}
	return &p, nil
}
