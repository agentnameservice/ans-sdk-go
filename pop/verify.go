package pop

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"time"
)

const (
	// MaxProofSize bounds the compact DPoP proof length to limit parser work
	// on untrusted input (mirrors scitt's MaxCoseInputSize discipline).
	MaxProofSize = 8 << 10 // 8 KiB
	// DefaultPoPSkew is the freshness window for a proof's iat. A possession
	// proof is single-use and short-lived, so this is deliberately tight and
	// far smaller than scitt.MaxClockSkew (which bounds status-token expiry).
	DefaultPoPSkew = 120 * time.Second
	// MaxJTISize bounds the jti claim. RFC 9449 §11.1 calls for rejecting
	// "unnecessarily large jti values" precisely because a verifier stores them:
	// without this, a cache bounded by entry COUNT is unbounded in BYTES (a
	// proof may carry a multi-kilobyte jti under MaxProofSize). 128 bytes is
	// ample for any collision-resistant identifier.
	MaxJTISize = 128
	// replayGrace keeps a jti in the replay cache slightly past the freshness
	// window, so a replay the freshness check would still accept is always
	// caught by the cache (no boundary gap). Cache retention = iat + skew + grace.
	replayGrace = 5 * time.Second
)

// ProofResult is a verified DPoP proof: the caller's identity certificate and
// key, the SHA-256 fingerprint the status-token binding matches on, the key's
// RFC 7638 thumbprint for OAuth2 cnf.jkt confirmation, and the proof's
// jti/htu/iat for the caller binding and structured logging.
type ProofResult struct {
	Cert        *x509.Certificate
	Key         *ecdsa.PublicKey
	Fingerprint [32]byte
	// JKT is the RFC 7638 thumbprint of Key. A resource server holding a
	// DPoP-bound access token MUST compare it to the token's cnf.jkt claim to
	// complete RFC 9449 §4.3 token binding; the ath check alone does not
	// establish sender-constraint.
	JKT string
	// ContentDigest is the proof's ans_content_digest: SHA-256 of the request
	// content the caller signed, compared against the received content by
	// checkContent before the jti is recorded.
	ContentDigest [sha256.Size]byte
	JTI           string
	HTU           string
	IssuedAt      time.Time
	// replayExp is the cache retention this proof's freshness window implies:
	// iat + effective skew + replayGrace. It is computed where the skew is
	// normalized, so the retention can never disagree with the window the
	// freshness check actually applied.
	replayExp time.Time
}

// verifyConfig is the resolved options for VerifyProof.
type verifyConfig struct {
	accessToken    string
	tokenPresented bool
	content        func() ([]byte, error)
}

// VerifyOption configures a single VerifyProof call.
type VerifyOption func(*verifyConfig)

// WithBoundAccessToken tells the verifier the request presented this OAuth2
// access token ("Authorization: DPoP <token>", RFC 9449 §7.1), requiring the
// proof's ath to hash-match it. Without this option a proof carrying ath is
// rejected — the profile enforces ath ⟺ presented token in both directions.
func WithBoundAccessToken(token string) VerifyOption {
	return func(c *verifyConfig) {
		c.accessToken = token
		c.tokenPresented = true
	}
}

// VerifyProof verifies a compact DPoP proof against an HTTP method and URL at
// time now, with freshness window skew and replay protection via replay.
//
// Order: ctx, size cap, compact structure, pinned typ/alg plus required
// jwk/x5c (acceptES256DPoP), x5c[0] P-256 leaf, its validity period at now,
// jwk↔x5c key equality, signature under that single key, ans_profile,
// ans_content_digest shape, htm, normalized htu, ath ⟺ presented token, iat
// window, jti size, then the digest against the received content
// (WithReceivedContent) and jti single-use. Content is hashed and the replay
// recorded LAST, so only proofs that pass every other check touch either.
//
// A proof verified here is cryptographically well-formed but NOT yet trusted:
// nothing has established that its certificate belongs to a live ANS agent
// (leafCert performs no chain validation). Use VerifyCaller for the full
// three-proof check — it records the jti only after the status-token binding
// succeeds, so an untrusted flood cannot consume replay-cache capacity.
func VerifyProof(ctx context.Context, proofJWS, method, rawURL string,
	now time.Time, skew time.Duration, replay ReplayCache, opts ...VerifyOption) (*ProofResult, error) {
	if replay == nil {
		return nil, newErr(ErrMisconfigured, "nil ReplayCache: cannot enforce single-use proofs")
	}
	cfg := resolveVerifyOptions(opts)
	r, err := verifyProofUnrecorded(ctx, proofJWS, method, rawURL, now, skew, &cfg)
	if err != nil {
		return nil, err
	}
	if err := checkContent(r, cfg.content); err != nil {
		return nil, err
	}
	if err := commitReplay(r, replay); err != nil {
		return nil, err
	}
	return r, nil
}

// WithReceivedContent supplies the request content the verifier received, read
// lazily: read runs only after every other check — under VerifyCaller, only
// after the proof is bound to a live ANS identity — and SHA-256 of what it
// returns must equal the proof's ans_content_digest before the jti is recorded.
// Without this option the verifier binds empty content, so a proof minted over
// a body fails closed. Middleware wires it from the request body; non-HTTP
// embedders supply their own reader.
func WithReceivedContent(read func() ([]byte, error)) VerifyOption {
	return func(c *verifyConfig) { c.content = read }
}

// resolveVerifyOptions applies opts to a fresh verifyConfig.
func resolveVerifyOptions(opts []VerifyOption) verifyConfig {
	var cfg verifyConfig
	for _, o := range opts {
		o(&cfg)
	}
	return cfg
}

// verifyProofUnrecorded runs every proof check except the content comparison
// and the replay commit, so a caller with more trust checks to perform can
// defer both until the proof is known to belong to a vouched agent.
func verifyProofUnrecorded(ctx context.Context, proofJWS, method, rawURL string,
	now time.Time, skew time.Duration, cfg *verifyConfig) (*ProofResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, wrapErr(ErrClientGone, "request context done before verification", err)
	}
	if len(proofJWS) > MaxProofSize {
		return nil, newErr(ErrMalformedProof, "proof exceeds size limit")
	}
	if skew <= 0 {
		skew = DefaultPoPSkew
	}

	headerB64, payloadB64, sigB64, err := splitCompactJWS(proofJWS)
	if err != nil {
		return nil, err
	}
	hdr, err := decodeProofHeader(headerB64)
	if err != nil {
		return nil, err
	}
	if err := acceptES256DPoP(hdr); err != nil {
		return nil, err
	}
	cert, pub, err := leafCert(hdr)
	if err != nil {
		return nil, err
	}
	// Certificate dates are checked exactly, as a TLS handshake would check
	// them; the skew allowance covers the proof's own iat, not the credential's
	// lifetime.
	if now.Before(cert.NotBefore) {
		return nil, newErr(ErrCertInvalid,
			"proof identity certificate is not valid until "+cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return nil, newErr(ErrCertInvalid,
			"proof identity certificate expired at "+cert.NotAfter.UTC().Format(time.RFC3339))
	}
	if err := matchJWKToCert(hdr.Jwk, pub); err != nil {
		return nil, err
	}
	if err := verifyES256(pub, jwsSigningInput(headerB64, payloadB64), sigB64); err != nil {
		return nil, err
	}
	pl, err := decodeProofPayload(payloadB64)
	if err != nil {
		return nil, err
	}
	if err := checkProfile(pl.Profile); err != nil {
		return nil, err
	}
	contentDigest, err := decodeContentDigest(pl.ContentDigest)
	if err != nil {
		return nil, err
	}
	if err := checkHTTPBinding(pl, method, rawURL); err != nil {
		return nil, err
	}
	if err := checkTokenBinding(pl, cfg); err != nil {
		return nil, err
	}
	iat, err := checkFreshness(pl, now, skew)
	if err != nil {
		return nil, err
	}
	if pl.JTI == "" {
		return nil, newErr(ErrMalformedProof, "proof missing jti")
	}
	if len(pl.JTI) > MaxJTISize {
		return nil, newErr(ErrMalformedProof, "proof jti exceeds size limit")
	}

	return &ProofResult{
		Cert:          cert,
		Key:           pub,
		Fingerprint:   sha256.Sum256(cert.Raw),
		JKT:           jwkThumbprint(pub),
		ContentDigest: contentDigest,
		JTI:           pl.JTI,
		HTU:           pl.HTU,
		IssuedAt:      iat,
		replayExp:     iat.Add(skew + replayGrace),
	}, nil
}

// checkContent compares the proof's ans_content_digest with SHA-256 of the
// content the callee received. A nil read means the request carried no content.
func checkContent(r *ProofResult, read func() ([]byte, error)) error {
	var content []byte
	if read != nil {
		b, err := read()
		if err != nil {
			return wrapErr(ErrContentUnreadable, "request content could not be read", err)
		}
		content = b
	}
	got := sha256.Sum256(content)
	if subtle.ConstantTimeCompare(got[:], r.ContentDigest[:]) != 1 {
		return newErr(ErrContentBindingMismatch, "ans_content_digest does not match the received content")
	}
	return nil
}

// checkHTTPBinding confirms the proof's htm/htu match the request method and
// normalized URL.
func checkHTTPBinding(p *proofPayload, method, rawURL string) error {
	if p.HTM != method {
		return newErr(ErrHTTPBindingMismatch, "htm does not match request method")
	}
	wantHTU, err := normalizeHTU(rawURL)
	if err != nil {
		return err
	}
	if p.HTU != wantHTU {
		return newErr(ErrHTTPBindingMismatch, "htu does not match request URL")
	}
	return nil
}

// checkTokenBinding enforces ath ⟺ presented access token, strictly in both
// directions: a proof minted for a token-bound context is not accepted
// without its token, and a presented token demands a matching ath (RFC 9449
// §4.3).
func checkTokenBinding(p *proofPayload, cfg *verifyConfig) error {
	if !cfg.tokenPresented {
		if p.ATH != "" {
			return newErr(ErrTokenBindingMismatch, "proof carries ath but no access token was presented")
		}
		return nil
	}
	if p.ATH == "" {
		return newErr(ErrTokenBindingMismatch, "access token presented but proof carries no ath")
	}
	want := accessTokenHash(cfg.accessToken)
	if subtle.ConstantTimeCompare([]byte(p.ATH), []byte(want)) != 1 {
		return newErr(ErrTokenBindingMismatch, "ath does not match the presented access token")
	}
	return nil
}

// checkFreshness rejects an iat outside [now-skew, now+skew] and returns the iat.
func checkFreshness(p *proofPayload, now time.Time, skew time.Duration) (time.Time, error) {
	if p.IAT == 0 {
		return time.Time{}, newErr(ErrMalformedProof, "proof missing iat")
	}
	iat := time.Unix(p.IAT, 0)
	delta := now.Sub(iat)
	if delta > skew {
		return time.Time{}, newErr(ErrProofStale, "proof iat is too old")
	}
	if delta < -skew {
		return time.Time{}, newErr(ErrProofStale, "proof iat is too far in the future")
	}
	return iat, nil
}

// commitReplay records the jti single-use, retaining it until the proof's
// replayExp so any replay still inside the freshness window is caught by the
// cache. A cache error (e.g. at capacity) fails closed.
//
// Call this only once a proof is trusted: the cache is a bounded, shared
// resource, so recording an unvouched proof lets anyone who can reach the port
// exhaust capacity and fail-close authentication for every legitimate caller.
func commitReplay(r *ProofResult, replay ReplayCache) error {
	// Store a fixed-width digest rather than the jti itself, so a cache bounded
	// by entry count is also bounded in bytes — including third-party backends
	// that cannot see MaxJTISize (RFC 9449 §11.1 sanctions storing "only a hash
	// thereof"). Collision resistance of SHA-256 preserves single-use semantics.
	key := sha256.Sum256([]byte(r.JTI))
	seen, err := replay.CheckAndStore(b64urlEncode(key[:]), r.replayExp)
	if err != nil {
		return err // fail closed (e.g. ErrReplayCacheFull)
	}
	if seen {
		return newErr(ErrReplay, "jti already seen within the freshness window")
	}
	return nil
}
