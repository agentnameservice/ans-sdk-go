// Package pop adds sender-constrained, application-layer caller authentication
// for ANS agent-to-agent (A2A) traffic — proof-of-possession without mutual
// TLS.
//
// # Why
//
// Today an ANS caller proves its identity to a callee with an mTLS client
// certificate. mTLS breaks through L7 proxies and gateways (which terminate
// TLS and drop the client identity), carries no delegation semantics, and is
// operationally heavy. This package moves the caller's proof to the application
// layer as a DPoP proof (RFC 9449) — the RFC-stable form of the IETF WIMSE
// Workload Proof Token. It is carried in a standard "DPoP" HTTP header over
// ordinary server-authenticated HTTPS; no client certificate is presented in
// the handshake.
//
// # The three-proof model
//
// A2A caller authentication is three independent proofs, all bound to one
// identity certificate:
//
//   - Identity — the caller's name and identity certificate are in the
//     transparency log. Provided by the SCITT receipt (verify/scitt.VerifyReceipt).
//   - Liveness — that certificate is currently valid (ACTIVE, not revoked).
//     Provided by the status token's ValidIdentityCerts (verify/scitt.VerifyStatusToken).
//   - Possession — the caller holds the certificate's private key, for THIS
//     request. Provided by the DPoP proof in this package. This is the proof
//     that replaces the mTLS handshake.
//
// pop composes with SCITT; it does not replace it. The receipt and status
// token are verified by verify/scitt unchanged; pop adds the possession proof
// and binds all three to the same certificate.
//
// # Binding
//
// The proof header carries both the bare public key (jwk, required by RFC
// 9449 §4.2) and the caller's identity certificate (x5c, RFC 7515 §4.1.6) —
// which MUST present the same key. A verifier (a) confirms that equality and
// verifies the JWS under the single key, (b) confirms SHA-256(cert) is among
// the status token's ValidIdentityCerts fingerprints, and (c) confirms the
// certificate's own ans:// URI SAN equals the status token's AnsName. To pass,
// a caller must hold the private key for a certificate its own
// transparency-log-signed status token vouches for. The status token
// (TL-signed) is the trust statement — there is no CA-chain validation, and
// the certificate's own validity dates, key usage, and cert-type entry are
// deliberately not consulted. A captured receipt and status token (both
// public) are useless without the key, and the proof's jti/htm/htu/iat defeat
// replay and redirection.
//
// The htu binding is only as trustworthy as the URL the callee compares
// against. Middleware's fallback derives it from the request's Host header,
// which the client controls; deployments MUST set WithExternalURL or
// WithTrustedHosts so a proof captured from a call to another origin cannot be
// presented here with a spoofed Host. Note also that htu excludes the query
// string (RFC 9449 §4.2), so a proof does not bind request parameters.
//
// # RFC 9449 conformance and OAuth 2.0
//
// Proofs are wire-conformant RFC 9449 DPoP: a textbook §4.3 verifier
// validates them via the jwk header and ignores the x5c. The profile adds two
// restrictions the RFC permits a deployment to impose: ES256 only, and no
// JOSE header parameters beyond {typ, alg, jwk, x5c} (strict decoding, so a
// private-key "d" member or any extra field fails closed).
//
// OAuth 2.0 composes on top, unchanged from the RFC. When a request presents
// a DPoP-bound access token ("Authorization: DPoP <token>", RFC 9449 §7.1),
// the proof binds it via the ath claim: Sign(..., WithAccessToken(token)) on
// the caller — AttachIdentity does this automatically when the Authorization
// header is already set — and WithBoundAccessToken on the verifier, which
// Middleware likewise applies automatically. The rule is strict in both
// directions: ath ⟺ presented token. Without OAuth there is no access token
// and no ath — the SCITT receipt and status token are the credential, and the
// proof's absence of ath is itself RFC-conformant (ath is required only when
// a token is presented).
//
// # Authentication is not authorization
//
// VerifyCaller and Middleware AUTHENTICATE the caller — they return the
// cryptographically proven identity. They do NOT authorize it. A nil error
// means "this request genuinely came from ans://…X", never "X is allowed to do
// this." The callee MUST apply its own authorization to the returned
// CallerIdentity. Use WithExpectedAnsName / WithAllowedAnsNames to pin specific
// peers when the callee only accepts known callers.
//
// # What dropping mTLS gives up
//
// DPoP provides sender-constraint (possession), but not the channel binding,
// mutual endpoint authentication, or credential confidentiality that mTLS
// provided. The channel is still server-authenticated HTTPS; a caller induced
// to connect to a hostile callee discloses its (public) receipt/status token
// and a single-use, htu-bound proof. Deployments that need channel binding or
// mutual endpoint auth keep mTLS or add token binding.
//
// # Scope
//
// This package implements the autonomous A2A model (no Authorization Server):
// the callee verifies the three proofs and authorizes locally. It does NOT
// implement delegation (an agent acting on behalf of a user across a call
// chain) — that is a separate, higher-risk concern. It diverges from the
// originating research sketch (a minted Workload Identity Token bound via a key
// thumbprint) by reusing the caller's existing identity certificate and the
// status token instead, minting no new credential and adding no wire format.
package pop
