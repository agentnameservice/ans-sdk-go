package pop

import "fmt"

// ErrorType classifies a proof-of-possession verification failure so callers
// (and the HTTP middleware) can branch on a stable category rather than a
// string. Every failure on the verify path carries one of these.
type ErrorType string

const (
	// ErrMalformedProof is a structurally invalid DPoP proof (bad compact JWS,
	// base64, JSON, or missing required header/claim).
	ErrMalformedProof ErrorType = "MALFORMED_PROOF"
	// ErrUnsupportedAlg is a proof whose alg/typ is not the pinned
	// ES256 / "dpop+jwt" pair (covers the alg:"none" downgrade), or a jwk
	// that is not EC/P-256.
	ErrUnsupportedAlg ErrorType = "UNSUPPORTED_ALG"
	// ErrHTTPBindingMismatch is an htm/htu that does not match the request.
	ErrHTTPBindingMismatch ErrorType = "HTTP_BINDING_MISMATCH"
	// ErrProofStale is an iat outside the accepted freshness window
	// (too old or too far in the future).
	ErrProofStale ErrorType = "PROOF_STALE"
	// ErrReplay is a jti already seen within the freshness window.
	ErrReplay ErrorType = "REPLAY"
	// ErrReplayCacheFull means the replay cache is at capacity and cannot
	// record this jti; the proof is rejected (fail closed).
	ErrReplayCacheFull ErrorType = "REPLAY_CACHE_FULL"
	// ErrSignatureInvalid is a proof whose signature does not verify under
	// the x5c[0] certificate key.
	ErrSignatureInvalid ErrorType = "SIGNATURE_INVALID"
	// ErrCertInvalid is a missing/unparseable x5c, or a leaf key that is not
	// ECDSA P-256.
	ErrCertInvalid ErrorType = "CERT_INVALID"
	// ErrKeyMismatch means the header's jwk and x5c[0] do not present the same
	// public key — the dual-header consistency invariant failed.
	ErrKeyMismatch ErrorType = "KEY_MISMATCH"
	// ErrTokenBindingMismatch means the proof's ath claim and the presented
	// OAuth2 access token disagree: ath present with no token presented,
	// absent when one was, or a hash mismatch (RFC 9449 §4.3 / §7.1).
	ErrTokenBindingMismatch ErrorType = "TOKEN_BINDING_MISMATCH"
	// ErrBindingFailed means a verified proof and a verified status token do
	// not describe the same agent (fingerprint, ans:// SAN, or receipt agent
	// mismatch).
	ErrBindingFailed ErrorType = "BINDING_FAILED"
	// ErrStatusInvalid means the SCITT status token failed verification
	// (bad signature, expired, terminal status, or malformed).
	ErrStatusInvalid ErrorType = "STATUS_INVALID"
	// ErrReceiptInvalid means the SCITT receipt failed verification or its
	// leaf event could not be decoded.
	ErrReceiptInvalid ErrorType = "RECEIPT_INVALID"
	// ErrMissingHeaders means the request carried no SCITT receipt / status
	// token, or no DPoP proof.
	ErrMissingHeaders ErrorType = "MISSING_HEADERS"
	// ErrScittHeaderInvalid means the X-SCITT-Receipt or X-ANS-Status-Token
	// header could not be extracted (oversized or not valid base64). The DPoP
	// proof has not been examined at that point.
	ErrScittHeaderInvalid ErrorType = "SCITT_HEADER_INVALID"
	// ErrMisconfigured means a required dependency or argument was not supplied
	// (a nil KeyLookup, ReplayCache, request, or Signer). This is a programmer
	// error in wiring, not attacker-influenced input; verification fails closed.
	ErrMisconfigured ErrorType = "MISCONFIGURED"
	// ErrClientGone means the request context was canceled or timed out — the
	// caller hung up. Nothing was rejected on authentication grounds.
	ErrClientGone ErrorType = "CLIENT_GONE"
	// ErrExpectedPeerMismatch means the proven caller is not the peer the
	// callee was configured to accept (WithExpectedAnsName / WithAllowedAnsNames).
	ErrExpectedPeerMismatch ErrorType = "EXPECTED_PEER_MISMATCH"
)

// ProofError is the typed error returned by all pop verification paths. It
// wraps an optional cause so callers can use errors.As to read Type and
// errors.Is/Unwrap to reach the underlying error.
type ProofError struct {
	Type    ErrorType
	Message string
	Cause   error
}

// Error implements error.
func (e *ProofError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("pop: %s: %s: %v", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("pop: %s: %s", e.Type, e.Message)
}

// Unwrap exposes the wrapped cause for errors.Is / errors.As.
func (e *ProofError) Unwrap() error { return e.Cause }

// newErr builds a ProofError with no wrapped cause.
func newErr(t ErrorType, msg string) *ProofError {
	return &ProofError{Type: t, Message: msg}
}

// wrapErr builds a ProofError that wraps cause.
func wrapErr(t ErrorType, msg string, cause error) *ProofError {
	return &ProofError{Type: t, Message: msg, Cause: cause}
}

// maxEchoedInput bounds how much attacker-supplied text an error message may
// quote back.
const maxEchoedInput = 64

// echo truncates untrusted input before it is interpolated into an error
// message. Messages reach the operator's log on every rejection, and a proof may
// carry kilobytes of attacker-chosen text in any string field; the category
// already conveys what failed, so a bounded excerpt is all the value there is.
func echo(s string) string {
	if len(s) <= maxEchoedInput {
		return s
	}
	return s[:maxEchoedInput] + "…"
}
