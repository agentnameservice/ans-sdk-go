package scitt

import "fmt"

// CoseErrorType represents the type of COSE_Sign1 parsing error.
type CoseErrorType int

const (
	// CoseErrOversizedInput indicates the input exceeds the maximum allowed size.
	CoseErrOversizedInput CoseErrorType = iota
	// CoseErrNotACoseSign1 indicates the data is not a valid COSE_Sign1 structure.
	CoseErrNotACoseSign1
	// CoseErrCborDecode indicates a CBOR decoding failure.
	CoseErrCborDecode
	// CoseErrInvalidArrayLength indicates the COSE_Sign1 array does not have exactly 4 elements.
	CoseErrInvalidArrayLength
	// CoseErrInvalidSignatureLength indicates the signature is not exactly 64 bytes (P1363).
	CoseErrInvalidSignatureLength
	// CoseErrInvalidProtectedHeader indicates the protected header is malformed.
	CoseErrInvalidProtectedHeader
	// CoseErrInvalidUnprotectedHeader indicates the unprotected header or VDP is malformed.
	CoseErrInvalidUnprotectedHeader
	// CoseErrUnsupportedAlgorithm indicates an unsupported COSE algorithm.
	CoseErrUnsupportedAlgorithm
	// CoseErrMissingKid indicates the key ID (kid) is missing from the protected header.
	CoseErrMissingKid
)

// CoseError represents a COSE_Sign1 structure or parsing failure.
type CoseError struct {
	Type    CoseErrorType
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *CoseError) Error() string {
	switch e.Type {
	case CoseErrOversizedInput:
		return fmt.Sprintf("COSE oversized input: %s", e.Message)
	case CoseErrNotACoseSign1:
		return fmt.Sprintf("not a COSE_Sign1 structure: %s", e.Message)
	case CoseErrCborDecode:
		return fmt.Sprintf("CBOR decode failed: %s", e.Message)
	case CoseErrInvalidArrayLength:
		return fmt.Sprintf("invalid COSE_Sign1 array length: %s", e.Message)
	case CoseErrInvalidSignatureLength:
		return fmt.Sprintf("invalid signature length: %s", e.Message)
	case CoseErrInvalidProtectedHeader:
		return fmt.Sprintf("invalid protected header: %s", e.Message)
	case CoseErrInvalidUnprotectedHeader:
		return fmt.Sprintf("invalid unprotected header: %s", e.Message)
	case CoseErrUnsupportedAlgorithm:
		return fmt.Sprintf("unsupported COSE algorithm: %s", e.Message)
	case CoseErrMissingKid:
		return fmt.Sprintf("missing key ID (kid): %s", e.Message)
	default:
		return fmt.Sprintf("COSE error: %s", e.Message)
	}
}

// Unwrap returns the underlying cause.
func (e *CoseError) Unwrap() error {
	return e.Cause
}

// SignatureErrorType represents the type of signature verification error.
type SignatureErrorType int

const (
	// SigErrSignatureInvalid indicates ECDSA signature verification failed.
	SigErrSignatureInvalid SignatureErrorType = iota
	// SigErrUnknownKeyID indicates the key ID was not found in the key store.
	SigErrUnknownKeyID
	// SigErrIssuerMismatch indicates the issuer claim does not match the key.
	SigErrIssuerMismatch
	// SigErrInvalidKeyFormat indicates the key material is not in the expected format.
	SigErrInvalidKeyFormat
	// SigErrKeyHashMismatch indicates the key ID does not match the key's SHA-256 prefix.
	SigErrKeyHashMismatch
	// SigErrInvalidPublicKey indicates the public key is invalid.
	SigErrInvalidPublicKey
	// SigErrUntrustedKeyDomain indicates a domain-restricted key was used outside its trust boundary.
	SigErrUntrustedKeyDomain
)

// SignatureError represents an ECDSA verification or key management failure.
type SignatureError struct {
	Type    SignatureErrorType
	Message string
	Kid     [4]byte
	Cause   error
}

// Error implements the error interface.
func (e *SignatureError) Error() string {
	kidHex := fmt.Sprintf("%x", e.Kid)
	switch e.Type {
	case SigErrSignatureInvalid:
		return fmt.Sprintf("signature invalid [kid=%s]: %s", kidHex, e.Message)
	case SigErrUnknownKeyID:
		return fmt.Sprintf("unknown key ID [kid=%s]: %s", kidHex, e.Message)
	case SigErrIssuerMismatch:
		return fmt.Sprintf("issuer mismatch [kid=%s]: %s", kidHex, e.Message)
	case SigErrInvalidKeyFormat:
		return fmt.Sprintf("invalid key format [kid=%s]: %s", kidHex, e.Message)
	case SigErrKeyHashMismatch:
		return fmt.Sprintf("key hash mismatch [kid=%s]: %s", kidHex, e.Message)
	case SigErrInvalidPublicKey:
		return fmt.Sprintf("invalid public key [kid=%s]: %s", kidHex, e.Message)
	case SigErrUntrustedKeyDomain:
		return fmt.Sprintf("untrusted key domain [kid=%s]: %s", kidHex, e.Message)
	default:
		return fmt.Sprintf("signature error [kid=%s]: %s", kidHex, e.Message)
	}
}

// Unwrap returns the underlying cause.
func (e *SignatureError) Unwrap() error {
	return e.Cause
}

// MerkleErrorType represents the type of Merkle proof verification error.
type MerkleErrorType int

const (
	// MerkleErrInvalidProof indicates the inclusion proof is structurally invalid.
	MerkleErrInvalidProof MerkleErrorType = iota
	// MerkleErrRootMismatch indicates the computed root does not match the expected root.
	MerkleErrRootMismatch
)

// MerkleError represents an RFC 9162 inclusion proof verification failure.
type MerkleError struct {
	Type    MerkleErrorType
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *MerkleError) Error() string {
	switch e.Type {
	case MerkleErrInvalidProof:
		return fmt.Sprintf("invalid inclusion proof: %s", e.Message)
	case MerkleErrRootMismatch:
		return fmt.Sprintf("Merkle root mismatch: %s", e.Message)
	default:
		return fmt.Sprintf("Merkle error: %s", e.Message)
	}
}

// Unwrap returns the underlying cause.
func (e *MerkleError) Unwrap() error {
	return e.Cause
}

// TokenErrorType represents the type of status token error.
type TokenErrorType int

const (
	// TokenErrExpired indicates the status token has expired.
	TokenErrExpired TokenErrorType = iota
	// TokenErrMissingField indicates a required field is missing from the token payload.
	TokenErrMissingField
	// TokenErrPayloadInvalid indicates the token payload structure is invalid.
	TokenErrPayloadInvalid
	// TokenErrTerminalStatus indicates the agent has a terminal status.
	TokenErrTerminalStatus
	// TokenErrPayloadEmpty indicates the token payload is empty.
	TokenErrPayloadEmpty
)

// TokenError represents a status token payload or lifecycle failure.
type TokenError struct {
	Type    TokenErrorType
	Message string
	Status  AgentStatus
	Exp     int64
	Now     int64
	Cause   error
}

// Error implements the error interface.
func (e *TokenError) Error() string {
	switch e.Type {
	case TokenErrExpired:
		return fmt.Sprintf("token expired (exp=%d, now=%d): %s", e.Exp, e.Now, e.Message)
	case TokenErrMissingField:
		return fmt.Sprintf("missing required field: %s", e.Message)
	case TokenErrPayloadInvalid:
		return fmt.Sprintf("invalid token payload: %s", e.Message)
	case TokenErrTerminalStatus:
		return fmt.Sprintf("terminal status [%s]: %s", e.Status, e.Message)
	case TokenErrPayloadEmpty:
		return fmt.Sprintf("token payload empty: %s", e.Message)
	default:
		return fmt.Sprintf("token error: %s", e.Message)
	}
}

// Unwrap returns the underlying cause.
func (e *TokenError) Unwrap() error {
	return e.Cause
}

// TransportErrorType represents the type of HTTP transport error.
type TransportErrorType int

const (
	// TransportErrNotFound indicates the endpoint returned 404.
	TransportErrNotFound TransportErrorType = iota
	// TransportErrAgentTerminal indicates the agent is in a terminal state (410).
	TransportErrAgentTerminal
	// TransportErrNotSupported indicates SCITT is not supported (501).
	TransportErrNotSupported
	// TransportErrHTTPError indicates a generic HTTP error.
	TransportErrHTTPError
	// TransportErrBase64Decode indicates Base64 decoding of a response failed.
	TransportErrBase64Decode
)

// TransportError represents an HTTP client or endpoint failure.
type TransportError struct {
	Type       TransportErrorType
	Message    string
	StatusCode int
	Cause      error
}

// Error implements the error interface.
func (e *TransportError) Error() string {
	switch e.Type {
	case TransportErrNotFound:
		return fmt.Sprintf("not found: %s", e.Message)
	case TransportErrAgentTerminal:
		return fmt.Sprintf("agent terminal: %s", e.Message)
	case TransportErrNotSupported:
		return fmt.Sprintf("not supported: %s", e.Message)
	case TransportErrHTTPError:
		return fmt.Sprintf("HTTP error (%d): %s", e.StatusCode, e.Message)
	case TransportErrBase64Decode:
		return fmt.Sprintf("base64 decode failed: %s", e.Message)
	default:
		return fmt.Sprintf("transport error: %s", e.Message)
	}
}

// Unwrap returns the underlying cause.
func (e *TransportError) Unwrap() error {
	return e.Cause
}

// ShouldFallbackToBadge returns true if this transport error is eligible for
// fallback to badge-based verification. Only transient/infrastructure errors
// are eligible — terminal agent states and decode errors are not.
func (e *TransportError) ShouldFallbackToBadge() bool {
	switch e.Type { //nolint:exhaustive // intentional allowlist — unlisted types default to no fallback
	case TransportErrNotFound, TransportErrNotSupported, TransportErrHTTPError:
		return true
	default:
		return false
	}
}
