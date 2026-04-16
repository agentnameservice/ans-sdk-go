package scitt

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCoseErrorMessages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *CoseError
		contains string
	}{
		{
			name:     "oversized input",
			err:      &CoseError{Type: CoseErrOversizedInput, Message: "input exceeds 1MB"},
			contains: "COSE oversized input: input exceeds 1MB",
		},
		{
			name:     "not a COSE_Sign1",
			err:      &CoseError{Type: CoseErrNotACoseSign1, Message: "expected tag 18"},
			contains: "not a COSE_Sign1 structure: expected tag 18",
		},
		{
			name:     "CBOR decode failure",
			err:      &CoseError{Type: CoseErrCborDecode, Message: "unexpected EOF"},
			contains: "CBOR decode failed: unexpected EOF",
		},
		{
			name:     "invalid array length",
			err:      &CoseError{Type: CoseErrInvalidArrayLength, Message: "expected 4 elements, got 3"},
			contains: "invalid COSE_Sign1 array length: expected 4 elements, got 3",
		},
		{
			name:     "invalid signature length",
			err:      &CoseError{Type: CoseErrInvalidSignatureLength, Message: "expected 64 bytes"},
			contains: "invalid signature length: expected 64 bytes",
		},
		{
			name:     "invalid protected header",
			err:      &CoseError{Type: CoseErrInvalidProtectedHeader, Message: "missing alg"},
			contains: "invalid protected header: missing alg",
		},
		{
			name:     "invalid unprotected header",
			err:      &CoseError{Type: CoseErrInvalidUnprotectedHeader, Message: "missing VDP"},
			contains: "invalid unprotected header: missing VDP",
		},
		{
			name:     "unsupported algorithm",
			err:      &CoseError{Type: CoseErrUnsupportedAlgorithm, Message: "alg -8 not supported"},
			contains: "unsupported COSE algorithm: alg -8 not supported",
		},
		{
			name:     "missing kid",
			err:      &CoseError{Type: CoseErrMissingKid, Message: "kid header absent"},
			contains: "missing key ID (kid): kid header absent",
		},
		{
			name:     "unknown type",
			err:      &CoseError{Type: CoseErrorType(99), Message: "something unexpected"},
			contains: "COSE error: something unexpected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.err.Error()
			if !strings.Contains(got, tt.contains) {
				t.Errorf("Error() = %q, want containing %q", got, tt.contains)
			}
		})
	}
}

func TestCoseErrorUnwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("underlying cbor error")
	tests := []struct {
		name      string
		err       *CoseError
		wantCause error
	}{
		{
			name:      "with cause",
			err:       &CoseError{Type: CoseErrCborDecode, Message: "decode failed", Cause: cause},
			wantCause: cause,
		},
		{
			name:      "nil cause",
			err:       &CoseError{Type: CoseErrMissingKid, Message: "no kid"},
			wantCause: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.err.Unwrap()
			if !errorEqual(got, tt.wantCause) {
				t.Errorf("Unwrap() = %v, want %v", got, tt.wantCause)
			}
		})
	}
}

func TestSignatureErrorMessages(t *testing.T) {
	t.Parallel()

	kid := [4]byte{0xAA, 0xBB, 0xCC, 0xDD}

	tests := []struct {
		name     string
		err      *SignatureError
		contains string
	}{
		{
			name:     "signature invalid",
			err:      &SignatureError{Type: SigErrSignatureInvalid, Message: "ECDSA verify failed", Kid: kid},
			contains: "signature invalid",
		},
		{
			name:     "unknown key ID",
			err:      &SignatureError{Type: SigErrUnknownKeyID, Message: "kid not in trust store", Kid: kid},
			contains: "unknown key ID",
		},
		{
			name:     "issuer mismatch",
			err:      &SignatureError{Type: SigErrIssuerMismatch, Message: "expected issuer X got Y", Kid: kid},
			contains: "issuer mismatch",
		},
		{
			name:     "invalid key format",
			err:      &SignatureError{Type: SigErrInvalidKeyFormat, Message: "not a P-256 key", Kid: kid},
			contains: "invalid key format",
		},
		{
			name:     "key hash mismatch",
			err:      &SignatureError{Type: SigErrKeyHashMismatch, Message: "hash does not match", Kid: kid},
			contains: "key hash mismatch",
		},
		{
			name:     "invalid public key",
			err:      &SignatureError{Type: SigErrInvalidPublicKey, Message: "point not on curve", Kid: kid},
			contains: "invalid public key",
		},
		{
			name:     "unknown type",
			err:      &SignatureError{Type: SignatureErrorType(99), Message: "unexpected", Kid: kid},
			contains: "signature error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.err.Error()
			if !strings.Contains(got, tt.contains) {
				t.Errorf("Error() = %q, want containing %q", got, tt.contains)
			}
			// All signature errors should include kid hex in output
			kidHex := fmt.Sprintf("%x", tt.err.Kid)
			if !strings.Contains(got, kidHex) {
				t.Errorf("Error() = %q, want containing kid hex %q", got, kidHex)
			}
		})
	}
}

func TestSignatureErrorUnwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("x509 parse error")
	tests := []struct {
		name      string
		err       *SignatureError
		wantCause error
	}{
		{
			name:      "with cause",
			err:       &SignatureError{Type: SigErrInvalidKeyFormat, Message: "bad key", Cause: cause},
			wantCause: cause,
		},
		{
			name:      "nil cause",
			err:       &SignatureError{Type: SigErrSignatureInvalid, Message: "failed"},
			wantCause: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.err.Unwrap()
			if !errorEqual(got, tt.wantCause) {
				t.Errorf("Unwrap() = %v, want %v", got, tt.wantCause)
			}
		})
	}
}

func TestMerkleErrorMessages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *MerkleError
		contains string
	}{
		{
			name:     "invalid proof",
			err:      &MerkleError{Type: MerkleErrInvalidProof, Message: "proof has 0 nodes"},
			contains: "invalid inclusion proof: proof has 0 nodes",
		},
		{
			name:     "root mismatch",
			err:      &MerkleError{Type: MerkleErrRootMismatch, Message: "computed root differs"},
			contains: "Merkle root mismatch: computed root differs",
		},
		{
			name:     "unknown type",
			err:      &MerkleError{Type: MerkleErrorType(99), Message: "unexpected"},
			contains: "Merkle error: unexpected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.err.Error()
			if !strings.Contains(got, tt.contains) {
				t.Errorf("Error() = %q, want containing %q", got, tt.contains)
			}
		})
	}
}

func TestTokenErrorMessages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *TokenError
		contains string
	}{
		{
			name:     "expired",
			err:      &TokenError{Type: TokenErrExpired, Message: "token expired", Exp: 1000, Now: 2000},
			contains: "token expired",
		},
		{
			name:     "missing field",
			err:      &TokenError{Type: TokenErrMissingField, Message: "agent_id required"},
			contains: "missing required field: agent_id required",
		},
		{
			name:     "payload invalid",
			err:      &TokenError{Type: TokenErrPayloadInvalid, Message: "cert array too large"},
			contains: "invalid token payload: cert array too large",
		},
		{
			name:     "terminal status",
			err:      &TokenError{Type: TokenErrTerminalStatus, Message: "agent is revoked", Status: StatusRevoked},
			contains: "terminal status",
		},
		{
			name:     "payload empty",
			err:      &TokenError{Type: TokenErrPayloadEmpty, Message: "no payload in token"},
			contains: "token payload empty: no payload in token",
		},
		{
			name:     "unknown type",
			err:      &TokenError{Type: TokenErrorType(99), Message: "unexpected"},
			contains: "token error: unexpected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.err.Error()
			if !strings.Contains(got, tt.contains) {
				t.Errorf("Error() = %q, want containing %q", got, tt.contains)
			}
		})
	}
}

func TestTransportErrorMessages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *TransportError
		contains string
	}{
		{
			name:     "not found",
			err:      &TransportError{Type: TransportErrNotFound, Message: "endpoint returned 404", StatusCode: 404},
			contains: "not found: endpoint returned 404",
		},
		{
			name:     "agent terminal",
			err:      &TransportError{Type: TransportErrAgentTerminal, Message: "agent is revoked", StatusCode: 410},
			contains: "agent terminal: agent is revoked",
		},
		{
			name:     "not supported",
			err:      &TransportError{Type: TransportErrNotSupported, Message: "SCITT not enabled"},
			contains: "not supported: SCITT not enabled",
		},
		{
			name:     "HTTP error",
			err:      &TransportError{Type: TransportErrHTTPError, Message: "server error", StatusCode: 500},
			contains: "HTTP error (500): server error",
		},
		{
			name:     "base64 decode",
			err:      &TransportError{Type: TransportErrBase64Decode, Message: "illegal base64 char"},
			contains: "base64 decode failed: illegal base64 char",
		},
		{
			name:     "unknown type",
			err:      &TransportError{Type: TransportErrorType(99), Message: "unexpected"},
			contains: "transport error: unexpected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.err.Error()
			if !strings.Contains(got, tt.contains) {
				t.Errorf("Error() = %q, want containing %q", got, tt.contains)
			}
		})
	}
}

func TestTransportErrorUnwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("connection refused")
	tests := []struct {
		name      string
		err       *TransportError
		wantCause error
	}{
		{
			name:      "with cause",
			err:       &TransportError{Type: TransportErrHTTPError, Message: "failed", Cause: cause},
			wantCause: cause,
		},
		{
			name:      "nil cause",
			err:       &TransportError{Type: TransportErrNotFound, Message: "missing"},
			wantCause: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.err.Unwrap()
			if !errorEqual(got, tt.wantCause) {
				t.Errorf("Unwrap() = %v, want %v", got, tt.wantCause)
			}
		})
	}
}

func TestTransportErrorShouldFallbackToBadge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  *TransportError
		want bool
	}{
		{name: "NotFound returns true", err: &TransportError{Type: TransportErrNotFound}, want: true},
		{name: "NotSupported returns true", err: &TransportError{Type: TransportErrNotSupported}, want: true},
		{name: "HTTPError returns true", err: &TransportError{Type: TransportErrHTTPError}, want: true},
		{name: "AgentTerminal returns false", err: &TransportError{Type: TransportErrAgentTerminal}, want: false},
		{name: "Base64Decode returns false", err: &TransportError{Type: TransportErrBase64Decode}, want: false},
		{name: "unknown type returns false", err: &TransportError{Type: TransportErrorType(99)}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.err.ShouldFallbackToBadge()
			if got != tt.want {
				t.Errorf("ShouldFallbackToBadge() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAllErrorsImplementErrorInterface(t *testing.T) {
	t.Parallel()

	var _ error = (*CoseError)(nil)
	var _ error = (*SignatureError)(nil)
	var _ error = (*MerkleError)(nil)
	var _ error = (*TokenError)(nil)
	var _ error = (*TransportError)(nil)
}

// errorEqual compares two errors safely — both nil, or errors.Is matches.
func errorEqual(a, b error) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return errors.Is(a, b)
}

func TestErrorsWorkWithErrorsIs(t *testing.T) {
	t.Parallel()

	inner := errors.New("root cause")

	tests := []struct {
		name string
		err  error
	}{
		{name: "CoseError wraps cause", err: &CoseError{Type: CoseErrCborDecode, Message: "decode", Cause: inner}},
		{name: "SignatureError wraps cause", err: &SignatureError{Type: SigErrInvalidKeyFormat, Message: "bad", Cause: inner}},
		{name: "TransportError wraps cause", err: &TransportError{Type: TransportErrHTTPError, Message: "fail", Cause: inner}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if !errors.Is(tt.err, inner) {
				t.Errorf("errors.Is(%v, inner) = false, want true", tt.err)
			}
		})
	}
}
