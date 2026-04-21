package scitt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}

// buildStatusPayloadCBOR builds a CBOR-encoded status token payload with integer keys.
func buildStatusPayloadCBOR(t *testing.T, agentID, ansName string, status AgentStatus, iat, exp int64, identityCerts, serverCerts []CertEntry, metadataHashes map[string]string) []byte {
	t.Helper()
	m := make(map[interface{}]interface{})
	if agentID != "" {
		m[int64(1)] = agentID
	}
	if status != "" {
		m[int64(2)] = string(status)
	}
	if iat != 0 {
		m[int64(3)] = iat
	}
	if exp != 0 {
		m[int64(4)] = exp
	}
	if ansName != "" {
		m[int64(5)] = ansName
	}
	if identityCerts != nil {
		certs := make([]map[interface{}]interface{}, 0, len(identityCerts))
		for _, c := range identityCerts {
			certs = append(certs, map[interface{}]interface{}{
				"fingerprint": c.Fingerprint[:],
				"cert_type":   string(c.CertType),
			})
		}
		m[int64(6)] = certs
	}
	if serverCerts != nil {
		certs := make([]map[interface{}]interface{}, 0, len(serverCerts))
		for _, c := range serverCerts {
			certs = append(certs, map[interface{}]interface{}{
				"fingerprint": c.Fingerprint[:],
				"cert_type":   string(c.CertType),
			})
		}
		m[int64(7)] = certs
	}
	if metadataHashes != nil {
		m[int64(8)] = metadataHashes
	}
	data, err := cbor.Marshal(m)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	return data
}

// buildStatusProtectedHeader builds a CBOR protected header for status tokens.
func buildStatusProtectedHeader(t *testing.T, kid [4]byte, issuer *string) []byte {
	t.Helper()
	hdr := map[int64]interface{}{
		1: int64(-7), // alg = ES256
		4: kid[:],    // kid
	}
	if issuer != nil {
		cwt := map[int64]interface{}{
			1: *issuer,
		}
		hdr[15] = cwt
	}
	encoded, err := cbor.Marshal(hdr)
	if err != nil {
		t.Fatalf("failed to encode protected header: %v", err)
	}
	return encoded
}

// signStatusToken builds a complete COSE_Sign1 token (CBOR Tag 18) for a status token.
func signStatusToken(t *testing.T, key *ecdsa.PrivateKey, kid [4]byte, payload []byte, issuer *string) []byte {
	t.Helper()
	protectedBytes := buildStatusProtectedHeader(t, kid, issuer)

	digest, err := ComputeSigStructureDigest(protectedBytes, payload)
	if err != nil {
		t.Fatalf("failed to compute sig structure digest: %v", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)

	unprotected, err := cbor.Marshal(map[int64]interface{}{})
	if err != nil {
		t.Fatalf("failed to marshal unprotected: %v", err)
	}

	arr := []cbor.RawMessage{
		mustCBOREncode(t, protectedBytes),
		unprotected,
		mustCBOREncode(t, payload),
		mustCBOREncode(t, sig),
	}
	arrayBytes, err := cbor.Marshal(arr)
	if err != nil {
		t.Fatalf("failed to marshal COSE array: %v", err)
	}

	tag := cbor.RawTag{Number: 18, Content: arrayBytes}
	tagged, err := tag.MarshalCBOR()
	if err != nil {
		t.Fatalf("failed to marshal tag 18: %v", err)
	}
	return tagged
}

func mustCBOREncode(t *testing.T, data []byte) cbor.RawMessage {
	t.Helper()
	encoded, err := cbor.Marshal(data)
	if err != nil {
		t.Fatalf("failed to encode cbor bytes: %v", err)
	}
	return encoded
}

//nolint:cyclop,gocyclo // table-driven test
func TestVerifyStatusTokenAt(t *testing.T) {
	t.Parallel()

	ki := generateTestKey(t, "test-key")
	ki2 := generateTestKey(t, "other-key")
	store := newTestKeyStore(ki, ki2)

	now := time.Now().Unix()

	validPayload := buildStatusPayloadCBOR(t,
		"agent-123", "example.ans", StatusActive, now-60, now+3600,
		nil, nil, nil,
	)

	fp1 := sha256.Sum256([]byte("cert-1"))
	fp2 := sha256.Sum256([]byte("cert-2"))
	payloadWithCerts := buildStatusPayloadCBOR(t,
		"agent-123", "example.ans", StatusActive, now-60, now+3600,
		[]CertEntry{{Fingerprint: fp1, CertType: CertTypeX509OVClient}},
		[]CertEntry{{Fingerprint: fp2, CertType: CertTypeX509DVServer}},
		nil,
	)

	validToken := signStatusToken(t, ki.priv, ki.kid, validPayload, nil)
	tokenWithCerts := signStatusToken(t, ki.priv, ki.kid, payloadWithCerts, nil)

	expiredPayload := buildStatusPayloadCBOR(t,
		"agent-123", "example.ans", StatusActive, now-7200, now-3600,
		nil, nil, nil,
	)
	expiredToken := signStatusToken(t, ki.priv, ki.kid, expiredPayload, nil)

	// Expired but within clock skew (skew = 2h).
	barelyExpiredPayload := buildStatusPayloadCBOR(t,
		"agent-123", "example.ans", StatusActive, now-7200, now-60,
		nil, nil, nil,
	)
	barelyExpiredToken := signStatusToken(t, ki.priv, ki.kid, barelyExpiredPayload, nil)

	// Expired beyond clock skew (exp = now - 7201, skew = 7200s, so now > exp + skew).
	expiredBeyondSkewPayload := buildStatusPayloadCBOR(t,
		"agent-123", "example.ans", StatusActive, now-86400, now-7201,
		nil, nil, nil,
	)
	expiredBeyondSkewToken := signStatusToken(t, ki.priv, ki.kid, expiredBeyondSkewPayload, nil)

	// Scenario 3.5: Unknown status value "FOOBAR" — NOT terminal, should be accepted.
	unknownStatusPayload := buildStatusPayloadCBOR(t,
		"agent-123", "example.ans", AgentStatus("FOOBAR"), now-60, now+3600,
		nil, nil, nil,
	)
	unknownStatusToken := signStatusToken(t, ki.priv, ki.kid, unknownStatusPayload, nil)

	// Scenario 6.5: Token without expiration (exp=0 treated as missing).
	noExpPayload := buildStatusPayloadCBOR(t,
		"agent-123", "example.ans", StatusActive, now-60, 0,
		nil, nil, nil,
	)
	noExpToken := signStatusToken(t, ki.priv, ki.kid, noExpPayload, nil)

	terminalExpiredPayload := buildStatusPayloadCBOR(t,
		"agent-123", "example.ans", StatusExpired, now-60, now+3600,
		nil, nil, nil,
	)
	terminalExpiredToken := signStatusToken(t, ki.priv, ki.kid, terminalExpiredPayload, nil)

	terminalRevokedPayload := buildStatusPayloadCBOR(t,
		"agent-123", "example.ans", StatusRevoked, now-60, now+3600,
		nil, nil, nil,
	)
	terminalRevokedToken := signStatusToken(t, ki.priv, ki.kid, terminalRevokedPayload, nil)

	missingAgentIDPayload := buildStatusPayloadCBOR(t,
		"", "example.ans", StatusActive, now-60, now+3600,
		nil, nil, nil,
	)
	missingAgentIDToken := signStatusToken(t, ki.priv, ki.kid, missingAgentIDPayload, nil)

	missingAnsNamePayload := buildStatusPayloadCBOR(t,
		"agent-123", "", StatusActive, now-60, now+3600,
		nil, nil, nil,
	)
	missingAnsNameToken := signStatusToken(t, ki.priv, ki.kid, missingAnsNamePayload, nil)

	missingStatusPayload := buildStatusPayloadCBOR(t,
		"agent-123", "example.ans", "", now-60, now+3600,
		nil, nil, nil,
	)
	missingStatusToken := signStatusToken(t, ki.priv, ki.kid, missingStatusPayload, nil)

	missingExpPayload := buildStatusPayloadCBOR(t,
		"agent-123", "example.ans", StatusActive, now-60, 0,
		nil, nil, nil,
	)
	missingExpToken := signStatusToken(t, ki.priv, ki.kid, missingExpPayload, nil)

	// Token signed with wrong key (ki2's key, but kid points to ki).
	wrongSigToken := signStatusToken(t, ki2.priv, ki.kid, validPayload, nil)

	// Token with unknown kid.
	unknownKid := [4]byte{0xFF, 0xFE, 0xFD, 0xFC}
	unknownKidToken := signStatusToken(t, ki.priv, unknownKid, validPayload, nil)

	// Token with issuer matching key name.
	issName := ki.name
	issuerMatchToken := signStatusToken(t, ki.priv, ki.kid, validPayload, &issName)

	// Token with issuer NOT matching key name.
	wrongIss := "wrong-issuer"
	issuerMismatchToken := signStatusToken(t, ki.priv, ki.kid, validPayload, &wrongIss)

	tests := []struct {
		name        string
		token       []byte
		keys        KeyLookup
		clockSkew   time.Duration
		now         int64
		wantErr     bool
		errCheck    func(t *testing.T, err error)
		resultCheck func(t *testing.T, result *VerifiedStatusToken)
	}{
		{
			name:      "valid token",
			token:     validToken,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   false,
			resultCheck: func(t *testing.T, result *VerifiedStatusToken) {
				t.Helper()
				if result.Payload.AgentID != "agent-123" {
					t.Errorf("AgentID = %q, want %q", result.Payload.AgentID, "agent-123")
				}
				if result.Payload.Status != StatusActive {
					t.Errorf("Status = %q, want %q", result.Payload.Status, StatusActive)
				}
				if result.KeyID != ki.kid {
					t.Errorf("KeyID = %x, want %x", result.KeyID, ki.kid)
				}
			},
		},
		{
			name:      "valid token with certs",
			token:     tokenWithCerts,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   false,
			resultCheck: func(t *testing.T, result *VerifiedStatusToken) {
				t.Helper()
				if len(result.Payload.ValidIdentityCerts) != 1 {
					t.Fatalf("expected 1 identity cert, got %d", len(result.Payload.ValidIdentityCerts))
				}
				if subtle.ConstantTimeCompare(result.Payload.ValidIdentityCerts[0].Fingerprint[:], fp1[:]) != 1 {
					t.Error("identity cert fingerprint mismatch")
				}
				if len(result.Payload.ValidServerCerts) != 1 {
					t.Fatalf("expected 1 server cert, got %d", len(result.Payload.ValidServerCerts))
				}
				if subtle.ConstantTimeCompare(result.Payload.ValidServerCerts[0].Fingerprint[:], fp2[:]) != 1 {
					t.Error("server cert fingerprint mismatch")
				}
			},
		},
		{
			name:      "expired token - no skew",
			token:     expiredToken,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var tokErr *TokenError
				if !errors.As(err, &tokErr) {
					t.Fatalf("expected *TokenError, got %T: %v", err, err)
				}
				if tokErr.Type != TokenErrExpired {
					t.Errorf("error type = %d, want TokenErrExpired", tokErr.Type)
				}
			},
		},
		{
			name:      "expired token within clock skew tolerance",
			token:     barelyExpiredToken,
			keys:      store,
			clockSkew: 2 * time.Hour,
			now:       now,
			wantErr:   false,
		},
		{
			name:      "expired token beyond clock skew",
			token:     expiredBeyondSkewToken,
			keys:      store,
			clockSkew: 2 * time.Hour,
			now:       now,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var tokErr *TokenError
				if !errors.As(err, &tokErr) {
					t.Fatalf("expected *TokenError, got %T: %v", err, err)
				}
				if tokErr.Type != TokenErrExpired {
					t.Errorf("error type = %d, want TokenErrExpired", tokErr.Type)
				}
			},
		},
		{
			name:      "terminal status EXPIRED",
			token:     terminalExpiredToken,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var tokErr *TokenError
				if !errors.As(err, &tokErr) {
					t.Fatalf("expected *TokenError, got %T: %v", err, err)
				}
				if tokErr.Type != TokenErrTerminalStatus {
					t.Errorf("error type = %d, want TokenErrTerminalStatus", tokErr.Type)
				}
				if tokErr.Status != StatusExpired {
					t.Errorf("status = %q, want %q", tokErr.Status, StatusExpired)
				}
			},
		},
		{
			name:      "terminal status REVOKED",
			token:     terminalRevokedToken,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var tokErr *TokenError
				if !errors.As(err, &tokErr) {
					t.Fatalf("expected *TokenError, got %T: %v", err, err)
				}
				if tokErr.Type != TokenErrTerminalStatus {
					t.Errorf("error type = %d, want TokenErrTerminalStatus", tokErr.Type)
				}
				if tokErr.Status != StatusRevoked {
					t.Errorf("status = %q, want %q", tokErr.Status, StatusRevoked)
				}
			},
		},
		{
			name:      "missing agent_id",
			token:     missingAgentIDToken,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var tokErr *TokenError
				if !errors.As(err, &tokErr) {
					t.Fatalf("expected *TokenError, got %T: %v", err, err)
				}
				if tokErr.Type != TokenErrMissingField {
					t.Errorf("error type = %d, want TokenErrMissingField", tokErr.Type)
				}
			},
		},
		{
			name:      "missing status",
			token:     missingStatusToken,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var tokErr *TokenError
				if !errors.As(err, &tokErr) {
					t.Fatalf("expected *TokenError, got %T: %v", err, err)
				}
				if tokErr.Type != TokenErrMissingField {
					t.Errorf("error type = %d, want TokenErrMissingField", tokErr.Type)
				}
			},
		},
		{
			name:      "missing exp",
			token:     missingExpToken,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var tokErr *TokenError
				if !errors.As(err, &tokErr) {
					t.Fatalf("expected *TokenError, got %T: %v", err, err)
				}
				if tokErr.Type != TokenErrMissingField {
					t.Errorf("error type = %d, want TokenErrMissingField", tokErr.Type)
				}
			},
		},
		{
			name:      "missing ans_name",
			token:     missingAnsNameToken,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var tokErr *TokenError
				if !errors.As(err, &tokErr) {
					t.Fatalf("expected *TokenError, got %T: %v", err, err)
				}
				if tokErr.Type != TokenErrMissingField {
					t.Errorf("error type = %d, want TokenErrMissingField", tokErr.Type)
				}
				if tokErr.Message != "ans_name" {
					t.Errorf("error message = %q, want %q", tokErr.Message, "ans_name")
				}
			},
		},
		{
			name:      "wrong signature",
			token:     wrongSigToken,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var sigErr *SignatureError
				if !errors.As(err, &sigErr) {
					t.Fatalf("expected *SignatureError, got %T: %v", err, err)
				}
				if sigErr.Type != SigErrSignatureInvalid {
					t.Errorf("error type = %d, want SigErrSignatureInvalid", sigErr.Type)
				}
			},
		},
		{
			name:      "unknown key ID",
			token:     unknownKidToken,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var sigErr *SignatureError
				if !errors.As(err, &sigErr) {
					t.Fatalf("expected *SignatureError, got %T: %v", err, err)
				}
				if sigErr.Type != SigErrUnknownKeyID {
					t.Errorf("error type = %d, want SigErrUnknownKeyID", sigErr.Type)
				}
			},
		},
		{
			name:      "issuer matches key name",
			token:     issuerMatchToken,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   false,
			resultCheck: func(t *testing.T, result *VerifiedStatusToken) {
				t.Helper()
				if result.Payload.AgentID != "agent-123" {
					t.Errorf("AgentID = %q, want %q", result.Payload.AgentID, "agent-123")
				}
			},
		},
		{
			name:      "issuer mismatch",
			token:     issuerMismatchToken,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var sigErr *SignatureError
				if !errors.As(err, &sigErr) {
					t.Fatalf("expected *SignatureError, got %T: %v", err, err)
				}
				if sigErr.Type != SigErrIssuerMismatch {
					t.Errorf("error type = %d, want SigErrIssuerMismatch", sigErr.Type)
				}
			},
		},
		{
			name:      "unknown status FOOBAR accepted (not terminal)",
			token:     unknownStatusToken,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   false,
			resultCheck: func(t *testing.T, result *VerifiedStatusToken) {
				t.Helper()
				if result.Payload.Status != AgentStatus("FOOBAR") {
					t.Errorf("Status = %q, want %q", result.Payload.Status, "FOOBAR")
				}
				if result.Payload.AgentID != "agent-123" {
					t.Errorf("AgentID = %q, want %q", result.Payload.AgentID, "agent-123")
				}
			},
		},
		{
			name:      "token without expiration (exp=0 defensive)",
			token:     noExpToken,
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var tokErr *TokenError
				if !errors.As(err, &tokErr) {
					t.Fatalf("expected *TokenError, got %T: %v", err, err)
				}
				if tokErr.Type != TokenErrMissingField {
					t.Errorf("error type = %d, want TokenErrMissingField", tokErr.Type)
				}
				if tokErr.Message != "exp" {
					t.Errorf("error message = %q, want %q", tokErr.Message, "exp")
				}
			},
		},
		{
			name: "cert array exceeds MaxCertArrayLen",
			token: func() []byte {
				oversizedCerts := make([]CertEntry, MaxCertArrayLen+1)
				for i := range oversizedCerts {
					fp := sha256.Sum256([]byte(fmt.Sprintf("cert-%d", i)))
					oversizedCerts[i] = CertEntry{Fingerprint: fp, CertType: CertTypeX509DVServer}
				}
				payload := buildStatusPayloadCBOR(t,
					"agent-overflow", "example.ans", StatusActive, now-60, now+3600,
					nil, oversizedCerts, nil,
				)
				return signStatusToken(t, ki.priv, ki.kid, payload, nil)
			}(),
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var tokErr *TokenError
				if !errors.As(err, &tokErr) {
					t.Fatalf("expected *TokenError, got %T: %v", err, err)
				}
				if tokErr.Type != TokenErrPayloadInvalid {
					t.Errorf("error type = %d, want TokenErrPayloadInvalid", tokErr.Type)
				}
				if !containsString(tokErr.Message, "exceeds maximum") {
					t.Errorf("error message = %q, want containing 'exceeds maximum'", tokErr.Message)
				}
			},
		},
		{
			name:      "garbage input bytes",
			token:     []byte("not cbor at all"),
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   true,
		},
		{
			name:      "empty payload COSE_Sign1",
			token:     buildEmptyPayloadCoseSign1(t, ki),
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   true,
		},
		{
			name:      "valid token with metadata hashes",
			token:     buildMetadataHashesToken(t, ki, now),
			keys:      store,
			clockSkew: 0,
			now:       now,
			wantErr:   false,
			resultCheck: func(t *testing.T, result *VerifiedStatusToken) {
				t.Helper()
				if len(result.Payload.MetadataHashes) != 1 {
					t.Fatalf("expected 1 metadata hash, got %d", len(result.Payload.MetadataHashes))
				}
				if result.Payload.MetadataHashes["logo"] != "abc123" {
					t.Errorf("metadata hash = %q, want %q", result.Payload.MetadataHashes["logo"], "abc123")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := VerifyStatusTokenAt(tt.token, tt.keys, tt.clockSkew, tt.now)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errCheck != nil {
					tt.errCheck(t, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if tt.resultCheck != nil {
				tt.resultCheck(t, result)
			}
		})
	}
}

func TestVerifyStatusTokenAt_ClockSkewClamping(t *testing.T) {
	t.Parallel()

	ki := generateTestKey(t, "skew-test")
	store := newTestKeyStore(ki)
	now := time.Now().Unix()

	// Token expired 30 seconds ago — within 10-minute MaxClockSkew.
	recentlyExpiredPayload := buildStatusPayloadCBOR(t,
		"agent-skew", "example.ans", StatusActive, now-3600, now-30,
		nil, nil, nil,
	)
	recentlyExpiredToken := signStatusToken(t, ki.priv, ki.kid, recentlyExpiredPayload, nil)

	// Token expired 15 minutes ago — beyond 10-minute MaxClockSkew.
	expiredBeyondMaxPayload := buildStatusPayloadCBOR(t,
		"agent-skew", "example.ans", StatusActive, now-3600, now-900,
		nil, nil, nil,
	)
	expiredBeyondMaxToken := signStatusToken(t, ki.priv, ki.kid, expiredBeyondMaxPayload, nil)

	tests := []struct {
		name      string
		token     []byte
		clockSkew time.Duration
		wantErr   bool
		errCheck  func(t *testing.T, err error)
	}{
		{
			name:      "negative skew clamped to zero — recently expired token rejected",
			token:     recentlyExpiredToken,
			clockSkew: -5 * time.Minute,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var tokErr *TokenError
				if !errors.As(err, &tokErr) {
					t.Fatalf("expected *TokenError, got %T: %v", err, err)
				}
				if tokErr.Type != TokenErrExpired {
					t.Errorf("error type = %d, want TokenErrExpired", tokErr.Type)
				}
			},
		},
		{
			name:      "massive skew clamped to MaxClockSkew — expired beyond max still rejected",
			token:     expiredBeyondMaxToken,
			clockSkew: 100 * 24 * time.Hour,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var tokErr *TokenError
				if !errors.As(err, &tokErr) {
					t.Fatalf("expected *TokenError, got %T: %v", err, err)
				}
				if tokErr.Type != TokenErrExpired {
					t.Errorf("error type = %d, want TokenErrExpired", tokErr.Type)
				}
			},
		},
		{
			name:      "normal skew within MaxClockSkew — recently expired token accepted",
			token:     recentlyExpiredToken,
			clockSkew: 2 * time.Minute,
			wantErr:   false,
		},
		{
			name:      "math.MaxInt64 skew does not overflow — expired token still rejected",
			token:     expiredBeyondMaxToken,
			clockSkew: time.Duration(math.MaxInt64),
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				t.Helper()
				var tokErr *TokenError
				if !errors.As(err, &tokErr) {
					t.Fatalf("expected *TokenError, got %T: %v", err, err)
				}
				if tokErr.Type != TokenErrExpired {
					t.Errorf("error type = %d, want TokenErrExpired", tokErr.Type)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := VerifyStatusTokenAt(tt.token, store, tt.clockSkew, now)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errCheck != nil {
					tt.errCheck(t, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
		})
	}
}

// buildEmptyPayloadCoseSign1 builds a COSE_Sign1 with empty payload to trigger CoseError.
func buildEmptyPayloadCoseSign1(t *testing.T, ki *testKeyBundle) []byte {
	t.Helper()
	protectedBytes := buildStatusProtectedHeader(t, ki.kid, nil)
	unprotected, _ := cbor.Marshal(map[int64]interface{}{})
	fakeSig := make([]byte, 64)

	arr := []cbor.RawMessage{
		mustCBOREncode(t, protectedBytes),
		unprotected,
		mustCBOREncode(t, []byte{}),
		mustCBOREncode(t, fakeSig),
	}
	arrayBytes, _ := cbor.Marshal(arr)
	tag := cbor.RawTag{Number: 18, Content: arrayBytes}
	tagged, _ := tag.MarshalCBOR()
	return tagged
}

func buildMetadataHashesToken(t *testing.T, ki *testKeyBundle, now int64) []byte {
	t.Helper()
	payload := buildStatusPayloadCBOR(t,
		"agent-123", "example.ans", StatusActive, now-60, now+3600,
		nil, nil, map[string]string{"logo": "abc123"},
	)
	return signStatusToken(t, ki.priv, ki.kid, payload, nil)
}

func TestVerifyStatusToken(t *testing.T) {
	t.Parallel()

	ki := generateTestKey(t, "live-key")
	store := newTestKeyStore(ki)

	now := time.Now().Unix()
	payload := buildStatusPayloadCBOR(t,
		"agent-456", "live.ans", StatusActive, now-60, now+3600,
		nil, nil, nil,
	)
	token := signStatusToken(t, ki.priv, ki.kid, payload, nil)

	result, err := VerifyStatusToken(token, store, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Payload.AgentID != "agent-456" {
		t.Errorf("AgentID = %q, want %q", result.Payload.AgentID, "agent-456")
	}
}

func TestMatchesServerCert(t *testing.T) {
	t.Parallel()

	fp1 := sha256.Sum256([]byte("server-cert-1"))
	fp2 := sha256.Sum256([]byte("server-cert-2"))
	fpUnknown := sha256.Sum256([]byte("unknown-cert"))

	payload := &StatusTokenPayload{
		ValidServerCerts: []CertEntry{
			{Fingerprint: fp1, CertType: CertTypeX509DVServer},
			{Fingerprint: fp2, CertType: CertTypeX509DVServer},
		},
	}

	tests := []struct {
		name        string
		payload     *StatusTokenPayload
		fingerprint [32]byte
		want        bool
	}{
		{
			name:        "matches first cert",
			payload:     payload,
			fingerprint: fp1,
			want:        true,
		},
		{
			name:        "matches second cert",
			payload:     payload,
			fingerprint: fp2,
			want:        true,
		},
		{
			name:        "no match",
			payload:     payload,
			fingerprint: fpUnknown,
			want:        false,
		},
		{
			name:        "empty cert list",
			payload:     &StatusTokenPayload{},
			fingerprint: fp1,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := MatchesServerCert(tt.payload, tt.fingerprint)
			if got != tt.want {
				t.Errorf("MatchesServerCert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatchesIdentityCert(t *testing.T) {
	t.Parallel()

	fp1 := sha256.Sum256([]byte("identity-cert-1"))
	fp2 := sha256.Sum256([]byte("identity-cert-2"))
	fpUnknown := sha256.Sum256([]byte("unknown-cert"))

	payload := &StatusTokenPayload{
		ValidIdentityCerts: []CertEntry{
			{Fingerprint: fp1, CertType: CertTypeX509OVClient},
			{Fingerprint: fp2, CertType: CertTypeX509OVClient},
		},
	}

	tests := []struct {
		name        string
		payload     *StatusTokenPayload
		fingerprint [32]byte
		want        bool
	}{
		{
			name:        "matches first cert",
			payload:     payload,
			fingerprint: fp1,
			want:        true,
		},
		{
			name:        "matches second cert",
			payload:     payload,
			fingerprint: fp2,
			want:        true,
		},
		{
			name:        "no match",
			payload:     payload,
			fingerprint: fpUnknown,
			want:        false,
		},
		{
			name:        "empty cert list",
			payload:     &StatusTokenPayload{},
			fingerprint: fp1,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := MatchesIdentityCert(tt.payload, tt.fingerprint)
			if got != tt.want {
				t.Errorf("MatchesIdentityCert() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFingerprintFormatNormalization verifies that MatchesServerCert works with raw [32]byte
// fingerprints regardless of how they were originally encoded — the same 32 bytes always match.
func TestFingerprintFormatNormalization(t *testing.T) {
	t.Parallel()

	// Generate a fingerprint from a known source.
	fp := sha256.Sum256([]byte("cert-data-for-normalization"))

	// Construct the same fingerprint via different paths to ensure raw bytes are all that matter.
	var fpFromSlice [32]byte
	copy(fpFromSlice[:], fp[:])

	fpFromLoop := fp

	payload := &StatusTokenPayload{
		ValidServerCerts: []CertEntry{
			{Fingerprint: fp, CertType: CertTypeX509DVServer},
		},
	}

	tests := []struct {
		name        string
		fingerprint [32]byte
		want        bool
	}{
		{
			name:        "original fingerprint matches",
			fingerprint: fp,
			want:        true,
		},
		{
			name:        "fingerprint copied via slice matches",
			fingerprint: fpFromSlice,
			want:        true,
		},
		{
			name:        "fingerprint copied via loop matches",
			fingerprint: fpFromLoop,
			want:        true,
		},
		{
			name:        "different fingerprint does not match",
			fingerprint: sha256.Sum256([]byte("different-cert")),
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := MatchesServerCert(payload, tt.fingerprint)
			if got != tt.want {
				t.Errorf("MatchesServerCert() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFingerprintComparisonUsesConstantTime verifies that MatchesServerCert and MatchesIdentityCert
// use constant-time comparison (subtle.ConstantTimeCompare). The behavioral test confirms that
// non-matching fingerprints differing in the first byte vs the last byte both return false.
// The implementation uses subtle.ConstantTimeCompare — see status_token.go:MatchesServerCert
// and status_token.go:MatchesIdentityCert.
func TestFingerprintComparisonUsesConstantTime(t *testing.T) {
	t.Parallel()

	baseFP := sha256.Sum256([]byte("base-cert-for-timing"))

	payload := &StatusTokenPayload{
		ValidServerCerts: []CertEntry{
			{Fingerprint: baseFP, CertType: CertTypeX509DVServer},
		},
		ValidIdentityCerts: []CertEntry{
			{Fingerprint: baseFP, CertType: CertTypeX509OVClient},
		},
	}

	// Build a fingerprint that differs only in the first byte.
	fpDiffFirst := baseFP
	fpDiffFirst[0] ^= 0xFF

	// Build a fingerprint that differs only in the last byte.
	fpDiffLast := baseFP
	fpDiffLast[31] ^= 0xFF

	tests := []struct {
		name        string
		matchFn     func(*StatusTokenPayload, [32]byte) bool
		fingerprint [32]byte
		want        bool
	}{
		{
			name:        "server cert - exact match",
			matchFn:     MatchesServerCert,
			fingerprint: baseFP,
			want:        true,
		},
		{
			name:        "server cert - differs in first byte",
			matchFn:     MatchesServerCert,
			fingerprint: fpDiffFirst,
			want:        false,
		},
		{
			name:        "server cert - differs in last byte",
			matchFn:     MatchesServerCert,
			fingerprint: fpDiffLast,
			want:        false,
		},
		{
			name:        "identity cert - exact match",
			matchFn:     MatchesIdentityCert,
			fingerprint: baseFP,
			want:        true,
		},
		{
			name:        "identity cert - differs in first byte",
			matchFn:     MatchesIdentityCert,
			fingerprint: fpDiffFirst,
			want:        false,
		},
		{
			name:        "identity cert - differs in last byte",
			matchFn:     MatchesIdentityCert,
			fingerprint: fpDiffLast,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.matchFn(payload, tt.fingerprint)
			if got != tt.want {
				t.Errorf("match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCertificateRenewalWindow simulates a certificate renewal scenario where both
// old and new server certs are present in the payload, and verifies matching behavior.
func TestCertificateRenewalWindow(t *testing.T) {
	t.Parallel()

	fpOld := sha256.Sum256([]byte("old-server-cert"))
	fpNew := sha256.Sum256([]byte("new-server-cert"))
	fpNeither := sha256.Sum256([]byte("unrelated-cert"))

	tests := []struct {
		name        string
		serverCerts []CertEntry
		fingerprint [32]byte
		want        bool
	}{
		{
			name: "old cert matches (old-first order)",
			serverCerts: []CertEntry{
				{Fingerprint: fpOld, CertType: CertTypeX509DVServer},
				{Fingerprint: fpNew, CertType: CertTypeX509DVServer},
			},
			fingerprint: fpOld,
			want:        true,
		},
		{
			name: "new cert matches (old-first order)",
			serverCerts: []CertEntry{
				{Fingerprint: fpOld, CertType: CertTypeX509DVServer},
				{Fingerprint: fpNew, CertType: CertTypeX509DVServer},
			},
			fingerprint: fpNew,
			want:        true,
		},
		{
			name: "neither cert matches",
			serverCerts: []CertEntry{
				{Fingerprint: fpOld, CertType: CertTypeX509DVServer},
				{Fingerprint: fpNew, CertType: CertTypeX509DVServer},
			},
			fingerprint: fpNeither,
			want:        false,
		},
		{
			name: "old cert matches (new-first order)",
			serverCerts: []CertEntry{
				{Fingerprint: fpNew, CertType: CertTypeX509DVServer},
				{Fingerprint: fpOld, CertType: CertTypeX509DVServer},
			},
			fingerprint: fpOld,
			want:        true,
		},
		{
			name: "new cert matches (new-first order)",
			serverCerts: []CertEntry{
				{Fingerprint: fpNew, CertType: CertTypeX509DVServer},
				{Fingerprint: fpOld, CertType: CertTypeX509DVServer},
			},
			fingerprint: fpNew,
			want:        true,
		},
		{
			name: "neither cert matches (new-first order)",
			serverCerts: []CertEntry{
				{Fingerprint: fpNew, CertType: CertTypeX509DVServer},
				{Fingerprint: fpOld, CertType: CertTypeX509DVServer},
			},
			fingerprint: fpNeither,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			payload := &StatusTokenPayload{
				ValidServerCerts: tt.serverCerts,
			}
			got := MatchesServerCert(payload, tt.fingerprint)
			if got != tt.want {
				t.Errorf("MatchesServerCert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeStatusPayload_ErrorPaths(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "empty payload",
			data:    []byte{},
			wantErr: "payload is empty",
		},
		{
			name: "non-map CBOR (integer)",
			data: func() []byte {
				d, _ := cbor.Marshal(42)
				return d
			}(),
			wantErr: "failed to decode payload",
		},
		{
			name: "non-map CBOR (array)",
			data: func() []byte {
				d, _ := cbor.Marshal([]int{1, 2, 3})
				return d
			}(),
			wantErr: "failed to decode payload",
		},
		{
			name: "missing agent_id",
			data: func() []byte {
				m := map[interface{}]interface{}{
					int64(2): "ACTIVE",
					int64(4): time.Now().Add(time.Hour).Unix(),
				}
				d, _ := cbor.Marshal(m)
				return d
			}(),
			wantErr: "agent_id",
		},
		{
			name: "missing status",
			data: func() []byte {
				m := map[interface{}]interface{}{
					int64(1): "agent-1",
					int64(4): time.Now().Add(time.Hour).Unix(),
				}
				d, _ := cbor.Marshal(m)
				return d
			}(),
			wantErr: "status",
		},
		{
			name: "missing exp",
			data: func() []byte {
				m := map[interface{}]interface{}{
					int64(1): "agent-1",
					int64(2): "ACTIVE",
				}
				d, _ := cbor.Marshal(m)
				return d
			}(),
			wantErr: "exp",
		},
		{
			name: "missing ans_name",
			data: func() []byte {
				m := map[interface{}]interface{}{
					int64(1): "agent-1",
					int64(2): "ACTIVE",
					int64(4): time.Now().Add(time.Hour).Unix(),
				}
				d, _ := cbor.Marshal(m)
				return d
			}(),
			wantErr: "ans_name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeStatusPayload(tt.data)
			if err == nil {
				t.Fatal("expected error")
			}
			if !containsString(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestDecodeStringField_InvalidCBOR(t *testing.T) {
	dm, _ := newDecMode()

	tests := []struct {
		name string
		raw  cbor.RawMessage
		want string
	}{
		{
			name: "integer instead of string",
			raw: func() cbor.RawMessage {
				d, _ := cbor.Marshal(42)
				return d
			}(),
			want: "",
		},
		{
			name: "array instead of string",
			raw: func() cbor.RawMessage {
				d, _ := cbor.Marshal([]int{1, 2})
				return d
			}(),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeStringField(dm, tt.raw)
			if got != tt.want {
				t.Errorf("decodeStringField() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeInt64Field_InvalidCBOR(t *testing.T) {
	dm, _ := newDecMode()

	tests := []struct {
		name string
		raw  cbor.RawMessage
		want int64
	}{
		{
			name: "string instead of int",
			raw: func() cbor.RawMessage {
				d, _ := cbor.Marshal("not-a-number")
				return d
			}(),
			want: 0,
		},
		{
			name: "array instead of int",
			raw: func() cbor.RawMessage {
				d, _ := cbor.Marshal([]string{"a"})
				return d
			}(),
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeInt64Field(dm, tt.raw)
			if got != tt.want {
				t.Errorf("decodeInt64Field() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNewPayloadFieldGetter_StringKeyFallback(t *testing.T) {
	// Build a payload map with only string keys (no integer keys)
	rawMap := make(map[interface{}]cbor.RawMessage)
	agentIDBytes, _ := cbor.Marshal("agent-from-string-key")
	rawMap["agent_id"] = agentIDBytes
	statusBytes, _ := cbor.Marshal("ACTIVE")
	rawMap["status"] = statusBytes

	get := newPayloadFieldGetter(rawMap)

	tests := []struct {
		name   string
		intKey uint64
		strKey string
		want   bool
	}{
		{
			name:   "string key found for agent_id",
			intKey: 1,
			strKey: "agent_id",
			want:   true,
		},
		{
			name:   "string key found for status",
			intKey: 2,
			strKey: "status",
			want:   true,
		},
		{
			name:   "key not found at all",
			intKey: 99,
			strKey: "nonexistent",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := get(tt.intKey, tt.strKey)
			if ok != tt.want {
				t.Errorf("get(%d, %q) found = %v, want %v", tt.intKey, tt.strKey, ok, tt.want)
			}
		})
	}
}
