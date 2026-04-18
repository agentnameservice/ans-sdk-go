package scitt

import (
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// MaxCertArrayLen is the maximum number of entries allowed in cert arrays.
const MaxCertArrayLen = 128

// CBOR payload key constants for status token fields.
const (
	payloadKeyAgentID        = 1
	payloadKeyStatus         = 2
	payloadKeyIat            = 3
	payloadKeyExp            = 4
	payloadKeyAnsName        = 5
	payloadKeyIdentityCerts  = 6
	payloadKeyServerCerts    = 7
	payloadKeyMetadataHashes = 8
)

// CBOR cert entry key constants (used within valid_identity_certs / valid_server_certs arrays).
const (
	certEntryKeyFingerprint = 1
	certEntryKeyCertType    = 2
)

// VerifiedStatusToken holds the decoded payload and key ID of a verified status token.
type VerifiedStatusToken struct {
	Payload StatusTokenPayload
	KeyID   [4]byte
}

// VerifyStatusToken verifies a COSE_Sign1 status token using the current time.
func VerifyStatusToken(tokenBytes []byte, keys KeyLookup, clockSkew time.Duration) (*VerifiedStatusToken, error) {
	return VerifyStatusTokenAt(tokenBytes, keys, clockSkew, time.Now().Unix())
}

// VerifyStatusTokenAt verifies a COSE_Sign1 status token at the given unix timestamp.
func VerifyStatusTokenAt(tokenBytes []byte, keys KeyLookup, clockSkew time.Duration, now int64) (*VerifiedStatusToken, error) {
	// Step 1: Parse COSE_Sign1.
	cose, err := ParseCoseSign1(tokenBytes)
	if err != nil {
		return nil, err
	}

	// Step 2: Key lookup.
	kid := cose.Protected.Kid
	trustedKey, err := keys.Get(kid)
	if err != nil {
		return nil, err
	}

	// Step 3: ECDSA verify (P1363 → DER → VerifyASN1).
	if err := verifyECDSA(trustedKey.Key, cose.ProtectedBytes, cose.Payload, cose.Signature, kid); err != nil {
		return nil, err
	}

	// Step 4: Issuer binding.
	if cose.Protected.CwtIss != nil && *cose.Protected.CwtIss != trustedKey.Name {
		return nil, &SignatureError{
			Type:    SigErrIssuerMismatch,
			Kid:     kid,
			Message: fmt.Sprintf("issuer %q does not match key name %q", *cose.Protected.CwtIss, trustedKey.Name),
		}
	}

	// Step 5: Decode CBOR payload.
	payload, err := decodeStatusPayload(cose.Payload)
	if err != nil {
		return nil, err
	}

	// Step 6: Check expiry.
	skewSeconds := int64(clockSkew / time.Second)
	if now > payload.Exp+skewSeconds {
		return nil, &TokenError{
			Type:    TokenErrExpired,
			Exp:     payload.Exp,
			Now:     now,
			Message: fmt.Sprintf("token expired at %d, now %d (skew %ds)", payload.Exp, now, skewSeconds),
		}
	}

	// Step 7: Check terminal status.
	if payload.Status.IsTerminal() {
		return nil, &TokenError{
			Type:    TokenErrTerminalStatus,
			Status:  payload.Status,
			Message: fmt.Sprintf("agent status is %s", payload.Status),
		}
	}

	return &VerifiedStatusToken{
		Payload: *payload,
		KeyID:   kid,
	}, nil
}

// verifyECDSA verifies a P1363-formatted ECDSA signature against a protected header and payload.
func verifyECDSA(key *ecdsa.PublicKey, protectedBytes, payload, sig []byte, kid [4]byte) error {
	digest, err := ComputeSigStructureDigest(protectedBytes, payload)
	if err != nil {
		return &SignatureError{
			Type:    SigErrSignatureInvalid,
			Kid:     kid,
			Message: "failed to compute sig structure digest",
			Cause:   err,
		}
	}

	// P1363 → DER: split 64-byte sig into r (first 32) and s (last 32).
	r := new(big.Int).SetBytes(sig[:hashLen])
	s := new(big.Int).SetBytes(sig[hashLen:p1363SignatureLen])

	derSig, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	if err != nil {
		return &SignatureError{
			Type:    SigErrSignatureInvalid,
			Kid:     kid,
			Message: "failed to marshal DER signature",
			Cause:   err,
		}
	}

	if !ecdsa.VerifyASN1(key, digest[:], derSig) {
		return &SignatureError{
			Type:    SigErrSignatureInvalid,
			Kid:     kid,
			Message: "ECDSA signature verification failed",
		}
	}

	return nil
}

// payloadFieldGetter looks up a raw CBOR value by integer key (uint64 or int64) or string key fallback.
type payloadFieldGetter func(intKey uint64, strKey string) (cbor.RawMessage, bool)

// newPayloadFieldGetter returns a getter that resolves integer and string keys from a raw CBOR map.
func newPayloadFieldGetter(rawMap map[interface{}]cbor.RawMessage) payloadFieldGetter {
	return func(intKey uint64, strKey string) (cbor.RawMessage, bool) {
		if raw, ok := rawMap[intKey]; ok {
			return raw, true
		}
		if raw, ok := rawMap[int64(intKey)]; ok { //nolint:gosec // G115: keys 1-8 fit safely in both uint64 and int64
			return raw, true
		}
		if raw, ok := rawMap[strKey]; ok {
			return raw, true
		}
		return nil, false
	}
}

// decodeStringField unmarshals a CBOR string field, returning empty string on failure.
func decodeStringField(dm cbor.DecMode, raw cbor.RawMessage) string {
	var v string
	if err := dm.Unmarshal(raw, &v); err == nil {
		return v
	}
	return ""
}

// decodeInt64Field unmarshals a CBOR int64 field, returning 0 on failure.
func decodeInt64Field(dm cbor.DecMode, raw cbor.RawMessage) int64 {
	var v int64
	if err := dm.Unmarshal(raw, &v); err == nil {
		return v
	}
	return 0
}

// decodePayloadFields extracts all status token fields from the raw CBOR map into a StatusTokenPayload.
func decodePayloadFields(dm cbor.DecMode, rawMap map[interface{}]cbor.RawMessage) (*StatusTokenPayload, error) {
	get := newPayloadFieldGetter(rawMap)
	payload := &StatusTokenPayload{}

	if raw, ok := get(payloadKeyAgentID, "agent_id"); ok {
		payload.AgentID = decodeStringField(dm, raw)
	}

	if raw, ok := get(payloadKeyStatus, "status"); ok {
		payload.Status = AgentStatus(decodeStringField(dm, raw))
	}

	if raw, ok := get(payloadKeyIat, "iat"); ok {
		payload.Iat = decodeInt64Field(dm, raw)
	}

	if raw, ok := get(payloadKeyExp, "exp"); ok {
		payload.Exp = decodeInt64Field(dm, raw)
	}

	if raw, ok := get(payloadKeyAnsName, "ans_name"); ok {
		payload.AnsName = decodeStringField(dm, raw)
	}

	if raw, ok := get(payloadKeyIdentityCerts, "valid_identity_certs"); ok {
		certs, err := decodeCertArray(dm, raw)
		if err != nil {
			return nil, err
		}
		payload.ValidIdentityCerts = certs
	}

	if raw, ok := get(payloadKeyServerCerts, "valid_server_certs"); ok {
		certs, err := decodeCertArray(dm, raw)
		if err != nil {
			return nil, err
		}
		payload.ValidServerCerts = certs
	}

	if raw, ok := get(payloadKeyMetadataHashes, "metadata_hashes"); ok {
		var v map[string]string
		if err := dm.Unmarshal(raw, &v); err == nil {
			payload.MetadataHashes = v
		}
	}

	return payload, nil
}

// decodeStatusPayload decodes a CBOR map payload into a StatusTokenPayload.
// Supports both integer and string keys for compatibility.
func decodeStatusPayload(data []byte) (*StatusTokenPayload, error) {
	if len(data) == 0 {
		return nil, &TokenError{
			Type:    TokenErrPayloadEmpty,
			Message: "payload is empty",
		}
	}

	dm, err := newDecMode()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR decode mode: %w", err)
	}

	var rawMap map[interface{}]cbor.RawMessage
	if err := dm.Unmarshal(data, &rawMap); err != nil {
		return nil, &TokenError{
			Type:    TokenErrPayloadEmpty,
			Message: fmt.Sprintf("failed to decode payload: %v", err),
			Cause:   err,
		}
	}

	payload, err := decodePayloadFields(dm, rawMap)
	if err != nil {
		return nil, err
	}

	// Validate required fields.
	if payload.AgentID == "" {
		return nil, &TokenError{
			Type:    TokenErrMissingField,
			Message: "agent_id",
		}
	}
	if payload.Status == "" {
		return nil, &TokenError{
			Type:    TokenErrMissingField,
			Message: "status",
		}
	}
	if payload.Exp == 0 {
		return nil, &TokenError{
			Type:    TokenErrMissingField,
			Message: "exp",
		}
	}

	return payload, nil
}

// decodeCertArray decodes a CBOR array of cert entries.
// Cert entries may use integer keys (1=fingerprint, 2=cert_type) or string keys
// ("fingerprint", "cert_type"). Fingerprints may be raw 32-byte values or
// "SHA256:<hex>" strings.
func decodeCertArray(dm cbor.DecMode, raw cbor.RawMessage) ([]CertEntry, error) {
	var arr []cbor.RawMessage
	if err := dm.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("failed to decode cert array: %w", err)
	}
	if len(arr) > MaxCertArrayLen {
		return nil, &TokenError{
			Type:    TokenErrPayloadInvalid,
			Message: fmt.Sprintf("cert array length %d exceeds maximum %d", len(arr), MaxCertArrayLen),
		}
	}

	entries := make([]CertEntry, 0, len(arr))
	for _, item := range arr {
		var certMap map[interface{}]cbor.RawMessage
		if err := dm.Unmarshal(item, &certMap); err != nil {
			continue
		}
		get := newPayloadFieldGetter(certMap)

		var entry CertEntry
		if fpRaw, ok := get(certEntryKeyFingerprint, "fingerprint"); ok {
			entry.Fingerprint = decodeFingerprintField(dm, fpRaw)
		}
		if ctRaw, ok := get(certEntryKeyCertType, "cert_type"); ok {
			entry.CertType = CertType(decodeStringField(dm, ctRaw))
		}
		if entry.Fingerprint != ([32]byte{}) {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

// decodeFingerprintField decodes a fingerprint from either raw 32-byte CBOR bytes
// or a "SHA256:<hex>" CBOR text string.
func decodeFingerprintField(dm cbor.DecMode, raw cbor.RawMessage) [32]byte {
	var fp []byte
	if err := dm.Unmarshal(raw, &fp); err == nil && len(fp) == 32 {
		var out [32]byte
		copy(out[:], fp)
		return out
	}

	var s string
	if err := dm.Unmarshal(raw, &s); err == nil {
		if parsed, ok := parseHexFingerprint(s); ok {
			return parsed
		}
	}
	return [32]byte{}
}

// parseHexFingerprint parses "SHA256:<hex>" or bare hex into a 32-byte fingerprint.
func parseHexFingerprint(s string) ([32]byte, bool) {
	hexStr := s
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "sha256:") {
		hexStr = s[7:]
	}
	decoded, err := hex.DecodeString(hexStr)
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, false
	}
	var out [32]byte
	copy(out[:], decoded)
	return out, true
}

// MatchesServerCert checks if any server cert in the payload matches the given fingerprint.
// Uses constant-time comparison.
func MatchesServerCert(payload *StatusTokenPayload, fingerprint [32]byte) bool {
	for _, cert := range payload.ValidServerCerts {
		if subtle.ConstantTimeCompare(cert.Fingerprint[:], fingerprint[:]) == 1 {
			return true
		}
	}
	return false
}

// MatchesIdentityCert checks if any identity cert in the payload matches the given fingerprint.
// Uses constant-time comparison.
func MatchesIdentityCert(payload *StatusTokenPayload, fingerprint [32]byte) bool {
	for _, cert := range payload.ValidIdentityCerts {
		if subtle.ConstantTimeCompare(cert.Fingerprint[:], fingerprint[:]) == 1 {
			return true
		}
	}
	return false
}
