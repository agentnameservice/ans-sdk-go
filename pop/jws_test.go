package pop

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

func TestSignVerifyES256_RoundTrip(t *testing.T) {
	key := genKey(t)
	input := []byte("header.payload")
	sig, err := signES256(key, input)
	if err != nil {
		t.Fatalf("signES256: %v", err)
	}
	if err := verifyES256(&key.PublicKey, input, sig); err != nil {
		t.Fatalf("verifyES256 round-trip: %v", err)
	}
	// Tampered input must fail.
	if err := verifyES256(&key.PublicKey, []byte("header.PAYLOAD"), sig); err == nil {
		t.Fatal("verifyES256 accepted tampered input")
	}
	// Wrong key must fail.
	other := genKey(t)
	if err := verifyES256(&other.PublicKey, input, sig); err == nil {
		t.Fatal("verifyES256 accepted wrong key")
	}
}

func TestVerifyES256_BadSignatureEncoding(t *testing.T) {
	key := genKey(t)
	input := []byte("a.b")
	tests := []struct {
		name string
		sig  string
		want ErrorType
	}{
		{"not base64url", "!!!not base64!!!", ErrMalformedProof},
		{"too short (63 bytes)", b64urlEncode(make([]byte, 63)), ErrSignatureInvalid},
		{"too long (65 bytes)", b64urlEncode(make([]byte, 65)), ErrSignatureInvalid},
		{"zero sig wrong", b64urlEncode(make([]byte, 64)), ErrSignatureInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertProofErr(t, verifyES256(&key.PublicKey, input, tt.sig), tt.want)
		})
	}
}

func TestSplitCompactJWS(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{"three segments", "aaa.bbb.ccc", false},
		{"two segments", "aaa.bbb", true},
		{"four segments", "aaa.bbb.ccc.ddd", true},
		{"empty middle", "aaa..ccc", true},
		{"empty first", ".bbb.ccc", true},
		{"empty last", "aaa.bbb.", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := splitCompactJWS(tt.token)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestProof_CrossValidateAgainstStdlib confirms a pop-minted proof verifies
// when checked field-by-field with crypto/ecdsa primitives independently of
// pop's own verify path — so the JWS construction is not merely self-consistent.
func TestProof_CrossValidateAgainstStdlib(t *testing.T) {
	h := newHarness(t)
	const method, rawURL = "GET", "https://callee.example/resource"
	token := h.proof(t, method, rawURL)

	headerB64, payloadB64, sigB64, err := splitCompactJWS(token)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	// Independently reconstruct the signing input and verify with stdlib.
	digest := sha256.Sum256([]byte(headerB64 + "." + payloadB64))
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("sig length = %d, want 64", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])

	// Extract the leaf cert key from x5c independently.
	hdr, err := decodeProofHeader(headerB64)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(hdr.X5c[0])
	if err != nil {
		t.Fatalf("x5c decode: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("cert key is not ECDSA")
	}
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatal("stdlib ecdsa.Verify rejected a pop-minted proof signature")
	}
	// The header must be exactly the pinned profile.
	if hdr.Typ != "dpop+jwt" || hdr.Alg != "ES256" {
		t.Errorf("header typ/alg = %q/%q", hdr.Typ, hdr.Alg)
	}
	if !strings.HasPrefix(token, headerB64+".") {
		t.Error("token does not start with its header segment")
	}
}
