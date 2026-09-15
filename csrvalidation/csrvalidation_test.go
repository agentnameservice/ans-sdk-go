package csrvalidation

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		key     func(t *testing.T) crypto.Signer
		sigAlg  x509.SignatureAlgorithm
		rules   Rules
		wantErr error
	}{
		{name: "identity RSA 2048 SHA256", key: rsaKey(2048), sigAlg: x509.SHA256WithRSA, rules: IdentityRules()},
		{name: "identity RSA 3072 SHA384", key: rsaKey(3072), sigAlg: x509.SHA384WithRSA, rules: IdentityRules()},
		{name: "identity RSA 4096 SHA512", key: rsaKey(4096), sigAlg: x509.SHA512WithRSA, rules: IdentityRules()},
		{name: "identity EC P-256 ECDSA-SHA256", key: ecKey(elliptic.P256()), sigAlg: x509.ECDSAWithSHA256, rules: IdentityRules()},
		{name: "identity EC P-256 ECDSA-SHA384", key: ecKey(elliptic.P256()), sigAlg: x509.ECDSAWithSHA384, rules: IdentityRules()},
		{name: "identity EC P-384 rejected", key: ecKey(elliptic.P384()), sigAlg: x509.ECDSAWithSHA384, rules: IdentityRules(), wantErr: ErrCurve},
		{name: "identity RSA 1024 rejected", key: rsaKey(1024), sigAlg: x509.SHA256WithRSA, rules: IdentityRules(), wantErr: ErrKeySize},
		{name: "identity Ed25519 rejected", key: ed25519Key, sigAlg: x509.PureEd25519, rules: IdentityRules(), wantErr: ErrKeyAlgorithm},
		{name: "server RSA 2048 SHA256", key: rsaKey(2048), sigAlg: x509.SHA256WithRSA, rules: ServerRules()},
		{name: "server RSA 4096 SHA256", key: rsaKey(4096), sigAlg: x509.SHA256WithRSA, rules: ServerRules()},
		{name: "server RSA 3072 rejected", key: rsaKey(3072), sigAlg: x509.SHA256WithRSA, rules: ServerRules(), wantErr: ErrKeySize},
		{name: "server RSA 2048 SHA384 rejected", key: rsaKey(2048), sigAlg: x509.SHA384WithRSA, rules: ServerRules(), wantErr: ErrSignatureAlgorithm},
		{name: "server EC P-256 rejected", key: ecKey(elliptic.P256()), sigAlg: x509.ECDSAWithSHA256, rules: ServerRules(), wantErr: ErrKeyAlgorithm},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			csrPEM := newCSR(t, tc.key(t), tc.sigAlg)

			csr, err := Validate(csrPEM, tc.rules)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Validate() error = %v, want %v", err, tc.wantErr)
				}
				if csr != nil {
					t.Error("expected nil request on error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if csr == nil || csr.Subject.CommonName != testHost {
				t.Fatalf("Validate() returned request %+v, want CN %q", csr, testHost)
			}
		})
	}
}

func TestValidate_MalformedInput(t *testing.T) {
	good := newCSR(t, ecKey(elliptic.P256())(t), x509.ECDSAWithSHA256)

	tests := []struct {
		name    string
		csrPEM  []byte
		wantErr error
	}{
		{name: "not PEM", csrPEM: []byte("not a csr"), wantErr: ErrInvalidCSR},
		{name: "wrong PEM block type", csrPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x00}}), wantErr: ErrInvalidCSR},
		{name: "garbage DER", csrPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("garbage")}), wantErr: ErrInvalidCSR},
		{name: "tampered subject breaks the self-signature", csrPEM: tamperCommonName(t, good), wantErr: ErrSignature},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(tc.csrPEM, IdentityRules())
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate() error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidate_ErrorMessagesNameTheRule(t *testing.T) {
	tests := []struct {
		name  string
		key   func(t *testing.T) crypto.Signer
		alg   x509.SignatureAlgorithm
		rules Rules
		want  string
	}{
		{name: "RSA size", key: rsaKey(3072), alg: x509.SHA256WithRSA, rules: ServerRules(), want: "RSA key size must be 2048 or 4096 bits, but was 3072 bits"},
		{name: "EC curve", key: ecKey(elliptic.P384()), alg: x509.ECDSAWithSHA384, rules: IdentityRules(), want: `EC key curve must be P-256, but was "P-384"`},
		{name: "EC not allowed", key: ecKey(elliptic.P256()), alg: x509.ECDSAWithSHA256, rules: ServerRules(), want: "CSR public key must use RSA, but was EC"},
		{name: "signature algorithm", key: rsaKey(2048), alg: x509.SHA384WithRSA, rules: ServerRules(), want: "CSR signature algorithm must be SHA256-RSA, but was SHA384-RSA"},
		{name: "unsupported key type", key: ed25519Key, alg: x509.PureEd25519, rules: IdentityRules(), want: "CSR public key must use RSA or EC, but was ed25519.PublicKey"},
		{name: "unsupported key type, RSA-only rules", key: ed25519Key, alg: x509.PureEd25519, rules: ServerRules(), want: "CSR public key must use RSA, but was ed25519.PublicKey"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(newCSR(t, tc.key(t), tc.alg), tc.rules)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

const testHost = "agent.example.com"

// newCSR builds a PEM CSR for key with the requested signature algorithm and
// the SAN shape the registry expects (DNS host plus ans:// URI).
func newCSR(t *testing.T, key crypto.Signer, sigAlg x509.SignatureAlgorithm) []byte {
	t.Helper()
	template := x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: testHost},
		DNSNames:           []string{testHost},
		SignatureAlgorithm: sigAlg,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// tamperCommonName flips one character of the CN inside the DER so the request
// still parses but its self-signature no longer verifies.
func tamperCommonName(t *testing.T, csrPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	der := bytes.Replace(block.Bytes, []byte(testHost), []byte("agenu.example.com"), 1)
	if bytes.Equal(der, block.Bytes) {
		t.Fatal("CN not found in DER")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

var (
	rsaKeysMu sync.Mutex
	rsaKeys   = map[int]*rsa.PrivateKey{}
)

// rsaKey returns a generator that caches one RSA key per size, since 3072 and
// 4096-bit generation dominates the test runtime.
func rsaKey(bits int) func(t *testing.T) crypto.Signer {
	return func(t *testing.T) crypto.Signer {
		t.Helper()
		rsaKeysMu.Lock()
		defer rsaKeysMu.Unlock()
		if key, ok := rsaKeys[bits]; ok {
			return key
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatalf("rsa.GenerateKey(%d): %v", bits, err)
		}
		rsaKeys[bits] = key
		return key
	}
}

func ecKey(curve elliptic.Curve) func(t *testing.T) crypto.Signer {
	return func(t *testing.T) crypto.Signer {
		t.Helper()
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		return key
	}
}

func ed25519Key(t *testing.T) crypto.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return key
}
