package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/keygen"
)

const (
	testHost    = "test.example.com"
	testOrg     = "TestOrg"
	testCountry = "US"
	testVersion = "1.0.0"
	testANSURI  = "ans://v1.0.0.test.example.com"
)

func TestBuildGenerateCSRCmd(t *testing.T) {
	cmd := buildGenerateCSRCmd()

	if cmd == nil {
		t.Fatal("buildGenerateCSRCmd() returned nil")
	}

	if cmd.Use != "generate-csr" {
		t.Errorf("Use = %q, want %q", cmd.Use, "generate-csr")
	}

	tests := []struct {
		flag        string
		wantDefault string
	}{
		{flag: "host", wantDefault: ""},
		{flag: "org", wantDefault: ""},
		{flag: "version", wantDefault: ""},
		{flag: "country", wantDefault: "US"},
		{flag: "out-dir", wantDefault: "."},
		{flag: "key-type", wantDefault: ""},
		{flag: "key-size", wantDefault: "2048"},
		{flag: "csr-type", wantDefault: DefaultCSRType},
	}

	for _, tc := range tests {
		t.Run(tc.flag, func(t *testing.T) {
			f := cmd.Flags().Lookup(tc.flag)
			if f == nil {
				t.Fatalf("missing flag %q", tc.flag)
			}
			if f.DefValue != tc.wantDefault {
				t.Errorf("flag %q default = %q, want %q", tc.flag, f.DefValue, tc.wantDefault)
			}
		})
	}
	if cmd.Flags().Lookup("curve") != nil {
		t.Error("the curve flag was removed; only P-256 can be issued")
	}
}

func TestNewKeyGenerator(t *testing.T) {
	tests := []struct {
		name      string
		keyType   string
		keySize   int
		wantLabel string
		wantCurve elliptic.Curve // nil means an RSA key of keySize bits is expected
		wantErr   string
	}{
		{name: "rsa", keyType: "rsa", keySize: 2048, wantLabel: "RSA 2048 bits"},
		{name: "rsa is case-insensitive", keyType: "RSA", keySize: 2048, wantLabel: "RSA 2048 bits"},
		{name: "ec is always P-256", keyType: "ec", wantLabel: "EC P-256", wantCurve: elliptic.P256()},
		{name: "ec is case-insensitive", keyType: "EC", wantLabel: "EC P-256", wantCurve: elliptic.P256()},
		{name: "rsa below minimum size", keyType: "rsa", keySize: 1024, wantErr: "invalid RSA key size"},
		{name: "unknown key type", keyType: "dsa", keySize: 2048, wantErr: "invalid key type"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gen, label, err := newKeyGenerator(tc.keyType, tc.keySize)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
				}
				if gen != nil {
					t.Error("expected nil generator on error")
				}
				return
			}
			if err != nil {
				t.Fatalf("newKeyGenerator() error = %v", err)
			}
			if label != tc.wantLabel {
				t.Errorf("label = %q, want %q", label, tc.wantLabel)
			}

			key, err := gen()
			if err != nil {
				t.Fatalf("generator error = %v", err)
			}
			assertKeyMatches(t, key, tc.keySize, tc.wantCurve)
		})
	}
}

func TestRunGenerateCSR(t *testing.T) {
	tests := []struct {
		name        string
		keyType     string
		keySize     int
		csrType     string
		wantKeyPEM  string
		wantPubAlgo x509.PublicKeyAlgorithm
		wantSigAlgo x509.SignatureAlgorithm
		wantCurve   elliptic.Curve
		wantErr     string
	}{
		{
			name: "rsa forced for both", keyType: "rsa", keySize: DefaultRSAKeySize, csrType: "both",
			wantKeyPEM: "RSA PRIVATE KEY", wantPubAlgo: x509.RSA, wantSigAlgo: x509.SHA256WithRSA,
		},
		{
			name: "rsa 3072 identity only", keyType: "rsa", keySize: 3072, csrType: "identity",
			wantKeyPEM: "RSA PRIVATE KEY", wantPubAlgo: x509.RSA, wantSigAlgo: x509.SHA256WithRSA,
		},
		{
			name: "ec identity only", keyType: "ec", keySize: DefaultRSAKeySize, csrType: "identity",
			wantKeyPEM: "EC PRIVATE KEY", wantPubAlgo: x509.ECDSA, wantSigAlgo: x509.ECDSAWithSHA256, wantCurve: elliptic.P256(),
		},
		{name: "rsa 3072 for both is refused for the server CSR", keyType: "rsa", keySize: 3072, csrType: "both", wantErr: "rejects this key for the server CSR"},
		{name: "ec forced for both is refused for the server CSR", keyType: "ec", keySize: DefaultRSAKeySize, csrType: "both", wantErr: "rejects this key for the server CSR"},
		{name: "rsa below minimum size", keyType: "rsa", keySize: 1024, csrType: "both", wantErr: "invalid RSA key size"},
		{name: "invalid key type", keyType: "dsa", keySize: DefaultRSAKeySize, csrType: "both", wantErr: "invalid key type"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outDir := filepath.Join(t.TempDir(), "out")
			err := runGenerateCSR(&generateCSRParams{
				host: testHost, org: testOrg, country: testCountry, version: testVersion, outDir: outDir,
				keyType: tc.keyType, keySize: tc.keySize, csrType: tc.csrType,
			})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
				}
				if _, statErr := os.Stat(outDir); !errors.Is(statErr, fs.ErrNotExist) {
					t.Errorf("output directory %s was created despite invalid flags", outDir)
				}
				return
			}
			if err != nil {
				t.Fatalf("runGenerateCSR() error = %v", err)
			}

			names, err := csrNames(tc.csrType)
			if err != nil {
				t.Fatalf("csrNames: %v", err)
			}
			for _, name := range names {
				key := readPrivateKeyFile(t, filepath.Join(outDir, name+".key"), tc.wantKeyPEM)
				assertKeyMatches(t, key, tc.keySize, tc.wantCurve)

				csr := readCSRFile(t, filepath.Join(outDir, name+".csr"))
				if csr.PublicKeyAlgorithm != tc.wantPubAlgo {
					t.Errorf("%s CSR public key algorithm = %v, want %v", name, csr.PublicKeyAlgorithm, tc.wantPubAlgo)
				}
				if csr.SignatureAlgorithm != tc.wantSigAlgo {
					t.Errorf("%s CSR signature algorithm = %v, want %v", name, csr.SignatureAlgorithm, tc.wantSigAlgo)
				}
				if csr.Subject.CommonName != testHost {
					t.Errorf("%s CSR CN = %q, want %q", name, csr.Subject.CommonName, testHost)
				}
				if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != testOrg {
					t.Errorf("%s CSR O = %v, want [%s]", name, csr.Subject.Organization, testOrg)
				}
				if len(csr.Subject.Country) != 1 || csr.Subject.Country[0] != testCountry {
					t.Errorf("%s CSR C = %v, want [%s]", name, csr.Subject.Country, testCountry)
				}
				if len(csr.DNSNames) != 1 || csr.DNSNames[0] != testHost {
					t.Errorf("%s CSR DNS SANs = %v, want [%s]", name, csr.DNSNames, testHost)
				}
				if len(csr.URIs) != 1 || csr.URIs[0].String() != testANSURI {
					t.Errorf("%s CSR URI SANs = %v, want [%s]", name, csr.URIs, testANSURI)
				}
			}
		})
	}
}

func TestRunGenerateCSR_DefaultKeyTypes(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "out")
	err := runGenerateCSR(&generateCSRParams{
		host: testHost, org: testOrg, country: testCountry, version: testVersion, outDir: outDir,
		keySize: DefaultRSAKeySize, csrType: DefaultCSRType,
	})
	if err != nil {
		t.Fatalf("runGenerateCSR() error = %v", err)
	}

	identityKey := readPrivateKeyFile(t, filepath.Join(outDir, "identity.key"), "EC PRIVATE KEY")
	assertKeyMatches(t, identityKey, 0, elliptic.P256())
	if csr := readCSRFile(t, filepath.Join(outDir, "identity.csr")); csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("identity CSR signature algorithm = %v, want %v", csr.SignatureAlgorithm, x509.ECDSAWithSHA256)
	}

	serverKey := readPrivateKeyFile(t, filepath.Join(outDir, "server.key"), "RSA PRIVATE KEY")
	assertKeyMatches(t, serverKey, DefaultRSAKeySize, nil)
	if csr := readCSRFile(t, filepath.Join(outDir, "server.csr")); csr.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("server CSR signature algorithm = %v, want %v", csr.SignatureAlgorithm, x509.SHA256WithRSA)
	}
}

func TestRunGenerateCSR_CSRType(t *testing.T) {
	tests := []struct {
		name        string
		csrType     string
		wantFiles   []string
		absentFiles []string
		wantErr     string
	}{
		{name: "both", csrType: "both", wantFiles: []string{"identity.key", "identity.csr", "server.key", "server.csr"}},
		{name: "identity only", csrType: "identity", wantFiles: []string{"identity.key", "identity.csr"}, absentFiles: []string{"server.key", "server.csr"}},
		{name: "server only", csrType: "SERVER", wantFiles: []string{"server.key", "server.csr"}, absentFiles: []string{"identity.key", "identity.csr"}},
		{name: "invalid", csrType: "client", wantErr: "invalid CSR type"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outDir := filepath.Join(t.TempDir(), "out")
			err := runGenerateCSR(&generateCSRParams{
				host: testHost, org: testOrg, country: testCountry, version: testVersion, outDir: outDir,
				keySize: DefaultRSAKeySize, csrType: tc.csrType,
			})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
				}
				if _, statErr := os.Stat(outDir); !errors.Is(statErr, fs.ErrNotExist) {
					t.Errorf("output directory %s was created despite an invalid CSR type", outDir)
				}
				return
			}
			if err != nil {
				t.Fatalf("runGenerateCSR() error = %v", err)
			}
			for _, f := range tc.wantFiles {
				if _, statErr := os.Stat(filepath.Join(outDir, f)); statErr != nil {
					t.Errorf("expected %s to exist: %v", f, statErr)
				}
			}
			for _, f := range tc.absentFiles {
				if _, statErr := os.Stat(filepath.Join(outDir, f)); !errors.Is(statErr, fs.ErrNotExist) {
					t.Errorf("expected %s to be absent, stat err = %v", f, statErr)
				}
			}
		})
	}
}

func TestRunGenerateCSR_InvalidOutDir(t *testing.T) {
	// A path nested under a regular file can never be created as a directory.
	tmpDir := t.TempDir()
	fakePath := filepath.Join(tmpDir, "file.txt")
	if err := os.WriteFile(fakePath, []byte("content"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	err := runGenerateCSR(&generateCSRParams{
		host: testHost, org: testOrg, country: testCountry, version: testVersion,
		outDir: filepath.Join(fakePath, "subdir"), keySize: DefaultRSAKeySize, csrType: DefaultCSRType,
	})
	if err == nil {
		t.Fatal("expected error for invalid output directory, got nil")
	}
}

func TestRunGenerateCSR_CreatesNestedDir(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "a", "b", "c")

	err := runGenerateCSR(&generateCSRParams{
		host: testHost, org: testOrg, country: testCountry, version: testVersion,
		outDir: outDir, keySize: DefaultRSAKeySize, csrType: "identity",
	})
	if err != nil {
		t.Fatalf("runGenerateCSR() error = %v", err)
	}

	info, err := os.Stat(outDir)
	if err != nil {
		t.Fatalf("expected output directory to exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected output path to be a directory")
	}
}

// stubSigner is a crypto.Signer whose public key type x509 does not support,
// forcing x509.CreateCertificateRequest to fail after key generation succeeds.
type stubSigner struct{}

func (stubSigner) Public() crypto.PublicKey { return struct{}{} }

func (stubSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("stub signer cannot sign")
}

func TestGenerateCSR(t *testing.T) {
	ecP256 := func() (crypto.Signer, error) { return keygen.GenerateECKeyPair(keygen.CurveP256()) }
	ed25519Key := func() (crypto.Signer, error) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	}

	tests := []struct {
		name    string
		ansURI  string
		newKey  keyGenerator
		outDir  string                            // empty means a fresh temp dir
		setup   func(t *testing.T, outDir string) // optional precondition applied to outDir
		wantErr string                            // substring expected in the error; empty means success
	}{
		{name: "ec key", ansURI: testANSURI, newKey: ecP256},
		{
			name: "key generation fails", ansURI: testANSURI,
			newKey:  func() (crypto.Signer, error) { return nil, errors.New("entropy exhausted") },
			wantErr: "failed to generate private key",
		},
		{name: "unparseable ANS URI", ansURI: "ans://v1.0.0.bad host", newKey: ecP256, wantErr: "failed to parse ANS URI"},
		{
			name: "signer x509 cannot use", ansURI: testANSURI,
			newKey:  func() (crypto.Signer, error) { return stubSigner{}, nil },
			wantErr: "failed to create CSR",
		},
		{name: "key type keygen cannot encode", ansURI: testANSURI, newKey: ed25519Key, wantErr: "failed to write private key"},
		{name: "unwritable output directory", ansURI: testANSURI, newKey: ecP256, outDir: "/dev/null/nodir", wantErr: "failed to write private key"},
		{
			name: "CSR path is a directory", ansURI: testANSURI, newKey: ecP256,
			setup: func(t *testing.T, outDir string) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(outDir, "test.csr"), 0750); err != nil {
					t.Fatalf("setup: %v", err)
				}
			},
			wantErr: "failed to write CSR",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			outDir := tc.outDir
			if outDir == "" {
				outDir = t.TempDir()
			}
			if tc.setup != nil {
				tc.setup(t, outDir)
			}

			err := generateCSR("test", testHost, testOrg, testCountry, tc.ansURI, tc.newKey, outDir)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("generateCSR() error = %v", err)
			}

			for _, path := range []string{filepath.Join(outDir, "test.key"), filepath.Join(outDir, "test.csr")} {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatalf("expected file to exist at %s: %v", path, err)
				}
				if info.Size() == 0 {
					t.Errorf("expected file %s to have content", path)
				}
				if info.Mode().Perm() != 0600 {
					t.Errorf("%s permissions = %v, want 0600", path, info.Mode().Perm())
				}
			}
		})
	}
}

// assertKeyMatches checks that key is an RSA key of keySize bits when wantCurve
// is nil, or an ECDSA key on wantCurve otherwise.
func assertKeyMatches(t *testing.T, key crypto.PrivateKey, keySize int, wantCurve elliptic.Curve) {
	t.Helper()
	if wantCurve == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("key type = %T, want *rsa.PrivateKey", key)
		}
		if rsaKey.N.BitLen() != keySize {
			t.Errorf("RSA key size = %d, want %d", rsaKey.N.BitLen(), keySize)
		}
		return
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("key type = %T, want *ecdsa.PrivateKey", key)
	}
	if ecKey.Curve != wantCurve {
		t.Errorf("EC curve = %s, want %s", ecKey.Curve.Params().Name, wantCurve.Params().Name)
	}
}

// readPrivateKeyFile checks the key file's permissions and PEM block type, then
// returns the parsed private key.
func readPrivateKeyFile(t *testing.T, path, wantPEMType string) crypto.PrivateKey {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected key file %s to exist: %v", path, err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("key file %s permissions = %v, want 0600", path, info.Mode().Perm())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read key file %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("key file %s is not PEM", path)
	}
	if block.Type != wantPEMType {
		t.Errorf("key file %s PEM type = %q, want %q", path, block.Type, wantPEMType)
	}

	key, err := keygen.ParsePrivateKeyPEM(data, nil)
	if err != nil {
		t.Fatalf("failed to parse key file %s: %v", path, err)
	}
	return key
}

// readCSRFile parses the PEM-encoded CSR at path and verifies its self-signature.
func readCSRFile(t *testing.T, path string) *x509.CertificateRequest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read CSR file %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("CSR file %s is not a PEM CERTIFICATE REQUEST", path)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR %s: %v", path, err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR %s self-signature invalid: %v", path, err)
	}
	return csr
}
