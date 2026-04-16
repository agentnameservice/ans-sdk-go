package keygen

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertKeyPairValid(t *testing.T, kp *KeyPair, wantEncrypted bool) {
	t.Helper()
	if kp.PrivateKey == nil {
		t.Error("KeyPair.PrivateKey is nil")
	}
	if kp.PublicKey == nil {
		t.Error("KeyPair.PublicKey is nil")
	}
	if len(kp.PrivateKeyPEM) == 0 {
		t.Error("KeyPair.PrivateKeyPEM is empty")
	}
	if len(kp.PublicKeyPEM) == 0 {
		t.Error("KeyPair.PublicKeyPEM is empty")
	}
	if wantEncrypted && !bytes.Contains(kp.PrivateKeyPEM, []byte("ENCRYPTED")) {
		t.Error("Expected encrypted PEM block")
	}
}

func assertFilePermissions(t *testing.T, path string, wantPerm os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file not created: %v", err)
	}
	if info.Mode().Perm() != wantPerm {
		t.Errorf("file permissions = %v, want %v", info.Mode().Perm(), wantPerm)
	}
}

func assertKeyPairFilesWritten(t *testing.T, privPath, pubPath string) {
	t.Helper()
	assertFilePermissions(t, privPath, 0600)
	assertFilePermissions(t, pubPath, 0644)
	if _, err := LoadPrivateKeyPEM(privPath, nil); err != nil {
		t.Errorf("failed to load saved private key: %v", err)
	}
	if _, err := LoadPublicKeyPEM(pubPath); err != nil {
		t.Errorf("failed to load saved public key: %v", err)
	}
}

func assertPublicKeyFileSaved(t *testing.T, path string, roundtrip bool) {
	t.Helper()
	assertFilePermissions(t, path, 0644)
	if !roundtrip {
		return
	}
	loaded, err := LoadPublicKeyPEM(path)
	if err != nil {
		t.Fatalf("LoadPublicKeyPEM() error = %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadPublicKeyPEM() returned nil")
	}
}

func TestGenerateRSAKeyPair(t *testing.T) {
	tests := []struct {
		name    string
		bits    int
		wantErr bool
	}{
		{
			name:    "valid 2048 bits",
			bits:    2048,
			wantErr: false,
		},
		{
			name:    "valid 4096 bits",
			bits:    4096,
			wantErr: false,
		},
		{
			name:    "invalid 1024 bits (too small)",
			bits:    1024,
			wantErr: true,
		},
		{
			name:    "invalid 512 bits (too small)",
			bits:    512,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateRSAKeyPair(tt.bits)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateRSAKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && key == nil {
				t.Error("GenerateRSAKeyPair() returned nil key")
			}
			if !tt.wantErr && key.N.BitLen() != tt.bits {
				t.Errorf("GenerateRSAKeyPair() key size = %d, want %d", key.N.BitLen(), tt.bits)
			}
		})
	}
}

func TestGenerateECKeyPair(t *testing.T) {
	tests := []struct {
		name    string
		curve   elliptic.Curve
		wantErr bool
	}{
		{
			name:    "P-256 curve",
			curve:   CurveP256(),
			wantErr: false,
		},
		{
			name:    "P-384 curve",
			curve:   CurveP384(),
			wantErr: false,
		},
		{
			name:    "P-521 curve",
			curve:   CurveP521(),
			wantErr: false,
		},
		{
			name:    "nil curve",
			curve:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateECKeyPair(tt.curve)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateECKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && key == nil {
				t.Error("GenerateECKeyPair() returned nil key")
			}
			if !tt.wantErr && key.Curve != tt.curve {
				t.Errorf("GenerateECKeyPair() curve mismatch")
			}
		})
	}
}

func TestPrivateKeyToPEM(t *testing.T) {
	rsaKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	ecKey, err := GenerateECKeyPair(CurveP256())
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	tests := []struct {
		name     string
		key      any
		password []byte
		wantErr  bool
	}{
		{
			name:     "RSA key without password",
			key:      rsaKey,
			password: nil,
			wantErr:  false,
		},
		{
			name:     "RSA key with password",
			key:      rsaKey,
			password: []byte("testpassword"),
			wantErr:  false,
		},
		{
			name:     "EC key without password",
			key:      ecKey,
			password: nil,
			wantErr:  false,
		},
		{
			name:     "EC key with password",
			key:      ecKey,
			password: []byte("testpassword"),
			wantErr:  false,
		},
		{
			name:     "unsupported key type",
			key:      "not a key",
			password: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pem, err := PrivateKeyToPEM(tt.key, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("PrivateKeyToPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(pem) == 0 {
				t.Error("PrivateKeyToPEM() returned empty PEM")
			}
		})
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	rsaKey, _ := GenerateRSAKeyPair(2048)
	rsaPEM, _ := PrivateKeyToPEM(rsaKey, nil)
	rsaEncPEM, _ := PrivateKeyToPEM(rsaKey, []byte("password"))

	ecKey, _ := GenerateECKeyPair(CurveP256())
	ecPEM, _ := PrivateKeyToPEM(ecKey, nil)
	ecEncPEM, _ := PrivateKeyToPEM(ecKey, []byte("password"))

	// Build a PKCS8-encoded EC key PEM (not EC-specific format)
	// This exercises the x509.ParsePKCS8PrivateKey path in ParsePrivateKeyPEM
	ecPKCS8DER, _ := x509.MarshalPKCS8PrivateKey(ecKey)
	ecPKCS8PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: ecPKCS8DER,
	})

	tests := []struct {
		name     string
		pemData  []byte
		password []byte
		wantType string
		wantErr  bool
	}{
		{
			name:     "RSA key without encryption",
			pemData:  rsaPEM,
			password: nil,
			wantType: "*rsa.PrivateKey",
			wantErr:  false,
		},
		{
			name:     "RSA key with correct password",
			pemData:  rsaEncPEM,
			password: []byte("password"),
			wantType: "*rsa.PrivateKey",
			wantErr:  false,
		},
		{
			name:     "RSA key with wrong password",
			pemData:  rsaEncPEM,
			password: []byte("wrong"),
			wantErr:  true,
		},
		{
			name:     "EC key without encryption",
			pemData:  ecPEM,
			password: nil,
			wantType: "*ecdsa.PrivateKey",
			wantErr:  false,
		},
		{
			name:     "EC key with correct password",
			pemData:  ecEncPEM,
			password: []byte("password"),
			wantType: "*ecdsa.PrivateKey",
			wantErr:  false,
		},
		{
			name:     "PKCS8 EC key (exercises PKCS8 parse path)",
			pemData:  ecPKCS8PEM,
			password: nil,
			wantType: "*ecdsa.PrivateKey",
			wantErr:  false,
		},
		{
			name:     "invalid PEM data",
			pemData:  []byte("not a pem"),
			password: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParsePrivateKeyPEM(tt.pemData, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePrivateKeyPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				switch tt.wantType {
				case "*rsa.PrivateKey":
					if _, ok := key.(*rsa.PrivateKey); !ok {
						t.Errorf("ParsePrivateKeyPEM() returned %T, want %s", key, tt.wantType)
					}
				case "*ecdsa.PrivateKey":
					if _, ok := key.(*ecdsa.PrivateKey); !ok {
						t.Errorf("ParsePrivateKeyPEM() returned %T, want %s", key, tt.wantType)
					}
				}
			}
		})
	}
}

func TestPublicKeyToPEM(t *testing.T) {
	rsaKey, _ := GenerateRSAKeyPair(2048)
	ecKey, _ := GenerateECKeyPair(CurveP256())

	tests := []struct {
		name    string
		key     any
		wantErr bool
	}{
		{
			name:    "RSA public key",
			key:     &rsaKey.PublicKey,
			wantErr: false,
		},
		{
			name:    "EC public key",
			key:     &ecKey.PublicKey,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pem, err := PublicKeyToPEM(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKeyToPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(pem) == 0 {
				t.Error("PublicKeyToPEM() returned empty PEM")
			}
		})
	}
}

func TestSaveAndLoadPrivateKeyPEM(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		keyGen   func() (any, error)
		password []byte
	}{
		{
			name: "RSA key without password",
			keyGen: func() (any, error) {
				return GenerateRSAKeyPair(2048)
			},
			password: nil,
		},
		{
			name: "RSA key with password",
			keyGen: func() (any, error) {
				return GenerateRSAKeyPair(2048)
			},
			password: []byte("testpassword"),
		},
		{
			name: "EC key without password",
			keyGen: func() (any, error) {
				return GenerateECKeyPair(CurveP256())
			},
			password: nil,
		},
		{
			name: "EC P-384 key with password",
			keyGen: func() (any, error) {
				return GenerateECKeyPair(CurveP384())
			},
			password: []byte("secret-password"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.keyGen()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			path := filepath.Join(tmpDir, tt.name+".pem")

			// Save
			err = SavePrivateKeyPEM(key, path, tt.password)
			if err != nil {
				t.Fatalf("SavePrivateKeyPEM() error = %v", err)
			}

			// Check file permissions
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("failed to stat file: %v", err)
			}
			if info.Mode().Perm() != 0600 {
				t.Errorf("file permissions = %v, want 0600", info.Mode().Perm())
			}

			// Load
			loaded, err := LoadPrivateKeyPEM(path, tt.password)
			if err != nil {
				t.Fatalf("LoadPrivateKeyPEM() error = %v", err)
			}

			// Verify same key type
			switch key.(type) {
			case *rsa.PrivateKey:
				if _, ok := loaded.(*rsa.PrivateKey); !ok {
					t.Errorf("loaded key type mismatch: got %T", loaded)
				}
			case *ecdsa.PrivateKey:
				if _, ok := loaded.(*ecdsa.PrivateKey); !ok {
					t.Errorf("loaded key type mismatch: got %T", loaded)
				}
			}
		})
	}
}

func TestSavePrivateKeyPEM(t *testing.T) {
	rsaKey, _ := GenerateRSAKeyPair(2048)
	ecKey, _ := GenerateECKeyPair(CurveP256())

	tests := []struct {
		name    string
		key     any
		pathFn  func(tmpDir string) string
		wantErr bool
	}{
		{
			name: "RSA key success",
			key:  rsaKey,
			pathFn: func(tmpDir string) string {
				return filepath.Join(tmpDir, "rsa.key")
			},
			wantErr: false,
		},
		{
			name: "EC key success",
			key:  ecKey,
			pathFn: func(tmpDir string) string {
				return filepath.Join(tmpDir, "ec.key")
			},
			wantErr: false,
		},
		{
			name: "unsupported key type",
			key:  "not-a-key",
			pathFn: func(tmpDir string) string {
				return filepath.Join(tmpDir, "bad.pem")
			},
			wantErr: true,
		},
		{
			name: "invalid path",
			key:  rsaKey,
			pathFn: func(_ string) string {
				return "/nonexistent/deep/path/key.pem"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := tt.pathFn(tmpDir)

			err := SavePrivateKeyPEM(tt.key, path, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("SavePrivateKeyPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatalf("file not created: %v", err)
				}
				if info.Mode().Perm() != 0600 {
					t.Errorf("file permissions = %v, want 0600", info.Mode().Perm())
				}
			}
		})
	}
}

func TestLoadPrivateKeyPEM_Errors(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{
			name: "non-existent file",
			path: "/nonexistent/deep/path/key.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadPrivateKeyPEM(tt.path, nil)
			if err == nil {
				t.Error("LoadPrivateKeyPEM() expected error")
			}
		})
	}
}

func TestGetPublicKey(t *testing.T) {
	rsaKey, _ := GenerateRSAKeyPair(2048)
	ecKey, _ := GenerateECKeyPair(CurveP256())

	tests := []struct {
		name    string
		key     any
		wantErr bool
	}{
		{
			name:    "RSA private key",
			key:     rsaKey,
			wantErr: false,
		},
		{
			name:    "EC private key",
			key:     ecKey,
			wantErr: false,
		},
		{
			name:    "unsupported key type",
			key:     "not a key",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := GetPublicKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && pub == nil {
				t.Error("GetPublicKey() returned nil public key")
			}
		})
	}
}

func TestGenerateRSAKeyPairWithPEM(t *testing.T) {
	tests := []struct {
		name     string
		bits     int
		password []byte
		wantErr  bool
	}{
		{
			name:     "2048 bits without password",
			bits:     2048,
			password: nil,
			wantErr:  false,
		},
		{
			name:     "2048 bits with password",
			bits:     2048,
			password: []byte("test"),
			wantErr:  false,
		},
		{
			name:     "invalid key size",
			bits:     1024,
			password: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, err := GenerateRSAKeyPairWithPEM(tt.bits, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateRSAKeyPairWithPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if kp.PrivateKey == nil {
					t.Error("KeyPair.PrivateKey is nil")
				}
				if kp.PublicKey == nil {
					t.Error("KeyPair.PublicKey is nil")
				}
				if len(kp.PrivateKeyPEM) == 0 {
					t.Error("KeyPair.PrivateKeyPEM is empty")
				}
				if len(kp.PublicKeyPEM) == 0 {
					t.Error("KeyPair.PublicKeyPEM is empty")
				}
			}
		})
	}
}

func TestGenerateECKeyPairWithPEM(t *testing.T) {
	tests := []struct {
		name          string
		curve         elliptic.Curve
		password      []byte
		wantErr       bool
		wantEncrypted bool
	}{
		{
			name:     "P-256 without password",
			curve:    CurveP256(),
			password: nil,
			wantErr:  false,
		},
		{
			name:     "P-384 with password",
			curve:    CurveP384(),
			password: []byte("test"),
			wantErr:  false,
		},
		{
			name:          "P-384 with password verifies encryption",
			curve:         CurveP384(),
			password:      []byte("secret"),
			wantErr:       false,
			wantEncrypted: true,
		},
		{
			name:     "nil curve",
			curve:    nil,
			password: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, err := GenerateECKeyPairWithPEM(tt.curve, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateECKeyPairWithPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				assertKeyPairValid(t, kp, tt.wantEncrypted)
			}
		})
	}
}

func TestKeyPairWriteToFiles(t *testing.T) {
	tests := []struct {
		name       string
		privPathFn func(tmpDir string) string
		pubPathFn  func(tmpDir string) string
		wantErr    bool
	}{
		{
			name: "success",
			privPathFn: func(tmpDir string) string {
				return filepath.Join(tmpDir, "test.key")
			},
			pubPathFn: func(tmpDir string) string {
				return filepath.Join(tmpDir, "test.pub")
			},
			wantErr: false,
		},
		{
			name: "invalid private key path",
			privPathFn: func(_ string) string {
				return "/nonexistent/deep/path/private.pem"
			},
			pubPathFn: func(tmpDir string) string {
				return filepath.Join(tmpDir, "public.pem")
			},
			wantErr: true,
		},
		{
			name: "invalid public key path",
			privPathFn: func(tmpDir string) string {
				return filepath.Join(tmpDir, "private.pem")
			},
			pubPathFn: func(_ string) string {
				return "/nonexistent/deep/path/public.pem"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			kp, err := GenerateRSAKeyPairWithPEM(2048, nil)
			if err != nil {
				t.Fatalf("failed to generate key pair: %v", err)
			}

			privPath := tt.privPathFn(tmpDir)
			pubPath := tt.pubPathFn(tmpDir)

			err = kp.WriteKeyPairToFiles(privPath, pubPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteKeyPairToFiles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				assertKeyPairFilesWritten(t, privPath, pubPath)
			}
		})
	}
}

func TestSavePublicKeyPEM(t *testing.T) {
	rsaKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	ecKey, err := GenerateECKeyPair(CurveP256())
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	ecKey521, err := GenerateECKeyPair(CurveP521())
	if err != nil {
		t.Fatalf("failed to generate EC P-521 key: %v", err)
	}

	tests := []struct {
		name      string
		key       any
		pathFn    func(tmpDir string) string
		wantErr   bool
		roundtrip bool
	}{
		{
			name: "RSA public key",
			key:  &rsaKey.PublicKey,
			pathFn: func(tmpDir string) string {
				return filepath.Join(tmpDir, "rsa.pub")
			},
		},
		{
			name: "EC public key",
			key:  &ecKey.PublicKey,
			pathFn: func(tmpDir string) string {
				return filepath.Join(tmpDir, "ec.pub")
			},
		},
		{
			name:      "EC P-521 public key roundtrip",
			key:       &ecKey521.PublicKey,
			pathFn:    func(tmpDir string) string { return filepath.Join(tmpDir, "ec521.pub") },
			roundtrip: true,
		},
		{
			name: "unsupported key type",
			key:  "not-a-key",
			pathFn: func(tmpDir string) string {
				return filepath.Join(tmpDir, "bad.pub")
			},
			wantErr: true,
		},
		{
			name: "invalid path",
			key:  &rsaKey.PublicKey,
			pathFn: func(_ string) string {
				return filepath.Join("/nonexistent", "deep", "path", "key.pub")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := tt.pathFn(tmpDir)

			err := SavePublicKeyPEM(tt.key, path)
			if (err != nil) != tt.wantErr {
				t.Errorf("SavePublicKeyPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				assertPublicKeyFileSaved(t, path, tt.roundtrip)
			}
		})
	}
}

func TestLoadPublicKeyPEM(t *testing.T) {
	tmpDir := t.TempDir()

	rsaKey, _ := GenerateRSAKeyPair(2048)
	rsaPubPath := filepath.Join(tmpDir, "rsa.pub")
	if err := SavePublicKeyPEM(&rsaKey.PublicKey, rsaPubPath); err != nil {
		t.Fatalf("failed to save RSA public key: %v", err)
	}

	ecKey, _ := GenerateECKeyPair(CurveP256())
	ecPubPath := filepath.Join(tmpDir, "ec.pub")
	if err := SavePublicKeyPEM(&ecKey.PublicKey, ecPubPath); err != nil {
		t.Fatalf("failed to save EC public key: %v", err)
	}

	invalidPEMPath := filepath.Join(tmpDir, "invalid.pub")
	if err := os.WriteFile(invalidPEMPath, []byte("not a pem"), 0644); err != nil {
		t.Fatalf("failed to write invalid PEM: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name: "RSA public key",
			path: rsaPubPath,
		},
		{
			name: "EC public key",
			path: ecPubPath,
		},
		{
			name:    "non-existent file",
			path:    filepath.Join(tmpDir, "nonexistent.pub"),
			wantErr: true,
		},
		{
			name:    "invalid PEM",
			path:    invalidPEMPath,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := LoadPublicKeyPEM(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadPublicKeyPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && key == nil {
				t.Error("LoadPublicKeyPEM() returned nil key")
			}
		})
	}
}

func TestKeyPair_WritePrivateKeyTo(t *testing.T) {
	tests := []struct {
		name string
		bits int
	}{
		{
			name: "RSA 2048",
			bits: 2048,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, err := GenerateRSAKeyPairWithPEM(tt.bits, nil)
			if err != nil {
				t.Fatalf("failed to generate key pair: %v", err)
			}

			var buf bytes.Buffer
			n, err := kp.WritePrivateKeyTo(&buf)
			if err != nil {
				t.Fatalf("WritePrivateKeyTo() error = %v", err)
			}
			if n == 0 {
				t.Error("WritePrivateKeyTo() wrote 0 bytes")
			}
			if !bytes.Equal(buf.Bytes(), kp.PrivateKeyPEM) {
				t.Error("WritePrivateKeyTo() wrote different bytes than PrivateKeyPEM")
			}
		})
	}
}

func TestParsePrivateKeyPEM_UnknownFormat(t *testing.T) {
	// A valid PEM block that doesn't decode as RSA, PKCS8, or EC
	unknownPEM := []byte("-----BEGIN UNKNOWN KEY-----\nAQIDBAUGBwgJCgsMDQ4PEA==\n-----END UNKNOWN KEY-----\n")

	tests := []struct {
		name    string
		pemData []byte
		wantErr string
	}{
		{
			name:    "unknown key format",
			pemData: unknownPEM,
			wantErr: "unknown format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePrivateKeyPEM(tt.pemData, nil)
			if err == nil {
				t.Fatal("ParsePrivateKeyPEM() expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestSavePrivateKeyPEM_WriteToReadOnlyDir(t *testing.T) {
	rsaKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	tests := []struct {
		name   string
		pathFn func() string
	}{
		{
			name: "write to read-only directory",
			pathFn: func() string {
				dir := t.TempDir()
				readOnly := filepath.Join(dir, "readonly")
				if err := os.MkdirAll(readOnly, 0555); err != nil {
					t.Fatalf("failed to create read-only dir: %v", err)
				}
				return filepath.Join(readOnly, "key.pem")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.pathFn()
			err := SavePrivateKeyPEM(rsaKey, path, nil)
			if err == nil {
				t.Error("SavePrivateKeyPEM() expected error for read-only directory")
			}
		})
	}
}

func TestSavePublicKeyPEM_WriteToReadOnlyDir(t *testing.T) {
	rsaKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	tests := []struct {
		name   string
		pathFn func() string
	}{
		{
			name: "write to read-only directory",
			pathFn: func() string {
				dir := t.TempDir()
				readOnly := filepath.Join(dir, "readonly")
				if err := os.MkdirAll(readOnly, 0555); err != nil {
					t.Fatalf("failed to create read-only dir: %v", err)
				}
				return filepath.Join(readOnly, "key.pub")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.pathFn()
			err := SavePublicKeyPEM(&rsaKey.PublicKey, path)
			if err == nil {
				t.Error("SavePublicKeyPEM() expected error for read-only directory")
			}
		})
	}
}

func TestKeyPair_WritePublicKeyTo(t *testing.T) {
	tests := []struct {
		name string
		bits int
	}{
		{
			name: "RSA 2048",
			bits: 2048,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp, err := GenerateRSAKeyPairWithPEM(tt.bits, nil)
			if err != nil {
				t.Fatalf("failed to generate key pair: %v", err)
			}

			var buf bytes.Buffer
			n, err := kp.WritePublicKeyTo(&buf)
			if err != nil {
				t.Fatalf("WritePublicKeyTo() error = %v", err)
			}
			if n == 0 {
				t.Error("WritePublicKeyTo() wrote 0 bytes")
			}
			if !bytes.Equal(buf.Bytes(), kp.PublicKeyPEM) {
				t.Error("WritePublicKeyTo() wrote different bytes than PublicKeyPEM")
			}
		})
	}
}
