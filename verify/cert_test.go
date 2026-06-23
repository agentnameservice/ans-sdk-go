package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestCertFingerprint(t *testing.T) {
	t.Run("FromDER", func(t *testing.T) {
		der := []byte("test certificate data")
		fp := CertFingerprintFromDER(der)

		// Compute expected hash
		hash := sha256.Sum256(der)
		want := "SHA256:" + toHexString(hash[:])

		if got := fp.String(); got != want {
			t.Errorf("CertFingerprintFromDER().String() = %q, want %q", got, want)
		}
	})

	t.Run("Parse valid uppercase", func(t *testing.T) {
		input := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
		fp, err := ParseCertFingerprint(input)
		if err != nil {
			t.Fatalf("ParseCertFingerprint() error = %v", err)
		}
		if fp.String() != input {
			t.Errorf("String() = %q, want %q", fp.String(), input)
		}
	})

	t.Run("Parse valid lowercase", func(t *testing.T) {
		input := "sha256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
		want := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
		fp, err := ParseCertFingerprint(input)
		if err != nil {
			t.Fatalf("ParseCertFingerprint() error = %v", err)
		}
		if fp.String() != want {
			t.Errorf("String() = %q, want %q", fp.String(), want)
		}
	})

	t.Run("Parse invalid prefix", func(t *testing.T) {
		input := "MD5:abc123"
		_, err := ParseCertFingerprint(input)
		if err == nil {
			t.Error("ParseCertFingerprint() expected error for invalid prefix")
		}
	})

	t.Run("Parse invalid hex", func(t *testing.T) {
		input := "SHA256:gggg"
		_, err := ParseCertFingerprint(input)
		if err == nil {
			t.Error("ParseCertFingerprint() expected error for invalid hex")
		}
	})

	t.Run("Parse too short", func(t *testing.T) {
		input := "SHA256:e7b64d"
		_, err := ParseCertFingerprint(input)
		if err == nil {
			t.Error("ParseCertFingerprint() expected error for too short")
		}
	})

	t.Run("Matches", func(t *testing.T) {
		fp, _ := ParseCertFingerprint("SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")

		tests := []struct {
			name  string
			other string
			want  bool
		}{
			{
				name:  "exact match",
				other: "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
				want:  true,
			},
			{
				name:  "case insensitive prefix",
				other: "sha256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
				want:  true,
			},
			{
				name:  "different fingerprint",
				other: "SHA256:0000000000000000000000000000000000000000000000000000000000000000",
				want:  false,
			},
			{
				name:  "invalid format",
				other: "invalid",
				want:  false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := fp.Matches(tt.other); got != tt.want {
					t.Errorf("Matches(%q) = %v, want %v", tt.other, got, tt.want)
				}
			})
		}
	})
}

// toHexString helper to convert bytes to hex string
func toHexString(b []byte) string {
	const hexDigits = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexDigits[v>>4]
		result[i*2+1] = hexDigits[v&0x0f]
	}
	return string(result)
}

func TestAnsName(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		wantErr     bool
		wantVersion models.Version
		wantFqdn    string
	}{
		{
			name:        "valid ans name",
			uri:         "ans://v1.0.0.agent.example.com",
			wantErr:     false,
			wantVersion: models.NewVersion(1, 0, 0),
			wantFqdn:    "agent.example.com",
		},
		{
			name:        "valid multi-digit version",
			uri:         "ans://v12.3.45.agent.example.com",
			wantErr:     false,
			wantVersion: models.NewVersion(12, 3, 45),
			wantFqdn:    "agent.example.com",
		},
		{
			name:        "valid complex fqdn",
			uri:         "ans://v2.1.3.ote.agent.cs3p.com",
			wantErr:     false,
			wantVersion: models.NewVersion(2, 1, 3),
			wantFqdn:    "ote.agent.cs3p.com",
		},
		{
			name:    "missing prefix",
			uri:     "v1.0.0.agent.example.com",
			wantErr: true,
		},
		{
			name:    "missing version",
			uri:     "ans://agent.example.com",
			wantErr: true,
		},
		{
			name:    "invalid version",
			uri:     "ans://va.b.c.agent.example.com",
			wantErr: true,
		},
		{
			name:    "empty string",
			uri:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ans, err := ParseAnsName(tt.uri)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseAnsName(%q) expected error, got nil", tt.uri)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAnsName(%q) unexpected error: %v", tt.uri, err)
			}
			if !ans.Version.Equal(tt.wantVersion) {
				t.Errorf("Version = %v, want %v", ans.Version, tt.wantVersion)
			}
			if ans.Host != tt.wantFqdn {
				t.Errorf("Host = %q, want %q", ans.Host, tt.wantFqdn)
			}
		})
	}
}

func TestAnsName_String(t *testing.T) {
	ans, err := ParseAnsName("ans://v1.0.0.agent.example.com")
	if err != nil {
		t.Fatalf("ParseAnsName() unexpected error: %v", err)
	}
	want := "ans://v1.0.0.agent.example.com"
	if got := ans.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestCertIdentity(t *testing.T) {
	t.Run("FromComponents", func(t *testing.T) {
		fp, _ := ParseCertFingerprint("SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
		cn := "test.example.com"

		identity := NewCertIdentity(
			&cn,
			[]string{"test.example.com"},
			[]string{"ans://v1.0.0.test.example.com"},
			fp,
		)

		// Test FQDN (prefers DNS SAN)
		fqdn := identity.FQDN()
		if fqdn == nil || *fqdn != "test.example.com" {
			t.Errorf("FQDN() = %v, want test.example.com", fqdn)
		}

		// Test AnsName
		ans := identity.AnsName()
		if ans == nil {
			t.Fatal("AnsName() returned nil, want non-nil")
		}
		if ans.Host != "test.example.com" {
			t.Errorf("AnsName().Host = %q, want test.example.com", ans.Host)
		}

		// Test Version
		version := identity.Version()
		if version == nil {
			t.Fatal("Version() returned nil, want non-nil")
		}
		if !version.Equal(models.NewVersion(1, 0, 0)) {
			t.Errorf("Version() = %v, want v1.0.0", version)
		}
	})

	t.Run("FQDN prefers DNS SAN", func(t *testing.T) {
		fp, _ := ParseCertFingerprint("SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
		cn := "cn.example.com"

		identity := NewCertIdentity(
			&cn,
			[]string{"dnssan.example.com"},
			nil,
			fp,
		)

		fqdn := identity.FQDN()
		if fqdn == nil || *fqdn != "dnssan.example.com" {
			t.Errorf("FQDN() = %v, want dnssan.example.com (DNS SAN preferred)", fqdn)
		}
	})

	t.Run("FQDN falls back to CN", func(t *testing.T) {
		fp, _ := ParseCertFingerprint("SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
		cn := "cn.example.com"

		identity := NewCertIdentity(
			&cn,
			nil,
			nil,
			fp,
		)

		fqdn := identity.FQDN()
		if fqdn == nil || *fqdn != "cn.example.com" {
			t.Errorf("FQDN() = %v, want cn.example.com (CN fallback)", fqdn)
		}
	})

	t.Run("FQDN returns nil when no CN or DNS SAN", func(t *testing.T) {
		fp, _ := ParseCertFingerprint("SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")

		identity := NewCertIdentity(nil, nil, nil, fp)

		fqdn := identity.FQDN()
		if fqdn != nil {
			t.Errorf("FQDN() = %v, want nil", fqdn)
		}
	})

	t.Run("AnsName filters non-ans URIs", func(t *testing.T) {
		fp, _ := ParseCertFingerprint("SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")

		identity := NewCertIdentity(
			nil,
			nil,
			[]string{"https://example.com", "ans://v1.0.0.test.example.com"},
			fp,
		)

		ans := identity.AnsName()
		if ans == nil {
			t.Fatal("AnsName() returned nil, want non-nil")
		}
		if ans.Host != "test.example.com" {
			t.Errorf("AnsName().Host = %q, want test.example.com", ans.Host)
		}
	})

	t.Run("FromFingerprintAndCN", func(t *testing.T) {
		fp, _ := ParseCertFingerprint("SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")

		identity := CertIdentityFromFingerprintAndCN(fp, "test.example.com")

		fqdn := identity.FQDN()
		if fqdn == nil || *fqdn != "test.example.com" {
			t.Errorf("FQDN() = %v, want test.example.com", fqdn)
		}
	})
}

func TestCertFingerprint_Bytes(t *testing.T) {
	tests := []struct {
		name string
		raw  [32]byte
	}{
		{
			name: "non-zero bytes",
			raw:  [32]byte{1, 2, 3, 4, 5},
		},
		{
			name: "zero bytes",
			raw:  [32]byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := CertFingerprintFromBytes(tt.raw)
			got := fp.Bytes()
			if got != tt.raw {
				t.Errorf("Bytes() = %v, want %v", got, tt.raw)
			}
		})
	}
}

func TestCertFingerprint_Equal(t *testing.T) {
	tests := []struct {
		name string
		a    [32]byte
		b    [32]byte
		want bool
	}{
		{
			name: "identical fingerprints",
			a:    [32]byte{1, 2, 3},
			b:    [32]byte{1, 2, 3},
			want: true,
		},
		{
			name: "different fingerprints",
			a:    [32]byte{1, 2, 3},
			b:    [32]byte{4, 5, 6},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fpA := CertFingerprintFromBytes(tt.a)
			fpB := CertFingerprintFromBytes(tt.b)
			if got := fpA.Equal(fpB); got != tt.want {
				t.Errorf("Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertFingerprint_IsZero(t *testing.T) {
	tests := []struct {
		name string
		fp   CertFingerprint
		want bool
	}{
		{
			name: "zero fingerprint",
			fp:   CertFingerprint{},
			want: true,
		},
		{
			name: "non-zero fingerprint",
			fp:   CertFingerprintFromBytes([32]byte{1}),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fp.IsZero(); got != tt.want {
				t.Errorf("IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertFingerprintFromDER(t *testing.T) {
	tests := []struct {
		name string
		der  []byte
	}{
		{
			name: "standard DER data",
			der:  []byte("test DER data for fingerprint"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := CertFingerprintFromDER(tt.der)
			if fp.IsZero() {
				t.Error("CertFingerprintFromDER() returned zero fingerprint")
			}
			if fp.ToHex() == "" {
				t.Error("CertFingerprintFromDER() ToHex() is empty")
			}
		})
	}
}

func TestCertIdentity_FQDN(t *testing.T) {
	cn := "example.com"
	tests := []struct {
		name    string
		cert    *CertIdentity
		wantNil bool
		want    string
	}{
		{
			name: "DNS SANs present",
			cert: &CertIdentity{
				CommonName: &cn,
				DNSSANs:    []string{"san.example.com"},
			},
			want: "san.example.com",
		},
		{
			name: "no DNS SANs, uses CN",
			cert: &CertIdentity{
				CommonName: &cn,
			},
			want: "example.com",
		},
		{
			name:    "no DNS SANs, no CN",
			cert:    &CertIdentity{},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cert.FQDN()
			if tt.wantNil {
				if got != nil {
					t.Errorf("FQDN() = %v, want nil", *got)
				}
				return
			}
			if got == nil {
				t.Fatal("FQDN() = nil, want non-nil")
			}
			if *got != tt.want {
				t.Errorf("FQDN() = %q, want %q", *got, tt.want)
			}
		})
	}
}

func TestCertIdentity_AnsName(t *testing.T) {
	tests := []struct {
		name    string
		cert    *CertIdentity
		wantNil bool
		wantURI string
	}{
		{
			name: "valid ANS URI SAN",
			cert: &CertIdentity{
				URISANs: []string{"ans://v1.0.0.example.com"},
			},
			wantURI: "ans://v1.0.0.example.com",
		},
		{
			name:    "no URI SANs",
			cert:    &CertIdentity{},
			wantNil: true,
		},
		{
			name: "non-ANS URI SAN",
			cert: &CertIdentity{
				URISANs: []string{"https://example.com"},
			},
			wantNil: true,
		},
		{
			name: "invalid ANS URI SAN",
			cert: &CertIdentity{
				URISANs: []string{"ans://invalid"},
			},
			wantNil: true,
		},
		{
			name: "first valid ANS among multiple",
			cert: &CertIdentity{
				URISANs: []string{"https://other.com", "ans://v2.0.0.test.com"},
			},
			wantURI: "ans://v2.0.0.test.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cert.AnsName()
			if tt.wantNil {
				if got != nil {
					t.Errorf("AnsName() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("AnsName() = nil, want non-nil")
			}
			if got.String() != tt.wantURI {
				t.Errorf("AnsName().String() = %q, want %q", got.String(), tt.wantURI)
			}
		})
	}
}

func TestCertIdentity_Version(t *testing.T) {
	tests := []struct {
		name    string
		cert    *CertIdentity
		wantNil bool
		want    string
	}{
		{
			name: "with ANS URI SAN",
			cert: &CertIdentity{
				URISANs: []string{"ans://v1.2.3.example.com"},
			},
			want: "v1.2.3",
		},
		{
			name:    "without ANS URI SAN",
			cert:    &CertIdentity{},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cert.Version()
			if tt.wantNil {
				if got != nil {
					t.Errorf("Version() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("Version() = nil, want non-nil")
			}
			if got.String() != tt.want {
				t.Errorf("Version().String() = %q, want %q", got.String(), tt.want)
			}
		})
	}
}

func TestCertIdentityFromX509(t *testing.T) {
	tests := []struct {
		name       string
		template   *x509.Certificate
		uris       []*url.URL
		wantCN     *string
		wantDNSLen int
		wantURILen int
	}{
		{
			name: "full cert with CN, DNS SANs, and URI SANs",
			template: &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject:      pkix.Name{CommonName: "test.example.com"},
				DNSNames:     []string{"test.example.com", "alt.example.com"},
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(time.Hour),
			},
			uris: func() []*url.URL {
				u, _ := url.Parse("ans://v1.0.0.test.example.com")
				return []*url.URL{u}
			}(),
			wantCN:     strPtr("test.example.com"),
			wantDNSLen: 2,
			wantURILen: 1,
		},
		{
			name: "cert with no CN",
			template: &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject:      pkix.Name{},
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(time.Hour),
			},
			wantCN:     nil,
			wantDNSLen: 0,
			wantURILen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			if tt.uris != nil {
				tt.template.URIs = tt.uris
			}

			certDER, err := x509.CreateCertificate(rand.Reader, tt.template, tt.template, &key.PublicKey, key)
			if err != nil {
				t.Fatalf("failed to create certificate: %v", err)
			}

			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				t.Fatalf("failed to parse certificate: %v", err)
			}

			identity := CertIdentityFromX509(cert)

			if tt.wantCN == nil {
				if identity.CommonName != nil {
					t.Errorf("CommonName = %v, want nil", *identity.CommonName)
				}
			} else {
				if identity.CommonName == nil || *identity.CommonName != *tt.wantCN {
					t.Errorf("CommonName = %v, want %s", identity.CommonName, *tt.wantCN)
				}
			}
			if len(identity.DNSSANs) != tt.wantDNSLen {
				t.Errorf("DNSSANs length = %d, want %d", len(identity.DNSSANs), tt.wantDNSLen)
			}
			if len(identity.URISANs) != tt.wantURILen {
				t.Errorf("URISANs length = %d, want %d", len(identity.URISANs), tt.wantURILen)
			}
			if identity.Fingerprint.IsZero() {
				t.Error("Fingerprint is zero")
			}
		})
	}
}

func TestCertIdentityFromDER(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	validDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	tests := []struct {
		name    string
		der     []byte
		wantErr bool
		wantCN  string
	}{
		{
			name:   "valid DER",
			der:    validDER,
			wantCN: "test.example.com",
		},
		{
			name:    "invalid DER",
			der:     []byte("invalid DER"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := CertIdentityFromDER(tt.der)
			if tt.wantErr {
				if err == nil {
					t.Error("CertIdentityFromDER() expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("CertIdentityFromDER() error = %v", err)
			}
			if identity.CommonName == nil || *identity.CommonName != tt.wantCN {
				t.Errorf("CommonName = %v, want %s", identity.CommonName, tt.wantCN)
			}
		})
	}
}

func TestNewCertIdentity(t *testing.T) {
	tests := []struct {
		name       string
		cn         *string
		dnsSANs    []string
		uriSANs    []string
		fp         CertFingerprint
		wantCN     string
		wantDNSLen int
		wantURILen int
	}{
		{
			name:       "full identity",
			cn:         strPtr("test.example.com"),
			dnsSANs:    []string{"test.example.com"},
			uriSANs:    []string{"ans://v1.0.0.test.example.com"},
			fp:         CertFingerprintFromBytes([32]byte{1, 2, 3}),
			wantCN:     "test.example.com",
			wantDNSLen: 1,
			wantURILen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := NewCertIdentity(tt.cn, tt.dnsSANs, tt.uriSANs, tt.fp)

			if identity.CommonName == nil || *identity.CommonName != tt.wantCN {
				t.Errorf("CommonName = %v, want %s", identity.CommonName, tt.wantCN)
			}
			if len(identity.DNSSANs) != tt.wantDNSLen {
				t.Errorf("DNSSANs length = %d, want %d", len(identity.DNSSANs), tt.wantDNSLen)
			}
			if len(identity.URISANs) != tt.wantURILen {
				t.Errorf("URISANs length = %d, want %d", len(identity.URISANs), tt.wantURILen)
			}
			if !identity.Fingerprint.Equal(tt.fp) {
				t.Error("Fingerprint mismatch")
			}
		})
	}
}

func TestAnsName_String_Additional(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		wantString  string
		wantHost    string
		wantVersion string
	}{
		{
			name:        "standard ANS name",
			uri:         "ans://v1.2.3.test.example.com",
			wantString:  "ans://v1.2.3.test.example.com",
			wantHost:    "test.example.com",
			wantVersion: "v1.2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ansName, err := ParseAnsName(tt.uri)
			if err != nil {
				t.Fatalf("ParseAnsName() error = %v", err)
			}
			if got := ansName.String(); got != tt.wantString {
				t.Errorf("String() = %q, want %q", got, tt.wantString)
			}
			if ansName.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", ansName.Host, tt.wantHost)
			}
			expected, _ := models.ParseVersion(tt.wantVersion)
			if !ansName.Version.Equal(expected) {
				t.Errorf("Version = %v, want %v", ansName.Version, expected)
			}
		})
	}
}

func strPtr(s string) *string {
	return &s
}
