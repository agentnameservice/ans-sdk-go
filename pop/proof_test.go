package pop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

func TestNormalizeHTU(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"lowercase scheme+host, drop 443, strip query/frag", "HTTPS://Callee.Example:443/v1/Do?x=1#f", "https://callee.example/v1/Do", false},
		{"drop http 80", "http://h.example:80/a", "http://h.example/a", false},
		{"keep non-default port", "https://h.example:8443/a", "https://h.example:8443/a", false},
		{"empty path normalizes to /", "https://h.example", "https://h.example/", false},
		{"explicit root path preserved", "https://h.example/", "https://h.example/", false},
		{"empty path with port normalizes", "https://h.example:8443", "https://h.example:8443/", false},
		{"path case preserved", "https://h.example/AbC", "https://h.example/AbC", false},
		{"relative URL rejected", "/just/a/path", "", true},
		{"missing scheme rejected", "h.example/a", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeHTU(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("normalizeHTU(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestAcceptES256DPoP(t *testing.T) {
	good := []string{"cert"}
	jwk := &proofJWK{Kty: "EC", Crv: "P-256"}
	tests := []struct {
		name string
		hdr  proofHeader
		want ErrorType
		ok   bool
	}{
		{"valid", proofHeader{Typ: "dpop+jwt", Alg: "ES256", Jwk: jwk, X5c: good}, "", true},
		{"wrong typ", proofHeader{Typ: "jwt", Alg: "ES256", Jwk: jwk, X5c: good}, ErrUnsupportedAlg, false},
		{"alg none", proofHeader{Typ: "dpop+jwt", Alg: "none", Jwk: jwk, X5c: good}, ErrUnsupportedAlg, false},
		{"alg RS256", proofHeader{Typ: "dpop+jwt", Alg: "RS256", Jwk: jwk, X5c: good}, ErrUnsupportedAlg, false},
		{"empty alg", proofHeader{Typ: "dpop+jwt", Alg: "", Jwk: jwk, X5c: good}, ErrUnsupportedAlg, false},
		{"no jwk", proofHeader{Typ: "dpop+jwt", Alg: "ES256", X5c: good}, ErrMalformedProof, false},
		{"no x5c", proofHeader{Typ: "dpop+jwt", Alg: "ES256", Jwk: jwk}, ErrCertInvalid, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := acceptDPoP(&tt.hdr, false)
			if tt.ok {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			assertProofErr(t, err, tt.want)
		})
	}
}

func TestLeafCert(t *testing.T) {
	p256 := genKey(t)
	p256DER := identityCert(t, p256, "ans://v1.0.0.h.example")

	t.Run("valid P-256", func(t *testing.T) {
		_, pub, err := leafCert(&proofHeader{X5c: []string{base64.StdEncoding.EncodeToString(p256DER)}})
		if err != nil {
			t.Fatalf("leafCert: %v", err)
		}
		if !pub.Equal(&p256.PublicKey) {
			t.Error("returned key does not match")
		}
	})
	t.Run("bad base64", func(t *testing.T) {
		assertProofErr(t, mustLeafErr(&proofHeader{X5c: []string{"@@@"}}), ErrCertInvalid)
	})
	t.Run("bad DER", func(t *testing.T) {
		assertProofErr(t, mustLeafErr(&proofHeader{X5c: []string{base64.StdEncoding.EncodeToString([]byte("nope"))}}), ErrCertInvalid)
	})
	t.Run("RSA key rejected", func(t *testing.T) {
		assertProofErr(t, mustLeafErr(&proofHeader{X5c: []string{base64.StdEncoding.EncodeToString(rsaCertDER(t))}}), ErrCertInvalid)
	})
	t.Run("P-384 key rejected", func(t *testing.T) {
		assertProofErr(t, mustLeafErr(&proofHeader{X5c: []string{base64.StdEncoding.EncodeToString(p384CertDER(t))}}), ErrCertInvalid)
	})
}

func mustLeafErr(h *proofHeader) error {
	_, _, err := leafCert(h)
	return err
}

func TestDecodeProofHeader(t *testing.T) {
	const goodJWK = `{"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB"}`
	t.Run("valid", func(t *testing.T) {
		hb := b64urlEncode([]byte(`{"typ":"dpop+jwt","alg":"ES256","jwk":` + goodJWK + `,"x5c":["a"]}`))
		if _, err := decodeProofHeader(hb); err != nil {
			t.Fatalf("decode: %v", err)
		}
	})
	t.Run("unknown top-level field rejected", func(t *testing.T) {
		hb := b64urlEncode([]byte(`{"typ":"dpop+jwt","alg":"ES256","jwk":` + goodJWK + `,"x5c":["a"],"kid":"k"}`))
		assertProofErr(t, mustHeaderErr(hb), ErrMalformedProof)
	})
	t.Run("jwk private key material rejected", func(t *testing.T) {
		hb := b64urlEncode([]byte(`{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB","d":"secret"},"x5c":["a"]}`))
		assertProofErr(t, mustHeaderErr(hb), ErrMalformedProof)
	})
	t.Run("jwk member outside profile shape rejected", func(t *testing.T) {
		hb := b64urlEncode([]byte(`{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB","use":"sig"},"x5c":["a"]}`))
		assertProofErr(t, mustHeaderErr(hb), ErrMalformedProof)
	})
	t.Run("bad base64", func(t *testing.T) {
		assertProofErr(t, mustHeaderErr("@@@"), ErrMalformedProof)
	})
	t.Run("not json", func(t *testing.T) {
		assertProofErr(t, mustHeaderErr(b64urlEncode([]byte("not json"))), ErrMalformedProof)
	})
}

func TestJWKThumbprint(t *testing.T) {
	// RFC 7638 §3.1 requires the hash input to be the JWK's required members
	// only, lexicographically ordered, with no whitespace: {"crv","kty","x","y"}.
	key := genKey(t)
	got := jwkThumbprint(&key.PublicKey)
	j := publicJWK(&key.PublicKey)
	want := b64urlEncode(sha256Sum(`{"crv":"P-256","kty":"EC","x":"` + j.X + `","y":"` + j.Y + `"}`))
	if got != want {
		t.Errorf("jwkThumbprint = %q, want %q", got, want)
	}
	if got == jwkThumbprint(&genKey(t).PublicKey) {
		t.Error("distinct keys produced the same thumbprint")
	}
}

func sha256Sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func TestMatchJWKToCert(t *testing.T) {
	key := genKey(t)
	good := publicJWK(&key.PublicKey)
	other := genKey(t)
	tests := []struct {
		name string
		jwk  *proofJWK
		want ErrorType // "" = match
	}{
		{"match", good, ""},
		{"different key", publicJWK(&other.PublicKey), ErrKeyMismatch},
		{"wrong kty", &proofJWK{Kty: "RSA", Crv: "P-256", X: good.X, Y: good.Y}, ErrUnsupportedAlg},
		{"wrong crv", &proofJWK{Kty: "EC", Crv: "P-384", X: good.X, Y: good.Y}, ErrUnsupportedAlg},
		{"bad x base64", &proofJWK{Kty: "EC", Crv: "P-256", X: "@@@", Y: good.Y}, ErrMalformedProof},
		{"bad y base64", &proofJWK{Kty: "EC", Crv: "P-256", X: good.X, Y: "@@@"}, ErrMalformedProof},
		{"short coordinate", &proofJWK{Kty: "EC", Crv: "P-256", X: b64urlEncode(make([]byte, 16)), Y: good.Y}, ErrMalformedProof},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := matchJWKToCert(tt.jwk, &key.PublicKey)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			assertProofErr(t, err, tt.want)
		})
	}
}

func mustHeaderErr(hb string) error {
	_, err := decodeProofHeader(hb)
	return err
}

func TestDecodeProofPayload(t *testing.T) {
	t.Run("valid with extra claim tolerated", func(t *testing.T) {
		pb := b64urlEncode([]byte(`{"htm":"GET","htu":"https://h/","iat":1,"jti":"x","nonce":"extra"}`))
		p, err := decodeProofPayload(pb)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if p.HTM != "GET" || p.JTI != "x" {
			t.Errorf("payload = %+v", p)
		}
	})
	t.Run("bad base64", func(t *testing.T) {
		_, err := decodeProofPayload("@@@")
		assertProofErr(t, err, ErrMalformedProof)
	})
	t.Run("not json", func(t *testing.T) {
		_, err := decodeProofPayload(b64urlEncode([]byte("nope")))
		assertProofErr(t, err, ErrMalformedProof)
	})
}

// rsaCertDER returns a self-signed RSA certificate's DER (a non-ECDSA leaf).
func rsaCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	return selfSign(t, key, &key.PublicKey)
}

// p384CertDER returns a self-signed ECDSA P-384 certificate's DER.
func p384CertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("p384 key: %v", err)
	}
	return selfSign(t, key, &key.PublicKey)
}

func selfSign(t *testing.T, priv, pub any) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "other"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}
