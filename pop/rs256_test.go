package pop

// RSA-THROWAWAY(remove when prod supports ES256): tests for the throwaway RS256 opt-in.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// genRSAKey returns a fresh 2048-bit RSA key.
func genRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genRSAKey: %v", err)
	}
	return k
}

// rsaIdentityCert self-signs an RSA identity certificate carrying the given
// ans:// URI SAN (needed for the VerifyCaller SAN binding) and returns its DER.
func rsaIdentityCert(t *testing.T, key *rsa.PrivateKey, ansName string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-rsa-agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if ansName != "" {
		u, err := url.Parse(ansName)
		if err != nil {
			t.Fatalf("parse ansName: %v", err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create RSA cert: %v", err)
	}
	return der
}

// TestRS256_SignVerify_OptIn is the round trip: NewRSASigner mints an RS256
// proof, the default profile rejects it, and WithAllowRSA accepts it, returning
// the RSA key and its thumbprint.
func TestRS256_SignVerify_OptIn(t *testing.T) {
	key := genRSAKey(t)
	certDER := rsaIdentityCert(t, key, "ans://v1.0.0.h.example")
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	signer, err := NewRSASigner(key, certDER, withSignerClock(clock))
	if err != nil {
		t.Fatalf("NewRSASigner: %v", err)
	}
	proof, err := signer.Sign(context.Background(), callMethod, callURL)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	replay := NewMemoryReplayCache(context.Background(), 0, withReplayClock(clock))
	t.Cleanup(replay.Close)

	// Secure default: RS256 is rejected as an unsupported algorithm (before any
	// replay slot is consumed), so the same proof can be reused below.
	if _, rejErr := VerifyProof(context.Background(), proof, callMethod, callURL,
		now, DefaultPoPSkew, replay); rejErr == nil {
		t.Fatal("default profile accepted an RS256 proof")
	} else {
		assertProofErr(t, rejErr, ErrUnsupportedAlg)
	}

	// Opt-in: accepted, RSA key returned, EC key nil, thumbprint matches signer.
	res, err := VerifyProof(context.Background(), proof, callMethod, callURL,
		now, DefaultPoPSkew, replay, WithAllowRSA())
	if err != nil {
		t.Fatalf("VerifyProof with WithAllowRSA: %v", err)
	}
	if res.RSAKey == nil {
		t.Fatal("RSAKey is nil for an RS256 proof")
	}
	if res.Key != nil {
		t.Error("EC Key should be nil for an RS256 proof")
	}
	if !res.RSAKey.Equal(&key.PublicKey) {
		t.Error("returned RSA key does not match the signer")
	}
	if res.JKT != signer.JKT() {
		t.Errorf("JKT %q != signer.JKT() %q", res.JKT, signer.JKT())
	}
}

// TestVerifyCaller_RSAIdentity_OptIn proves the full three-proof flow with an
// RSA identity certificate: the EC transparency-log key still signs the status
// token and receipt (which vouch for the RSA cert's fingerprint), and only the
// caller's possession proof is RS256.
func TestVerifyCaller_RSAIdentity_OptIn(t *testing.T) {
	const ansName = "ans://v1.0.0.payments.acme.example"
	const agentID = "agent-rsa-1"
	key := genRSAKey(t)
	certDER := rsaIdentityCert(t, key, ansName)
	fp := sha256.Sum256(certDER)
	tlKey := genKey(t) // TL stays EC
	keys := newKeyLookup(t, "tl", &tlKey.PublicKey)
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	signer, err := NewRSASigner(key, certDER, withSignerClock(clock))
	if err != nil {
		t.Fatalf("NewRSASigner: %v", err)
	}
	proof, err := signer.Sign(context.Background(), callMethod, callURL)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	hdrs := &scitt.Headers{
		StatusToken: statusToken(t, tlKey, agentID, ansName, scitt.StatusActive,
			now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), fp),
		Receipt: receipt(t, tlKey, eventJSON(t, agentID, ansName)),
	}
	replay := NewMemoryReplayCache(context.Background(), 0, withReplayClock(clock))
	t.Cleanup(replay.Close)

	// Without the opt-in the caller is rejected at the possession proof.
	_, err = VerifyCaller(context.Background(), proof, hdrs, callMethod, callURL,
		keys, replay, withCallerClock(clock))
	assertProofErr(t, err, ErrUnsupportedAlg)

	// With the opt-in the caller authenticates end to end.
	id, err := VerifyCaller(context.Background(), proof, hdrs, callMethod, callURL,
		keys, replay, withCallerClock(clock), WithVerifyOptions(WithAllowRSA()))
	if err != nil {
		t.Fatalf("VerifyCaller RSA opt-in: %v", err)
	}
	if id.AnsName != ansName {
		t.Errorf("AnsName = %q, want %q", id.AnsName, ansName)
	}
	if id.AgentID != agentID {
		t.Errorf("AgentID = %q, want %q", id.AgentID, agentID)
	}
	if id.Fingerprint != fp {
		t.Error("fingerprint mismatch")
	}
	if id.JKT != signer.JKT() {
		t.Errorf("JKT %q != signer.JKT() %q", id.JKT, signer.JKT())
	}
}

func TestNewRSASigner_Validation(t *testing.T) {
	key := genRSAKey(t)
	good := rsaIdentityCert(t, key, "ans://v1.0.0.h.example")

	t.Run("nil key", func(t *testing.T) {
		_, err := NewRSASigner(nil, good)
		assertProofErr(t, err, ErrCertInvalid)
	})
	t.Run("small key", func(t *testing.T) {
		small, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("gen small key: %v", err)
		}
		_, err = NewRSASigner(small, rsaIdentityCert(t, small, "ans://v1.0.0.h.example"))
		assertProofErr(t, err, ErrCertInvalid)
	})
	t.Run("cert key mismatch", func(t *testing.T) {
		other := genRSAKey(t)
		_, err := NewRSASigner(other, good) // cert binds `key`, not `other`
		assertProofErr(t, err, ErrCertInvalid)
	})
	t.Run("unparseable cert", func(t *testing.T) {
		_, err := NewRSASigner(key, []byte("not der"))
		assertProofErr(t, err, ErrCertInvalid)
	})
}

func TestRSAJWKKey_Strict(t *testing.T) {
	valid := rsaPublicJWK(&genRSAKey(t).PublicKey)

	t.Run("valid round trips", func(t *testing.T) {
		if _, err := rsaJWKKey(valid); err != nil {
			t.Fatalf("rsaJWKKey(valid): %v", err)
		}
	})
	t.Run("wrong kty", func(t *testing.T) {
		j := *valid
		j.Kty = "EC"
		_, err := rsaJWKKey(&j)
		assertProofErr(t, err, ErrUnsupportedAlg)
	})
	t.Run("EC members present", func(t *testing.T) {
		j := *valid
		j.X = "AAAA"
		_, err := rsaJWKKey(&j)
		assertProofErr(t, err, ErrMalformedProof)
	})
	t.Run("bad n base64", func(t *testing.T) {
		j := *valid
		j.N = "@@@"
		_, err := rsaJWKKey(&j)
		assertProofErr(t, err, ErrMalformedProof)
	})
	t.Run("modulus too small", func(t *testing.T) {
		small, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("gen small: %v", err)
		}
		_, err = rsaJWKKey(rsaPublicJWK(&small.PublicKey))
		assertProofErr(t, err, ErrCertInvalid)
	})
	t.Run("even exponent", func(t *testing.T) {
		j := *valid
		j.E = b64urlEncode([]byte{0x04})
		_, err := rsaJWKKey(&j)
		assertProofErr(t, err, ErrMalformedProof)
	})
}

func TestMatchRSAJWKToCert_Mismatch(t *testing.T) {
	certKey := genRSAKey(t)
	otherKey := genRSAKey(t)
	err := matchRSAJWKToCert(rsaPublicJWK(&otherKey.PublicKey), &certKey.PublicKey)
	assertProofErr(t, err, ErrKeyMismatch)
}

func TestVerifyRS256_BadSignature(t *testing.T) {
	key := genRSAKey(t)
	err := verifyRS256(&key.PublicKey, []byte("header.payload"), b64urlEncode([]byte("not a signature")))
	assertProofErr(t, err, ErrSignatureInvalid)
}

// TestECJWK_RejectsRSAMembers proves the ES256 path fails closed if an EC jwk
// smuggles RSA members past the shared struct.
func TestECJWK_RejectsRSAMembers(t *testing.T) {
	ec := publicJWK(&genKey(t).PublicKey)
	ec.N = "AAAA"
	_, _, err := jwkCoords(ec)
	assertProofErr(t, err, ErrMalformedProof)
}

func TestLeafCertRSA_RejectsNonRSA(t *testing.T) {
	// An EC (P-256) cert must be rejected by the RSA leaf parser.
	ecCert := identityCert(t, genKey(t), "ans://v1.0.0.h.example")
	_, _, err := leafCertRSA(&proofHeader{X5c: []string{
		base64.StdEncoding.EncodeToString(ecCert),
	}})
	assertProofErr(t, err, ErrCertInvalid)
}
