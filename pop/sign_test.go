package pop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewSigner(t *testing.T) {
	key := genKey(t)
	certDER := identityCert(t, key, "ans://v1.0.0.h.example")

	t.Run("valid", func(t *testing.T) {
		if _, err := NewSigner(key, certDER); err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
	})
	t.Run("nil key", func(t *testing.T) {
		_, err := NewSigner(nil, certDER)
		assertProofErr(t, err, ErrCertInvalid)
	})
	t.Run("non-P256 key", func(t *testing.T) {
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("p384: %v", err)
		}
		_, err = NewSigner(k, certDER)
		assertProofErr(t, err, ErrCertInvalid)
	})
	t.Run("bad certDER", func(t *testing.T) {
		_, err := NewSigner(key, []byte("not a cert"))
		assertProofErr(t, err, ErrCertInvalid)
	})
	t.Run("cert key does not match private key", func(t *testing.T) {
		other := genKey(t)
		_, err := NewSigner(other, certDER) // certDER binds key, not other
		assertProofErr(t, err, ErrCertInvalid)
	})
}

func TestSignerSign(t *testing.T) {
	h := newHarness(t)

	t.Run("produces a verifiable proof", func(t *testing.T) {
		const method, rawURL = "POST", "https://h.example/x"
		token := h.proof(t, method, rawURL)
		if _, err := VerifyProof(context.Background(), token, method, rawURL, h.now, DefaultPoPSkew, h.replay); err != nil {
			t.Fatalf("VerifyProof: %v", err)
		}
	})
	t.Run("header carries jwk matching x5c", func(t *testing.T) {
		token := h.proof(t, "GET", "https://h.example/x")
		hB64, _, _, err := splitCompactJWS(token)
		if err != nil {
			t.Fatalf("split: %v", err)
		}
		hdr, err := decodeProofHeader(hB64)
		if err != nil {
			t.Fatalf("decode header: %v", err)
		}
		if hdr.Jwk == nil {
			t.Fatal("proof header has no jwk")
		}
		if err := matchJWKToCert(hdr.Jwk, &h.agentKey.PublicKey); err != nil {
			t.Fatalf("jwk does not match signer key: %v", err)
		}
		if len(hdr.X5c) != 1 || hdr.X5c[0] != base64.StdEncoding.EncodeToString(h.certDER) {
			t.Error("x5c does not carry the identity certificate")
		}
	})
	t.Run("WithAccessToken mints matching ath", func(t *testing.T) {
		const tok = "an-access-token"
		token := h.proofWithToken(t, "GET", "https://h.example/x", tok)
		_, pB64, _, err := splitCompactJWS(token)
		if err != nil {
			t.Fatalf("split: %v", err)
		}
		pl, err := decodeProofPayload(pB64)
		if err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if pl.ATH != accessTokenHash(tok) {
			t.Errorf("ath = %q, want %q", pl.ATH, accessTokenHash(tok))
		}
	})
	t.Run("no token means no ath claim", func(t *testing.T) {
		token := h.proof(t, "GET", "https://h.example/x")
		_, pB64, _, err := splitCompactJWS(token)
		if err != nil {
			t.Fatalf("split: %v", err)
		}
		raw, err := b64urlDecode(pB64)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if strings.Contains(string(raw), `"ath"`) {
			t.Errorf("payload unexpectedly contains ath: %s", raw)
		}
	})
	t.Run("JKT matches the verified proof's thumbprint", func(t *testing.T) {
		id, err := VerifyCaller(context.Background(), h.proof(t, "GET", "https://h.example/x"),
			h.headers(t), "GET", "https://h.example/x", h.keys, h.replay, h.callerOpts()...)
		if err != nil {
			t.Fatalf("VerifyCaller: %v", err)
		}
		if h.signer.JKT() != id.JKT {
			t.Errorf("Signer.JKT() = %q, verified JKT = %q", h.signer.JKT(), id.JKT)
		}
	})
	t.Run("canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := h.signer.Sign(ctx, "GET", "https://h.example/x"); err == nil {
			t.Fatal("expected context error")
		}
	})
	t.Run("bad url", func(t *testing.T) {
		if _, err := h.signer.Sign(context.Background(), "GET", "/relative-only"); err == nil {
			t.Fatal("expected htu normalization error")
		}
	})
}
