package pop

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// craftProof builds a compact DPoP proof from arbitrary header/payload maps,
// signed by signKey (which may differ from the x5c cert key, to exercise
// key-substitution). It bypasses Signer so malformed proofs can be crafted.
func craftProof(t *testing.T, signKey *ecdsa.PrivateKey, header, payload map[string]any) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	hB64, pB64 := b64urlEncode(hb), b64urlEncode(pb)
	sig, err := signES256(signKey, jwsSigningInput(hB64, pB64))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return hB64 + "." + pB64 + "." + sig
}

func (h *harness) goodHeader() map[string]any {
	return map[string]any{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": jwkMapFor(&h.agentKey.PublicKey),
		"x5c": []string{base64.StdEncoding.EncodeToString(h.certDER)},
	}
}

// jwkMapFor renders pub as the profile's bare {kty,crv,x,y} JWK map, for
// crafting proof headers directly.
func jwkMapFor(pub *ecdsa.PublicKey) map[string]any {
	x := make([]byte, coordLen)
	y := make([]byte, coordLen)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return map[string]any{"kty": "EC", "crv": "P-256", "x": b64urlEncode(x), "y": b64urlEncode(y)}
}

func (h *harness) goodPayload(t *testing.T, method, htu string) map[string]any {
	t.Helper()
	jti, err := newJTI()
	if err != nil {
		t.Fatalf("jti: %v", err)
	}
	return map[string]any{"htm": method, "htu": htu, "iat": h.now.Unix(), "jti": jti}
}

func TestVerifyProof_Matrix(t *testing.T) {
	const method, rawURL = "POST", "https://callee.example/v1/x"
	htu, err := normalizeHTU(rawURL)
	if err != nil {
		t.Fatalf("normalizeHTU: %v", err)
	}

	// verify runs VerifyProof against a fresh harness with the given crafted proof.
	verify := func(h *harness, token string) error {
		_, err := VerifyProof(context.Background(), token, method, rawURL, h.now, DefaultPoPSkew, h.replay)
		return err
	}

	t.Run("valid", func(t *testing.T) {
		h := newHarness(t)
		if err := verify(h, craftProof(t, h.agentKey, h.goodHeader(), h.goodPayload(t, method, htu))); err != nil {
			t.Fatalf("valid proof rejected: %v", err)
		}
	})

	t.Run("wrong htm", func(t *testing.T) {
		h := newHarness(t)
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, h.goodHeader(), h.goodPayload(t, "GET", htu))), ErrHTTPBindingMismatch)
	})
	t.Run("wrong htu", func(t *testing.T) {
		h := newHarness(t)
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, h.goodHeader(), h.goodPayload(t, method, "https://evil.example/x"))), ErrHTTPBindingMismatch)
	})

	t.Run("iat too old", func(t *testing.T) {
		h := newHarness(t)
		p := h.goodPayload(t, method, htu)
		p["iat"] = h.now.Add(-10 * time.Minute).Unix()
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, h.goodHeader(), p)), ErrProofStale)
	})
	t.Run("iat too far future", func(t *testing.T) {
		h := newHarness(t)
		p := h.goodPayload(t, method, htu)
		p["iat"] = h.now.Add(10 * time.Minute).Unix()
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, h.goodHeader(), p)), ErrProofStale)
	})
	t.Run("missing iat", func(t *testing.T) {
		h := newHarness(t)
		p := h.goodPayload(t, method, htu)
		delete(p, "iat")
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, h.goodHeader(), p)), ErrMalformedProof)
	})
	t.Run("missing jti", func(t *testing.T) {
		h := newHarness(t)
		p := h.goodPayload(t, method, htu)
		delete(p, "jti")
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, h.goodHeader(), p)), ErrMalformedProof)
	})
	t.Run("oversized jti rejected", func(t *testing.T) {
		h := newHarness(t)
		p := h.goodPayload(t, method, htu)
		p["jti"] = strings.Repeat("a", MaxJTISize+1)
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, h.goodHeader(), p)), ErrMalformedProof)
	})
	t.Run("jti at the size limit accepted", func(t *testing.T) {
		h := newHarness(t)
		p := h.goodPayload(t, method, htu)
		p["jti"] = strings.Repeat("a", MaxJTISize)
		if err := verify(h, craftProof(t, h.agentKey, h.goodHeader(), p)); err != nil {
			t.Fatalf("jti of exactly MaxJTISize rejected: %v", err)
		}
	})

	t.Run("alg none", func(t *testing.T) {
		h := newHarness(t)
		hdr := h.goodHeader()
		hdr["alg"] = "none"
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, hdr, h.goodPayload(t, method, htu))), ErrUnsupportedAlg)
	})
	t.Run("alg RS256", func(t *testing.T) {
		h := newHarness(t)
		hdr := h.goodHeader()
		hdr["alg"] = "RS256"
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, hdr, h.goodPayload(t, method, htu))), ErrUnsupportedAlg)
	})
	t.Run("wrong typ", func(t *testing.T) {
		h := newHarness(t)
		hdr := h.goodHeader()
		hdr["typ"] = "jwt"
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, hdr, h.goodPayload(t, method, htu))), ErrUnsupportedAlg)
	})
	t.Run("unknown header field rejected", func(t *testing.T) {
		h := newHarness(t)
		hdr := h.goodHeader()
		hdr["kid"] = "some-key-id"
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, hdr, h.goodPayload(t, method, htu))), ErrMalformedProof)
	})
	t.Run("missing jwk", func(t *testing.T) {
		h := newHarness(t)
		hdr := h.goodHeader()
		delete(hdr, "jwk")
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, hdr, h.goodPayload(t, method, htu))), ErrMalformedProof)
	})
	t.Run("jwk with private key material rejected", func(t *testing.T) {
		h := newHarness(t)
		hdr := h.goodHeader()
		j := jwkMapFor(&h.agentKey.PublicKey)
		j["d"] = "private-scalar"
		hdr["jwk"] = j
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, hdr, h.goodPayload(t, method, htu))), ErrMalformedProof)
	})
	t.Run("jwk does not match x5c key", func(t *testing.T) {
		h := newHarness(t)
		attacker := genKey(t)
		hdr := h.goodHeader()
		hdr["jwk"] = jwkMapFor(&attacker.PublicKey)
		// Even signed under the attacker's own key, the dual-header consistency
		// check kills the proof before any signature work.
		assertProofErr(t, verify(h, craftProof(t, attacker, hdr, h.goodPayload(t, method, htu))), ErrKeyMismatch)
	})
	t.Run("missing x5c", func(t *testing.T) {
		h := newHarness(t)
		hdr := h.goodHeader()
		delete(hdr, "x5c")
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, hdr, h.goodPayload(t, method, htu))), ErrCertInvalid)
	})
	t.Run("x5c with extra certificate rejected", func(t *testing.T) {
		h := newHarness(t)
		hdr := h.goodHeader()
		hdr["x5c"] = []string{
			base64.StdEncoding.EncodeToString(h.certDER),
			base64.StdEncoding.EncodeToString(identityCert(t, genKey(t), "ans://v1.0.0.other.example")),
		}
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, hdr, h.goodPayload(t, method, htu))), ErrCertInvalid)
	})
	t.Run("non-P256 x5c leaf", func(t *testing.T) {
		h := newHarness(t)
		hdr := h.goodHeader()
		hdr["x5c"] = []string{base64.StdEncoding.EncodeToString(p384CertDER(t))}
		assertProofErr(t, verify(h, craftProof(t, h.agentKey, hdr, h.goodPayload(t, method, htu))), ErrCertInvalid)
	})

	t.Run("key substitution (signed by attacker, x5c is victim)", func(t *testing.T) {
		h := newHarness(t)
		attacker := genKey(t)
		// Header carries the victim's cert; signature is by the attacker's key.
		assertProofErr(t, verify(h, craftProof(t, attacker, h.goodHeader(), h.goodPayload(t, method, htu))), ErrSignatureInvalid)
	})

	t.Run("bad signature length", func(t *testing.T) {
		h := newHarness(t)
		token := craftProof(t, h.agentKey, h.goodHeader(), h.goodPayload(t, method, htu))
		hB64, pB64, _, _ := splitCompactJWS(token)
		bad := hB64 + "." + pB64 + "." + b64urlEncode(make([]byte, 63))
		assertProofErr(t, verify(h, bad), ErrSignatureInvalid)
	})
	t.Run("tampered payload breaks signature", func(t *testing.T) {
		h := newHarness(t)
		token := craftProof(t, h.agentKey, h.goodHeader(), h.goodPayload(t, method, htu))
		hB64, _, sB64, _ := splitCompactJWS(token)
		other := b64urlEncode([]byte(`{"htm":"POST","htu":"https://callee.example/v1/x","iat":1700000000,"jti":"swapped"}`))
		assertProofErr(t, verify(h, hB64+"."+other+"."+sB64), ErrSignatureInvalid)
	})

	t.Run("oversize proof", func(t *testing.T) {
		h := newHarness(t)
		assertProofErr(t, verify(h, strings.Repeat("a", MaxProofSize+1)), ErrMalformedProof)
	})
	t.Run("malformed compact (2 segments)", func(t *testing.T) {
		h := newHarness(t)
		assertProofErr(t, verify(h, "aaa.bbb"), ErrMalformedProof)
	})
	t.Run("canceled context", func(t *testing.T) {
		h := newHarness(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := VerifyProof(ctx, "x.y.z", method, rawURL, h.now, DefaultPoPSkew, h.replay); err == nil {
			t.Fatal("expected context error")
		}
	})
}

func TestVerifyProof_TokenBinding(t *testing.T) {
	const method, rawURL = "POST", "https://callee.example/v1/x"
	const token = "opaque-access-token-value"

	tests := []struct {
		name       string
		signOpts   []ProofOption
		verifyOpts []VerifyOption
		want       ErrorType // "" = accept
	}{
		{"no token, no ath", nil, nil, ""},
		{"token presented, matching ath", []ProofOption{WithAccessToken(token)}, []VerifyOption{WithBoundAccessToken(token)}, ""},
		{"ath without presented token", []ProofOption{WithAccessToken(token)}, nil, ErrTokenBindingMismatch},
		{"presented token without ath", nil, []VerifyOption{WithBoundAccessToken(token)}, ErrTokenBindingMismatch},
		{"ath for a different token", []ProofOption{WithAccessToken("other-token")}, []VerifyOption{WithBoundAccessToken(token)}, ErrTokenBindingMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			p, err := h.signer.Sign(context.Background(), method, rawURL, tt.signOpts...)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			_, err = VerifyProof(context.Background(), p, method, rawURL, h.now, DefaultPoPSkew, h.replay, tt.verifyOpts...)
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

func TestVerifyProof_Replay(t *testing.T) {
	h := newHarness(t)
	const method, rawURL = "POST", "https://callee.example/v1/x"
	htu, _ := normalizeHTU(rawURL)
	token := craftProof(t, h.agentKey, h.goodHeader(), h.goodPayload(t, method, htu))

	if _, err := VerifyProof(context.Background(), token, method, rawURL, h.now, DefaultPoPSkew, h.replay); err != nil {
		t.Fatalf("first use rejected: %v", err)
	}
	_, err := VerifyProof(context.Background(), token, method, rawURL, h.now, DefaultPoPSkew, h.replay)
	assertProofErr(t, err, ErrReplay)
}

func TestVerifyProof_ReplayCacheFull(t *testing.T) {
	h := newHarness(t)
	const method, rawURL = "POST", "https://callee.example/v1/x"
	htu, _ := normalizeHTU(rawURL)
	full := NewMemoryReplayCache(context.Background(), 1, withReplayClock(func() time.Time { return h.now }))
	defer full.Close()

	t1 := craftProof(t, h.agentKey, h.goodHeader(), h.goodPayload(t, method, htu))
	if _, err := VerifyProof(context.Background(), t1, method, rawURL, h.now, DefaultPoPSkew, full); err != nil {
		t.Fatalf("first proof: %v", err)
	}
	t2 := craftProof(t, h.agentKey, h.goodHeader(), h.goodPayload(t, method, htu))
	_, err := VerifyProof(context.Background(), t2, method, rawURL, h.now, DefaultPoPSkew, full)
	assertProofErr(t, err, ErrReplayCacheFull)
}

func TestVerifyProof_ReplayBoundary(t *testing.T) {
	// A replay attempted at the very edge of the freshness window is still
	// caught: the cache retains the jti to iat+skew+grace, which outlives the
	// freshness window — so even with the cache clock advanced to the edge, the
	// entry is still live.
	h := newHarness(t)
	const method, rawURL = "POST", "https://callee.example/v1/x"
	htu, _ := normalizeHTU(rawURL)

	var nowUnix atomic.Int64
	nowUnix.Store(h.now.Unix())
	cache := NewMemoryReplayCache(context.Background(), 10,
		withReplayClock(func() time.Time { return time.Unix(nowUnix.Load(), 0) }))
	defer cache.Close()

	token := craftProof(t, h.agentKey, h.goodHeader(), h.goodPayload(t, method, htu))
	if _, err := VerifyProof(context.Background(), token, method, rawURL, h.now, DefaultPoPSkew, cache); err != nil {
		t.Fatalf("first use: %v", err)
	}
	edge := h.now.Add(DefaultPoPSkew) // latest still-fresh instant
	nowUnix.Store(edge.Unix())
	_, err := VerifyProof(context.Background(), token, method, rawURL, edge, DefaultPoPSkew, cache)
	assertProofErr(t, err, ErrReplay)
}
