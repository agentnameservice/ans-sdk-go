package pop

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

const (
	callMethod = "POST"
	callURL    = "https://callee.example/v1/do?x=1"
)

func TestVerifyCaller_HappyPath(t *testing.T) {
	h := newHarness(t)
	id, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), h.headers(t),
		callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
	if err != nil {
		t.Fatalf("VerifyCaller happy path: %v", err)
	}
	if id.AnsName != h.ansName {
		t.Errorf("AnsName = %q, want %q", id.AnsName, h.ansName)
	}
	if id.AgentID != h.agentID {
		t.Errorf("AgentID = %q, want %q", id.AgentID, h.agentID)
	}
	if id.Fingerprint != h.fp {
		t.Errorf("Fingerprint mismatch")
	}
	if id.FingerprintHex() == "" {
		t.Errorf("FingerprintHex empty")
	}
}

func TestVerifyCaller_MissingInputs(t *testing.T) {
	h := newHarness(t)
	proof := h.proof(t, callMethod, callURL)
	hdrs := h.headers(t)

	cases := []struct {
		name  string
		proof string
		hdrs  *scitt.Headers
	}{
		{"no proof", "", hdrs},
		{"nil headers", proof, nil},
		{"no status token", proof, &scitt.Headers{Receipt: hdrs.Receipt}},
		{"require receipt but none present", proof, &scitt.Headers{StatusToken: hdrs.StatusToken}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyCaller(context.Background(), tc.proof, tc.hdrs, callMethod, callURL,
				h.keys, h.replay, h.callerOpts()...)
			assertProofErr(t, err, ErrMissingHeaders)
		})
	}
}

func TestVerifyCaller_RequireReceiptFalse(t *testing.T) {
	h := newHarness(t)
	hdrs := &scitt.Headers{StatusToken: h.statusToken(t)} // no receipt
	id, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), hdrs,
		callMethod, callURL, h.keys, h.replay, h.callerOpts(WithRequireReceipt(false))...)
	if err != nil {
		t.Fatalf("require-receipt=false: %v", err)
	}
	if id.AnsName != h.ansName {
		t.Errorf("AnsName = %q", id.AnsName)
	}
}

// TestVerifyCaller_UntrustedProofDoesNotConsumeReplaySlot proves an
// unauthenticated caller cannot fill the replay cache: a structurally valid
// proof from a self-signed certificate (no status-token vouching) must be
// rejected WITHOUT recording its jti, or a flood of such proofs would fill the
// bounded cache and fail-close authentication for every legitimate caller.
func TestVerifyCaller_UntrustedProofDoesNotConsumeReplaySlot(t *testing.T) {
	h := newHarness(t)
	clock := func() time.Time { return h.now }
	cache := NewMemoryReplayCache(context.Background(), 100, withReplayClock(clock))
	defer cache.Close()

	// Attacker: own key, own self-signed cert, valid proof mechanics, but no
	// status token vouching for that certificate.
	attackerKey := genKey(t)
	attackerCert := identityCert(t, attackerKey, h.ansName)
	attackerSigner, signerErr := NewSigner(attackerKey, attackerCert, withSignerClock(clock))
	if signerErr != nil {
		t.Fatalf("NewSigner: %v", signerErr)
	}

	const floods = 5
	for i := range floods {
		proof, signErr := attackerSigner.Sign(context.Background(), callMethod, callURL)
		if signErr != nil {
			t.Fatalf("sign %d: %v", i, signErr)
		}
		_, verifyErr := VerifyCaller(context.Background(), proof, h.headers(t), callMethod, callURL,
			h.keys, cache, h.callerOpts()...)
		assertProofErr(t, verifyErr, ErrBindingFailed)
	}
	if got := cache.Len(); got != 0 {
		t.Fatalf("untrusted proofs consumed %d replay-cache slots, want 0", got)
	}

	// A legitimate caller still authenticates and still gets replay protection.
	good := h.proof(t, callMethod, callURL)
	if _, firstErr := VerifyCaller(context.Background(), good, h.headers(t), callMethod, callURL,
		h.keys, cache, h.callerOpts()...); firstErr != nil {
		t.Fatalf("legitimate caller rejected: %v", firstErr)
	}
	if got := cache.Len(); got != 1 {
		t.Fatalf("authenticated proof recorded %d slots, want 1", got)
	}
	_, replayErr := VerifyCaller(context.Background(), good, h.headers(t), callMethod, callURL,
		h.keys, cache, h.callerOpts()...)
	assertProofErr(t, replayErr, ErrReplay)
}

func TestVerifyCaller_ExposesProofKeyThumbprint(t *testing.T) {
	h := newHarness(t)
	id, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), h.headers(t),
		callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
	if err != nil {
		t.Fatalf("VerifyCaller: %v", err)
	}
	// A handler completing RFC 9449 token binding compares the token's cnf.jkt
	// to this value, so it must equal the RFC 7638 thumbprint of the proof key.
	if want := jwkThumbprint(&h.agentKey.PublicKey); id.JKT != want {
		t.Errorf("JKT = %q, want %q", id.JKT, want)
	}
}

func TestVerifyCaller_TokenBinding(t *testing.T) {
	const tok = "caller-access-token"
	t.Run("matching binding accepted", func(t *testing.T) {
		h := newHarness(t)
		_, err := VerifyCaller(context.Background(), h.proofWithToken(t, callMethod, callURL, tok),
			h.headers(t), callMethod, callURL, h.keys, h.replay,
			h.callerOpts(WithVerifyOptions(WithBoundAccessToken(tok)))...)
		if err != nil {
			t.Fatalf("matching token binding rejected: %v", err)
		}
	})
	t.Run("mismatched binding rejected", func(t *testing.T) {
		h := newHarness(t)
		_, err := VerifyCaller(context.Background(), h.proofWithToken(t, callMethod, callURL, "other-token"),
			h.headers(t), callMethod, callURL, h.keys, h.replay,
			h.callerOpts(WithVerifyOptions(WithBoundAccessToken(tok)))...)
		assertProofErr(t, err, ErrTokenBindingMismatch)
	})
}

func TestVerifyCaller_BindingFailures(t *testing.T) {
	t.Run("fingerprint not in status token", func(t *testing.T) {
		h := newHarness(t)
		var otherFP [32]byte
		otherFP[0] = 0xAB
		st := statusToken(t, h.tlKey, h.agentID, h.ansName, scitt.StatusActive,
			h.now.Add(-time.Minute).Unix(), h.now.Add(time.Hour).Unix(), otherFP)
		hdrs := &scitt.Headers{Receipt: h.receipt(t), StatusToken: st}
		_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), hdrs,
			callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
		assertProofErr(t, err, ErrBindingFailed)
	})

	t.Run("certificate has no ans:// SAN", func(t *testing.T) {
		h := newHarness(t)
		noSANKey := genKey(t)
		noSANDER := identityCert(t, noSANKey, "") // no URI SAN
		fp := sha256.Sum256(noSANDER)
		signer, err := NewSigner(noSANKey, noSANDER, withSignerClock(func() time.Time { return h.now }))
		if err != nil {
			t.Fatalf("NewSigner: %v", err)
		}
		proof, err := signer.Sign(context.Background(), callMethod, callURL)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		st := statusToken(t, h.tlKey, h.agentID, h.ansName, scitt.StatusActive,
			h.now.Add(-time.Minute).Unix(), h.now.Add(time.Hour).Unix(), fp)
		hdrs := &scitt.Headers{Receipt: h.receipt(t), StatusToken: st}
		_, err = VerifyCaller(context.Background(), proof, hdrs, callMethod, callURL,
			h.keys, h.replay, h.callerOpts()...)
		assertProofErr(t, err, ErrBindingFailed)
	})

	t.Run("cert SAN host does not match status token AnsName", func(t *testing.T) {
		h := newHarness(t)
		st := statusToken(t, h.tlKey, h.agentID, "ans://v1.0.0.other.example", scitt.StatusActive,
			h.now.Add(-time.Minute).Unix(), h.now.Add(time.Hour).Unix(), h.fp)
		hdrs := &scitt.Headers{Receipt: h.receipt(t), StatusToken: st}
		_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), hdrs,
			callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
		assertProofErr(t, err, ErrBindingFailed)
	})

	t.Run("receipt names a different agent", func(t *testing.T) {
		h := newHarness(t)
		bad := receipt(t, h.tlKey, eventJSON(t, "different-agent", h.ansName))
		hdrs := &scitt.Headers{Receipt: bad, StatusToken: h.statusToken(t)}
		_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), hdrs,
			callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
		assertProofErr(t, err, ErrBindingFailed)
	})
}

func TestVerifyCaller_ReceiptInvalid(t *testing.T) {
	t.Run("leaf not decodable JSON", func(t *testing.T) {
		h := newHarness(t)
		bad := receipt(t, h.tlKey, []byte{0x00, 0x01, 0x02}) // signed but not JSON
		hdrs := &scitt.Headers{Receipt: bad, StatusToken: h.statusToken(t)}
		_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), hdrs,
			callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
		assertProofErr(t, err, ErrReceiptInvalid)
	})
	t.Run("signed by untrusted key", func(t *testing.T) {
		h := newHarness(t)
		rogue := genKey(t)
		bad := receipt(t, rogue, eventJSON(t, h.agentID, h.ansName))
		hdrs := &scitt.Headers{Receipt: bad, StatusToken: h.statusToken(t)}
		_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), hdrs,
			callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
		assertProofErr(t, err, ErrReceiptInvalid)
	})
}

func TestVerifyCaller_StatusInvalid(t *testing.T) {
	t.Run("expired status token", func(t *testing.T) {
		h := newHarness(t)
		expired := statusToken(t, h.tlKey, h.agentID, h.ansName, scitt.StatusActive,
			h.now.Add(-2*time.Hour).Unix(), h.now.Add(-time.Hour).Unix(), h.fp) // exp in the past
		hdrs := &scitt.Headers{Receipt: h.receipt(t), StatusToken: expired}
		_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), hdrs,
			callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
		assertProofErr(t, err, ErrStatusInvalid)
	})
	t.Run("revoked (terminal) status", func(t *testing.T) {
		h := newHarness(t)
		revoked := statusToken(t, h.tlKey, h.agentID, h.ansName, scitt.StatusRevoked,
			h.now.Add(-time.Minute).Unix(), h.now.Add(time.Hour).Unix(), h.fp)
		hdrs := &scitt.Headers{Receipt: h.receipt(t), StatusToken: revoked}
		_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), hdrs,
			callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
		assertProofErr(t, err, ErrStatusInvalid)
	})
}

func TestVerifyCaller_ExpectedPeer(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		h := newHarness(t)
		_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), h.headers(t),
			callMethod, callURL, h.keys, h.replay, h.callerOpts(WithExpectedAnsName(h.ansName))...)
		if err != nil {
			t.Fatalf("expected-peer match: %v", err)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		h := newHarness(t)
		_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), h.headers(t),
			callMethod, callURL, h.keys, h.replay,
			h.callerOpts(WithAllowedAnsNames("ans://v1.0.0.nope.example"))...)
		assertProofErr(t, err, ErrExpectedPeerMismatch)
	})
	t.Run("malformed expected name fails closed", func(t *testing.T) {
		h := newHarness(t)
		_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), h.headers(t),
			callMethod, callURL, h.keys, h.replay,
			h.callerOpts(WithExpectedAnsName("not-an-ans-name"))...)
		assertProofErr(t, err, ErrExpectedPeerMismatch)
	})
}
