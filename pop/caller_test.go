package pop

import (
	"context"
	"crypto/sha256"
	"strings"
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

	t.Run("cert SAN version does not match status token AnsName", func(t *testing.T) {
		h := newHarness(t)
		const otherVersion = "ans://v2.0.0.payments.acme.example"
		st := statusToken(t, h.tlKey, h.agentID, otherVersion, scitt.StatusActive,
			h.now.Add(-time.Minute).Unix(), h.now.Add(time.Hour).Unix(), h.fp)
		hdrs := &scitt.Headers{Receipt: receipt(t, h.tlKey, eventJSON(t, h.agentID, otherVersion)), StatusToken: st}
		_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), hdrs,
			callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
		assertProofErr(t, err, ErrBindingFailed)
		for _, want := range []string{h.ansName, otherVersion} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not name %q", err.Error(), want)
			}
		}
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

// TestVerifyCaller_CertValidity: the log derives ACTIVE from lifecycle events,
// not from certificate expiry, so a fresh status token can still vouch for an
// expired certificate. The verifier enforces the certificate's own dates.
func TestVerifyCaller_CertValidity(t *testing.T) {
	tests := []struct {
		name      string
		notBefore time.Duration // relative to the harness clock
		notAfter  time.Duration
		wantErr   ErrorType
		wantMsg   string
	}{
		{name: "within validity period", notBefore: -time.Hour, notAfter: time.Hour},
		{name: "expires exactly now", notBefore: -time.Hour, notAfter: 0},
		{name: "becomes valid exactly now", notBefore: 0, notAfter: time.Hour},
		{name: "expired a day ago", notBefore: -48 * time.Hour, notAfter: -24 * time.Hour,
			wantErr: ErrCertInvalid, wantMsg: "expired at 2023-11-13T22:13:20Z"},
		{name: "expired one second ago", notBefore: -time.Hour, notAfter: -time.Second,
			wantErr: ErrCertInvalid, wantMsg: "expired at 2023-11-14T22:13:19Z"},
		{name: "not yet valid", notBefore: time.Hour, notAfter: 48 * time.Hour,
			wantErr: ErrCertInvalid, wantMsg: "not valid until 2023-11-14T23:13:20Z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const ansName = "ans://v1.0.0.payments.acme.example"
			key := genKey(t)
			der := identityCertValid(t, key, ansName, testEpoch.Add(tt.notBefore), testEpoch.Add(tt.notAfter))
			h := newHarnessWithCert(t, key, der, "agent-123", ansName)
			expect := func(what string, err error) {
				t.Helper()
				if tt.wantErr == "" {
					if err != nil {
						t.Fatalf("%s: %v", what, err)
					}
					return
				}
				assertProofErr(t, err, tt.wantErr)
				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("%s error %q does not mention %q", what, err.Error(), tt.wantMsg)
				}
			}

			_, err := VerifyProof(context.Background(), h.proof(t, callMethod, callURL), callMethod, callURL,
				h.now, DefaultPoPSkew, h.replay)
			expect("VerifyProof", err)

			_, err = VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), h.headers(t),
				callMethod, callURL, h.keys, h.replay, h.callerOpts()...)
			expect("VerifyCaller", err)
		})
	}
}

// TestVerifyCaller_ExpectedPeer: a pin names one registration. Registrations
// are keyed by the full versioned ans:// name and versions of one host can have
// different owners, so another version of the same host is another peer. A pin
// that is not an ans:// name is a wiring mistake, not a peer mismatch. The
// harness caller is ans://v1.0.0.payments.acme.example.
func TestVerifyCaller_ExpectedPeer(t *testing.T) {
	tests := []struct {
		name    string
		pins    []string
		wantErr ErrorType
		wantMsg string
	}{
		{name: "exact name", pins: []string{"ans://v1.0.0.payments.acme.example"}},
		{name: "host compared case-insensitively", pins: []string{"ans://v1.0.0.Payments.ACME.example"}},
		{name: "set containing the caller", pins: []string{
			"ans://v2.0.0.payments.acme.example", "ans://v1.0.0.payments.acme.example"}},
		{name: "different host", pins: []string{"ans://v1.0.0.nope.example"}, wantErr: ErrExpectedPeerMismatch},
		{name: "different version of the same host", pins: []string{"ans://v2.0.0.payments.acme.example"},
			wantErr: ErrExpectedPeerMismatch,
			wantMsg: "caller ans://v1.0.0.payments.acme.example is not in the accepted set"},
		{name: "malformed pin is a misconfiguration", pins: []string{"not-an-ans-name"}, wantErr: ErrMisconfigured},
		{name: "malformed pin spelled like the host is a misconfiguration", pins: []string{"payments.acme.example"},
			wantErr: ErrMisconfigured},
		{name: "malformed pin alongside a valid one is a misconfiguration", pins: []string{
			"ans://v1.0.0.payments.acme.example", "not-an-ans-name"}, wantErr: ErrMisconfigured},
		{name: "empty allow-list is a misconfiguration", pins: []string{}, wantErr: ErrMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			pin := WithAllowedAnsNames(tt.pins...)
			if len(tt.pins) == 1 {
				pin = WithExpectedAnsName(tt.pins[0])
			}
			_, err := VerifyCaller(context.Background(), h.proof(t, callMethod, callURL), h.headers(t),
				callMethod, callURL, h.keys, h.replay, h.callerOpts(pin)...)
			if tt.wantErr != "" {
				assertProofErr(t, err, tt.wantErr)
				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("error %q does not mention %q", err.Error(), tt.wantMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyCaller with pins %v: %v", tt.pins, err)
			}
		})
	}
}
