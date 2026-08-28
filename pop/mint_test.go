package pop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/fxamacker/cbor/v2"
)

// This file holds test-only helpers that mint the COSE artifacts an RA/TL
// normally issues (status tokens, SCITT receipts) and the identity certificate
// a caller holds. They adapt the patterns in verify/scitt/*_test.go so the
// minted artifacts verify under the real scitt verifiers.

const (
	coseAlgKey  = 1
	coseKidKey  = 4
	coseVdsKey  = 395
	cwtClaimKey = 15
	vdpKey      = 396
	algES256ID  = -7
	vdsRFC9162  = 1
)

// genKey returns a fresh P-256 key.
func genKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genKey: %v", err)
	}
	return k
}

// kidFor derives the 4-byte kid = SHA-256(SPKI)[:4] used across the SDK.
func kidFor(t testing.TB, pub *ecdsa.PublicKey) [4]byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	h := sha256.Sum256(spki)
	var kid [4]byte
	copy(kid[:], h[:4])
	return kid
}

// keyLookup implements scitt.KeyLookup over a kid->TrustedKey map.
type keyLookup struct{ keys map[[4]byte]*scitt.TrustedKey }

func (k *keyLookup) Get(kid [4]byte) (*scitt.TrustedKey, error) {
	tk, ok := k.keys[kid]
	if !ok {
		return nil, errors.New("unknown kid")
	}
	return tk, nil
}

func newKeyLookup(t testing.TB, name string, pub *ecdsa.PublicKey) *keyLookup {
	t.Helper()
	kid := kidFor(t, pub)
	return &keyLookup{keys: map[[4]byte]*scitt.TrustedKey{
		kid: {Name: name, Kid: kid, Key: pub},
	}}
}

// identityCert creates a P-256 identity certificate carrying the given ans://
// URI SAN and returns its DER. Self-signed; trust comes from the status-token
// fingerprint, not a chain.
func identityCert(t testing.TB, key *ecdsa.PrivateKey, ansName string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-agent"},
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
		t.Fatalf("create cert: %v", err)
	}
	return der
}

// cborMarshal marshals v to CBOR, failing the test on error.
func cborMarshal(t testing.TB, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("cbor marshal: %v", err)
	}
	return b
}

// p1363 signs digest with key and returns a 64-byte R‖S signature.
func p1363(t testing.TB, key *ecdsa.PrivateKey, digest [32]byte) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig
}

// coseSign1 assembles a COSE_Sign1 (CBOR Tag 18) over protectedBytes+payload,
// signed by key, with the given unprotected header.
func coseSign1(t testing.TB, key *ecdsa.PrivateKey, protectedBytes []byte, unprotected any, payload []byte) []byte {
	t.Helper()
	digest, err := scitt.ComputeSigStructureDigest(protectedBytes, payload)
	if err != nil {
		t.Fatalf("sig structure digest: %v", err)
	}
	sig := p1363(t, key, digest)
	arr := []any{protectedBytes, unprotected, payload, sig}
	return cborMarshal(t, cbor.Tag{Number: 18, Content: arr})
}

// statusToken mints a COSE status token signed by tlKey vouching identityFP as
// an x509-ov-client identity cert for the given agent.
func statusToken(t testing.TB, tlKey *ecdsa.PrivateKey, agentID, ansName string,
	status scitt.AgentStatus, iat, exp int64, identityFP [32]byte) []byte {
	t.Helper()
	kid := kidFor(t, &tlKey.PublicKey)
	protected := cborMarshal(t, map[int64]any{coseAlgKey: int64(algES256ID), coseKidKey: kid[:]})
	certs := []any{map[any]any{"fingerprint": identityFP[:], "cert_type": string(scitt.CertTypeX509OVClient)}}
	payload := cborMarshal(t, map[any]any{
		int64(1): agentID,
		int64(2): string(status),
		int64(3): iat,
		int64(4): exp,
		int64(5): ansName,
		int64(6): certs,
	})
	return coseSign1(t, tlKey, protected, map[int64]any{}, payload)
}

// receipt mints a COSE_Sign1 SCITT receipt (vds=1, single-leaf tree) signed by
// tlKey over the given leaf-event payload.
func receipt(t testing.TB, tlKey *ecdsa.PrivateKey, eventJSON []byte) []byte {
	t.Helper()
	kid := kidFor(t, &tlKey.PublicKey)
	protected := cborMarshal(t, map[int64]any{
		coseAlgKey: int64(algES256ID),
		coseKidKey: kid[:],
		coseVdsKey: int64(vdsRFC9162),
	})
	unprotected := map[int64]any{vdpKey: map[int64]any{int64(-1): uint64(1), int64(-2): uint64(0)}}
	return coseSign1(t, tlKey, protected, unprotected, eventJSON)
}

// eventJSON builds a transparency-log leaf-event JSON naming an agent.
func eventJSON(t testing.TB, agentID, ansName string) []byte {
	t.Helper()
	b, err := json.Marshal(leafEvent{AgentID: agentID, AnsName: ansName})
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return b
}

// harness bundles a caller's identity material, a trusted TL key, and a fixed
// clock so tests can mint a full, mutually-consistent three-proof bundle.
type harness struct {
	agentKey *ecdsa.PrivateKey
	certDER  []byte
	fp       [32]byte
	tlKey    *ecdsa.PrivateKey
	keys     *keyLookup
	agentID  string
	ansName  string
	now      time.Time
	signer   *Signer
	replay   *MemoryReplayCache
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	const ansName = "ans://v1.0.0.payments.acme.example"
	agentKey := genKey(t)
	certDER := identityCert(t, agentKey, ansName)
	tlKey := genKey(t)
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	signer, err := NewSigner(agentKey, certDER, withSignerClock(clock))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	replay := NewMemoryReplayCache(context.Background(), 0, withReplayClock(clock))
	t.Cleanup(replay.Close)
	return &harness{
		agentKey: agentKey,
		certDER:  certDER,
		fp:       sha256.Sum256(certDER),
		tlKey:    tlKey,
		keys:     newKeyLookup(t, "tl", &tlKey.PublicKey),
		agentID:  "agent-123",
		ansName:  ansName,
		now:      now,
		signer:   signer,
		replay:   replay,
	}
}

func (h *harness) statusToken(t *testing.T) []byte {
	t.Helper()
	return statusToken(t, h.tlKey, h.agentID, h.ansName, scitt.StatusActive,
		h.now.Add(-time.Minute).Unix(), h.now.Add(time.Hour).Unix(), h.fp)
}

func (h *harness) receipt(t *testing.T) []byte {
	t.Helper()
	return receipt(t, h.tlKey, eventJSON(t, h.agentID, h.ansName))
}

func (h *harness) headers(t *testing.T) *scitt.Headers {
	t.Helper()
	return &scitt.Headers{Receipt: h.receipt(t), StatusToken: h.statusToken(t)}
}

func (h *harness) proof(t *testing.T, method, rawURL string) string {
	t.Helper()
	p, err := h.signer.Sign(context.Background(), method, rawURL)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	return p
}

// proofWithToken mints a proof bound to an OAuth2 access token (ath claim).
func (h *harness) proofWithToken(t *testing.T, method, rawURL, token string) string {
	t.Helper()
	p, err := h.signer.Sign(context.Background(), method, rawURL, WithAccessToken(token))
	if err != nil {
		t.Fatalf("sign proof with token: %v", err)
	}
	return p
}

// callerOpts returns the options that make the harness clock authoritative.
func (h *harness) callerOpts(extra ...CallerOption) []CallerOption {
	return append([]CallerOption{withCallerClock(func() time.Time { return h.now })}, extra...)
}

// quiet returns a MiddlewareOption silencing the default logger, for tests that
// deliberately provoke rejections.
func quiet() MiddlewareOption {
	return WithMiddlewareLogger(slog.New(slog.DiscardHandler))
}

// assertProofErr fails unless err is a *ProofError of the given type.
func assertProofErr(t *testing.T, err error, want ErrorType) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error of type %s, got nil", want)
	}
	var pe *ProofError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *ProofError, got %T: %v", err, err)
	}
	if pe.Type != want {
		t.Fatalf("error type = %s, want %s (%v)", pe.Type, want, err)
	}
}
