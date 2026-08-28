package pop

// Benchmarks for the offline cost of authenticating an A2A caller: each of the
// three proofs alone — status token (liveness), SCITT receipt (identity), DPoP
// proof (possession) — and VerifyCaller composing them, which is what
// Middleware pays per request. No network I/O anywhere on these paths.
//
// Fixtures mirror production shapes rather than the unit-test minimums: the
// receipt places its leaf in a 2^20-entry transparency log (20-node inclusion
// path) over a ~512-byte registration event. DPoP proofs are single-use (the
// verifier consumes each jti), so every proof-verifying benchmark pre-mints
// b.N proofs and sizes the replay cache to hold them, keeping ECDSA signing
// out of the timed loop.
//
// Run: go test -bench . -benchmem -run '^$' ./pop/

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

const (
	benchMethod = "POST"
	benchURL    = "https://callee.example/v1/do"

	// benchTreeSize/benchLeafIndex give the receipt's Merkle walk a 20-node
	// inclusion path — a million-entry log, not the single-leaf tree the unit
	// tests use.
	benchTreeSize  = uint64(1) << 20
	benchLeafIndex = uint64(524_287)
	// benchEventPadBytes pads the leaf event to ~512 bytes, the size of a
	// realistic registration event.
	benchEventPadBytes = 336
)

// inclusionPathLen mirrors WalkInclusionPath's fn/sn state machine to return
// the exact number of path elements RFC 9162 requires for (leaf, size).
func inclusionPathLen(leafIndex, treeSize uint64) int {
	fn, sn := leafIndex, treeSize-1
	n := 0
	for sn != 0 {
		if fn&1 == 1 || fn == sn {
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		}
		fn >>= 1
		sn >>= 1
		n++
	}
	return n
}

// benchEvent is a ~512-byte transparency-log leaf event naming the agent.
// receiptNamesAgent reads only agentId/ansName; the pad key is ignored.
func benchEvent(t testing.TB, agentID, ansName string) []byte {
	t.Helper()
	pad := make([]byte, benchEventPadBytes)
	if _, err := rand.Read(pad); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ev, err := json.Marshal(map[string]string{
		"agentId": agentID,
		"ansName": ansName,
		"pad":     base64.RawStdEncoding.EncodeToString(pad),
	})
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return ev
}

// benchReceipt mints a receipt whose leaf sits at benchLeafIndex in a
// benchTreeSize log. The path nodes are random bytes: VerifyReceipt computes
// the root from them (the root is not anchored to a witnessed tree head), so
// the walk costs exactly what a real 2^20-log inclusion proof costs.
func benchReceipt(t testing.TB, tlKey *ecdsa.PrivateKey, event []byte) []byte {
	t.Helper()
	kid := kidFor(t, &tlKey.PublicKey)
	protected := cborMarshal(t, map[int64]any{
		coseAlgKey: int64(algES256ID),
		coseKidKey: kid[:],
		coseVdsKey: int64(vdsRFC9162),
	})
	path := make([]any, inclusionPathLen(benchLeafIndex, benchTreeSize))
	for i := range path {
		node := make([]byte, sha256.Size)
		if _, err := rand.Read(node); err != nil {
			t.Fatalf("rand: %v", err)
		}
		path[i] = node
	}
	unprotected := map[int64]any{vdpKey: map[int64]any{
		int64(-1): benchTreeSize,
		int64(-2): benchLeafIndex,
		int64(-3): path,
	}}
	return coseSign1(t, tlKey, protected, unprotected, event)
}

// benchFixture is the server-side view of one caller: the caller's signer and
// SCITT headers, the verifier's trust store, and a fixed clock so freshness
// windows never move mid-run.
type benchFixture struct {
	signer  *Signer
	headers *scitt.Headers
	keys    *keyLookup
	now     time.Time
	clock   func() time.Time
}

func newBenchFixture(b *testing.B) *benchFixture {
	b.Helper()
	const (
		ansName = "ans://v1.0.0.payments.acme.example"
		agentID = "agent-bench-1"
	)
	now := time.Now()
	clock := func() time.Time { return now }

	agentKey := genKey(b)
	certDER := identityCert(b, agentKey, ansName)
	fp := sha256.Sum256(certDER)
	tlKey := genKey(b)

	signer, err := NewSigner(agentKey, certDER, withSignerClock(clock))
	if err != nil {
		b.Fatalf("NewSigner: %v", err)
	}
	f := &benchFixture{
		signer: signer,
		headers: &scitt.Headers{
			StatusToken: statusToken(b, tlKey, agentID, ansName, scitt.StatusActive,
				now.Add(-time.Minute).Unix(), now.Add(time.Hour).Unix(), fp),
			Receipt: benchReceipt(b, tlKey, benchEvent(b, agentID, ansName)),
		},
		keys:  newKeyLookup(b, "tl", &tlKey.PublicKey),
		now:   now,
		clock: clock,
	}

	// A fixture that does not verify measures nothing: check all three legs
	// composed once before any timing.
	sanity := f.replayCache(b, 1)
	if _, err := VerifyCaller(context.Background(), f.mintProofs(b, 1)[0], f.headers,
		benchMethod, benchURL, f.keys, sanity, withCallerClock(clock)); err != nil {
		b.Fatalf("bench fixture does not verify: %v", err)
	}
	return f
}

// mintProofs pre-mints n single-use proofs so a timed loop measures
// verification only, never ECDSA signing.
func (f *benchFixture) mintProofs(b *testing.B, n int) []string {
	b.Helper()
	proofs := make([]string, n)
	for i := range proofs {
		p, err := f.signer.Sign(context.Background(), benchMethod, benchURL)
		if err != nil {
			b.Fatalf("sign proof %d: %v", i, err)
		}
		proofs[i] = p
	}
	return proofs
}

// replayCache builds a cache sized for the run. The fixture clock is fixed, so
// entries never expire and capacity must cover every proof the run verifies.
func (f *benchFixture) replayCache(b *testing.B, capacity int) *MemoryReplayCache {
	b.Helper()
	c := NewMemoryReplayCache(context.Background(), capacity, withReplayClock(f.clock))
	b.Cleanup(c.Close)
	return c
}

// BenchmarkVerifyStatusToken is the liveness leg alone: one COSE ES256
// signature over the status token vouching the identity certificate.
func BenchmarkVerifyStatusToken(b *testing.B) {
	f := newBenchFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := scitt.VerifyStatusTokenAt(f.headers.StatusToken, f.keys,
			scitt.MaxClockSkew, f.now.Unix()); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyReceipt is the identity leg alone: one COSE ES256 signature
// plus the 20-node Merkle inclusion walk of a 2^20-entry log.
func BenchmarkVerifyReceipt(b *testing.B) {
	f := newBenchFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := scitt.VerifyReceipt(f.headers.Receipt, f.keys); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyProof is the possession leg alone: strict header decode,
// jwk↔x5c key equality, one ES256 signature, htm/htu binding, freshness, and
// the replay-cache commit.
func BenchmarkVerifyProof(b *testing.B) {
	f := newBenchFixture(b)
	proofs := f.mintProofs(b, b.N)
	replay := f.replayCache(b, b.N+1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		if _, err := VerifyProof(context.Background(), proofs[i], benchMethod, benchURL,
			f.now, DefaultPoPSkew, replay); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyCaller composes all three legs — what Middleware pays per
// request: three ES256 verifies plus the binding checks tying proof, status
// token, and receipt to one identity certificate.
func BenchmarkVerifyCaller(b *testing.B) {
	f := newBenchFixture(b)
	proofs := f.mintProofs(b, b.N)
	replay := f.replayCache(b, b.N+1)
	opts := withCallerClock(f.clock)
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		if _, err := VerifyCaller(context.Background(), proofs[i], f.headers,
			benchMethod, benchURL, f.keys, replay, opts); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyCaller_NoReceipt is the WithRequireReceipt(false) deployment:
// liveness + possession only, two ES256 verifies instead of three.
func BenchmarkVerifyCaller_NoReceipt(b *testing.B) {
	f := newBenchFixture(b)
	proofs := f.mintProofs(b, b.N)
	replay := f.replayCache(b, b.N+1)
	clockOpt := withCallerClock(f.clock)
	noReceipt := WithRequireReceipt(false)
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		if _, err := VerifyCaller(context.Background(), proofs[i], f.headers,
			benchMethod, benchURL, f.keys, replay, clockOpt, noReceipt); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyCaller_Parallel runs the composed check across all cores —
// the aggregate throughput a multi-core callee gets, including contention on
// the shared replay cache.
func BenchmarkVerifyCaller_Parallel(b *testing.B) {
	f := newBenchFixture(b)
	proofs := f.mintProofs(b, b.N)
	replay := f.replayCache(b, b.N+1)
	opts := withCallerClock(f.clock)
	var next atomic.Int64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := next.Add(1) - 1
			if _, err := VerifyCaller(context.Background(), proofs[i], f.headers,
				benchMethod, benchURL, f.keys, replay, opts); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkSignProof is the caller's side: minting one DPoP proof (one ES256
// signature plus 16 bytes of jti entropy).
func BenchmarkSignProof(b *testing.B) {
	f := newBenchFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := f.signer.Sign(context.Background(), benchMethod, benchURL); err != nil {
			b.Fatal(err)
		}
	}
}
