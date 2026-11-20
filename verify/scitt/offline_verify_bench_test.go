package scitt

// Measurement-only benchmarks for server-side offline verification cost:
// SCITT receipt + status token (this SDK) plus a reference RFC 9449 DPoP
// proof verifier and an ES256 access-token check. The DPoP/JWT code here is
// benchmark scaffolding, not a production verifier.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// --- fixture construction (mirrors the *_test.go helpers, but on testing.TB) ---

type benchKeyPair struct {
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
	kid  [4]byte
	name string
}

func benchGenKey(tb testing.TB, name string) *benchKeyPair {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	var kid [4]byte
	h := sha256.Sum256(append(priv.PublicKey.X.FillBytes(make([]byte, 32)), priv.PublicKey.Y.FillBytes(make([]byte, 32))...))
	copy(kid[:], h[:4])
	return &benchKeyPair{priv: priv, pub: &priv.PublicKey, kid: kid, name: name}
}

type benchKeyStore struct {
	keys map[[4]byte]*TrustedKey
}

func (s *benchKeyStore) Get(kid [4]byte) (*TrustedKey, error) {
	tk, ok := s.keys[kid]
	if !ok {
		return nil, &SignatureError{Type: SigErrUnknownKeyID, Kid: kid, Message: "unknown key ID"}
	}
	return tk, nil
}

func benchSignP1363(tb testing.TB, priv *ecdsa.PrivateKey, digest [32]byte) []byte {
	tb.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		tb.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):64], sb)
	return sig
}

func benchMarshal(tb testing.TB, v interface{}) []byte {
	tb.Helper()
	out, err := cbor.Marshal(v)
	if err != nil {
		tb.Fatalf("cbor marshal: %v", err)
	}
	return out
}

func benchCoseSign1(tb testing.TB, kp *benchKeyPair, protected []byte, unprotected interface{}, payload []byte) []byte {
	tb.Helper()
	digest, err := ComputeSigStructureDigest(protected, payload)
	if err != nil {
		tb.Fatalf("sig structure digest: %v", err)
	}
	arr := []interface{}{protected, cbor.RawMessage(benchMarshal(tb, unprotected)), payload, benchSignP1363(tb, kp.priv, digest)}
	return benchMarshal(tb, cbor.Tag{Number: 18, Content: arr})
}

// benchInclusionPathLen mirrors WalkInclusionPath's fn/sn state machine to
// return the exact number of path elements RFC 9162 requires for (leaf, size).
func benchInclusionPathLen(leafIndex, treeSize uint64) int {
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

const (
	benchTreeSize  = uint64(1) << 20 // 1,048,576 log entries
	benchLeafIndex = uint64(524287)
	benchEventSize = 512 // typical registration event payload
)

func benchReceipt(tb testing.TB, kp *benchKeyPair) []byte {
	tb.Helper()
	iss, iat, vds := kp.name, time.Now().Unix(), int64(1)
	protected := benchMarshal(tb, map[int64]interface{}{
		1:   int64(-7),
		4:   kp.kid[:],
		15:  map[int64]interface{}{1: iss, 6: iat},
		395: vds,
	})

	pathLen := benchInclusionPathLen(benchLeafIndex, benchTreeSize)
	path := make([]interface{}, pathLen)
	for i := range path {
		node := make([]byte, 32)
		if _, err := rand.Read(node); err != nil {
			tb.Fatalf("rand: %v", err)
		}
		path[i] = node
	}

	event := make([]byte, benchEventSize)
	if _, err := rand.Read(event); err != nil {
		tb.Fatalf("rand: %v", err)
	}

	unprotected := map[int64]interface{}{
		396: map[int64]interface{}{
			int64(-1): benchTreeSize,
			int64(-2): benchLeafIndex,
			int64(-3): path,
		},
	}
	return benchCoseSign1(tb, kp, protected, unprotected, event)
}

// benchStatusToken builds a status token whose metadata_hashes carries the
// agent's DPoP key thumbprint, so proof-of-possession binds to the registered
// key with no authorization server in the loop.
func benchStatusToken(tb testing.TB, kp *benchKeyPair, now int64, jkt string) []byte {
	tb.Helper()

	certEntry := func(seed byte) map[interface{}]interface{} {
		fp := sha256.Sum256([]byte{seed})
		return map[interface{}]interface{}{"fingerprint": fp[:], "cert_type": "x509-dv-server"}
	}

	payload := benchMarshal(tb, map[interface{}]interface{}{
		int64(1): "agent-7f3c9a21-bench",
		int64(2): string(StatusActive),
		int64(3): now,
		int64(4): now + 300,
		int64(5): "ans://v1.0.0.bench-agent.example.com",
		int64(6): []map[interface{}]interface{}{certEntry(1), certEntry(2)},
		int64(7): []map[interface{}]interface{}{certEntry(3), certEntry(4)},
		int64(8): map[string]string{
			"agent_card": "sha256:9f2c1e0a", "policy": "sha256:33bb71de",
			"endpoints": "sha256:c40de1aa", "dpop_jkt": jkt,
		},
	})

	protected := benchMarshal(tb, map[int64]interface{}{
		1: int64(-7), 4: kp.kid[:], 15: map[int64]interface{}{1: kp.name},
	})
	return benchCoseSign1(tb, kp, protected, map[int64]interface{}{}, payload)
}

// --- reference DPoP (RFC 9449) + ES256 access token verifier ---

const (
	dpopIATWindow  = 300 * time.Second
	replayShards   = 256
	replayMaxPerSh = 8192
)

type dpopJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type dpopHeader struct {
	Typ string  `json:"typ"`
	Alg string  `json:"alg"`
	JWK dpopJWK `json:"jwk"`
}

type dpopClaims struct {
	Jti string `json:"jti"`
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Iat int64  `json:"iat"`
	Ath string `json:"ath"`
}

type atClaims struct {
	Sub string `json:"sub"`
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
	Cnf struct {
		Jkt string `json:"jkt"`
	} `json:"cnf"`
}

// replayCache is a sharded jti seen-set, sized to keep lookups O(1) under load.
type replayCache struct {
	shards [replayShards]struct {
		mu   sync.Mutex
		seen map[string]int64
	}
}

func newReplayCache() *replayCache {
	c := &replayCache{}
	for i := range c.shards {
		c.shards[i].seen = make(map[string]int64, replayMaxPerSh)
	}
	return c
}

func (c *replayCache) checkAndStore(jti string, now int64) bool {
	idx := 0
	if len(jti) > 0 {
		idx = int(jti[len(jti)-1]) % replayShards
	}
	sh := &c.shards[idx]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if _, dup := sh.seen[jti]; dup {
		return false
	}
	if len(sh.seen) >= replayMaxPerSh {
		sh.seen = make(map[string]int64, replayMaxPerSh)
	}
	sh.seen[jti] = now
	return true
}

func b64uDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// verifyES256JWS verifies a compact JWS with a P-256 key, returning the raw claims segment.
func verifyES256JWS(token string, key *ecdsa.PublicKey) ([]byte, error) {
	dot1 := strings.IndexByte(token, '.')
	dot2 := strings.LastIndexByte(token, '.')
	if dot1 <= 0 || dot2 <= dot1 {
		return nil, errBenchInvalid
	}
	sig, err := b64uDecode(token[dot2+1:])
	if err != nil || len(sig) != 64 {
		return nil, errBenchInvalid
	}
	digest := sha256.Sum256([]byte(token[:dot2]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return nil, errBenchInvalid
	}
	return b64uDecode(token[dot1+1 : dot2])
}

type benchErr string

func (e benchErr) Error() string { return string(e) }

const errBenchInvalid benchErr = "invalid token"

// jwkThumbprint computes the RFC 7638 SHA-256 thumbprint of a P-256 JWK.
func jwkThumbprint(j dpopJWK) string {
	canon := `{"crv":"` + j.Crv + `","kty":"` + j.Kty + `","x":"` + j.X + `","y":"` + j.Y + `"}`
	sum := sha256.Sum256([]byte(canon))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyDPoP performs full offline DPoP proof validation against an already-trusted jkt.
func verifyDPoP(proof, method, uri, expectJkt, accessToken string, cache *replayCache, now int64) error {
	dot1 := strings.IndexByte(proof, '.')
	if dot1 <= 0 {
		return errBenchInvalid
	}
	hdrRaw, err := b64uDecode(proof[:dot1])
	if err != nil {
		return errBenchInvalid
	}
	var hdr dpopHeader
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return errBenchInvalid
	}
	if hdr.Typ != "dpop+jwt" || hdr.Alg != "ES256" || hdr.JWK.Kty != "EC" || hdr.JWK.Crv != "P-256" {
		return errBenchInvalid
	}

	xb, err := b64uDecode(hdr.JWK.X)
	if err != nil {
		return errBenchInvalid
	}
	yb, err := b64uDecode(hdr.JWK.Y)
	if err != nil {
		return errBenchInvalid
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return errBenchInvalid
	}

	if subtle.ConstantTimeCompare([]byte(jwkThumbprint(hdr.JWK)), []byte(expectJkt)) != 1 {
		return errBenchInvalid
	}

	claimsRaw, err := verifyES256JWS(proof, pub)
	if err != nil {
		return err
	}
	var c dpopClaims
	if err := json.Unmarshal(claimsRaw, &c); err != nil {
		return errBenchInvalid
	}
	if c.Htm != method || c.Htu != uri {
		return errBenchInvalid
	}
	if c.Iat < now-int64(dpopIATWindow.Seconds()) || c.Iat > now+int64(dpopIATWindow.Seconds()) {
		return errBenchInvalid
	}
	if c.Ath != "" {
		athSum := sha256.Sum256([]byte(accessToken))
		if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(athSum[:])), []byte(c.Ath)) != 1 {
			return errBenchInvalid
		}
	}
	cache.checkAndStore(c.Jti, now)
	return nil
}

func signJWS(tb testing.TB, priv *ecdsa.PrivateKey, header, claims interface{}) string {
	tb.Helper()
	hj, err := json.Marshal(header)
	if err != nil {
		tb.Fatalf("marshal header: %v", err)
	}
	cj, err := json.Marshal(claims)
	if err != nil {
		tb.Fatalf("marshal claims: %v", err)
	}
	signing := base64.RawURLEncoding.EncodeToString(hj) + "." + base64.RawURLEncoding.EncodeToString(cj)
	digest := sha256.Sum256([]byte(signing))
	sig := benchSignP1363(tb, priv, digest)
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// --- combined fixture ---

type offlineFixture struct {
	receiptB64 string
	tokenB64   string
	receipt    []byte
	token      []byte
	keys       KeyLookup

	dpopProof   string
	ansProof    string // no ath claim: no access token in the ANS-only path
	accessToken string
	asKey       *ecdsa.PublicKey
	jkt         string
	method      string
	uri         string
	cache       *replayCache
	now         int64
}

func newOfflineFixture(tb testing.TB) *offlineFixture {
	tb.Helper()
	now := time.Now().Unix()

	clientKey := benchGenKey(tb, "agent-client")
	xb := clientKey.pub.X.FillBytes(make([]byte, 32))
	yb := clientKey.pub.Y.FillBytes(make([]byte, 32))
	jwk := dpopJWK{Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(xb),
		Y: base64.RawURLEncoding.EncodeToString(yb)}
	jkt := jwkThumbprint(jwk)

	logKey := benchGenKey(tb, "ans-transparency-log")
	receipt := benchReceipt(tb, logKey)
	token := benchStatusToken(tb, logKey, now, jkt)
	keys := &benchKeyStore{keys: map[[4]byte]*TrustedKey{
		logKey.kid: {Name: logKey.name, Kid: logKey.kid, Key: logKey.pub},
	}}

	// Sanity: fixtures must actually verify, or the benchmark measures nothing.
	if _, err := VerifyReceipt(receipt, keys); err != nil {
		tb.Fatalf("fixture receipt does not verify: %v", err)
	}
	vt, err := VerifyStatusTokenAt(token, keys, 30*time.Second, now)
	if err != nil {
		tb.Fatalf("fixture status token does not verify: %v", err)
	}
	if vt.Payload.MetadataHashes["dpop_jkt"] != jkt {
		tb.Fatal("fixture status token does not carry the DPoP thumbprint")
	}

	asKey := benchGenKey(tb, "authorization-server")
	accessToken := signJWS(tb, asKey.priv,
		map[string]string{"typ": "at+jwt", "alg": "ES256", "kid": "as-1"},
		map[string]interface{}{
			"sub": "agent-7f3c9a21-bench", "iss": "https://as.example.com",
			"aud": "https://api.example.com", "exp": now + 600,
			"cnf": map[string]string{"jkt": jkt},
		})

	athSum := sha256.Sum256([]byte(accessToken))
	method, uri := "POST", "https://api.example.com/v1/agents/invoke"
	proof := signJWS(tb, clientKey.priv,
		dpopHeader{Typ: "dpop+jwt", Alg: "ES256", JWK: jwk},
		dpopClaims{Jti: "01JBQZ8K4WY7X2N9C3", Htm: method, Htu: uri, Iat: now,
			Ath: base64.RawURLEncoding.EncodeToString(athSum[:])})

	// RFC 9449 4.2: ath is required only when the proof accompanies an access
	// token. The ANS-only path has none, so the proof binds to the agent key
	// thumbprint carried in the status token instead.
	ansProof := signJWS(tb, clientKey.priv,
		dpopHeader{Typ: "dpop+jwt", Alg: "ES256", JWK: jwk},
		dpopClaims{Jti: "01JBQZ8K4WY7X2N9C4", Htm: method, Htu: uri, Iat: now})

	cache := newReplayCache()
	if err := verifyDPoP(proof, method, uri, jkt, accessToken, cache, now); err != nil {
		tb.Fatalf("fixture DPoP proof does not verify: %v", err)
	}
	if err := verifyDPoP(ansProof, method, uri, jkt, "", cache, now); err != nil {
		tb.Fatalf("fixture ANS DPoP proof does not verify: %v", err)
	}

	return &offlineFixture{
		receiptB64:  base64.StdEncoding.EncodeToString(receipt),
		tokenB64:    base64.StdEncoding.EncodeToString(token),
		receipt:     receipt,
		token:       token,
		keys:        keys,
		dpopProof:   proof,
		ansProof:    ansProof,
		accessToken: accessToken,
		asKey:       asKey.pub,
		jkt:         jkt,
		method:      method,
		uri:         uri,
		cache:       cache,
		now:         now,
	}
}

// verifyAccessToken checks the AS signature and returns the confirmed jkt.
func (f *offlineFixture) verifyAccessToken() (string, error) {
	claimsRaw, err := verifyES256JWS(f.accessToken, f.asKey)
	if err != nil {
		return "", err
	}
	var c atClaims
	if err := json.Unmarshal(claimsRaw, &c); err != nil {
		return "", errBenchInvalid
	}
	if c.Exp < f.now {
		return "", errBenchInvalid
	}
	return c.Cnf.Jkt, nil
}

// --- component benchmarks ---

func BenchmarkOffline_VerifyReceipt(b *testing.B) {
	f := newOfflineFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := VerifyReceipt(f.receipt, f.keys); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOffline_VerifyStatusToken(b *testing.B) {
	f := newOfflineFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := VerifyStatusTokenAt(f.token, f.keys, 30*time.Second, f.now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOffline_AccessTokenJWT(b *testing.B) {
	f := newOfflineFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := f.verifyAccessToken(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOffline_DPoPProof(b *testing.B) {
	f := newOfflineFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := verifyDPoP(f.dpopProof, f.method, f.uri, f.jkt, f.accessToken, f.cache, f.now); err != nil {
			b.Fatal(err)
		}
	}
}

// --- end-to-end request benchmarks ---

// coldRequest is the full first-contact path: decode both SCITT headers from
// base64, verify receipt, verify status token, verify access token, verify DPoP.
func coldRequest(f *offlineFixture) error {
	receipt, err := base64.StdEncoding.DecodeString(f.receiptB64)
	if err != nil {
		return err
	}
	token, err := base64.StdEncoding.DecodeString(f.tokenB64)
	if err != nil {
		return err
	}
	if _, err := VerifyReceipt(receipt, f.keys); err != nil {
		return err
	}
	if _, err := VerifyStatusTokenAt(token, f.keys, 30*time.Second, f.now); err != nil {
		return err
	}
	jkt, err := f.verifyAccessToken()
	if err != nil {
		return err
	}
	return verifyDPoP(f.dpopProof, f.method, f.uri, jkt, f.accessToken, f.cache, f.now)
}

// warmRequest is the steady-state path: receipt and status token served from
// cache (agent seen before, token still inside its exp), so only the two
// per-request signatures — access token and DPoP proof — are verified.
func warmRequest(f *offlineFixture, rc *ReceiptCache, sc *StatusTokenCache, agentID string) error {
	if _, ok := rc.Get(agentID); !ok {
		return errBenchInvalid
	}
	st, ok := sc.Get(agentID)
	if !ok {
		return errBenchInvalid
	}
	if st.Payload.Status.IsTerminal() {
		return errBenchInvalid
	}
	jkt, err := f.verifyAccessToken()
	if err != nil {
		return err
	}
	return verifyDPoP(f.dpopProof, f.method, f.uri, jkt, f.accessToken, f.cache, f.now)
}

func warmCaches(b *testing.B, f *offlineFixture, agentID string) (*ReceiptCache, *StatusTokenCache) {
	b.Helper()
	vr, err := VerifyReceipt(f.receipt, f.keys)
	if err != nil {
		b.Fatal(err)
	}
	vt, err := VerifyStatusTokenAt(f.token, f.keys, 30*time.Second, f.now)
	if err != nil {
		b.Fatal(err)
	}
	rc := NewReceiptCacheWithDefaults()
	sc := NewStatusTokenCacheWithDefaults()
	rc.Insert(agentID, vr)
	sc.Insert(agentID, vt)
	return rc, sc
}

func BenchmarkOffline_FullRequest_Cold(b *testing.B) {
	f := newOfflineFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := coldRequest(f); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOffline_FullRequest_Warm(b *testing.B) {
	f := newOfflineFixture(b)
	const agentID = "agent-7f3c9a21-bench"
	rc, sc := warmCaches(b, f, agentID)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := warmRequest(f, rc, sc, agentID); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOffline_FullRequest_ColdParallel(b *testing.B) {
	f := newOfflineFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := coldRequest(f); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkOffline_FullRequest_WarmParallel(b *testing.B) {
	f := newOfflineFixture(b)
	const agentID = "agent-7f3c9a21-bench"
	rc, sc := warmCaches(b, f, agentID)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := warmRequest(f, rc, sc, agentID); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// hotRequest is the theoretical floor: receipt, status token, and the access
// token's signature are all cached, leaving only the DPoP proof — which is
// per-request by construction and can never be cached.
func hotRequest(f *offlineFixture, rc *ReceiptCache, sc *StatusTokenCache, atCache *sync.Map, agentID string) error {
	if _, ok := rc.Get(agentID); !ok {
		return errBenchInvalid
	}
	st, ok := sc.Get(agentID)
	if !ok {
		return errBenchInvalid
	}
	if st.Payload.Status.IsTerminal() {
		return errBenchInvalid
	}
	cached, ok := atCache.Load(f.accessToken)
	if !ok {
		return errBenchInvalid
	}
	jkt, _ := cached.(string)
	return verifyDPoP(f.dpopProof, f.method, f.uri, jkt, f.accessToken, f.cache, f.now)
}

func BenchmarkOffline_FullRequest_Hot(b *testing.B) {
	f := newOfflineFixture(b)
	const agentID = "agent-7f3c9a21-bench"
	rc, sc := warmCaches(b, f, agentID)
	atCache := &sync.Map{}
	atCache.Store(f.accessToken, f.jkt)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := hotRequest(f, rc, sc, atCache, agentID); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOffline_FullRequest_HotParallel(b *testing.B) {
	f := newOfflineFixture(b)
	const agentID = "agent-7f3c9a21-bench"
	rc, sc := warmCaches(b, f, agentID)
	atCache := &sync.Map{}
	atCache.Store(f.accessToken, f.jkt)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := hotRequest(f, rc, sc, atCache, agentID); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// --- ANS-only paths: SCITT receipt + status token + DPoP, no OAuth ---
//
// The three tiers map to the SDK's own cache lifetimes in cache.go:
//   cold — first contact with an agent; nothing cached, 3 signatures verified
//   warm — receipt cached (24h TTL, stable per agent); status token has rotated
//          inside its 5-minute exp, so 2 signatures verified
//   hot  — receipt and status token both cached; only the DPoP proof, which is
//          bound per-request by jti/iat/htu and can never be cached

// ansCold is first contact: both SCITT headers arrive base64-encoded and every
// signature is verified from scratch.
func ansCold(f *offlineFixture) error {
	receipt, err := base64.StdEncoding.DecodeString(f.receiptB64)
	if err != nil {
		return err
	}
	tokenBytes, err := base64.StdEncoding.DecodeString(f.tokenB64)
	if err != nil {
		return err
	}
	if _, err := VerifyReceipt(receipt, f.keys); err != nil {
		return err
	}
	st, err := VerifyStatusTokenAt(tokenBytes, f.keys, 30*time.Second, f.now)
	if err != nil {
		return err
	}
	return verifyDPoP(f.ansProof, f.method, f.uri, st.Payload.MetadataHashes["dpop_jkt"], "", f.cache, f.now)
}

// ansWarm has the receipt cached but re-verifies a freshly rotated status token.
func ansWarm(f *offlineFixture, rc *ReceiptCache, agentID string) error {
	if _, ok := rc.Get(agentID); !ok {
		return errBenchInvalid
	}
	tokenBytes, err := base64.StdEncoding.DecodeString(f.tokenB64)
	if err != nil {
		return err
	}
	st, err := VerifyStatusTokenAt(tokenBytes, f.keys, 30*time.Second, f.now)
	if err != nil {
		return err
	}
	return verifyDPoP(f.ansProof, f.method, f.uri, st.Payload.MetadataHashes["dpop_jkt"], "", f.cache, f.now)
}

// ansHot serves both artifacts from cache, leaving only the DPoP proof.
func ansHot(f *offlineFixture, rc *ReceiptCache, sc *StatusTokenCache, agentID string) error {
	if _, ok := rc.Get(agentID); !ok {
		return errBenchInvalid
	}
	st, ok := sc.Get(agentID)
	if !ok {
		return errBenchInvalid
	}
	if st.Payload.Status.IsTerminal() {
		return errBenchInvalid
	}
	return verifyDPoP(f.ansProof, f.method, f.uri, st.Payload.MetadataHashes["dpop_jkt"], "", f.cache, f.now)
}

const benchAgentID = "agent-7f3c9a21-bench"

func BenchmarkANS_Cold(b *testing.B) {
	f := newOfflineFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := ansCold(f); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkANS_Warm(b *testing.B) {
	f := newOfflineFixture(b)
	rc, _ := warmCaches(b, f, benchAgentID)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := ansWarm(f, rc, benchAgentID); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkANS_Hot(b *testing.B) {
	f := newOfflineFixture(b)
	rc, sc := warmCaches(b, f, benchAgentID)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := ansHot(f, rc, sc, benchAgentID); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkANS_ColdParallel(b *testing.B) {
	f := newOfflineFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := ansCold(f); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkANS_WarmParallel(b *testing.B) {
	f := newOfflineFixture(b)
	rc, _ := warmCaches(b, f, benchAgentID)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := ansWarm(f, rc, benchAgentID); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkANS_HotParallel(b *testing.B) {
	f := newOfflineFixture(b)
	rc, sc := warmCaches(b, f, benchAgentID)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := ansHot(f, rc, sc, benchAgentID); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkANS_DPoPProofOnly(b *testing.B) {
	f := newOfflineFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := verifyDPoP(f.ansProof, f.method, f.uri, f.jkt, "", f.cache, f.now); err != nil {
			b.Fatal(err)
		}
	}
}

// --- primitive breakdown ---

func BenchmarkPrimitive_Ed25519Verify(b *testing.B) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, 256)
	sig := ed25519.Sign(priv, msg)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if !ed25519.Verify(pub, msg, sig) {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkPrimitive_ECDSAVerify_ASN1Path(b *testing.B) {
	f := newOfflineFixture(b)
	parsed, err := ParseCoseSign1(f.token)
	if err != nil {
		b.Fatal(err)
	}
	tk, err := f.keys.Get(parsed.Protected.Kid)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := verifyECDSA(tk.Key, parsed.ProtectedBytes, parsed.Payload, parsed.Signature, parsed.Protected.Kid); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPrimitive_ECDSAVerify_DirectRS(b *testing.B) {
	f := newOfflineFixture(b)
	parsed, err := ParseCoseSign1(f.token)
	if err != nil {
		b.Fatal(err)
	}
	tk, err := f.keys.Get(parsed.Protected.Kid)
	if err != nil {
		b.Fatal(err)
	}
	digest, err := ComputeSigStructureDigest(parsed.ProtectedBytes, parsed.Payload)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		r := new(big.Int).SetBytes(parsed.Signature[:32])
		s := new(big.Int).SetBytes(parsed.Signature[32:])
		if !ecdsa.Verify(tk.Key, digest[:], r, s) {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkPrimitive_ParseCoseSign1_Receipt(b *testing.B) {
	f := newOfflineFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := ParseCoseSign1(f.receipt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPrimitive_MerkleWalk_Depth20(b *testing.B) {
	pathLen := benchInclusionPathLen(benchLeafIndex, benchTreeSize)
	path := make([][32]byte, pathLen)
	event := make([]byte, benchEventSize)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := WalkInclusionPath(event, benchLeafIndex, benchTreeSize, path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPrimitive_Base64Decode_Headers(b *testing.B) {
	f := newOfflineFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := base64.StdEncoding.DecodeString(f.receiptB64); err != nil {
			b.Fatal(err)
		}
		if _, err := base64.StdEncoding.DecodeString(f.tokenB64); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPrimitive_ReplayCache(b *testing.B) {
	cache := newReplayCache()
	now := time.Now().Unix()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			cache.checkAndStore("01JBQZ8K4WY7X2N9C3"+string(rune('a'+i%26)), now)
			i++
		}
	})
}
