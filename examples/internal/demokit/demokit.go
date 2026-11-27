// Package demokit mints the SCITT artifacts and identity material that an ANS
// RA/TL would normally provision, so the examples can run self-contained with
// no network. Log is a miniature transparency log: one ES256 signing key and an
// append-only Merkle tree whose receipts carry real RFC 9162 inclusion proofs.
// It is demo scaffolding — not part of the SDK's API.
package demokit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/fxamacker/cbor/v2"
)

// COSE_Sign1 / CWT protected-header and VDP structural constants.
const (
	coseAlgKey          = 1
	coseKidKey          = 4
	coseVDSKey          = 395
	vdpKey              = 396
	vdpTreeSizeKey      = -1
	vdpLeafIndexKey     = -2
	vdpInclusionPathKey = -3
	algES256            = -7
	vdsRFC9162          = 1
	coseSign1Tag        = 18
)

// Status-token CBOR payload keys.
const (
	payloadAgentID     = 1
	payloadStatus      = 2
	payloadIat         = 3
	payloadExp         = 4
	payloadAnsName     = 5
	payloadIDCerts     = 6
	payloadServerCerts = 7
)

const (
	kidLen            = 4
	coordLen          = 32
	p1363SigLen       = 64
	statusBackdateSec = 60
	identityCertTTL   = time.Hour
	serverCertTTL     = 90 * 24 * time.Hour
	statusTTL         = time.Hour
)

// Demo identity values shared across the example binaries.
const (
	DemoAnsName = "ans://v1.0.0.payments.acme.example"
	DemoAgentID = "agent-demo-1"
)

// Bundle is the credential set a caller agent holds: its identity key and
// certificate plus the SCITT receipt and status token the TL issued for it.
type Bundle struct {
	AgentKey    *ecdsa.PrivateKey
	CertDER     []byte
	Receipt     []byte
	StatusToken []byte
}

// ServerIdentity is the TLS material an agent's HTTPS endpoint presents: the
// server key and a certificate whose DNS SAN is the agent's host. In ANS this
// certificate comes from a public CA; here it is self-signed, and a client
// trusts it by adding CertDER to its root pool.
type ServerIdentity struct {
	Key     *ecdsa.PrivateKey
	CertDER []byte
}

// Agent is everything one registered agent holds: its ans:// name, agent id,
// the caller-side Bundle, and the server-side TLS identity for its host.
type Agent struct {
	AnsName   string
	AgentID   string
	Host      string
	LeafIndex uint64
	Bundle    *Bundle
	Server    *ServerIdentity
}

const (
	fileAgentKey = "agent.key"
	fileAgentCrt = "agent.crt"
	fileReceipt  = "receipt.cose"
	fileStatus   = "status.cose"
)

// Log is a demo transparency log. Register appends the agent's registration
// event to the Merkle tree and mints the SCITT receipt (with the inclusion
// proof for that leaf at the current tree size) and the status token, both
// signed by the log key.
type Log struct {
	key    *ecdsa.PrivateKey
	kid    [4]byte
	leaves [][]byte
}

// NewLog generates a fresh log signing key.
func NewLog() (*Log, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	kid, err := keyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Log{key: key, kid: kid}, nil
}

// KeyLookup returns a trust store containing only this log's public key — what
// a verifier would load from the TL's published root keys.
func (l *Log) KeyLookup() scitt.KeyLookup {
	return keyLookup{kid: l.kid, pub: &l.key.PublicKey}
}

// KeyID is the 4-byte COSE kid of the log key, as receipts and status tokens
// name it.
func (l *Log) KeyID() [4]byte {
	return l.kid
}

// TreeSize is the number of registration events in the log.
func (l *Log) TreeSize() uint64 {
	return uint64(len(l.leaves))
}

// Register provisions an agent under ansName with the given lifecycle status:
// an identity key and certificate (ans:// URI SAN), a server key and
// certificate (DNS SAN = host), a status token vouching for both certificate
// fingerprints, and a receipt proving the registration event is in the log.
func (l *Log) Register(ansName, agentID string, status scitt.AgentStatus) (*Agent, error) {
	parsed, err := verify.ParseAnsName(ansName)
	if err != nil {
		return nil, err
	}
	host := parsed.Host
	agentKey, agentCert, err := SelfSignedIdentity(ansName)
	if err != nil {
		return nil, err
	}
	srv, err := newServerIdentity(host)
	if err != nil {
		return nil, err
	}
	token, err := l.mintStatusToken(agentID, ansName, status, time.Now().Add(statusTTL),
		sha256.Sum256(agentCert), sha256.Sum256(srv.CertDER))
	if err != nil {
		return nil, err
	}
	rcpt, err := l.mintReceipt(agentID, ansName)
	if err != nil {
		return nil, err
	}
	return &Agent{
		AnsName:   ansName,
		AgentID:   agentID,
		Host:      host,
		LeafIndex: l.TreeSize() - 1,
		Bundle:    &Bundle{AgentKey: agentKey, CertDER: agentCert, Receipt: rcpt, StatusToken: token},
		Server:    srv,
	}, nil
}

// IssueStatusToken mints a new status token for an agent this log registered,
// asserting status until expires. A transparency log re-issues these on a short
// TTL: a terminal status models the registration being revoked, and an expires
// in the past models the stale token an agent keeps presenting once the log
// stops issuing it fresh ones.
func (l *Log) IssueStatusToken(a *Agent, status scitt.AgentStatus, expires time.Time) ([]byte, error) {
	return l.mintStatusToken(a.AgentID, a.AnsName, status, expires,
		sha256.Sum256(a.Bundle.CertDER), sha256.Sum256(a.Server.CertDER))
}

// Provision generates a transparency-log signing key and a caller agent's full
// credential bundle (identity key+certificate, SCITT receipt, status token),
// the receipt and status token signed by the TL key. The TL key is returned so
// the callee can build its trust store with KeyLookup.
func Provision(ansName, agentID string) (*ecdsa.PrivateKey, *Bundle, error) {
	l, err := NewLog()
	if err != nil {
		return nil, nil, err
	}
	a, err := l.Register(ansName, agentID, scitt.StatusActive)
	if err != nil {
		return nil, nil, err
	}
	return l.key, a.Bundle, nil
}

// SelfSignedIdentity mints a P-256 key and a self-signed identity certificate
// naming ansName in its URI SAN and the agent host in CN and DNS SAN, the shape
// of an ANS identity certificate. Nothing vouches for it: a status token is
// what makes an identity certificate trusted, and this function is also how an
// attacker fabricates a certificate for a name it does not own.
func SelfSignedIdentity(ansName string) (*ecdsa.PrivateKey, []byte, error) {
	parsed, err := verify.ParseAnsName(ansName)
	if err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(ansName)
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: parsed.Host},
		NotBefore:    time.Now().Add(-identityCertTTL),
		NotAfter:     time.Now().Add(identityCertTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{parsed.Host},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return key, der, nil
}

// Save writes the bundle to dir as PEM and binary files.
func (b *Bundle) Save(dir string) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(b.AgentKey)
	if err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
	}{
		{fileAgentKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})},
		{fileAgentCrt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.CertDER})},
		{fileReceipt, b.Receipt},
		{fileStatus, b.StatusToken},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	return nil
}

// LoadBundle reads a bundle previously written by Save.
func LoadBundle(dir string) (*Bundle, error) {
	key, err := loadKey(filepath.Join(dir, fileAgentKey))
	if err != nil {
		return nil, err
	}
	certDER, err := loadCertDER(filepath.Join(dir, fileAgentCrt))
	if err != nil {
		return nil, err
	}
	rcpt, err := os.ReadFile(filepath.Join(dir, fileReceipt))
	if err != nil {
		return nil, err
	}
	status, err := os.ReadFile(filepath.Join(dir, fileStatus))
	if err != nil {
		return nil, err
	}
	return &Bundle{AgentKey: key, CertDER: certDER, Receipt: rcpt, StatusToken: status}, nil
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, fmt.Errorf("%s: not a PEM block", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ECDSA key", path)
	}
	return ecKey, nil
}

func loadCertDER(path string) ([]byte, error) {
	crtPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(crtPEM)
	if blk == nil {
		return nil, fmt.Errorf("%s: not a PEM block", path)
	}
	return blk.Bytes, nil
}

// UnsignedDemoToken is the minimal shape of a DPoP-bound OAuth2 access token: a
// subject, a scope, and the RFC 9449 §6 confirmation claim naming the RFC 7638
// thumbprint of the key the token was issued to.
//
// It is NOT an access token. There is no signature, no iss, no aud, and no exp,
// so anyone can mint one naming any subject and scope. A real authorization
// server issues a signed JWT and a real resource server validates that
// signature, expiry, and audience before reading cnf. The demo carries plain
// JSON so the example stays about the key binding rather than JWT plumbing.
type UnsignedDemoToken struct {
	Sub string `json:"sub"`
	Cnf struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
	Scope string `json:"scope"`
}

// MintUnsignedDemoToken produces a demo access token bound to jkt — the thumbprint an
// authorization server would have taken from the client's key at issuance.
// Binding it to a different thumbprint models a token stolen from another agent.
func MintUnsignedDemoToken(sub, scope, jkt string) (string, error) {
	var t UnsignedDemoToken
	t.Sub = sub
	t.Scope = scope
	t.Cnf.JKT = jkt
	raw, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// ParseUnsignedDemoToken decodes a token minted by MintUnsignedDemoToken. A production
// resource server instead validates the issuer signature, expiry, and audience
// before reading cnf.
func ParseUnsignedDemoToken(tok string) (*UnsignedDemoToken, error) {
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return nil, fmt.Errorf("decode access token: %w", err)
	}
	var t UnsignedDemoToken
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("parse access token: %w", err)
	}
	if t.Cnf.JKT == "" {
		return nil, errors.New("access token has no cnf.jkt: not sender-constrained")
	}
	return &t, nil
}

// KeyLookup builds a scitt.KeyLookup that trusts a single TL public key.
func KeyLookup(pub *ecdsa.PublicKey) (scitt.KeyLookup, error) {
	kid, err := keyID(pub)
	if err != nil {
		return nil, err
	}
	return keyLookup{kid: kid, pub: pub}, nil
}

type keyLookup struct {
	kid [4]byte
	pub *ecdsa.PublicKey
}

func (k keyLookup) Get(kid [4]byte) (*scitt.TrustedKey, error) {
	if kid != k.kid {
		return nil, fmt.Errorf("unknown kid %x", kid)
	}
	return &scitt.TrustedKey{Name: "demo-tl", Kid: k.kid, Key: k.pub}, nil
}

func keyID(pub *ecdsa.PublicKey) ([4]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return [4]byte{}, err
	}
	h := sha256.Sum256(spki)
	var kid [4]byte
	copy(kid[:], h[:kidLen])
	return kid, nil
}

func newServerIdentity(host string) (*ServerIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(serverCertTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &ServerIdentity{Key: key, CertDER: der}, nil
}

func signP1363(key *ecdsa.PrivateKey, digest [32]byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, p1363SigLen)
	r.FillBytes(sig[:coordLen])
	s.FillBytes(sig[coordLen:])
	return sig, nil
}

func (l *Log) coseSign1(protected []byte, unprotected any, payload []byte) ([]byte, error) {
	digest, err := scitt.ComputeSigStructureDigest(protected, payload)
	if err != nil {
		return nil, err
	}
	sig, err := signP1363(l.key, digest)
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(cbor.Tag{Number: coseSign1Tag, Content: []any{protected, unprotected, payload, sig}})
}

// mintStatusToken signs a status token that expires at expires and was issued
// one statusTTL (plus the backdate allowance) before that.
func (l *Log) mintStatusToken(agentID, ansName string, status scitt.AgentStatus, expires time.Time,
	idFP, srvFP [32]byte) ([]byte, error) {
	protected, err := cbor.Marshal(map[int64]any{coseAlgKey: int64(algES256), coseKidKey: l.kid[:]})
	if err != nil {
		return nil, err
	}
	exp := expires.Unix()
	payload, err := cbor.Marshal(map[any]any{
		int64(payloadAgentID): agentID,
		int64(payloadStatus):  string(status),
		int64(payloadIat):     exp - int64(statusTTL.Seconds()) - statusBackdateSec,
		int64(payloadExp):     exp,
		int64(payloadAnsName): ansName,
		int64(payloadIDCerts): []any{
			map[any]any{"fingerprint": idFP[:], "cert_type": string(scitt.CertTypeX509OVClient)},
		},
		int64(payloadServerCerts): []any{
			map[any]any{"fingerprint": srvFP[:], "cert_type": string(scitt.CertTypeX509DVServer)},
		},
	})
	if err != nil {
		return nil, err
	}
	return l.coseSign1(protected, map[int64]any{}, payload)
}

// mintReceipt appends the registration event as a new leaf and signs a receipt
// carrying the RFC 9162 inclusion proof for that leaf at the new tree size.
func (l *Log) mintReceipt(agentID, ansName string) ([]byte, error) {
	protected, err := cbor.Marshal(map[int64]any{
		coseAlgKey: int64(algES256),
		coseKidKey: l.kid[:],
		coseVDSKey: int64(vdsRFC9162),
	})
	if err != nil {
		return nil, err
	}
	event, err := json.Marshal(map[string]any{
		"schemaVersion": "V1",
		"payload": map[string]any{
			"producer": map[string]any{
				"event": map[string]string{
					"ansId":     agentID,
					"ansName":   ansName,
					"eventType": "AGENT_REGISTERED",
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	l.leaves = append(l.leaves, event)
	index := l.TreeSize() - 1
	path := inclusionPath(l.leaves, index)
	rawPath := make([][]byte, 0, len(path))
	for _, h := range path {
		rawPath = append(rawPath, h[:])
	}
	unprotected := map[int64]any{vdpKey: map[int64]any{
		int64(vdpTreeSizeKey):      l.TreeSize(),
		int64(vdpLeafIndexKey):     index,
		int64(vdpInclusionPathKey): rawPath,
	}}
	return l.coseSign1(protected, unprotected, event)
}

// inclusionPath is PATH(m, D[n]) from RFC 6962 §2.1.1: the sibling hashes that
// walk leaf m up to the root of the tree over leaves. The verifier's
// scitt.WalkInclusionPath consumes exactly this sequence.
func inclusionPath(leaves [][]byte, m uint64) [][32]byte {
	n := uint64(len(leaves))
	if n <= 1 {
		return nil
	}
	k := largestPowerOfTwoBelow(n)
	if m < k {
		return append(inclusionPath(leaves[:k], m), treeHash(leaves[k:]))
	}
	return append(inclusionPath(leaves[k:], m-k), treeHash(leaves[:k]))
}

// treeHash is MTH(D[n]) from RFC 6962 §2.1 for a non-empty leaf list.
func treeHash(leaves [][]byte) [32]byte {
	if len(leaves) == 1 {
		return scitt.ComputeLeafHash(leaves[0])
	}
	k := largestPowerOfTwoBelow(uint64(len(leaves)))
	return scitt.ComputeNodeHash(treeHash(leaves[:k]), treeHash(leaves[k:]))
}

// largestPowerOfTwoBelow returns the largest power of two strictly less than n
// (n must be at least 2).
func largestPowerOfTwoBelow(n uint64) uint64 {
	k := uint64(1)
	for k<<1 < n {
		k <<= 1
	}
	return k
}
