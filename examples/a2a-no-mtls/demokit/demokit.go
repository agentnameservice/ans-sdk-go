// Package demokit mints the SCITT artifacts and identity material that an ANS
// RA/TL would normally provision, so the no-mTLS A2A example can run
// self-contained across separate client and server processes. It is demo
// scaffolding — not part of the SDK's API.
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

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/fxamacker/cbor/v2"
)

// COSE_Sign1 / CWT protected-header and VDP structural constants.
const (
	coseAlgKey      = 1
	coseKidKey      = 4
	coseVDSKey      = 395
	vdpKey          = 396
	vdpTreeSizeKey  = -1
	vdpLeafIndexKey = -2
	algES256        = -7
	vdsRFC9162      = 1
	coseSign1Tag    = 18
)

// Status-token CBOR payload keys.
const (
	payloadStatus  = 2
	payloadIat     = 3
	payloadExp     = 4
	payloadAnsName = 5
	payloadIDCerts = 6
)

const (
	kidLen            = 4
	coordLen          = 32
	p1363SigLen       = 64
	statusBackdateSec = 60
	certTTL           = time.Hour
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

const (
	fileAgentKey = "agent.key"
	fileAgentCrt = "agent.crt"
	fileReceipt  = "receipt.cose"
	fileStatus   = "status.cose"
)

// Provision generates a transparency-log signing key and a caller agent's full
// credential bundle (identity key+certificate, SCITT receipt, status token),
// the receipt and status token signed by the TL key. The TL key is returned so
// the callee can build its trust store with KeyLookup.
func Provision(ansName, agentID string) (*ecdsa.PrivateKey, *Bundle, error) {
	tlKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	certDER, err := identityCert(agentKey, ansName)
	if err != nil {
		return nil, nil, err
	}
	fp := sha256.Sum256(certDER)
	status, err := mintStatusToken(tlKey, agentID, ansName, fp)
	if err != nil {
		return nil, nil, err
	}
	rcpt, err := mintReceipt(tlKey, agentID, ansName)
	if err != nil {
		return nil, nil, err
	}
	return tlKey, &Bundle{AgentKey: agentKey, CertDER: certDER, Receipt: rcpt, StatusToken: status}, nil
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

func identityCert(key *ecdsa.PrivateKey, ansName string) ([]byte, error) {
	u, err := url.Parse(ansName)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "demo-agent"},
		NotBefore:    time.Now().Add(-certTTL),
		NotAfter:     time.Now().Add(certTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
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

func coseSign1(key *ecdsa.PrivateKey, protected []byte, unprotected any, payload []byte) ([]byte, error) {
	digest, err := scitt.ComputeSigStructureDigest(protected, payload)
	if err != nil {
		return nil, err
	}
	sig, err := signP1363(key, digest)
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(cbor.Tag{Number: coseSign1Tag, Content: []any{protected, unprotected, payload, sig}})
}

func mintStatusToken(tlKey *ecdsa.PrivateKey, agentID, ansName string, fp [32]byte) ([]byte, error) {
	kid, err := keyID(&tlKey.PublicKey)
	if err != nil {
		return nil, err
	}
	protected, err := cbor.Marshal(map[int64]any{coseAlgKey: int64(algES256), coseKidKey: kid[:]})
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	certs := []any{map[any]any{"fingerprint": fp[:], "cert_type": string(scitt.CertTypeX509OVClient)}}
	payload, err := cbor.Marshal(map[any]any{
		int64(1):              agentID,
		int64(payloadStatus):  string(scitt.StatusActive),
		int64(payloadIat):     now - statusBackdateSec,
		int64(payloadExp):     now + int64(statusTTL.Seconds()),
		int64(payloadAnsName): ansName,
		int64(payloadIDCerts): certs,
	})
	if err != nil {
		return nil, err
	}
	return coseSign1(tlKey, protected, map[int64]any{}, payload)
}

func mintReceipt(tlKey *ecdsa.PrivateKey, agentID, ansName string) ([]byte, error) {
	kid, err := keyID(&tlKey.PublicKey)
	if err != nil {
		return nil, err
	}
	protected, err := cbor.Marshal(map[int64]any{
		coseAlgKey: int64(algES256),
		coseKidKey: kid[:],
		coseVDSKey: int64(vdsRFC9162),
	})
	if err != nil {
		return nil, err
	}
	event, err := json.Marshal(map[string]string{"agentId": agentID, "ansName": ansName})
	if err != nil {
		return nil, err
	}
	unprotected := map[int64]any{vdpKey: map[int64]any{
		int64(vdpTreeSizeKey):  uint64(1),
		int64(vdpLeafIndexKey): uint64(0),
	}}
	return coseSign1(tlKey, protected, unprotected, event)
}
