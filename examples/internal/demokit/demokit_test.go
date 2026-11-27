package demokit

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

func TestInclusionPathWalksToTreeHash(t *testing.T) {
	t.Parallel()
	for n := 1; n <= 9; n++ {
		leaves := make([][]byte, n)
		for i := range leaves {
			leaves[i] = fmt.Appendf(nil, "leaf-%d", i)
		}
		want := treeHash(leaves)
		for m := range leaves {
			got, err := scitt.WalkInclusionPath(leaves[m], uint64(m), uint64(n), inclusionPath(leaves, uint64(m)))
			if err != nil {
				t.Fatalf("n=%d m=%d: walk: %v", n, m, err)
			}
			if got != want {
				t.Fatalf("n=%d m=%d: walked root %x, want %x", n, m, got, want)
			}
		}
	}
}

func TestKeyLookupTrustsOnlyTheLogKey(t *testing.T) {
	t.Parallel()
	log, err := NewLog()
	if err != nil {
		t.Fatal(err)
	}
	tk, err := log.KeyLookup().Get(log.KeyID())
	if err != nil {
		t.Fatalf("KeyLookup rejects the log's own kid: %v", err)
	}
	if tk.Kid != log.KeyID() {
		t.Fatalf("trusted key kid %x, want %x", tk.Kid, log.KeyID())
	}
	if _, err := log.KeyLookup().Get([4]byte{}); err == nil {
		t.Fatal("KeyLookup accepted an unknown kid")
	}
	if _, err := KeyLookup(&ecdsa.PublicKey{}); err == nil {
		t.Fatal("KeyLookup built a trust store from a key with no curve")
	}
}

func TestRegisterMintsVerifiableArtifacts(t *testing.T) {
	t.Parallel()
	log, err := NewLog()
	if err != nil {
		t.Fatal(err)
	}
	keys := log.KeyLookup()

	agents := make([]*Agent, 0, 3)
	for i := range 3 {
		a, err := log.Register(fmt.Sprintf("ans://v1.0.%d.agent%d.example", i, i), fmt.Sprintf("agent-%d", i), scitt.StatusActive)
		if err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
		agents = append(agents, a)
	}
	if log.TreeSize() != 3 {
		t.Fatalf("tree size %d, want 3", log.TreeSize())
	}

	for i, a := range agents {
		rcpt, err := scitt.VerifyReceipt(a.Bundle.Receipt, keys)
		if err != nil {
			t.Fatalf("agent %d receipt: %v", i, err)
		}
		if rcpt.LeafIndex != uint64(i) || rcpt.TreeSize != uint64(i+1) || a.LeafIndex != uint64(i) {
			t.Fatalf("agent %d receipt leaf=%d size=%d agent leaf=%d, want leaf=%d size=%d",
				i, rcpt.LeafIndex, rcpt.TreeSize, a.LeafIndex, i, i+1)
		}

		tok, err := scitt.VerifyStatusToken(a.Bundle.StatusToken, keys, time.Minute)
		if err != nil {
			t.Fatalf("agent %d status token: %v", i, err)
		}
		if tok.Payload.AnsName != a.AnsName || tok.Payload.AgentID != a.AgentID {
			t.Fatalf("agent %d token names %s/%s, want %s/%s",
				i, tok.Payload.AnsName, tok.Payload.AgentID, a.AnsName, a.AgentID)
		}
		if !scitt.MatchesIdentityCert(&tok.Payload, sha256.Sum256(a.Bundle.CertDER)) {
			t.Fatalf("agent %d identity cert not vouched by its status token", i)
		}
		if !scitt.MatchesServerCert(&tok.Payload, sha256.Sum256(a.Server.CertDER)) {
			t.Fatalf("agent %d server cert not vouched by its status token", i)
		}
		if scitt.MatchesServerCert(&tok.Payload, sha256.Sum256(a.Bundle.CertDER)) {
			t.Fatalf("agent %d identity cert must not pass as a server cert", i)
		}
	}
}

func TestRegisterCertificatesNameTheAgent(t *testing.T) {
	t.Parallel()
	log, err := NewLog()
	if err != nil {
		t.Fatal(err)
	}
	a, err := log.Register("ans://v2.1.0.pay.acme.example", "agent-pay", scitt.StatusActive)
	if err != nil {
		t.Fatal(err)
	}
	if a.Host != "pay.acme.example" {
		t.Fatalf("host %q, want pay.acme.example", a.Host)
	}
	id, err := x509.ParseCertificate(a.Bundle.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.URIs) != 1 || id.URIs[0].String() != a.AnsName {
		t.Fatalf("identity cert URI SANs %v, want [%s]", id.URIs, a.AnsName)
	}
	if len(id.DNSNames) != 1 || id.DNSNames[0] != a.Host {
		t.Fatalf("identity cert DNS SANs %v, want [%s]", id.DNSNames, a.Host)
	}
	srv, err := x509.ParseCertificate(a.Server.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.VerifyHostname(a.Host); err != nil {
		t.Fatalf("server cert does not cover %s: %v", a.Host, err)
	}
	if len(srv.URIs) != 0 {
		t.Fatalf("server cert must not carry an ans:// SAN, got %v", srv.URIs)
	}
}

func TestNewServerIdentity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{name: "DNS name", host: "pay.acme.example"},
		{name: "host cannot be encoded in a certificate", host: "exämple.example", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			id, err := newServerIdentity(tt.host)
			if tt.wantErr {
				if err == nil {
					t.Fatal("newServerIdentity minted a certificate for the host")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(id.CertDER)
			if err != nil {
				t.Fatal(err)
			}
			if err := cert.VerifyHostname(tt.host); err != nil {
				t.Fatalf("certificate does not cover %s: %v", tt.host, err)
			}
			if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&id.Key.PublicKey) {
				t.Fatal("certificate does not carry the identity's public key")
			}
		})
	}
}

func TestUnusableAnsNamesAreRejected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		ansName string
	}{
		{name: "not an ans:// URI", ansName: "https://not-an-ans-name"},
		{name: "no version", ansName: "ans://missing-version.example"},
		{name: "host is not a valid URI host", ansName: "ans://v1.0.0.exa mple"},
		{name: "host cannot be encoded in a certificate", ansName: "ans://v1.0.0.exämple.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			log, err := NewLog()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := log.Register(tt.ansName, "agent-x", scitt.StatusActive); err == nil {
				t.Error("Register accepted the name")
			}
			if log.TreeSize() != 0 {
				t.Errorf("a rejected registration left %d leaves in the log", log.TreeSize())
			}
			if _, _, err := SelfSignedIdentity(tt.ansName); err == nil {
				t.Error("SelfSignedIdentity accepted the name")
			}
			if _, _, err := Provision(tt.ansName, "agent-x"); err == nil {
				t.Error("Provision accepted the name")
			}
		})
	}
}

func TestIssueStatusToken(t *testing.T) {
	t.Parallel()
	log, err := NewLog()
	if err != nil {
		t.Fatal(err)
	}
	agent, err := log.Register("ans://v1.0.0.payments.acme.example", "agent-payments", scitt.StatusActive)
	if err != nil {
		t.Fatal(err)
	}
	const skew = 2 * time.Minute

	tests := []struct {
		name       string
		status     scitt.AgentStatus
		expires    time.Time
		wantType   scitt.TokenErrorType
		wantStatus scitt.AgentStatus
		wantErr    bool
	}{
		{name: "active and current verifies", status: scitt.StatusActive, expires: time.Now().Add(time.Hour)},
		{name: "expired within skew still verifies", status: scitt.StatusActive, expires: time.Now().Add(-time.Minute)},
		{
			name: "expired beyond skew", status: scitt.StatusActive, expires: time.Now().Add(-10 * time.Minute),
			wantErr: true, wantType: scitt.TokenErrExpired,
		},
		{
			name: "revoked", status: scitt.StatusRevoked, expires: time.Now().Add(time.Hour),
			wantErr: true, wantType: scitt.TokenErrTerminalStatus, wantStatus: scitt.StatusRevoked,
		},
		{
			name: "expired wins over revoked", status: scitt.StatusRevoked, expires: time.Now().Add(-10 * time.Minute),
			wantErr: true, wantType: scitt.TokenErrExpired,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			raw, err := log.IssueStatusToken(agent, tt.status, tt.expires)
			if err != nil {
				t.Fatal(err)
			}
			tok, err := scitt.VerifyStatusToken(raw, log.KeyLookup(), skew)
			if tt.wantErr {
				var te *scitt.TokenError
				if !errors.As(err, &te) || te.Type != tt.wantType || te.Status != tt.wantStatus {
					t.Fatalf("got %v, want TokenError type %d status %q", err, tt.wantType, tt.wantStatus)
				}
				return
			}
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if tok.Payload.AgentID != agent.AgentID || tok.Payload.AnsName != agent.AnsName {
				t.Fatalf("token names %s/%s, want %s/%s",
					tok.Payload.AnsName, tok.Payload.AgentID, agent.AnsName, agent.AgentID)
			}
			if tok.Payload.Exp != tt.expires.Unix() || tok.Payload.Iat >= tok.Payload.Exp {
				t.Fatalf("token iat=%d exp=%d, want exp=%d and iat before it",
					tok.Payload.Iat, tok.Payload.Exp, tt.expires.Unix())
			}
			if !scitt.MatchesIdentityCert(&tok.Payload, sha256.Sum256(agent.Bundle.CertDER)) ||
				!scitt.MatchesServerCert(&tok.Payload, sha256.Sum256(agent.Server.CertDER)) {
				t.Fatal("re-issued token must vouch for the agent's registered certificates")
			}
		})
	}
}

func TestArtifactsRejectedUnderAnotherLog(t *testing.T) {
	t.Parallel()
	issuer, err := NewLog()
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewLog()
	if err != nil {
		t.Fatal(err)
	}
	a, err := issuer.Register("ans://v1.0.0.a.example", "agent-a", scitt.StatusActive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scitt.VerifyReceipt(a.Bundle.Receipt, other.KeyLookup()); err == nil {
		t.Fatal("receipt verified under a log that did not sign it")
	}
	if _, err := scitt.VerifyStatusToken(a.Bundle.StatusToken, other.KeyLookup(), time.Minute); err == nil {
		t.Fatal("status token verified under a log that did not sign it")
	}
}

func TestSelfSignedIdentityIsNotVouchedFor(t *testing.T) {
	t.Parallel()
	log, err := NewLog()
	if err != nil {
		t.Fatal(err)
	}
	victim, err := log.Register("ans://v1.0.0.orders.acme.example", "agent-orders", scitt.StatusActive)
	if err != nil {
		t.Fatal(err)
	}
	_, forged, err := SelfSignedIdentity(victim.AnsName)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := scitt.VerifyStatusToken(victim.Bundle.StatusToken, log.KeyLookup(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if scitt.MatchesIdentityCert(&tok.Payload, sha256.Sum256(forged)) {
		t.Fatal("a forged certificate for the victim's name must not match the victim's status token")
	}
}

func TestProvisionAndBundleRoundTrip(t *testing.T) {
	t.Parallel()
	tlKey, bundle, err := Provision(DemoAnsName, DemoAgentID)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := KeyLookup(&tlKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := bundle.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.AgentKey.Equal(bundle.AgentKey) {
		t.Fatal("loaded agent key differs")
	}
	if _, err = scitt.VerifyReceipt(loaded.Receipt, keys); err != nil {
		t.Fatalf("loaded receipt: %v", err)
	}
	tok, err := scitt.VerifyStatusToken(loaded.StatusToken, keys, time.Minute)
	if err != nil {
		t.Fatalf("loaded status token: %v", err)
	}
	if !scitt.MatchesIdentityCert(&tok.Payload, sha256.Sum256(loaded.CertDER)) {
		t.Fatal("loaded identity cert not vouched by status token")
	}
	if err := bundle.Save(filepath.Join(dir, "no-such-directory")); err == nil {
		t.Fatal("Save reported success writing into a directory that does not exist")
	}
	if err := (&Bundle{AgentKey: &ecdsa.PrivateKey{}}).Save(t.TempDir()); err == nil {
		t.Fatal("Save reported success for a key that cannot be encoded")
	}
}

func TestLoadBundleRejectsDamagedBundles(t *testing.T) {
	t.Parallel()
	_, bundle, err := Provision(DemoAnsName, DemoAgentID)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := func(der []byte) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}

	tests := []struct {
		name    string
		file    string
		replace []byte // nil removes the file
	}{
		{name: "missing key", file: fileAgentKey},
		{name: "key is not PEM", file: fileAgentKey, replace: []byte("not pem")},
		{name: "key is not PKCS#8", file: fileAgentKey, replace: privateKeyPEM([]byte("not a key"))},
		{name: "key is not ECDSA", file: fileAgentKey, replace: privateKeyPEM(edDER)},
		{name: "missing certificate", file: fileAgentCrt},
		{name: "certificate is not PEM", file: fileAgentCrt, replace: []byte("not pem")},
		{name: "missing receipt", file: fileReceipt},
		{name: "missing status token", file: fileStatus},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if err := bundle.Save(dir); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, tt.file)
			damage := os.Remove(path)
			if tt.replace != nil {
				damage = os.WriteFile(path, tt.replace, 0o600)
			}
			if damage != nil {
				t.Fatal(damage)
			}
			if _, err := LoadBundle(dir); err == nil {
				t.Fatal("LoadBundle accepted a damaged bundle")
			}
		})
	}
}

func TestUnsignedDemoToken(t *testing.T) {
	t.Parallel()
	tok, err := MintUnsignedDemoToken("agent-x", "payments:read", "thumb")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseUnsignedDemoToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Sub != "agent-x" || parsed.Scope != "payments:read" || parsed.Cnf.JKT != "thumb" {
		t.Fatalf("round trip mismatch: %+v", parsed)
	}
	unbound, err := MintUnsignedDemoToken("agent-x", "payments:read", "")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		token string
	}{
		{name: "not base64", token: "!!not-base64"},
		{name: "not JSON", token: base64.RawURLEncoding.EncodeToString([]byte("not json"))},
		{name: "not bound to a key", token: unbound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, err := ParseUnsignedDemoToken(tt.token); err == nil {
				t.Fatalf("parsed %+v, want an error", got)
			}
		})
	}
}
