package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
)

// Fingerprints must be SHA256:<hex> so CertFingerprint.Matches can parse them.
const (
	fpA       = "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fpB       = "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	fpC       = "SHA256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	fpUnknown = "SHA256:0000000000000000000000000000000000000000000000000000000000000000"
)

// createMultiCertBadge builds a badge attesting several server and identity
// certificates, as a V2 badge (or a V1 badge with rotation arrays) decodes.
func createMultiCertBadge(host, version string, serverCerts, identityCerts []models.AttestedCert) *models.Badge {
	now := time.Now()
	return &models.Badge{
		Status:        models.BadgeStatusActive,
		SchemaVersion: string(models.SchemaVersionV2),
		Payload: models.BadgePayload{
			LogID: "test-log-id",
			Producer: models.Producer{
				KeyID:     "test-key",
				Signature: "test-sig",
				Event: models.AgentEvent{
					ANSID:   "test-ans-id",
					ANSName: "ans://" + version + "." + host,
					Agent:   models.AgentInfo{Host: host, Name: "Test Agent", Version: version},
					Attestations: models.Attestations{
						DomainValidation: "ACME-DNS-01",
						ServerCerts:      serverCerts,
						IdentityCerts:    identityCerts,
					},
					IssuedAt:  now,
					Timestamp: now,
				},
			},
		},
	}
}

func TestServerVerifier_MultipleAttestedCerts(t *testing.T) {
	host := "agent.example.com"
	expired := time.Now().Add(-time.Hour)
	future := time.Now().Add(24 * time.Hour)
	badge := createMultiCertBadge(host, "v1.0.0",
		[]models.AttestedCert{
			{Fingerprint: fpA, Type: "X509-DV-SERVER", NotAfter: &future},
			{Fingerprint: fpB, Type: "X509-DV-SERVER"},
			{Fingerprint: fpC, Type: "X509-DV-SERVER", NotAfter: &expired},
		},
		[]models.AttestedCert{{Fingerprint: fpC, Type: "X509-OV-CLIENT"}},
	)
	verifier := newBadgeVerifierForHost(t, host, badge, true)
	fqdn, _ := models.NewFqdn(host)

	tests := []struct {
		name     string
		cert     string
		wantType OutcomeType
	}{
		{name: "first cert with future notAfter accepted", cert: fpA, wantType: OutcomeVerified},
		{name: "second cert without notAfter accepted", cert: fpB, wantType: OutcomeVerified},
		{name: "expired cert rejected even though listed", cert: fpC, wantType: OutcomeFingerprintMismatch},
		{name: "unlisted cert rejected", cert: fpUnknown, wantType: OutcomeFingerprintMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcome := verifier.(*ServerVerifier).Verify(context.Background(), fqdn, createTestCertIdentity(host, tt.cert))
			if outcome.Type != tt.wantType {
				t.Fatalf("Verify() type = %v, want %v (error=%v)", outcome.Type, tt.wantType, outcome.Error)
			}
			if tt.wantType == OutcomeFingerprintMismatch {
				if !strings.Contains(outcome.Expected, fpA) || !strings.Contains(outcome.Expected, fpB) || strings.Contains(outcome.Expected, fpC) {
					t.Errorf("Expected should list the unexpired candidates only, got %q", outcome.Expected)
				}
			}
		})
	}
}

func TestClientVerifier_MultipleAttestedCerts(t *testing.T) {
	host := "agent.example.com"
	version := "v1.0.0"
	expired := time.Now().Add(-time.Hour)
	badge := createMultiCertBadge(host, version,
		[]models.AttestedCert{{Fingerprint: fpC, Type: "X509-DV-SERVER"}},
		[]models.AttestedCert{
			{Fingerprint: fpA, Type: "X509-OV-CLIENT"},
			{Fingerprint: fpB, Type: "X509-OV-CLIENT", NotAfter: &expired},
		},
	)
	verifier := newBadgeVerifierForHost(t, host, badge, false)

	tests := []struct {
		name     string
		cert     string
		wantType OutcomeType
	}{
		{name: "listed identity cert accepted", cert: fpA, wantType: OutcomeVerified},
		{name: "expired identity cert rejected", cert: fpB, wantType: OutcomeFingerprintMismatch},
		{name: "server cert is not an identity cert", cert: fpC, wantType: OutcomeFingerprintMismatch},
		{name: "unlisted cert rejected", cert: fpUnknown, wantType: OutcomeFingerprintMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcome := verifier.(*ClientVerifier).Verify(context.Background(), createMTLSCertIdentity(host, version, tt.cert))
			if outcome.Type != tt.wantType {
				t.Fatalf("Verify() type = %v, want %v (error=%v)", outcome.Type, tt.wantType, outcome.Error)
			}
		})
	}
}

// TestServerVerifier_V2BadgeFromWire drives a V2 badge through JSON decoding
// and the HTTP client, not a hand-built struct, so the wire layout the TL
// publishes is what the verifier is tested against.
func TestServerVerifier_V2BadgeFromWire(t *testing.T) {
	host := "agent.example.com"
	raw := `{
		"status": "ACTIVE",
		"schemaVersion": "V2",
		"payload": {"logId":"l","producer":{"keyId":"k","signature":"s","event":{
			"ansId":"a","ansName":"ans://v1.0.0.` + host + `","eventType":"AGENT_REGISTERED",
			"agent":{"host":"` + host + `","name":"Example","version":"v1.0.0"},
			"attestations":{
				"domainValidation":"ACME-DNS-01",
				"serverCerts":[{"fingerprint":"` + fpA + `","type":"X509-DV-SERVER","notAfter":"2099-01-01T00:00:00Z"}],
				"identityCerts":[{"fingerprint":"` + fpB + `","type":"X509-OV-CLIENT"}],
				"dnsRecordsProvisioned":[{"name":"_ans.` + host + `","data":"v=ans1","type":"TXT"}]
			},
			"issuedAt":"2026-05-01T00:00:00Z","raId":"r","timestamp":"2026-05-01T00:00:00Z"
		}}}
	}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(raw))
	}))
	defer server.Close()
	badgeURL := server.URL + "/v1/agents/a"
	badge, err := NewHTTPTransparencyLogClient().FetchBadge(context.Background(), badgeURL)
	if err != nil {
		t.Fatalf("FetchBadge: %v", err)
	}
	verifier := newBadgeVerifierForHost(t, host, badge, true)
	fqdn, _ := models.NewFqdn(host)
	outcome := verifier.(*ServerVerifier).Verify(context.Background(), fqdn, createTestCertIdentity(host, fpA))
	if !outcome.IsSuccess() {
		t.Fatalf("Verify() = %v (%v), want verified", outcome.Type, outcome.Error)
	}
}

func TestCurrentFingerprints(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute)
	future := now.Add(time.Minute)
	tests := []struct {
		name  string
		certs []models.AttestedCert
		want  []string
	}{
		{name: "nil", certs: nil, want: []string{}},
		{name: "keeps unexpired and undated", certs: []models.AttestedCert{{Fingerprint: "a", NotAfter: &future}, {Fingerprint: "b"}}, want: []string{"a", "b"}},
		{name: "drops expired", certs: []models.AttestedCert{{Fingerprint: "a", NotAfter: &past}, {Fingerprint: "b"}}, want: []string{"b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := currentFingerprints(tt.certs, now)
			if len(got) != len(tt.want) {
				t.Fatalf("currentFingerprints = %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("currentFingerprints[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// newBadgeVerifierForHost wires a mock DNS record and mock TL serving badge
// for host; server selects ServerVerifier, otherwise ClientVerifier.
func newBadgeVerifierForHost(t *testing.T, host string, badge *models.Badge, server bool) any {
	t.Helper()
	badgeURL := "https://tlog.example.com/v1/agents/" + badge.AgentID()
	dns := NewMockDNSResolver().WithRecords(host, []AnsBadgeRecord{{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}})
	tlog := NewMockTransparencyLogClient().WithBadge(badgeURL, badge)
	opts := []Option{WithDNSResolver(dns), WithTlogClient(tlog), WithoutURLValidation()}
	if server {
		return NewServerVerifier(opts...)
	}
	return NewClientVerifier(opts...)
}
