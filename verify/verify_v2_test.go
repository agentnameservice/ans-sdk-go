package verify

import (
	"context"
	"testing"
	"time"

	"github.com/godaddy/ans-sdk-go/models"
)

// createV2TestBadge builds a v2-style badge with plural ValidServerCerts and
// ValidIdentityCerts. The fingerprint strings must be in SHA256:<hex> format
// because verifyWithBadge iterates badge.ServerCertFingerprints() and compares
// each candidate against the presented cert via CertFingerprint.Matches, which
// parses the SHA256:<hex> form.
func createV2TestBadge(host, version string, serverFPs, identityFPs []string) *models.Badge {
	now := time.Now()

	validServerCerts := make([]models.ValidCertAttestation, 0, len(serverFPs))
	for _, fp := range serverFPs {
		validServerCerts = append(validServerCerts, models.ValidCertAttestation{
			Fingerprint: fp,
			Type:        "X509-DV-SERVER",
		})
	}

	validIdentityCerts := make([]models.ValidCertAttestation, 0, len(identityFPs))
	for _, fp := range identityFPs {
		validIdentityCerts = append(validIdentityCerts, models.ValidCertAttestation{
			Fingerprint: fp,
			Type:        "X509-OV-CLIENT",
		})
	}

	return &models.Badge{
		Status:        models.BadgeStatusActive,
		SchemaVersion: models.SchemaVersionV2,
		Payload: models.BadgePayload{
			LogID: "test-log-id",
			Producer: models.Producer{
				KeyID:     "test-key",
				Signature: "test-sig",
				Event: models.AgentEvent{
					ANSID:   "test-ans-id",
					ANSName: "ans://" + version + "." + host,
					Agent: models.AgentInfo{
						Host:    host,
						Name:    "Test Agent",
						Version: version,
					},
					Attestations: models.Attestations{
						DomainValidation:   "ACME-DNS-01",
						ValidServerCerts:   validServerCerts,
						ValidIdentityCerts: validIdentityCerts,
					},
					IssuedAt:  now,
					Timestamp: now,
				},
			},
		},
	}
}

// TestServerVerifyAcceptsAnyValidServerCert proves that a v2 badge with two
// valid server fingerprints accepts a presented cert matching EITHER one.
func TestServerVerifyAcceptsAnyValidServerCert(t *testing.T) {
	host := "agent.example.com"
	fpA := "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fpB := "SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	badgeURL := "https://tlog.example.com/v1/agents/v2-id"

	badge := createV2TestBadge(host, "v1.0.0", []string{fpA, fpB}, []string{"SHA256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"})

	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	dnsResolver := NewMockDNSResolver().
		WithRecords(host, []AnsBadgeRecord{dnsRecord})
	tlogClient := NewMockTransparencyLogClient().
		WithBadge(badgeURL, badge)

	verifier := NewServerVerifier(
		WithDNSResolver(dnsResolver),
		WithTlogClient(tlogClient),
		WithoutURLValidation(),
	)

	fqdn, _ := models.NewFqdn(host)

	t.Run("first valid server cert accepted", func(t *testing.T) {
		cert := createTestCertIdentity(host, fpA)
		outcome := verifier.Verify(context.Background(), fqdn, cert)
		if !outcome.IsSuccess() {
			t.Errorf("Verify() with fpA failed: type=%v, error=%v", outcome.Type, outcome.Error)
		}
	})

	t.Run("second valid server cert accepted", func(t *testing.T) {
		cert := createTestCertIdentity(host, fpB)
		outcome := verifier.Verify(context.Background(), fqdn, cert)
		if !outcome.IsSuccess() {
			t.Errorf("Verify() with fpB failed: type=%v, error=%v", outcome.Type, outcome.Error)
		}
	})

	t.Run("unknown cert rejected", func(t *testing.T) {
		unknownFP := "SHA256:0000000000000000000000000000000000000000000000000000000000000000"
		cert := createTestCertIdentity(host, unknownFP)
		outcome := verifier.Verify(context.Background(), fqdn, cert)
		if outcome.Type != OutcomeFingerprintMismatch {
			t.Errorf("Verify() with unknown cert: want FingerprintMismatch, got %v", outcome.Type)
		}
	})
}

// TestClientVerifyAcceptsAnyValidIdentityCert proves that a v2 badge with a
// valid identity fingerprint accepts the presented mTLS cert matching it.
func TestClientVerifyAcceptsAnyValidIdentityCert(t *testing.T) {
	host := "agent.example.com"
	version := "v1.0.0"
	idFP := "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	badgeURL := "https://tlog.example.com/v1/agents/v2-client-id"

	badge := createV2TestBadge(host, version,
		[]string{"SHA256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		[]string{idFP},
	)

	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	dnsResolver := NewMockDNSResolver().
		WithRecords(host, []AnsBadgeRecord{dnsRecord})
	tlogClient := NewMockTransparencyLogClient().
		WithBadge(badgeURL, badge)

	verifier := NewClientVerifier(
		WithDNSResolver(dnsResolver),
		WithTlogClient(tlogClient),
		WithoutURLValidation(),
	)

	t.Run("valid identity cert accepted", func(t *testing.T) {
		cert := createMTLSCertIdentity(host, version, idFP)
		outcome := verifier.Verify(context.Background(), cert)
		if !outcome.IsSuccess() {
			t.Errorf("Verify() with idFP failed: type=%v, error=%v", outcome.Type, outcome.Error)
		}
	})

	t.Run("unknown identity cert rejected", func(t *testing.T) {
		unknownFP := "SHA256:0000000000000000000000000000000000000000000000000000000000000000"
		cert := createMTLSCertIdentity(host, version, unknownFP)
		outcome := verifier.Verify(context.Background(), cert)
		if outcome.Type != OutcomeFingerprintMismatch {
			t.Errorf("Verify() with unknown identity cert: want FingerprintMismatch, got %v", outcome.Type)
		}
	})
}

// TestFirstOrEmpty verifies the helper function used in mismatch outcome construction.
func TestFirstOrEmpty(t *testing.T) {
	t.Run("empty slice returns empty string", func(t *testing.T) {
		got := firstOrEmpty(nil)
		if got != "" {
			t.Errorf("firstOrEmpty(nil) = %q, want %q", got, "")
		}
		got = firstOrEmpty([]string{})
		if got != "" {
			t.Errorf("firstOrEmpty([]) = %q, want %q", got, "")
		}
	})

	t.Run("non-empty slice returns first element", func(t *testing.T) {
		got := firstOrEmpty([]string{"first", "second"})
		if got != "first" {
			t.Errorf("firstOrEmpty([first, second]) = %q, want %q", got, "first")
		}
	})
}
