package verify

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/godaddy/ans-sdk-go/models"
	"github.com/godaddy/ans-sdk-go/verify/scitt"
)

func createTestBadge(host, version, serverFP, identityFP string) *models.Badge {
	return &models.Badge{
		Status:        models.BadgeStatusActive,
		SchemaVersion: "V1",
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
						DomainValidation: "ACME-DNS-01",
						ServerCert: &models.CertAttestationV1{
							Fingerprint: serverFP,
							Type:        "X509-DV-SERVER",
						},
						IdentityCert: &models.CertAttestationV1{
							Fingerprint: identityFP,
							Type:        "X509-OV-CLIENT",
						},
					},
					IssuedAt:  time.Now(),
					Timestamp: time.Now(),
				},
			},
		},
	}
}

func createTestCertIdentity(cn, fingerprint string) *CertIdentity {
	fp, _ := ParseCertFingerprint(fingerprint)
	return CertIdentityFromFingerprintAndCN(fp, cn)
}

func createMTLSCertIdentity(host, version, fingerprint string) *CertIdentity {
	fp, _ := ParseCertFingerprint(fingerprint)
	return NewCertIdentity(
		&host,
		[]string{host},
		[]string{"ans://" + version + "." + host},
		fp,
	)
}

func TestServerVerifier_Success(t *testing.T) {
	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"

	badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

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

	cert := createTestCertIdentity(host, fingerprint)
	fqdn, _ := models.NewFqdn(host)

	outcome := verifier.Verify(context.Background(), fqdn, cert)

	if !outcome.IsSuccess() {
		t.Errorf("Verify() failed: %v", outcome.Type)
	}
	if outcome.Badge == nil {
		t.Error("Verify() Badge is nil")
	}
	if outcome.MatchedFingerprint == nil {
		t.Error("Verify() MatchedFingerprint is nil")
	}
}

func TestServerVerifier_NotAnsAgent(t *testing.T) {
	dnsResolver := NewMockDNSResolver()
	tlogClient := NewMockTransparencyLogClient()

	verifier := NewServerVerifier(
		WithDNSResolver(dnsResolver),
		WithTlogClient(tlogClient),
		WithoutURLValidation(),
	)

	cert := createTestCertIdentity("unknown.example.com", "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
	fqdn, _ := models.NewFqdn("unknown.example.com")

	outcome := verifier.Verify(context.Background(), fqdn, cert)

	if !outcome.IsNotAnsAgent() {
		t.Errorf("Verify() expected NotAnsAgent, got %v", outcome.Type)
	}
}

func TestServerVerifier_FingerprintMismatch(t *testing.T) {
	host := "test.example.com"
	badgeFP := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	certFP := "SHA256:0000000000000000000000000000000000000000000000000000000000000000"

	badge := createTestBadge(host, "v1.0.0", badgeFP, "SHA256:aaa")
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

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

	cert := createTestCertIdentity(host, certFP)
	fqdn, _ := models.NewFqdn(host)

	outcome := verifier.Verify(context.Background(), fqdn, cert)

	if outcome.Type != OutcomeFingerprintMismatch {
		t.Errorf("Verify() expected FingerprintMismatch, got %v", outcome.Type)
	}
	if outcome.Badge == nil {
		t.Error("Verify() Badge should not be nil for FingerprintMismatch")
	}
}

func TestServerVerifier_InvalidStatus(t *testing.T) {
	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"

	badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")
	badge.Status = models.BadgeStatusRevoked
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

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

	cert := createTestCertIdentity(host, fingerprint)
	fqdn, _ := models.NewFqdn(host)

	outcome := verifier.Verify(context.Background(), fqdn, cert)

	if outcome.Type != OutcomeInvalidStatus {
		t.Errorf("Verify() expected InvalidStatus, got %v", outcome.Type)
	}
	if outcome.Status != models.BadgeStatusRevoked {
		t.Errorf("Verify() Status = %v, want Revoked", outcome.Status)
	}
}

func TestServerVerifier_WarningStatus(t *testing.T) {
	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"

	badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")
	badge.Status = models.BadgeStatusWarning
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

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

	cert := createTestCertIdentity(host, fingerprint)
	fqdn, _ := models.NewFqdn(host)

	outcome := verifier.Verify(context.Background(), fqdn, cert)

	if !outcome.IsSuccess() {
		t.Errorf("Verify() with WARNING badge failed: %v", outcome.Type)
	}
	if outcome.Badge == nil {
		t.Error("Verify() Badge is nil")
	}
	if outcome.MatchedFingerprint == nil {
		t.Error("Verify() MatchedFingerprint is nil")
	}
}

func TestServerVerifier_ExpiredStatus(t *testing.T) {
	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"

	badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")
	badge.Status = models.BadgeStatusExpired
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

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

	cert := createTestCertIdentity(host, fingerprint)
	fqdn, _ := models.NewFqdn(host)

	outcome := verifier.Verify(context.Background(), fqdn, cert)

	if outcome.Type != OutcomeInvalidStatus {
		t.Errorf("Verify() expected InvalidStatus, got %v", outcome.Type)
	}
	if outcome.Status != models.BadgeStatusExpired {
		t.Errorf("Verify() Status = %v, want Expired", outcome.Status)
	}
}

func TestServerVerifier_HostnameMismatch(t *testing.T) {
	badgeHost := "badge.example.com"
	certHost := "different.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"

	badge := createTestBadge(badgeHost, "v1.0.0", fingerprint, "SHA256:aaa")
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	dnsResolver := NewMockDNSResolver().
		WithRecords(certHost, []AnsBadgeRecord{dnsRecord})

	tlogClient := NewMockTransparencyLogClient().
		WithBadge(badgeURL, badge)

	verifier := NewServerVerifier(
		WithDNSResolver(dnsResolver),
		WithTlogClient(tlogClient),
		WithoutURLValidation(),
	)

	cert := createTestCertIdentity(certHost, fingerprint)
	fqdn, _ := models.NewFqdn(certHost)

	outcome := verifier.Verify(context.Background(), fqdn, cert)

	if outcome.Type != OutcomeHostnameMismatch {
		t.Errorf("Verify() expected HostnameMismatch, got %v", outcome.Type)
	}
}

func TestServerVerifier_WithCache(t *testing.T) {
	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"

	badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")

	// Pre-populate cache
	cache := NewBadgeCache(DefaultCacheConfig())
	fqdn, _ := models.NewFqdn(host)
	cache.Insert(fqdn, badge)

	// Empty DNS/TLog (should use cache)
	dnsResolver := NewMockDNSResolver()
	tlogClient := NewMockTransparencyLogClient()

	verifier := NewServerVerifier(
		WithDNSResolver(dnsResolver),
		WithTlogClient(tlogClient),
		WithCache(cache),
	)

	cert := createTestCertIdentity(host, fingerprint)

	outcome := verifier.Verify(context.Background(), fqdn, cert)

	if !outcome.IsSuccess() {
		t.Errorf("Verify() with cache failed: %v", outcome.Type)
	}
}

func TestServerVerifier_Prefetch(t *testing.T) {
	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"

	badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	dnsResolver := NewMockDNSResolver().
		WithRecords(host, []AnsBadgeRecord{dnsRecord})

	tlogClient := NewMockTransparencyLogClient().
		WithBadge(badgeURL, badge)

	cache := NewBadgeCache(DefaultCacheConfig())

	verifier := NewServerVerifier(
		WithDNSResolver(dnsResolver),
		WithTlogClient(tlogClient),
		WithCache(cache),
		WithoutURLValidation(),
	)

	fqdn, _ := models.NewFqdn(host)
	fetchedBadge, err := verifier.Prefetch(context.Background(), fqdn)

	if err != nil {
		t.Fatalf("Prefetch() error = %v", err)
	}
	if fetchedBadge == nil {
		t.Fatal("Prefetch() returned nil badge")
	}
	if fetchedBadge.AgentHost() != host {
		t.Errorf("Prefetch() AgentHost() = %q, want %q", fetchedBadge.AgentHost(), host)
	}

	// Badge should now be in cache
	cached, ok := cache.GetByFqdn(fqdn)
	if !ok {
		t.Error("Badge not in cache after Prefetch")
	}
	if cached.Badge.AgentHost() != host {
		t.Errorf("Cached badge AgentHost() = %q, want %q", cached.Badge.AgentHost(), host)
	}
}

func TestClientVerifier_Success(t *testing.T) {
	host := "test.example.com"
	version := "v1.0.0"
	identityFP := "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496"

	badge := createTestBadge(host, version, "SHA256:server", identityFP)
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

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

	cert := createMTLSCertIdentity(host, version, identityFP)

	outcome := verifier.Verify(context.Background(), cert)

	if !outcome.IsSuccess() {
		t.Errorf("Verify() failed: %v", outcome.Type)
	}
}

func TestClientVerifier_NoCN(t *testing.T) {
	dnsResolver := NewMockDNSResolver()
	tlogClient := NewMockTransparencyLogClient()

	verifier := NewClientVerifier(
		WithDNSResolver(dnsResolver),
		WithTlogClient(tlogClient),
		WithoutURLValidation(),
	)

	// Cert with no CN or DNS SANs
	fp, _ := ParseCertFingerprint("SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
	cert := NewCertIdentity(nil, nil, []string{"ans://v1.0.0.test.example.com"}, fp)

	outcome := verifier.Verify(context.Background(), cert)

	if outcome.Type != OutcomeCertError {
		t.Errorf("Verify() expected CertError, got %v", outcome.Type)
	}
}

func TestClientVerifier_NoAnsName(t *testing.T) {
	dnsResolver := NewMockDNSResolver()
	tlogClient := NewMockTransparencyLogClient()

	verifier := NewClientVerifier(
		WithDNSResolver(dnsResolver),
		WithTlogClient(tlogClient),
		WithoutURLValidation(),
	)

	// Cert with CN but no URI SANs
	fp, _ := ParseCertFingerprint("SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
	cn := "test.example.com"
	cert := NewCertIdentity(&cn, []string{cn}, nil, fp)

	outcome := verifier.Verify(context.Background(), cert)

	if outcome.Type != OutcomeCertError {
		t.Errorf("Verify() expected CertError, got %v", outcome.Type)
	}
}

func TestClientVerifier_AnsNameMismatch(t *testing.T) {
	host := "test.example.com"
	badgeVersion := "v1.0.0"
	certVersion := "v2.0.0"
	identityFP := "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496"

	// Badge has v1.0.0, cert has v2.0.0
	badge := createTestBadge(host, badgeVersion, "SHA256:server", identityFP)
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(2, 0, 0)),
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

	cert := createMTLSCertIdentity(host, certVersion, identityFP)

	outcome := verifier.Verify(context.Background(), cert)

	if outcome.Type != OutcomeAnsNameMismatch {
		t.Errorf("Verify() expected AnsNameMismatch, got %v", outcome.Type)
	}
}

func TestClientVerifier_FingerprintMismatch(t *testing.T) {
	host := "test.example.com"
	version := "v1.0.0"
	badgeFP := "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496"
	certFP := "SHA256:0000000000000000000000000000000000000000000000000000000000000000"

	badge := createTestBadge(host, version, "SHA256:server", badgeFP)
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

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

	cert := createMTLSCertIdentity(host, version, certFP)

	outcome := verifier.Verify(context.Background(), cert)

	if outcome.Type != OutcomeFingerprintMismatch {
		t.Errorf("Verify() expected FingerprintMismatch, got %v", outcome.Type)
	}
}

func TestClientVerifier_HostnameMismatch(t *testing.T) {
	badgeHost := "badge.example.com"
	certHost := "different.example.com"
	version := "v1.0.0"
	identityFP := "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496"

	badge := createTestBadge(badgeHost, version, "SHA256:server", identityFP)
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	dnsResolver := NewMockDNSResolver().
		WithRecords(certHost, []AnsBadgeRecord{dnsRecord})

	tlogClient := NewMockTransparencyLogClient().
		WithBadge(badgeURL, badge)

	verifier := NewClientVerifier(
		WithDNSResolver(dnsResolver),
		WithTlogClient(tlogClient),
		WithoutURLValidation(),
	)

	cert := createMTLSCertIdentity(certHost, version, identityFP)

	outcome := verifier.Verify(context.Background(), cert)

	if outcome.Type != OutcomeHostnameMismatch {
		t.Errorf("Verify() expected HostnameMismatch, got %v", outcome.Type)
	}
}

func TestClientVerifier_ExpiredStatus(t *testing.T) {
	host := "test.example.com"
	version := "v1.0.0"
	identityFP := "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496"

	badge := createTestBadge(host, version, "SHA256:server", identityFP)
	badge.Status = models.BadgeStatusExpired
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

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

	cert := createMTLSCertIdentity(host, version, identityFP)

	outcome := verifier.Verify(context.Background(), cert)

	if outcome.Type != OutcomeInvalidStatus {
		t.Errorf("Verify() expected InvalidStatus, got %v", outcome.Type)
	}
	if outcome.Status != models.BadgeStatusExpired {
		t.Errorf("Verify() Status = %v, want Expired", outcome.Status)
	}
}

func TestAnsVerifier(t *testing.T) {
	host := "test.example.com"
	serverFP := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	identityFP := "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496"

	badge := createTestBadge(host, "v1.0.0", serverFP, identityFP)
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	dnsResolver := NewMockDNSResolver().
		WithRecords(host, []AnsBadgeRecord{dnsRecord})

	tlogClient := NewMockTransparencyLogClient().
		WithBadge(badgeURL, badge)

	verifier := NewAnsVerifier(
		WithDNSResolver(dnsResolver),
		WithTlogClient(tlogClient),
		WithoutURLValidation(),
	)

	t.Run("VerifyServer", func(t *testing.T) {
		cert := createTestCertIdentity(host, serverFP)
		outcome := verifier.VerifyServer(context.Background(), host, cert)

		if !outcome.IsSuccess() {
			t.Errorf("VerifyServer() failed: %v", outcome.Type)
		}
	})

	t.Run("VerifyClient", func(t *testing.T) {
		cert := createMTLSCertIdentity(host, "v1.0.0", identityFP)
		outcome := verifier.VerifyClient(context.Background(), cert)

		if !outcome.IsSuccess() {
			t.Errorf("VerifyClient() failed: %v", outcome.Type)
		}
	})
}

func TestServerVerifier_RefreshOnMismatch(t *testing.T) {
	host := "test.example.com"
	oldFP := "SHA256:0000000000000000000000000000000000000000000000000000000000000000"
	newFP := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

	t.Run("fingerprint mismatch from cache triggers refresh", func(t *testing.T) {
		// Old badge in cache has oldFP
		oldBadge := createTestBadge(host, "v1.0.0", oldFP, "SHA256:aaa")

		cache := NewBadgeCache(DefaultCacheConfig())
		fqdn, _ := models.NewFqdn(host)
		cache.Insert(fqdn, oldBadge)

		// DNS + TLog serve new badge with newFP
		newBadge := createTestBadge(host, "v1.0.0", newFP, "SHA256:aaa")
		dnsRecord := AnsBadgeRecord{
			FormatVersion: "ans-badge1",
			Version:       ptr(models.NewVersion(1, 0, 0)),
			URL:           badgeURL,
		}

		dnsResolver := NewMockDNSResolver().
			WithRecords(host, []AnsBadgeRecord{dnsRecord})
		tlogClient := NewMockTransparencyLogClient().
			WithBadge(badgeURL, newBadge)

		verifier := NewServerVerifier(
			WithDNSResolver(dnsResolver),
			WithTlogClient(tlogClient),
			WithCache(cache),
			WithoutURLValidation(),
		)

		// Present cert with new fingerprint
		cert := createTestCertIdentity(host, newFP)
		outcome := verifier.Verify(context.Background(), fqdn, cert)

		if !outcome.IsSuccess() {
			t.Errorf("Verify() failed after refresh: type=%v", outcome.Type)
		}
	})

	t.Run("hostname mismatch from cache does not trigger refresh", func(t *testing.T) {
		badgeHost := "other.example.com"
		badge := createTestBadge(badgeHost, "v1.0.0", newFP, "SHA256:aaa")

		cache := NewBadgeCache(DefaultCacheConfig())
		fqdn, _ := models.NewFqdn(host)
		cache.Insert(fqdn, badge)

		dnsResolver := NewMockDNSResolver()
		tlogClient := NewMockTransparencyLogClient()

		verifier := NewServerVerifier(
			WithDNSResolver(dnsResolver),
			WithTlogClient(tlogClient),
			WithCache(cache),
			WithoutURLValidation(),
		)

		cert := createTestCertIdentity(host, newFP)
		outcome := verifier.Verify(context.Background(), fqdn, cert)

		// Should return hostname mismatch immediately (not try to refresh)
		if outcome.Type != OutcomeHostnameMismatch {
			t.Errorf("Verify() expected HostnameMismatch, got %v", outcome.Type)
		}
	})
}

func TestServerVerifier_FailurePolicy_DNSError(t *testing.T) {
	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	dnsErr := &DNSError{Type: DNSErrorTimeout, Fqdn: host}

	tests := []struct {
		name         string
		policy       FailurePolicy
		cache        *BadgeCache
		wantSuccess  bool
		wantFailOpen bool
	}{
		{
			name:        "FailClosed rejects on DNS error",
			policy:      FailClosed,
			wantSuccess: false,
		},
		{
			name:   "FailOpenWithCache uses stale cache",
			policy: FailOpenWithCache,
			cache: func() *BadgeCache {
				c := NewBadgeCache(CacheConfig{
					MaxEntries: 100,
					DefaultTTL: 1 * time.Millisecond,
				})
				fqdn, _ := models.NewFqdn(host)
				c.Insert(fqdn, createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa"))
				time.Sleep(5 * time.Millisecond) // Let it expire
				return c
			}(),
			wantSuccess:  true,
			wantFailOpen: true,
		},
		{
			name:        "FailOpenWithCache rejects without cache",
			policy:      FailOpenWithCache,
			wantSuccess: false,
		},
		{
			name:         "FailOpen accepts without verification",
			policy:       FailOpen,
			wantSuccess:  true,
			wantFailOpen: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnsResolver := NewMockDNSResolver().WithError(host, dnsErr)
			tlogClient := NewMockTransparencyLogClient()

			opts := []Option{
				WithDNSResolver(dnsResolver),
				WithTlogClient(tlogClient),
				WithFailurePolicy(tt.policy),
			}
			if tt.cache != nil {
				opts = append(opts, WithCache(tt.cache))
			}

			verifier := NewServerVerifier(opts...)
			cert := createTestCertIdentity(host, fingerprint)
			fqdn, _ := models.NewFqdn(host)

			outcome := verifier.Verify(context.Background(), fqdn, cert)

			if outcome.IsSuccess() != tt.wantSuccess {
				t.Errorf("IsSuccess() = %v, want %v (type=%v)", outcome.IsSuccess(), tt.wantSuccess, outcome.Type)
			}
			if tt.wantFailOpen && !outcome.IsFailOpen() {
				t.Errorf("IsFailOpen() = false, want true")
			}
		})
	}
}

func TestServerVerifier_FailurePolicy_TLogError(t *testing.T) {
	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	tests := []struct {
		name         string
		policy       FailurePolicy
		tlogErr      error
		wantSuccess  bool
		wantFailOpen bool
	}{
		{
			name:   "FailClosed rejects on TLog 5xx",
			policy: FailClosed,
			tlogErr: &TlogError{
				Type:     TlogErrorServiceUnavailable,
				URL:      badgeURL,
				HTTPCode: 500,
			},
			wantSuccess: false,
		},
		{
			name:   "FailOpen accepts on TLog 5xx",
			policy: FailOpen,
			tlogErr: &TlogError{
				Type:     TlogErrorServiceUnavailable,
				URL:      badgeURL,
				HTTPCode: 500,
			},
			wantSuccess:  true,
			wantFailOpen: true,
		},
		{
			name:   "FailOpen accepts on TLog 404",
			policy: FailOpen,
			tlogErr: &TlogError{
				Type:     TlogErrorNotFound,
				URL:      badgeURL,
				HTTPCode: 404,
			},
			wantSuccess:  true,
			wantFailOpen: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnsResolver := NewMockDNSResolver().
				WithRecords(host, []AnsBadgeRecord{dnsRecord})
			tlogClient := NewMockTransparencyLogClient().
				WithError(badgeURL, tt.tlogErr)

			verifier := NewServerVerifier(
				WithDNSResolver(dnsResolver),
				WithTlogClient(tlogClient),
				WithFailurePolicy(tt.policy),
				WithoutURLValidation(),
			)

			cert := createTestCertIdentity(host, fingerprint)
			fqdn, _ := models.NewFqdn(host)

			outcome := verifier.Verify(context.Background(), fqdn, cert)

			if outcome.IsSuccess() != tt.wantSuccess {
				t.Errorf("IsSuccess() = %v, want %v (type=%v)", outcome.IsSuccess(), tt.wantSuccess, outcome.Type)
			}
			if tt.wantFailOpen && !outcome.IsFailOpen() {
				t.Errorf("IsFailOpen() = false, want true")
			}
		})
	}
}

func TestServerVerifier_DeprecatedWarning(t *testing.T) {
	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"

	badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")
	badge.Status = models.BadgeStatusDeprecated
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

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

	cert := createTestCertIdentity(host, fingerprint)
	fqdn, _ := models.NewFqdn(host)

	outcome := verifier.Verify(context.Background(), fqdn, cert)

	if !outcome.IsSuccess() {
		t.Errorf("Verify() failed: %v", outcome.Type)
	}
	if len(outcome.Warnings) == 0 {
		t.Error("Verify() expected warnings for DEPRECATED badge")
	}
	if len(outcome.Warnings) > 0 && outcome.Warnings[0] != "badge status is DEPRECATED" {
		t.Errorf("Warnings[0] = %q, want 'badge status is DEPRECATED'", outcome.Warnings[0])
	}
}

func TestClientVerifier_DeprecatedWarning(t *testing.T) {
	host := "test.example.com"
	version := "v1.0.0"
	identityFP := "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496"

	badge := createTestBadge(host, version, "SHA256:server", identityFP)
	badge.Status = models.BadgeStatusDeprecated
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

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

	cert := createMTLSCertIdentity(host, version, identityFP)
	outcome := verifier.Verify(context.Background(), cert)

	if !outcome.IsSuccess() {
		t.Errorf("Verify() failed: %v", outcome.Type)
	}
	if len(outcome.Warnings) == 0 {
		t.Error("Verify() expected warnings for DEPRECATED badge")
	}
}

func TestClientVerifier_VersionEdgeCases(t *testing.T) {
	host := "test.example.com"
	identityFP := "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496"

	t.Run("6.1: two ACTIVE versions, client presents v1.0.0, correct badge selected", func(t *testing.T) {
		// v1.0.0 ACTIVE, v1.0.1 ACTIVE — client presents v1.0.0
		badge100 := createTestBadge(host, "v1.0.0", "SHA256:server1", identityFP)
		url100 := "https://tlog.example.com/v1/agents/v100-id"

		badge101 := createTestBadge(host, "v1.0.1", "SHA256:server2", "SHA256:identity2")
		url101 := "https://tlog.example.com/v1/agents/v101-id"

		dnsResolver := NewMockDNSResolver().
			WithRecords(host, []AnsBadgeRecord{
				{FormatVersion: "ans-badge1", Version: ptr(models.NewVersion(1, 0, 0)), URL: url100},
				{FormatVersion: "ans-badge1", Version: ptr(models.NewVersion(1, 0, 1)), URL: url101},
			})

		tlogClient := NewMockTransparencyLogClient().
			WithBadge(url100, badge100).
			WithBadge(url101, badge101)

		verifier := NewClientVerifier(
			WithDNSResolver(dnsResolver),
			WithTlogClient(tlogClient),
			WithoutURLValidation(),
		)

		cert := createMTLSCertIdentity(host, "v1.0.0", identityFP)
		outcome := verifier.Verify(context.Background(), cert)

		if !outcome.IsSuccess() {
			t.Errorf("Verify() failed: type=%v, error=%v", outcome.Type, outcome.Error)
		}
		// Verify the correct badge was selected (v1.0.0, not v1.0.1)
		if outcome.Badge == nil {
			t.Fatal("Verify() Badge is nil")
		}
		if outcome.Badge.AgentVersion() != "v1.0.0" {
			t.Errorf("Badge version = %q, want v1.0.0", outcome.Badge.AgentVersion())
		}
	})

	t.Run("6.2: old version DEPRECATED, new ACTIVE, client presents old version", func(t *testing.T) {
		// v1.0.0 DEPRECATED, v1.0.1 ACTIVE — client presents v1.0.0
		deprecatedBadge := createTestBadge(host, "v1.0.0", "SHA256:server", identityFP)
		deprecatedBadge.Status = models.BadgeStatusDeprecated
		deprecatedURL := "https://tlog.example.com/v1/agents/deprecated-id"

		activeBadge := createTestBadge(host, "v1.0.1", "SHA256:server2", "SHA256:identity2")
		activeURL := "https://tlog.example.com/v1/agents/active-id"

		dnsResolver := NewMockDNSResolver().
			WithRecords(host, []AnsBadgeRecord{
				{FormatVersion: "ans-badge1", Version: ptr(models.NewVersion(1, 0, 0)), URL: deprecatedURL},
				{FormatVersion: "ans-badge1", Version: ptr(models.NewVersion(1, 0, 1)), URL: activeURL},
			})

		tlogClient := NewMockTransparencyLogClient().
			WithBadge(deprecatedURL, deprecatedBadge).
			WithBadge(activeURL, activeBadge)

		verifier := NewClientVerifier(
			WithDNSResolver(dnsResolver),
			WithTlogClient(tlogClient),
			WithoutURLValidation(),
		)

		cert := createMTLSCertIdentity(host, "v1.0.0", identityFP)
		outcome := verifier.Verify(context.Background(), cert)

		if !outcome.IsSuccess() {
			t.Errorf("Verify() failed: type=%v, error=%v", outcome.Type, outcome.Error)
		}
		if len(outcome.Warnings) == 0 {
			t.Error("Expected DEPRECATED warning")
		}
	})

	t.Run("6.4: server verification, no version in cert, ACTIVE badge preferred", func(t *testing.T) {
		serverFP := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"

		activeBadge := createTestBadge(host, "v1.0.1", serverFP, "SHA256:identity2")
		activeURL := "https://tlog.example.com/v1/agents/active-id"

		deprecatedBadge := createTestBadge(host, "v1.0.0", "SHA256:old-fp", "SHA256:old-id")
		deprecatedBadge.Status = models.BadgeStatusDeprecated
		deprecatedURL := "https://tlog.example.com/v1/agents/deprecated-id"

		dnsResolver := NewMockDNSResolver().
			WithRecords(host, []AnsBadgeRecord{
				{FormatVersion: "ans-badge1", Version: ptr(models.NewVersion(1, 0, 0)), URL: deprecatedURL},
				{FormatVersion: "ans-badge1", Version: ptr(models.NewVersion(1, 0, 1)), URL: activeURL},
			})

		tlogClient := NewMockTransparencyLogClient().
			WithBadge(activeURL, activeBadge).
			WithBadge(deprecatedURL, deprecatedBadge)

		verifier := NewServerVerifier(
			WithDNSResolver(dnsResolver),
			WithTlogClient(tlogClient),
			WithoutURLValidation(),
		)

		// Server cert has no version info, just CN and fingerprint
		cert := createTestCertIdentity(host, serverFP)
		fqdn, _ := models.NewFqdn(host)

		outcome := verifier.Verify(context.Background(), fqdn, cert)

		// Should pick the newest version (v1.0.1 ACTIVE) via FindPreferredBadge
		if !outcome.IsSuccess() {
			t.Errorf("Verify() failed: type=%v", outcome.Type)
		}
	})

	t.Run("6.5: multiple records, one TLog URL fails, other matches", func(t *testing.T) {
		// Two DNS records, v1.0.0 TLog fails, v1.0.1 returns matching badge
		activeBadge := createTestBadge(host, "v1.0.1", "SHA256:server", identityFP)
		activeURL := "https://tlog.example.com/v1/agents/active-id"
		failURL := "https://tlog.example.com/v1/agents/fail-id"

		// Client presents v1.0.1
		dnsResolver := NewMockDNSResolver().
			WithRecords(host, []AnsBadgeRecord{
				{FormatVersion: "ans-badge1", Version: ptr(models.NewVersion(1, 0, 0)), URL: failURL},
				{FormatVersion: "ans-badge1", Version: ptr(models.NewVersion(1, 0, 1)), URL: activeURL},
			})

		tlogClient := NewMockTransparencyLogClient().
			WithError(failURL, &TlogError{Type: TlogErrorServiceUnavailable, URL: failURL, HTTPCode: 500}).
			WithBadge(activeURL, activeBadge)

		verifier := NewClientVerifier(
			WithDNSResolver(dnsResolver),
			WithTlogClient(tlogClient),
			WithoutURLValidation(),
		)

		cert := createMTLSCertIdentity(host, "v1.0.1", identityFP)
		outcome := verifier.Verify(context.Background(), cert)

		// Client looks up v1.0.1 specifically, which succeeds
		if !outcome.IsSuccess() {
			t.Errorf("Verify() failed: type=%v, error=%v", outcome.Type, outcome.Error)
		}
	})
}

func TestVerificationOutcome(t *testing.T) {
	badge := createTestBadge("test.example.com", "v1.0.0", "SHA256:server", "SHA256:identity")

	t.Run("IsSuccess", func(t *testing.T) {
		fp, _ := ParseCertFingerprint("SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
		outcome := NewVerifiedOutcome(badge, fp)
		if !outcome.IsSuccess() {
			t.Error("IsSuccess() = false, want true")
		}
		if outcome.IsNotAnsAgent() {
			t.Error("IsNotAnsAgent() = true, want false")
		}
	})

	t.Run("IsNotAnsAgent", func(t *testing.T) {
		outcome := NewNotAnsAgentOutcome("example.com")
		if outcome.IsSuccess() {
			t.Error("IsSuccess() = true, want false")
		}
		if !outcome.IsNotAnsAgent() {
			t.Error("IsNotAnsAgent() = false, want true")
		}
	})

	t.Run("ToError", func(t *testing.T) {
		// Verified returns nil
		fp, _ := ParseCertFingerprint("SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
		outcome := NewVerifiedOutcome(badge, fp)
		if outcome.ToError() != nil {
			t.Error("ToError() != nil for Verified outcome")
		}

		// NotAnsAgent returns error
		outcome = NewNotAnsAgentOutcome("example.com")
		if outcome.ToError() == nil {
			t.Error("ToError() == nil for NotAnsAgent outcome")
		}

		// InvalidStatus returns error
		outcome = NewInvalidStatusOutcome(badge, models.BadgeStatusRevoked)
		if outcome.ToError() == nil {
			t.Error("ToError() == nil for InvalidStatus outcome")
		}

		// FingerprintMismatch returns error
		outcome = NewFingerprintMismatchOutcome(badge, "expected", "actual")
		if outcome.ToError() == nil {
			t.Error("ToError() == nil for FingerprintMismatch outcome")
		}
	})
}

func TestAnsVerifier_Prefetch(t *testing.T) {
	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

	badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")
	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	tests := []struct {
		name        string
		fqdn        string
		dnsResolver *MockDNSResolver
		tlogClient  *MockTransparencyLogClient
		cache       *BadgeCache
		wantErr     bool
	}{
		{
			name: "success",
			fqdn: host,
			dnsResolver: NewMockDNSResolver().
				WithRecords(host, []AnsBadgeRecord{dnsRecord}),
			tlogClient: NewMockTransparencyLogClient().
				WithBadge(badgeURL, badge),
			cache: NewBadgeCache(DefaultCacheConfig()),
		},
		{
			name:        "empty FQDN",
			fqdn:        "",
			dnsResolver: NewMockDNSResolver(),
			tlogClient:  NewMockTransparencyLogClient(),
			wantErr:     true,
		},
		{
			name:        "not an agent",
			fqdn:        "unknown.example.com",
			dnsResolver: NewMockDNSResolver(),
			tlogClient:  NewMockTransparencyLogClient(),
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []Option{
				WithDNSResolver(tt.dnsResolver),
				WithTlogClient(tt.tlogClient),
				WithoutURLValidation(),
			}
			if tt.cache != nil {
				opts = append(opts, WithCache(tt.cache))
			}

			verifier := NewAnsVerifier(opts...)
			result, err := verifier.Prefetch(context.Background(), tt.fqdn)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Prefetch() expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Prefetch() error = %v", err)
			}
			if result == nil {
				t.Fatal("Prefetch() returned nil")
			}
		})
	}
}

func TestAnsVerifier_VerifyServer_EmptyFqdn(t *testing.T) {
	tests := []struct {
		name     string
		fqdn     string
		wantType OutcomeType
	}{
		{
			name:     "empty FQDN",
			fqdn:     "",
			wantType: OutcomeCertError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := NewAnsVerifier(
				WithDNSResolver(NewMockDNSResolver()),
				WithTlogClient(NewMockTransparencyLogClient()),
			)

			cert := createTestCertIdentity("test.example.com", "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
			outcome := verifier.VerifyServer(context.Background(), tt.fqdn, cert)

			if outcome.Type != tt.wantType {
				t.Errorf("VerifyServer() expected %v, got %v", tt.wantType, outcome.Type)
			}
		})
	}
}

func TestServerVerifier_Prefetch_CacheHit(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() (*ServerVerifier, models.Fqdn, *models.Badge)
		wantErr bool
	}{
		{
			name: "cache hit returns cached badge",
			setup: func() (*ServerVerifier, models.Fqdn, *models.Badge) {
				host := "test.example.com"
				fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
				badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")
				cache := NewBadgeCache(DefaultCacheConfig())
				fqdn, _ := models.NewFqdn(host)
				cache.Insert(fqdn, badge)

				verifier := NewServerVerifier(
					WithDNSResolver(NewMockDNSResolver()),
					WithTlogClient(NewMockTransparencyLogClient()),
					WithCache(cache),
				)
				return verifier, fqdn, badge
			},
		},
		{
			name: "not found returns error",
			setup: func() (*ServerVerifier, models.Fqdn, *models.Badge) {
				verifier := NewServerVerifier(
					WithDNSResolver(NewMockDNSResolver()),
					WithTlogClient(NewMockTransparencyLogClient()),
					WithoutURLValidation(),
				)
				fqdn, _ := models.NewFqdn("unknown.example.com")
				return verifier, fqdn, nil
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, fqdn, wantBadge := tt.setup()
			result, err := verifier.Prefetch(context.Background(), fqdn)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Prefetch() expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Prefetch() error = %v", err)
			}
			if result != wantBadge {
				t.Error("Prefetch() returned different badge than expected")
			}
		})
	}
}

func TestServerVerifier_URLValidation_Additional(t *testing.T) {
	tests := []struct {
		name     string
		badgeURL string
		domains  []string
		wantType OutcomeType
	}{
		{
			name:     "untrusted domain rejected",
			badgeURL: "https://evil.example.com/badge/123",
			domains:  []string{"trusted.example.com"},
			wantType: OutcomeURLValidationError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := "test.example.com"
			fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"

			dnsRecord := AnsBadgeRecord{
				FormatVersion: "ans-badge1",
				Version:       ptr(models.NewVersion(1, 0, 0)),
				URL:           tt.badgeURL,
			}

			dnsResolver := NewMockDNSResolver().
				WithRecords(host, []AnsBadgeRecord{dnsRecord})
			tlogClient := NewMockTransparencyLogClient()

			verifier := NewServerVerifier(
				WithDNSResolver(dnsResolver),
				WithTlogClient(tlogClient),
				WithTrustedRADomains(tt.domains),
			)

			cert := createTestCertIdentity(host, fingerprint)
			fqdn, _ := models.NewFqdn(host)

			outcome := verifier.Verify(context.Background(), fqdn, cert)
			if outcome.Type != tt.wantType {
				t.Errorf("Verify() expected %v, got %v", tt.wantType, outcome.Type)
			}
		})
	}
}

func TestServerVerifier_DANERejection(t *testing.T) {
	tests := []struct {
		name     string
		certHash string
		wantType OutcomeType
	}{
		{
			name:     "fingerprint mismatch rejects",
			certHash: "0000000000000000000000000000000000000000000000000000000000000000",
			wantType: OutcomeDANERejection,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := "test.example.com"
			fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
			badgeURL := "https://tlog.example.com/v1/agents/test-id"

			badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")
			dnsRecord := AnsBadgeRecord{
				FormatVersion: "ans-badge1",
				Version:       ptr(models.NewVersion(1, 0, 0)),
				URL:           badgeURL,
			}

			dnsResolver := NewMockDNSResolver().
				WithRecords(host, []AnsBadgeRecord{dnsRecord})
			tlogClient := NewMockTransparencyLogClient().
				WithBadge(badgeURL, badge)

			daneResolver := NewMockDANEResolver().
				WithTLSA(host, 443, TLSALookupResult{
					Found:       true,
					DNSSECValid: true,
					Records: []TLSARecord{
						{Usage: 3, CertHash: tt.certHash},
					},
				})

			verifier := NewServerVerifier(
				WithDNSResolver(dnsResolver),
				WithTlogClient(tlogClient),
				WithoutURLValidation(),
				WithDANEResolver(daneResolver),
			)

			cert := createTestCertIdentity(host, fingerprint)
			fqdn, _ := models.NewFqdn(host)

			outcome := verifier.Verify(context.Background(), fqdn, cert)
			if outcome.Type != tt.wantType {
				t.Errorf("Verify() expected %v, got %v", tt.wantType, outcome.Type)
			}
		})
	}
}

func TestServerVerifier_DANEVerified(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "DANE verified enriches outcome",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := "test.example.com"
			fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
			badgeURL := "https://tlog.example.com/v1/agents/test-id"

			badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")
			dnsRecord := AnsBadgeRecord{
				FormatVersion: "ans-badge1",
				Version:       ptr(models.NewVersion(1, 0, 0)),
				URL:           badgeURL,
			}

			dnsResolver := NewMockDNSResolver().
				WithRecords(host, []AnsBadgeRecord{dnsRecord})
			tlogClient := NewMockTransparencyLogClient().
				WithBadge(badgeURL, badge)

			fp, _ := ParseCertFingerprint(fingerprint)
			daneResolver := NewMockDANEResolver().
				WithTLSA(host, 443, TLSALookupResult{
					Found:       true,
					DNSSECValid: true,
					Records: []TLSARecord{
						{Usage: 3, CertHash: fp.ToHex()},
					},
				})

			verifier := NewServerVerifier(
				WithDNSResolver(dnsResolver),
				WithTlogClient(tlogClient),
				WithoutURLValidation(),
				WithDANEResolver(daneResolver),
			)

			cert := createTestCertIdentity(host, fingerprint)
			fqdn, _ := models.NewFqdn(host)

			outcome := verifier.Verify(context.Background(), fqdn, cert)
			if !outcome.IsSuccess() {
				t.Errorf("Verify() failed: %v", outcome.Type)
			}
			if outcome.DANEOutcome == nil {
				t.Error("DANEOutcome is nil, expected DANE info")
			}
		})
	}
}

func TestClientVerifier_FailurePolicy_DNSError(t *testing.T) {
	host := "test.example.com"
	version := "v1.0.0"
	identityFP := "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496"
	dnsErr := &DNSError{Type: DNSErrorTimeout, Fqdn: host}

	tests := []struct {
		name         string
		policy       FailurePolicy
		cache        *BadgeCache
		wantSuccess  bool
		wantFailOpen bool
	}{
		{
			name:        "FailClosed rejects",
			policy:      FailClosed,
			wantSuccess: false,
		},
		{
			name:         "FailOpen accepts",
			policy:       FailOpen,
			wantSuccess:  true,
			wantFailOpen: true,
		},
		{
			name:   "FailOpenWithCache uses stale versioned cache",
			policy: FailOpenWithCache,
			cache: func() *BadgeCache {
				c := NewBadgeCache(CacheConfig{
					MaxEntries: 100,
					DefaultTTL: 1 * time.Millisecond,
				})
				fqdn, _ := models.NewFqdn(host)
				badge := createTestBadge(host, version, "SHA256:server", identityFP)
				v := models.NewVersion(1, 0, 0)
				c.InsertForVersion(fqdn, v, badge)
				time.Sleep(5 * time.Millisecond)
				return c
			}(),
			wantSuccess:  true,
			wantFailOpen: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnsResolver := NewMockDNSResolver().WithError(host, dnsErr)
			tlogClient := NewMockTransparencyLogClient()

			opts := []Option{
				WithDNSResolver(dnsResolver),
				WithTlogClient(tlogClient),
				WithFailurePolicy(tt.policy),
				WithoutURLValidation(),
			}
			if tt.cache != nil {
				opts = append(opts, WithCache(tt.cache))
			}

			verifier := NewClientVerifier(opts...)
			cert := createMTLSCertIdentity(host, version, identityFP)
			outcome := verifier.Verify(context.Background(), cert)

			if outcome.IsSuccess() != tt.wantSuccess {
				t.Errorf("IsSuccess() = %v, want %v (type=%v)", outcome.IsSuccess(), tt.wantSuccess, outcome.Type)
			}
			if tt.wantFailOpen && !outcome.IsFailOpen() {
				t.Errorf("IsFailOpen() = false, want true")
			}
		})
	}
}

func TestClientVerifier_TLogError(t *testing.T) {
	tests := []struct {
		name     string
		wantType OutcomeType
	}{
		{
			name:     "TLog service unavailable",
			wantType: OutcomeTlogError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := "test.example.com"
			version := "v1.0.0"
			identityFP := "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496"
			badgeURL := "https://tlog.example.com/v1/agents/test-id"

			dnsRecord := AnsBadgeRecord{
				FormatVersion: "ans-badge1",
				Version:       ptr(models.NewVersion(1, 0, 0)),
				URL:           badgeURL,
			}

			tlogErr := &TlogError{
				Type:     TlogErrorServiceUnavailable,
				URL:      badgeURL,
				HTTPCode: 500,
			}

			dnsResolver := NewMockDNSResolver().
				WithRecords(host, []AnsBadgeRecord{dnsRecord})
			tlogClient := NewMockTransparencyLogClient().
				WithError(badgeURL, tlogErr)

			verifier := NewClientVerifier(
				WithDNSResolver(dnsResolver),
				WithTlogClient(tlogClient),
				WithFailurePolicy(FailClosed),
				WithoutURLValidation(),
			)

			cert := createMTLSCertIdentity(host, version, identityFP)
			outcome := verifier.Verify(context.Background(), cert)

			if outcome.IsSuccess() {
				t.Error("Verify() expected failure for TLog error")
			}
			if outcome.Type != tt.wantType {
				t.Errorf("Verify() Type = %v, want %v", outcome.Type, tt.wantType)
			}
		})
	}
}

func TestClientVerifier_WithCache(t *testing.T) {
	tests := []struct {
		name        string
		wantSuccess bool
	}{
		{
			name:        "cache hit succeeds",
			wantSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := "test.example.com"
			version := "v1.0.0"
			identityFP := "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496"

			badge := createTestBadge(host, version, "SHA256:server", identityFP)
			cache := NewBadgeCache(DefaultCacheConfig())
			fqdn, _ := models.NewFqdn(host)
			v := models.NewVersion(1, 0, 0)
			cache.InsertForVersion(fqdn, v, badge)

			verifier := NewClientVerifier(
				WithDNSResolver(NewMockDNSResolver()),
				WithTlogClient(NewMockTransparencyLogClient()),
				WithCache(cache),
				WithoutURLValidation(),
			)

			cert := createMTLSCertIdentity(host, version, identityFP)
			outcome := verifier.Verify(context.Background(), cert)

			if outcome.IsSuccess() != tt.wantSuccess {
				t.Errorf("Verify() IsSuccess() = %v, want %v (type=%v)", outcome.IsSuccess(), tt.wantSuccess, outcome.Type)
			}
		})
	}
}

func TestClientVerifier_URLValidation(t *testing.T) {
	tests := []struct {
		name     string
		badgeURL string
		domains  []string
		wantType OutcomeType
	}{
		{
			name:     "untrusted domain rejected",
			badgeURL: "https://evil.example.com/badge/123",
			domains:  []string{"trusted.example.com"},
			wantType: OutcomeURLValidationError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := "test.example.com"
			version := "v1.0.0"
			identityFP := "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496"

			dnsRecord := AnsBadgeRecord{
				FormatVersion: "ans-badge1",
				Version:       ptr(models.NewVersion(1, 0, 0)),
				URL:           tt.badgeURL,
			}

			dnsResolver := NewMockDNSResolver().
				WithRecords(host, []AnsBadgeRecord{dnsRecord})
			tlogClient := NewMockTransparencyLogClient()

			verifier := NewClientVerifier(
				WithDNSResolver(dnsResolver),
				WithTlogClient(tlogClient),
				WithTrustedRADomains(tt.domains),
			)

			cert := createMTLSCertIdentity(host, version, identityFP)
			outcome := verifier.Verify(context.Background(), cert)

			if outcome.Type != tt.wantType {
				t.Errorf("Verify() expected %v, got %v", tt.wantType, outcome.Type)
			}
		})
	}
}

func TestClientVerifier_DANERejection(t *testing.T) {
	tests := []struct {
		name     string
		wantType OutcomeType
	}{
		{
			name:     "DNSSEC failure rejects",
			wantType: OutcomeDANERejection,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host := "test.example.com"
			version := "v1.0.0"
			identityFP := "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496"
			badgeURL := "https://tlog.example.com/v1/agents/test-id"

			badge := createTestBadge(host, version, "SHA256:server", identityFP)
			dnsRecord := AnsBadgeRecord{
				FormatVersion: "ans-badge1",
				Version:       ptr(models.NewVersion(1, 0, 0)),
				URL:           badgeURL,
			}

			dnsResolver := NewMockDNSResolver().
				WithRecords(host, []AnsBadgeRecord{dnsRecord})
			tlogClient := NewMockTransparencyLogClient().
				WithBadge(badgeURL, badge)

			daneResolver := NewMockDANEResolver().
				WithError(host, 443, &DANEError{
					Type:   DANEErrorDNSSECFailed,
					Fqdn:   host,
					Reason: "DNSSEC failure",
				})

			verifier := NewClientVerifier(
				WithDNSResolver(dnsResolver),
				WithTlogClient(tlogClient),
				WithoutURLValidation(),
				WithDANEResolver(daneResolver),
			)

			cert := createMTLSCertIdentity(host, version, identityFP)
			outcome := verifier.Verify(context.Background(), cert)

			if outcome.Type != tt.wantType {
				t.Errorf("Verify() expected %v, got %v", tt.wantType, outcome.Type)
			}
		})
	}
}

func TestApplyFailurePolicy_Default(t *testing.T) {
	tests := []struct {
		name   string
		policy FailurePolicy
	}{
		{
			name:   "unknown policy returns error outcome",
			policy: FailurePolicy(99),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := defaultConfig()
			config.failurePolicy = tt.policy

			fqdn, _ := models.NewFqdn("test.example.com")
			errorOutcome := NewDNSErrorOutcome(errors.New("test error"))

			result := applyFailurePolicy(config, fqdn, nil, errorOutcome)
			if result != errorOutcome {
				t.Error("applyFailurePolicy() with unknown policy should return errorOutcome")
			}
		})
	}
}

func TestApplyFailOpenWithCache_NoCache(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "nil cache returns error outcome",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := defaultConfig()
			config.cache = nil

			fqdn, _ := models.NewFqdn("test.example.com")
			errorOutcome := NewDNSErrorOutcome(errors.New("test error"))

			result := applyFailOpenWithCache(config, fqdn, nil, errorOutcome)
			if result != errorOutcome {
				t.Error("applyFailOpenWithCache() with nil cache should return errorOutcome")
			}
		})
	}
}

func TestVerifyDANE_NoResolver(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "nil resolver returns nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := defaultConfig()
			config.daneResolver = nil

			fqdn, _ := models.NewFqdn("test.example.com")
			cert := createTestCertIdentity("test.example.com", "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
			fp, _ := ParseCertFingerprint("SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
			outcome := NewVerifiedOutcome(nil, fp)

			result := verifyDANE(context.Background(), config, fqdn, cert, outcome)
			if result != nil {
				t.Errorf("verifyDANE() with no resolver should return nil, got %v", result)
			}
		})
	}
}

func TestValidateBadgeURL(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		validator   *URLValidator
		wantOutcome bool
		wantType    OutcomeType
	}{
		{
			name:        "nil validator returns nil",
			url:         "https://evil.example.com",
			validator:   nil,
			wantOutcome: false,
		},
		{
			name:        "valid URL returns nil",
			url:         "https://transparency.ans.godaddy.com/badge/123",
			wantOutcome: false,
		},
		{
			name:        "untrusted domain returns error outcome",
			url:         "https://untrusted.example.com/badge/123",
			validator:   NewURLValidator([]string{"trusted.example.com"}),
			wantOutcome: true,
			wantType:    OutcomeURLValidationError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := defaultConfig()
			if tt.validator != nil {
				config.urlValidator = tt.validator
			} else if tt.name == "nil validator returns nil" {
				config.urlValidator = nil
			}

			result := validateBadgeURL(config, tt.url)
			if tt.wantOutcome {
				if result == nil {
					t.Fatal("validateBadgeURL() expected non-nil outcome")
				}
				if result.Type != tt.wantType {
					t.Errorf("Type = %v, want %v", result.Type, tt.wantType)
				}
			} else if result != nil {
				t.Errorf("validateBadgeURL() expected nil, got %v", result)
			}
		})
	}
}

func TestConfigLogger(t *testing.T) {
	tests := []struct {
		name      string
		logger    *slog.Logger
		wantIsNil bool
	}{
		{
			name:   "custom logger returned",
			logger: slog.Default(),
		},
		{
			name:   "nil logger returns slog.Default",
			logger: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			cfg.logger = tt.logger
			result := configLogger(cfg)
			if result == nil {
				t.Error("configLogger() returned nil")
			}
		})
	}
}

func TestServerVerifier_VerifyWithScitt_NilHeaders(t *testing.T) {
	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

	badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")
	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	verifier := NewServerVerifier(
		WithDNSResolver(NewMockDNSResolver().WithRecords(host, []AnsBadgeRecord{dnsRecord})),
		WithTlogClient(NewMockTransparencyLogClient().WithBadge(badgeURL, badge)),
		WithoutURLValidation(),
	)

	cert := createTestCertIdentity(host, fingerprint)
	fqdn, _ := models.NewFqdn(host)

	tests := []struct {
		name    string
		headers *scitt.Headers
	}{
		{name: "nil headers", headers: nil},
		{name: "empty headers", headers: &scitt.Headers{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.VerifyWithScitt(context.Background(), fqdn, cert, tt.headers)
			if !result.IsSuccess() {
				t.Errorf("expected success (badge fallback), got %v", result.Type)
			}
			if result.Tier != TierBadgeOnly {
				t.Errorf("Tier = %v, want TierBadgeOnly", result.Tier)
			}
		})
	}
}

func TestServerVerifier_VerifyWithScitt_PartialHeaders(t *testing.T) {
	verifier := NewServerVerifier(WithoutURLValidation())
	fqdn, _ := models.NewFqdn("test.example.com")
	cert := createTestCertIdentity("test.example.com", "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")

	tests := []struct {
		name    string
		headers *scitt.Headers
	}{
		{name: "only receipt", headers: &scitt.Headers{Receipt: []byte{1, 2, 3}}},
		{name: "only token", headers: &scitt.Headers{StatusToken: []byte{1, 2, 3}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.VerifyWithScitt(context.Background(), fqdn, cert, tt.headers)
			if result.Type != OutcomeScittError {
				t.Errorf("Type = %v, want OutcomeScittError", result.Type)
			}
		})
	}
}

func TestServerVerifier_VerifyWithScitt_NoKeyLookup(t *testing.T) {
	// No WithScittKeyLookup — should return ScittError (not silent badge fallback)
	verifier := NewServerVerifier(
		WithDNSResolver(NewMockDNSResolver()),
		WithTlogClient(NewMockTransparencyLogClient()),
		WithoutURLValidation(),
	)

	cert := createTestCertIdentity("test.example.com", "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
	fqdn, _ := models.NewFqdn("test.example.com")

	headers := &scitt.Headers{
		Receipt:     []byte{1, 2, 3},
		StatusToken: []byte{4, 5, 6},
	}

	result := verifier.VerifyWithScitt(context.Background(), fqdn, cert, headers)
	if result.Type != OutcomeScittError {
		t.Errorf("Type = %v, want OutcomeScittError", result.Type)
	}
	if result.Error == nil {
		t.Error("expected non-nil error for missing key lookup")
	}
}

func TestClientVerifier_VerifyWithScitt_NilHeaders(t *testing.T) {
	host := "test.example.com"
	version := "v1.0.0"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

	badge := createTestBadge(host, version, "SHA256:aaa", fingerprint)
	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	verifier := NewClientVerifier(
		WithDNSResolver(NewMockDNSResolver().WithRecords(host, []AnsBadgeRecord{dnsRecord})),
		WithTlogClient(NewMockTransparencyLogClient().WithBadge(badgeURL, badge)),
		WithoutURLValidation(),
	)

	cert := createMTLSCertIdentity(host, version, fingerprint)
	result := verifier.VerifyWithScitt(context.Background(), cert, nil)
	if !result.IsSuccess() {
		t.Errorf("expected success (badge fallback), got %v: %v", result.Type, result.Error)
	}
}

func TestClientVerifier_VerifyWithScitt_PartialHeaders(t *testing.T) {
	verifier := NewClientVerifier(WithoutURLValidation())

	host := "test.example.com"
	version := "v1.0.0"
	cert := createMTLSCertIdentity(host, version, "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")

	tests := []struct {
		name    string
		headers *scitt.Headers
	}{
		{name: "only receipt", headers: &scitt.Headers{Receipt: []byte{1, 2, 3}}},
		{name: "only token", headers: &scitt.Headers{StatusToken: []byte{1, 2, 3}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.VerifyWithScitt(context.Background(), cert, tt.headers)
			if result.Type != OutcomeScittError {
				t.Errorf("Type = %v, want OutcomeScittError", result.Type)
			}
		})
	}
}

func TestClientVerifier_VerifyWithScitt_NoKeyLookup(t *testing.T) {
	verifier := NewClientVerifier(
		WithDNSResolver(NewMockDNSResolver()),
		WithTlogClient(NewMockTransparencyLogClient()),
		WithoutURLValidation(),
	)

	host := "test.example.com"
	version := "v1.0.0"
	cert := createMTLSCertIdentity(host, version, "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")

	headers := &scitt.Headers{
		Receipt:     []byte{1, 2, 3},
		StatusToken: []byte{4, 5, 6},
	}

	result := verifier.VerifyWithScitt(context.Background(), cert, headers)
	if result.Type != OutcomeScittError {
		t.Errorf("Type = %v, want OutcomeScittError", result.Type)
	}
	if result.Error == nil || !strings.Contains(result.Error.Error(), "no key lookup configured") {
		t.Errorf("expected error about missing key lookup, got: %v", result.Error)
	}
}

func TestClientVerifier_VerifyWithScitt_NoCN(t *testing.T) {
	verifier := NewClientVerifier(
		WithDNSResolver(NewMockDNSResolver()),
		WithTlogClient(NewMockTransparencyLogClient()),
		WithoutURLValidation(),
	)

	// Cert with no CN or DNS SANs — FQDN() returns nil
	fp, _ := ParseCertFingerprint("SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904")
	cert := NewCertIdentity(nil, nil, []string{"ans://v1.0.0.test.example.com"}, fp)

	headers := &scitt.Headers{
		Receipt:     []byte{1, 2, 3},
		StatusToken: []byte{4, 5, 6},
	}

	result := verifier.VerifyWithScitt(context.Background(), cert, headers)
	if result.Type != OutcomeCertError {
		t.Errorf("Type = %v, want OutcomeCertError", result.Type)
	}
}

func TestClientVerifier_VerifyWithScitt_EmptyHeaders(t *testing.T) {
	host := "test.example.com"
	version := "v1.0.0"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

	badge := createTestBadge(host, version, "SHA256:aaa", fingerprint)
	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	verifier := NewClientVerifier(
		WithDNSResolver(NewMockDNSResolver().WithRecords(host, []AnsBadgeRecord{dnsRecord})),
		WithTlogClient(NewMockTransparencyLogClient().WithBadge(badgeURL, badge)),
		WithoutURLValidation(),
	)

	cert := createMTLSCertIdentity(host, version, fingerprint)
	result := verifier.VerifyWithScitt(context.Background(), cert, &scitt.Headers{})
	if !result.IsSuccess() {
		t.Errorf("expected success (badge fallback), got %v: %v", result.Type, result.Error)
	}
}

func TestVerifyWithScitt_PolicyEnforcement(t *testing.T) {
	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	badgeURL := "https://tlog.example.com/v1/agents/test-id"
	badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")

	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	// emptyKeyStore is a valid KeyLookup with no keys — receipt parsing will fail
	// before key lookup is even attempted when given garbage COSE bytes.
	emptyKeyStore, err := scitt.NewKeyStore(nil)
	if err != nil {
		t.Fatalf("NewKeyStore(nil) error: %v", err)
	}

	tests := []struct {
		name         string
		headers      *scitt.Headers
		keyLookup    scitt.KeyLookup
		daneResolver DANEResolver
		wantType     OutcomeType
		wantTier     VerificationTier
	}{
		{
			name: "10.1: SCITT configured, both headers present, receipt parse fails",
			headers: &scitt.Headers{
				Receipt:     []byte{0xDE, 0xAD, 0xBE, 0xEF},
				StatusToken: []byte{0xCA, 0xFE, 0xBA, 0xBE},
			},
			keyLookup: emptyKeyStore,
			wantType:  OutcomeScittError,
		},
		{
			name: "10.2: SCITT configured, invalid receipt bytes, no fallback to badge",
			headers: &scitt.Headers{
				Receipt:     []byte{0x01, 0x02, 0x03},
				StatusToken: []byte{0x04, 0x05, 0x06},
			},
			keyLookup: emptyKeyStore,
			wantType:  OutcomeScittError,
		},
		{
			name: "10.3: SCITT configured, malformed COSE receipt, returns SCITT error",
			headers: &scitt.Headers{
				Receipt:     []byte{0xFF, 0xFF, 0xFF, 0xFF},
				StatusToken: []byte{0xAA, 0xBB, 0xCC, 0xDD},
			},
			keyLookup: emptyKeyStore,
			wantType:  OutcomeScittError,
		},
		{
			name:      "10.4: SCITT configured, headers missing, falls through to badge",
			headers:   nil,
			keyLookup: emptyKeyStore,
			wantType:  OutcomeVerified,
			wantTier:  TierBadgeOnly,
		},
		{
			name: "10.5: SCITT not configured (no key lookup), headers present",
			headers: &scitt.Headers{
				Receipt:     []byte{0x01, 0x02, 0x03},
				StatusToken: []byte{0x04, 0x05, 0x06},
			},
			keyLookup: nil,
			wantType:  OutcomeScittError,
		},
		{
			name:      "10.6: SCITT configured + DANE configured, headers absent, badge+DANE path",
			headers:   nil,
			keyLookup: emptyKeyStore,
			daneResolver: func() DANEResolver {
				fp, _ := ParseCertFingerprint(fingerprint)
				return NewMockDANEResolver().
					WithTLSA(host, 443, TLSALookupResult{
						Found:       true,
						DNSSECValid: true,
						Records: []TLSARecord{
							{Usage: 3, CertHash: fp.ToHex()},
						},
					})
			}(),
			wantType: OutcomeVerified,
			wantTier: TierBadgeOnly,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []Option{
				WithDNSResolver(NewMockDNSResolver().WithRecords(host, []AnsBadgeRecord{dnsRecord})),
				WithTlogClient(NewMockTransparencyLogClient().WithBadge(badgeURL, badge)),
				WithoutURLValidation(),
			}
			if tt.keyLookup != nil {
				opts = append(opts, WithScittKeyLookup(tt.keyLookup))
			}
			if tt.daneResolver != nil {
				opts = append(opts, WithDANEResolver(tt.daneResolver))
			}

			verifier := NewServerVerifier(opts...)
			cert := createTestCertIdentity(host, fingerprint)
			fqdn, _ := models.NewFqdn(host)

			outcome := verifier.VerifyWithScitt(context.Background(), fqdn, cert, tt.headers)

			if outcome.Type != tt.wantType {
				t.Errorf("Type = %v, want %v (error: %v)", outcome.Type, tt.wantType, outcome.Error)
			}
			if tt.wantType == OutcomeVerified && outcome.Tier != tt.wantTier {
				t.Errorf("Tier = %v, want %v", outcome.Tier, tt.wantTier)
			}
			if tt.wantType == OutcomeScittError && outcome.Error == nil {
				t.Error("expected non-nil error for ScittError outcome")
			}
			// 10.5: verify error message mentions missing key lookup
			if tt.name == "10.5: SCITT not configured (no key lookup), headers present" {
				if outcome.Error == nil || !strings.Contains(outcome.Error.Error(), "no key lookup configured") {
					t.Errorf("expected error about missing key lookup, got: %v", outcome.Error)
				}
			}
			// 10.6: verify DANE outcome is populated
			if tt.name == "10.6: SCITT configured + DANE configured, headers absent, badge+DANE path" {
				if outcome.DANEOutcome == nil {
					t.Error("expected DANEOutcome to be populated for DANE-configured path")
				}
			}
		})
	}
}

// transportErrorKeyLookup implements scitt.KeyLookup and always returns a TransportError.
type transportErrorKeyLookup struct {
	errType scitt.TransportErrorType
}

func (t *transportErrorKeyLookup) Get(_ [4]byte) (*scitt.TrustedKey, error) {
	return nil, &scitt.TransportError{
		Type:    t.errType,
		Message: "simulated transport error",
	}
}

// buildMinimalCoseSign1 builds a minimal valid COSE_Sign1 structure for testing.
// The signature is fake (zeros) — only structure needs to be valid for parsing.
func buildMinimalCoseSign1(t *testing.T, kid [4]byte, payload []byte, withVDP bool) []byte {
	t.Helper()

	hdr := map[int64]interface{}{
		1:   int64(-7), // alg = ES256
		4:   kid[:],    // kid
		395: int64(1),  // vds (required for receipt)
	}
	protectedBytes, err := cbor.Marshal(hdr)
	if err != nil {
		t.Fatalf("failed to encode protected header: %v", err)
	}

	var unprotected cbor.RawMessage
	if withVDP {
		vdpMap := map[int64]interface{}{
			396: map[int64]interface{}{
				int64(-1): uint64(1), // tree_size
				int64(-2): uint64(0), // leaf_index
			},
		}
		unprotected, err = cbor.Marshal(vdpMap)
	} else {
		unprotected, err = cbor.Marshal(map[int64]interface{}{})
	}
	if err != nil {
		t.Fatalf("failed to encode unprotected header: %v", err)
	}

	sig := make([]byte, 64) // zero-filled fake signature

	protEncoded, _ := cbor.Marshal(protectedBytes)
	payloadEncoded, _ := cbor.Marshal(payload)
	sigEncoded, _ := cbor.Marshal(sig)

	arr := []cbor.RawMessage{protEncoded, unprotected, payloadEncoded, sigEncoded}
	arrayBytes, err := cbor.Marshal(arr)
	if err != nil {
		t.Fatalf("failed to marshal COSE array: %v", err)
	}

	tag := cbor.RawTag{Number: 18, Content: arrayBytes}
	tagged, err := tag.MarshalCBOR()
	if err != nil {
		t.Fatalf("failed to marshal tag: %v", err)
	}
	return tagged
}

func TestVerifyWithScitt_TransportErrorFallback(t *testing.T) {
	t.Parallel()

	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	badgeURL := "https://tlog.example.com/v1/agents/test-id"
	badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")

	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	kid := [4]byte{0x01, 0x02, 0x03, 0x04}
	receipt := buildMinimalCoseSign1(t, kid, []byte("test-payload"), true)
	token := buildMinimalCoseSign1(t, kid, []byte("token-payload"), false)

	tests := []struct {
		name     string
		headers  *scitt.Headers
		lookup   scitt.KeyLookup
		wantType OutcomeType
		wantTier VerificationTier
	}{
		{
			name: "receipt transport error falls back to badge",
			headers: &scitt.Headers{
				Receipt:     receipt,
				StatusToken: token,
			},
			lookup:   &transportErrorKeyLookup{errType: scitt.TransportErrHTTPError},
			wantType: OutcomeVerified,
			wantTier: TierBadgeOnly,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := []Option{
				WithDNSResolver(NewMockDNSResolver().WithRecords(host, []AnsBadgeRecord{dnsRecord})),
				WithTlogClient(NewMockTransparencyLogClient().WithBadge(badgeURL, badge)),
				WithoutURLValidation(),
				WithScittKeyLookup(tt.lookup),
			}

			verifier := NewServerVerifier(opts...)
			cert := createTestCertIdentity(host, fingerprint)
			fqdn, _ := models.NewFqdn(host)

			outcome := verifier.VerifyWithScitt(context.Background(), fqdn, cert, tt.headers)

			if outcome.Type != tt.wantType {
				t.Errorf("Type = %v, want %v (error: %v)", outcome.Type, tt.wantType, outcome.Error)
			}
			if tt.wantType == OutcomeVerified && outcome.Tier != tt.wantTier {
				t.Errorf("Tier = %v, want %v", outcome.Tier, tt.wantTier)
			}
		})
	}
}

func TestAnsVerifier_VerifyServerWithScitt(t *testing.T) {
	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

	badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")
	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	tests := []struct {
		name     string
		fqdn     string
		headers  *scitt.Headers
		wantType OutcomeType
	}{
		{
			name:     "nil headers falls back to badge",
			fqdn:     host,
			headers:  nil,
			wantType: OutcomeVerified,
		},
		{
			name:     "empty headers falls back to badge",
			fqdn:     host,
			headers:  &scitt.Headers{},
			wantType: OutcomeVerified,
		},
		{
			name:     "invalid fqdn returns CertError",
			fqdn:     "",
			headers:  nil,
			wantType: OutcomeCertError,
		},
		{
			name:     "partial headers returns ScittError",
			fqdn:     host,
			headers:  &scitt.Headers{Receipt: []byte{1, 2}},
			wantType: OutcomeScittError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := NewAnsVerifier(
				WithDNSResolver(NewMockDNSResolver().WithRecords(host, []AnsBadgeRecord{dnsRecord})),
				WithTlogClient(NewMockTransparencyLogClient().WithBadge(badgeURL, badge)),
				WithoutURLValidation(),
			)

			cert := createTestCertIdentity(host, fingerprint)
			outcome := verifier.VerifyServerWithScitt(context.Background(), tt.fqdn, cert, tt.headers)

			if outcome.Type != tt.wantType {
				t.Errorf("Type = %v, want %v (error: %v)", outcome.Type, tt.wantType, outcome.Error)
			}
		})
	}
}

func TestAnsVerifier_VerifyClientWithScitt(t *testing.T) {
	host := "test.example.com"
	version := "v1.0.0"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

	badge := createTestBadge(host, version, "SHA256:aaa", fingerprint)
	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	tests := []struct {
		name     string
		headers  *scitt.Headers
		wantType OutcomeType
	}{
		{
			name:     "nil headers falls back to badge",
			headers:  nil,
			wantType: OutcomeVerified,
		},
		{
			name:     "empty headers falls back to badge",
			headers:  &scitt.Headers{},
			wantType: OutcomeVerified,
		},
		{
			name:     "partial headers (only receipt) returns ScittError",
			headers:  &scitt.Headers{Receipt: []byte{1, 2}},
			wantType: OutcomeScittError,
		},
		{
			name:     "partial headers (only token) returns ScittError",
			headers:  &scitt.Headers{StatusToken: []byte{1, 2}},
			wantType: OutcomeScittError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := NewAnsVerifier(
				WithDNSResolver(NewMockDNSResolver().WithRecords(host, []AnsBadgeRecord{dnsRecord})),
				WithTlogClient(NewMockTransparencyLogClient().WithBadge(badgeURL, badge)),
				WithoutURLValidation(),
			)

			cert := createMTLSCertIdentity(host, version, fingerprint)
			outcome := verifier.VerifyClientWithScitt(context.Background(), cert, tt.headers)

			if outcome.Type != tt.wantType {
				t.Errorf("Type = %v, want %v (error: %v)", outcome.Type, tt.wantType, outcome.Error)
			}
		})
	}
}
