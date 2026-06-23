package verify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestDANEVerifier(t *testing.T) {
	const (
		testFP   = "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
		testHex  = "e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
		otherHex = "0000000000000000000000000000000000000000000000000000000000000000"
		testHost = "agent.example.com"
		testPort = uint16(443)
	)

	testFqdn, err := models.NewFqdn(testHost)
	if err != nil {
		t.Fatalf("failed to create test FQDN: %v", err)
	}

	tests := []struct {
		name         string
		resolver     *MockDANEResolver
		cert         *CertIdentity
		wantType     DANEOutcomeType
		wantIsPass   bool
		wantIsReject bool
	}{
		{
			name: "7.1 DNSSEC valid, TLSA matches",
			resolver: NewMockDANEResolver().WithTLSA(testHost, testPort, TLSALookupResult{
				Found:       true,
				DNSSECValid: true,
				Records: []TLSARecord{
					{Usage: 3, Selector: 1, MatchingType: 1, CertHash: testHex},
				},
			}),
			cert:         createTestCertIdentity(testHost, testFP),
			wantType:     DANEVerified,
			wantIsPass:   true,
			wantIsReject: false,
		},
		{
			name: "7.2 DNSSEC valid, TLSA mismatch",
			resolver: NewMockDANEResolver().WithTLSA(testHost, testPort, TLSALookupResult{
				Found:       true,
				DNSSECValid: true,
				Records: []TLSARecord{
					{Usage: 3, Selector: 1, MatchingType: 1, CertHash: otherHex},
				},
			}),
			cert:         createTestCertIdentity(testHost, testFP),
			wantType:     DANEMismatch,
			wantIsPass:   false,
			wantIsReject: true,
		},
		{
			name: "7.3 No DNSSEC present",
			resolver: NewMockDANEResolver().WithTLSA(testHost, testPort, TLSALookupResult{
				Found:       true,
				DNSSECValid: false,
				Records: []TLSARecord{
					{Usage: 3, Selector: 1, MatchingType: 1, CertHash: testHex},
				},
			}),
			cert:         createTestCertIdentity(testHost, testFP),
			wantType:     DANESkipped,
			wantIsPass:   true,
			wantIsReject: false,
		},
		{
			name: "7.4 DNSSEC validation failure",
			resolver: NewMockDANEResolver().WithError(testHost, testPort, &DANEError{
				Type:   DANEErrorDNSSECFailed,
				Fqdn:   testHost,
				Reason: "SERVFAIL response",
			}),
			cert:         createTestCertIdentity(testHost, testFP),
			wantType:     DANEDNSSECFailed,
			wantIsPass:   false,
			wantIsReject: true,
		},
		{
			name: "7.5 Multiple TLSA records (renewal), cert matches one",
			resolver: NewMockDANEResolver().WithTLSA(testHost, testPort, TLSALookupResult{
				Found:       true,
				DNSSECValid: true,
				Records: []TLSARecord{
					{Usage: 3, Selector: 1, MatchingType: 1, CertHash: otherHex},
					{Usage: 3, Selector: 1, MatchingType: 1, CertHash: testHex},
				},
			}),
			cert:         createTestCertIdentity(testHost, testFP),
			wantType:     DANEVerified,
			wantIsPass:   true,
			wantIsReject: false,
		},
		{
			name:         "No TLSA records found",
			resolver:     NewMockDANEResolver(),
			cert:         createTestCertIdentity(testHost, testFP),
			wantType:     DANENoRecords,
			wantIsPass:   true,
			wantIsReject: false,
		},
		{
			name: "DNS lookup error",
			resolver: NewMockDANEResolver().WithError(testHost, testPort,
				errors.New("network unreachable"),
			),
			cert:         createTestCertIdentity(testHost, testFP),
			wantType:     DANELookupError,
			wantIsPass:   false,
			wantIsReject: false,
		},
		{
			name: "Case-insensitive fingerprint comparison",
			resolver: NewMockDANEResolver().WithTLSA(testHost, testPort, TLSALookupResult{
				Found:       true,
				DNSSECValid: true,
				Records: []TLSARecord{
					{Usage: 3, Selector: 1, MatchingType: 1, CertHash: strings.ToUpper(testHex)},
				},
			}),
			cert:         createTestCertIdentity(testHost, testFP),
			wantType:     DANEVerified,
			wantIsPass:   true,
			wantIsReject: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := NewDANEVerifier(tt.resolver)
			outcome := verifier.Verify(context.Background(), testFqdn, testPort, tt.cert)

			if outcome.Type != tt.wantType {
				t.Errorf("Verify() outcome type = %v, want %v", outcome.Type, tt.wantType)
			}
			if outcome.IsPass() != tt.wantIsPass {
				t.Errorf("IsPass() = %v, want %v", outcome.IsPass(), tt.wantIsPass)
			}
			if outcome.IsReject() != tt.wantIsReject {
				t.Errorf("IsReject() = %v, want %v", outcome.IsReject(), tt.wantIsReject)
			}
		})
	}
}

func TestDANEOutcome_IsPass(t *testing.T) {
	tests := []struct {
		name     string
		outcome  DANEOutcomeType
		wantPass bool
	}{
		{"DANEVerified", DANEVerified, true},
		{"DANESkipped", DANESkipped, true},
		{"DANENoRecords", DANENoRecords, true},
		{"DANEMismatch", DANEMismatch, false},
		{"DANEDNSSECFailed", DANEDNSSECFailed, false},
		{"DANELookupError", DANELookupError, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &DANEOutcome{Type: tt.outcome}
			if got := o.IsPass(); got != tt.wantPass {
				t.Errorf("IsPass() = %v, want %v", got, tt.wantPass)
			}
		})
	}
}

func TestDANEOutcome_IsReject(t *testing.T) {
	tests := []struct {
		name       string
		outcome    DANEOutcomeType
		wantReject bool
	}{
		{"DANEVerified", DANEVerified, false},
		{"DANESkipped", DANESkipped, false},
		{"DANENoRecords", DANENoRecords, false},
		{"DANEMismatch", DANEMismatch, true},
		{"DANEDNSSECFailed", DANEDNSSECFailed, true},
		{"DANELookupError", DANELookupError, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &DANEOutcome{Type: tt.outcome}
			if got := o.IsReject(); got != tt.wantReject {
				t.Errorf("IsReject() = %v, want %v", got, tt.wantReject)
			}
		})
	}
}

func TestDANEOutcome_IsError(t *testing.T) {
	tests := []struct {
		name      string
		outcome   DANEOutcomeType
		wantError bool
	}{
		{"DANEVerified", DANEVerified, false},
		{"DANESkipped", DANESkipped, false},
		{"DANENoRecords", DANENoRecords, false},
		{"DANEMismatch", DANEMismatch, false},
		{"DANEDNSSECFailed", DANEDNSSECFailed, false},
		{"DANELookupError", DANELookupError, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &DANEOutcome{Type: tt.outcome}
			if got := o.IsError(); got != tt.wantError {
				t.Errorf("IsError() = %v, want %v", got, tt.wantError)
			}
		})
	}
}

func TestDANEOutcomeType_String(t *testing.T) {
	tests := []struct {
		outcome DANEOutcomeType
		want    string
	}{
		{DANEVerified, "DANEVerified"},
		{DANEMismatch, "DANEMismatch"},
		{DANESkipped, "DANESkipped"},
		{DANEDNSSECFailed, "DANEDNSSECFailed"},
		{DANENoRecords, "DANENoRecords"},
		{DANELookupError, "DANELookupError"},
		{DANEOutcomeType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.outcome.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDANEError(t *testing.T) {
	tests := []struct {
		name    string
		err     *DANEError
		wantMsg string
	}{
		{
			name:    "DNSSEC failed",
			err:     &DANEError{Type: DANEErrorDNSSECFailed, Fqdn: "example.com", Reason: "SERVFAIL"},
			wantMsg: "DNSSEC validation failed for example.com: SERVFAIL",
		},
		{
			name:    "Lookup failed with reason",
			err:     &DANEError{Type: DANEErrorLookupFailed, Fqdn: "example.com", Reason: "timeout"},
			wantMsg: "DANE TLSA lookup failed for example.com: timeout",
		},
		{
			name:    "Lookup failed without reason",
			err:     &DANEError{Type: DANEErrorLookupFailed, Fqdn: "example.com"},
			wantMsg: "DANE TLSA lookup failed for example.com",
		},
		{
			name:    "DNSSEC failed without reason",
			err:     &DANEError{Type: DANEErrorDNSSECFailed, Fqdn: "example.com"},
			wantMsg: "DNSSEC validation failed for example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tt.wantMsg)
			}
		})
	}
}

func TestMockDANEResolver(t *testing.T) {
	t.Run("returns configured result", func(t *testing.T) {
		fqdn, _ := models.NewFqdn("test.example.com")
		resolver := NewMockDANEResolver().WithTLSA("test.example.com", 443, TLSALookupResult{
			Found:       true,
			DNSSECValid: true,
			Records:     []TLSARecord{{Usage: 3, CertHash: "abc123"}},
		})

		result, err := resolver.LookupTLSA(context.Background(), fqdn, 443)
		if err != nil {
			t.Fatalf("LookupTLSA() unexpected error: %v", err)
		}
		if !result.Found {
			t.Error("LookupTLSA() Found = false, want true")
		}
		if len(result.Records) != 1 {
			t.Errorf("LookupTLSA() Records length = %d, want 1", len(result.Records))
		}
	})

	t.Run("returns configured error", func(t *testing.T) {
		fqdn, _ := models.NewFqdn("test.example.com")
		wantErr := errors.New("dns failure")
		resolver := NewMockDANEResolver().WithError("test.example.com", 443, wantErr)

		_, err := resolver.LookupTLSA(context.Background(), fqdn, 443)
		if !errors.Is(err, wantErr) {
			t.Errorf("LookupTLSA() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("returns not found for unconfigured FQDN", func(t *testing.T) {
		fqdn, _ := models.NewFqdn("unknown.example.com")
		resolver := NewMockDANEResolver()

		result, err := resolver.LookupTLSA(context.Background(), fqdn, 443)
		if err != nil {
			t.Fatalf("LookupTLSA() unexpected error: %v", err)
		}
		if result.Found {
			t.Error("LookupTLSA() Found = true, want false")
		}
	})
}

func TestWithDANEResolver(t *testing.T) {
	mock := NewMockDANEResolver()
	opt := WithDANEResolver(mock)

	cfg := &verifierConfig{}
	opt(cfg)

	if cfg.daneResolver != mock {
		t.Error("WithDANEResolver() did not set the DANE resolver")
	}
}

func TestNewStandardDANEResolver_Options(t *testing.T) {
	tests := []struct {
		name       string
		opts       []DANEResolverOption
		wantServer string
		wantCustom bool
	}{
		{
			name:       "default options",
			opts:       nil,
			wantServer: "8.8.8.8:53",
		},
		{
			name:       "custom server",
			opts:       []DANEResolverOption{WithDANEServer("1.1.1.1:53")},
			wantServer: "1.1.1.1:53",
		},
		{
			name:       "custom timeout",
			opts:       []DANEResolverOption{WithDANETimeout(10000000000)},
			wantServer: "8.8.8.8:53",
			wantCustom: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewStandardDANEResolver(tt.opts...)
			if r.server != tt.wantServer {
				t.Errorf("server = %q, want %q", r.server, tt.wantServer)
			}
			if tt.wantCustom && r.timeout != 10000000000 {
				t.Errorf("timeout = %v, want 10s", r.timeout)
			}
		})
	}
}

func TestDANEVerifier_NilCert(t *testing.T) {
	resolver := NewMockDANEResolver()
	verifier := NewDANEVerifier(resolver)
	fqdn, _ := models.NewFqdn("test.example.com")

	outcome := verifier.Verify(context.Background(), fqdn, 443, nil)

	if outcome.Type != DANELookupError {
		t.Errorf("Verify(nil cert) type = %v, want DANELookupError", outcome.Type)
	}
	if outcome.Error == nil {
		t.Error("Verify(nil cert) error should not be nil")
	}
}

func TestDANEVerifier_IgnoresNonDANEEE(t *testing.T) {
	testFP := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	testHex := "e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	fqdn, _ := models.NewFqdn("test.example.com")

	// DANE-TA (Usage=2) record with matching hash should NOT match
	resolver := NewMockDANEResolver().WithTLSA("test.example.com", 443, TLSALookupResult{
		Found:       true,
		DNSSECValid: true,
		Records: []TLSARecord{
			{Usage: 2, Selector: 1, MatchingType: 1, CertHash: testHex},
		},
	})

	verifier := NewDANEVerifier(resolver)
	cert := createTestCertIdentity("test.example.com", testFP)

	outcome := verifier.Verify(context.Background(), fqdn, 443, cert)

	if outcome.Type != DANEMismatch {
		t.Errorf("Verify() with DANE-TA record = %v, want DANEMismatch", outcome.Type)
	}
}

func TestServerVerifier_DANEIntegration(t *testing.T) {
	host := "test.example.com"
	fingerprint := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
	fpHex := "e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"

	badge := createTestBadge(host, "v1.0.0", fingerprint, "SHA256:aaa")
	badgeURL := "https://tlog.example.com/v1/agents/test-id"

	dnsRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           badgeURL,
	}

	t.Run("DANE verified enriches outcome", func(t *testing.T) {
		dnsResolver := NewMockDNSResolver().
			WithRecords(host, []AnsBadgeRecord{dnsRecord})
		tlogClient := NewMockTransparencyLogClient().
			WithBadge(badgeURL, badge)
		daneResolver := NewMockDANEResolver().WithTLSA(host, 443, TLSALookupResult{
			Found:       true,
			DNSSECValid: true,
			Records:     []TLSARecord{{Usage: 3, Selector: 1, MatchingType: 1, CertHash: fpHex}},
		})

		verifier := NewServerVerifier(
			WithDNSResolver(dnsResolver),
			WithTlogClient(tlogClient),
			WithDANEResolver(daneResolver),
			WithoutURLValidation(),
		)

		cert := createTestCertIdentity(host, fingerprint)
		fqdn, _ := models.NewFqdn(host)
		outcome := verifier.Verify(context.Background(), fqdn, cert)

		if !outcome.IsSuccess() {
			t.Errorf("Verify() failed: %v", outcome.Type)
		}
		if outcome.DANEOutcome == nil {
			t.Error("DANEOutcome should be set when DANE verification passes")
		}
	})

	t.Run("DANE mismatch rejects even if badge passes", func(t *testing.T) {
		dnsResolver := NewMockDNSResolver().
			WithRecords(host, []AnsBadgeRecord{dnsRecord})
		tlogClient := NewMockTransparencyLogClient().
			WithBadge(badgeURL, badge)
		daneResolver := NewMockDANEResolver().WithTLSA(host, 443, TLSALookupResult{
			Found:       true,
			DNSSECValid: true,
			Records:     []TLSARecord{{Usage: 3, Selector: 1, MatchingType: 1, CertHash: "0000000000000000000000000000000000000000000000000000000000000000"}},
		})

		verifier := NewServerVerifier(
			WithDNSResolver(dnsResolver),
			WithTlogClient(tlogClient),
			WithDANEResolver(daneResolver),
			WithoutURLValidation(),
		)

		cert := createTestCertIdentity(host, fingerprint)
		fqdn, _ := models.NewFqdn(host)
		outcome := verifier.Verify(context.Background(), fqdn, cert)

		if outcome.Type != OutcomeDANERejection {
			t.Errorf("Verify() expected DANERejection, got %v", outcome.Type)
		}
		if outcome.IsSuccess() {
			t.Error("DANE rejection should not be success")
		}
	})

	t.Run("DANE skipped (no DNSSEC) does not reject", func(t *testing.T) {
		dnsResolver := NewMockDNSResolver().
			WithRecords(host, []AnsBadgeRecord{dnsRecord})
		tlogClient := NewMockTransparencyLogClient().
			WithBadge(badgeURL, badge)
		daneResolver := NewMockDANEResolver().WithTLSA(host, 443, TLSALookupResult{
			Found:       true,
			DNSSECValid: false,
			Records:     []TLSARecord{{Usage: 3, Selector: 1, MatchingType: 1, CertHash: "different"}},
		})

		verifier := NewServerVerifier(
			WithDNSResolver(dnsResolver),
			WithTlogClient(tlogClient),
			WithDANEResolver(daneResolver),
			WithoutURLValidation(),
		)

		cert := createTestCertIdentity(host, fingerprint)
		fqdn, _ := models.NewFqdn(host)
		outcome := verifier.Verify(context.Background(), fqdn, cert)

		if !outcome.IsSuccess() {
			t.Errorf("Verify() should pass when DANE skipped: %v", outcome.Type)
		}
	})

	t.Run("no DANE resolver configured — no impact", func(t *testing.T) {
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
			t.Errorf("Verify() failed without DANE: %v", outcome.Type)
		}
		if outcome.DANEOutcome != nil {
			t.Error("DANEOutcome should be nil when DANE not configured")
		}
	})
}
