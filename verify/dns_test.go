package verify

import (
	"context"
	"errors"
	"testing"

	"github.com/godaddy/ans-sdk-go/models"
)

func TestMockDNSResolver(t *testing.T) {
	t.Run("LookupAnsBadge found", func(t *testing.T) {
		record := AnsBadgeRecord{
			FormatVersion: "ans-badge1",
			Version:       ptr(models.NewVersion(1, 0, 0)),
			URL:           "https://example.com/badge",
		}

		resolver := NewMockDNSResolver().
			WithRecords("agent.example.com", []AnsBadgeRecord{record})

		fqdn, _ := models.NewFqdn("agent.example.com")
		result, err := resolver.LookupAnsBadge(context.Background(), fqdn)

		if err != nil {
			t.Fatalf("LookupAnsBadge() error = %v", err)
		}
		if !result.Found {
			t.Fatal("LookupAnsBadge() Found = false, want true")
		}
		if len(result.Records) != 1 {
			t.Fatalf("LookupAnsBadge() len(Records) = %d, want 1", len(result.Records))
		}
		if result.Records[0].URL != "https://example.com/badge" {
			t.Errorf("Records[0].URL = %q, want https://example.com/badge", result.Records[0].URL)
		}
	})

	t.Run("LookupAnsBadge not found", func(t *testing.T) {
		resolver := NewMockDNSResolver()

		fqdn, _ := models.NewFqdn("unknown.example.com")
		result, err := resolver.LookupAnsBadge(context.Background(), fqdn)

		if err != nil {
			t.Fatalf("LookupAnsBadge() error = %v", err)
		}
		if result.Found {
			t.Fatal("LookupAnsBadge() Found = true, want false")
		}
	})

	t.Run("LookupAnsBadge error", func(t *testing.T) {
		resolver := NewMockDNSResolver().
			WithError("error.example.com", &DNSError{Type: DNSErrorTimeout, Fqdn: "error.example.com"})

		fqdn, _ := models.NewFqdn("error.example.com")
		_, err := resolver.LookupAnsBadge(context.Background(), fqdn)

		if err == nil {
			t.Fatal("LookupAnsBadge() expected error, got nil")
		}
	})

	t.Run("FindBadgeForVersion", func(t *testing.T) {
		v1 := AnsBadgeRecord{
			FormatVersion: "ans-badge1",
			Version:       ptr(models.NewVersion(1, 0, 0)),
			URL:           "https://example.com/v1",
		}
		v2 := AnsBadgeRecord{
			FormatVersion: "ans-badge1",
			Version:       ptr(models.NewVersion(1, 0, 1)),
			URL:           "https://example.com/v2",
		}

		resolver := NewMockDNSResolver().
			WithRecords("agent.example.com", []AnsBadgeRecord{v1, v2})

		fqdn, _ := models.NewFqdn("agent.example.com")

		// Find v1.0.0
		record, err := resolver.FindBadgeForVersion(context.Background(), fqdn, models.NewVersion(1, 0, 0))
		if err != nil {
			t.Fatalf("FindBadgeForVersion() error = %v", err)
		}
		if record == nil {
			t.Fatal("FindBadgeForVersion() returned nil, want record")
		}
		if record.URL != "https://example.com/v1" {
			t.Errorf("URL = %q, want https://example.com/v1", record.URL)
		}

		// Find v1.0.1
		record, err = resolver.FindBadgeForVersion(context.Background(), fqdn, models.NewVersion(1, 0, 1))
		if err != nil {
			t.Fatalf("FindBadgeForVersion() error = %v", err)
		}
		if record == nil {
			t.Fatal("FindBadgeForVersion() returned nil, want record")
		}
		if record.URL != "https://example.com/v2" {
			t.Errorf("URL = %q, want https://example.com/v2", record.URL)
		}

		// Version not found - should return ErrRecordNotFound
		record, err = resolver.FindBadgeForVersion(context.Background(), fqdn, models.NewVersion(2, 0, 0))
		if !errors.Is(err, ErrRecordNotFound) {
			t.Errorf("FindBadgeForVersion() error = %v, want ErrRecordNotFound", err)
		}
		if record != nil {
			t.Errorf("FindBadgeForVersion() = %v, want nil", record)
		}
	})

	t.Run("FindPreferredBadge returns newest version", func(t *testing.T) {
		v1 := AnsBadgeRecord{
			FormatVersion: "ans-badge1",
			Version:       ptr(models.NewVersion(1, 0, 0)),
			URL:           "https://example.com/v1",
		}
		v2 := AnsBadgeRecord{
			FormatVersion: "ans-badge1",
			Version:       ptr(models.NewVersion(2, 0, 0)),
			URL:           "https://example.com/v2",
		}

		resolver := NewMockDNSResolver().
			WithRecords("agent.example.com", []AnsBadgeRecord{v1, v2})

		fqdn, _ := models.NewFqdn("agent.example.com")
		record, err := resolver.FindPreferredBadge(context.Background(), fqdn)

		if err != nil {
			t.Fatalf("FindPreferredBadge() error = %v", err)
		}
		if record == nil {
			t.Fatal("FindPreferredBadge() returned nil, want record")
		}
		// Should return v2 (newest)
		if record.URL != "https://example.com/v2" {
			t.Errorf("URL = %q, want https://example.com/v2", record.URL)
		}
	})
}

func TestMockDNSResolver_FindBadgeForVersion_PrefersExactMatch(t *testing.T) {
	// A nil-version record should NOT shadow an exact version match
	// regardless of slice ordering (DNS TXT record order is not stable)
	versionless := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       nil, // matches any version
		URL:           "https://example.com/versionless",
	}
	v1 := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           "https://example.com/v1",
	}

	tests := []struct {
		name    string
		records []AnsBadgeRecord
		wantURL string
	}{
		{
			name:    "versionless first, exact match second",
			records: []AnsBadgeRecord{versionless, v1},
			wantURL: "https://example.com/v1",
		},
		{
			name:    "exact match first, versionless second",
			records: []AnsBadgeRecord{v1, versionless},
			wantURL: "https://example.com/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := NewMockDNSResolver().
				WithRecords("agent.example.com", tt.records)

			fqdn, _ := models.NewFqdn("agent.example.com")
			record, err := resolver.FindBadgeForVersion(context.Background(), fqdn, models.NewVersion(1, 0, 0))
			if err != nil {
				t.Fatalf("FindBadgeForVersion() error = %v", err)
			}
			if record.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", record.URL, tt.wantURL)
			}
		})
	}

	t.Run("falls back to versionless when no exact match", func(t *testing.T) {
		resolver := NewMockDNSResolver().
			WithRecords("agent.example.com", []AnsBadgeRecord{versionless})

		fqdn, _ := models.NewFqdn("agent.example.com")
		record, err := resolver.FindBadgeForVersion(context.Background(), fqdn, models.NewVersion(2, 0, 0))
		if err != nil {
			t.Fatalf("FindBadgeForVersion() error = %v", err)
		}
		if record.URL != "https://example.com/versionless" {
			t.Errorf("URL = %q, want versionless URL", record.URL)
		}
	})
}

func TestMockDNSResolver_RaBadgeFallback(t *testing.T) {
	ansRecord := AnsBadgeRecord{
		FormatVersion: "ans-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           "https://example.com/ans-badge",
	}
	raRecord := AnsBadgeRecord{
		FormatVersion: "ra-badge1",
		Version:       ptr(models.NewVersion(1, 0, 0)),
		URL:           "https://example.com/ra-badge",
	}

	tests := []struct {
		name           string
		resolver       *MockDNSResolver
		fqdn           string
		wantFound      bool
		wantErr        bool
		wantErrType    DNSErrorType // zero value = don't assert error type
		wantURL        string
		wantSource     BadgeRecordSource
		wantPrimaryErr bool
	}{
		{
			name: "ans-badge only",
			resolver: NewMockDNSResolver().
				WithRecords("agent.example.com", []AnsBadgeRecord{ansRecord}),
			fqdn:       "agent.example.com",
			wantFound:  true,
			wantURL:    "https://example.com/ans-badge",
			wantSource: BadgeRecordSourceAnsBadge,
		},
		{
			name: "ra-badge fallback when ans-badge absent",
			resolver: NewMockDNSResolver().
				WithRaBadgeRecords("agent.example.com", []AnsBadgeRecord{raRecord}),
			fqdn:       "agent.example.com",
			wantFound:  true,
			wantURL:    "https://example.com/ra-badge",
			wantSource: BadgeRecordSourceRaBadge,
			// Primary was simply absent (not errored); no PrimaryError stamped.
			wantPrimaryErr: false,
		},
		{
			name: "ans-badge takes priority over ra-badge",
			resolver: NewMockDNSResolver().
				WithRecords("agent.example.com", []AnsBadgeRecord{ansRecord}).
				WithRaBadgeRecords("agent.example.com", []AnsBadgeRecord{raRecord}),
			fqdn:       "agent.example.com",
			wantFound:  true,
			wantURL:    "https://example.com/ans-badge",
			wantSource: BadgeRecordSourceAnsBadge,
		},
		{
			name:      "neither record exists",
			resolver:  NewMockDNSResolver(),
			fqdn:      "agent.example.com",
			wantFound: false,
		},
		{
			name: "primary timeout falls back to ra-badge with PrimaryError stamped",
			resolver: NewMockDNSResolver().
				WithPrimaryError("agent.example.com", &DNSError{Type: DNSErrorTimeout, Fqdn: "agent.example.com"}).
				WithRaBadgeRecords("agent.example.com", []AnsBadgeRecord{raRecord}),
			fqdn:           "agent.example.com",
			wantFound:      true,
			wantURL:        "https://example.com/ra-badge",
			wantSource:     BadgeRecordSourceRaBadge,
			wantPrimaryErr: true,
		},
		{
			name: "primary timeout and no ra-badge returns primary error",
			resolver: NewMockDNSResolver().
				WithPrimaryError("agent.example.com", &DNSError{Type: DNSErrorTimeout, Fqdn: "agent.example.com"}),
			fqdn:    "agent.example.com",
			wantErr: true,
		},
		{
			name: "primary error wins over fallback error when both fail",
			resolver: NewMockDNSResolver().
				WithPrimaryError("agent.example.com", &DNSError{Type: DNSErrorTimeout, Fqdn: "agent.example.com"}).
				WithRaBadgeError("agent.example.com", &DNSError{Type: DNSErrorLookupFailed, Fqdn: "agent.example.com"}),
			fqdn:        "agent.example.com",
			wantErr:     true,
			wantErrType: DNSErrorTimeout,
		},
		{
			name: "primary absent and fallback errored returns fallback error",
			resolver: NewMockDNSResolver().
				WithRaBadgeError("agent.example.com", &DNSError{Type: DNSErrorLookupFailed, Fqdn: "agent.example.com"}),
			fqdn:    "agent.example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fqdn, _ := models.NewFqdn(tt.fqdn)
			result, err := tt.resolver.LookupAnsBadge(context.Background(), fqdn)

			if tt.wantErr {
				if err == nil {
					t.Fatal("LookupAnsBadge() expected error, got nil")
				}
				if tt.wantErrType != 0 {
					var dnsErr *DNSError
					if !errors.As(err, &dnsErr) {
						t.Fatalf("expected *DNSError, got %T: %v", err, err)
					}
					if dnsErr.Type != tt.wantErrType {
						t.Errorf("DNSError.Type = %v, want %v", dnsErr.Type, tt.wantErrType)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("LookupAnsBadge() unexpected error: %v", err)
			}

			if result.Found != tt.wantFound {
				t.Fatalf("Found = %v, want %v", result.Found, tt.wantFound)
			}

			if tt.wantFound {
				if len(result.Records) == 0 {
					t.Fatal("Found=true but no records")
				}
				if result.Records[0].URL != tt.wantURL {
					t.Errorf("URL = %q, want %q", result.Records[0].URL, tt.wantURL)
				}
				if result.Records[0].Source != tt.wantSource {
					t.Errorf("Source = %v, want %v", result.Records[0].Source, tt.wantSource)
				}
				if tt.wantPrimaryErr && result.Records[0].PrimaryError == nil {
					t.Error("PrimaryError = nil, want non-nil (primary errored, fallback used)")
				}
				if !tt.wantPrimaryErr && result.Records[0].PrimaryError != nil {
					t.Errorf("PrimaryError = %v, want nil", result.Records[0].PrimaryError)
				}
			}
		})
	}
}

func TestGetAnsBadgeRecords(t *testing.T) {
	tests := []struct {
		name      string
		fqdn      string
		resolver  *MockDNSResolver
		wantLen   int
		wantErr   bool
		wantErrFn func(t *testing.T, err error)
	}{
		{
			name: "found",
			fqdn: "test.example.com",
			resolver: NewMockDNSResolver().
				WithRecords("test.example.com", []AnsBadgeRecord{
					{URL: "https://tlog.example.com/badge/123"},
				}),
			wantLen: 1,
		},
		{
			name:     "not found",
			fqdn:     "notfound.example.com",
			resolver: NewMockDNSResolver(),
			wantErr:  true,
			wantErrFn: func(t *testing.T, err error) {
				var dnsErr *DNSError
				if !errors.As(err, &dnsErr) {
					t.Fatalf("expected *DNSError, got %T", err)
				}
				if dnsErr.Type != DNSErrorNotFound {
					t.Errorf("Type = %v, want DNSErrorNotFound", dnsErr.Type)
				}
			},
		},
		{
			name: "error",
			fqdn: "error.example.com",
			resolver: NewMockDNSResolver().
				WithError("error.example.com", errors.New("dns failure")),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fqdn, _ := models.NewFqdn(tt.fqdn)
			records, err := GetAnsBadgeRecords(context.Background(), tt.resolver, fqdn)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.wantErrFn != nil {
					tt.wantErrFn(t, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetAnsBadgeRecords() error = %v", err)
			}
			if len(records) != tt.wantLen {
				t.Errorf("expected %d record(s), got %d", tt.wantLen, len(records))
			}
		})
	}
}

func TestDNSError(t *testing.T) {
	tests := []struct {
		name      string
		errType   DNSErrorType
		fqdn      string
		wantError string
	}{
		{
			name:      "not found",
			errType:   DNSErrorNotFound,
			fqdn:      "test.example.com",
			wantError: "DNS record not found for test.example.com",
		},
		{
			name:      "timeout",
			errType:   DNSErrorTimeout,
			fqdn:      "test.example.com",
			wantError: "DNS timeout for test.example.com",
		},
		{
			name:      "lookup failed",
			errType:   DNSErrorLookupFailed,
			fqdn:      "test.example.com",
			wantError: "DNS lookup failed for test.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &DNSError{Type: tt.errType, Fqdn: tt.fqdn}
			if err.Error() != tt.wantError {
				t.Errorf("Error() = %q, want %q", err.Error(), tt.wantError)
			}
		})
	}
}
