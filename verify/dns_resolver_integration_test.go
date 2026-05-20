package verify

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/godaddy/ans-sdk-go/models"
	"github.com/miekg/dns"
)

// startFakeDNS starts a local DNS server that responds to TXT queries.
// It returns the server address and a cleanup function.
func startFakeDNS(t *testing.T, txtRecords map[string][]string) string {
	t.Helper()

	// Create a DNS handler
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		for _, q := range r.Question {
			if q.Qtype == dns.TypeTXT {
				if records, ok := txtRecords[q.Name]; ok {
					for _, txt := range records {
						rr := &dns.TXT{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeTXT,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							Txt: []string{txt},
						}
						m.Answer = append(m.Answer, rr)
					}
				} else {
					m.Rcode = dns.RcodeNameError // NXDOMAIN
				}
			}
		}

		w.WriteMsg(m)
	})

	// Start on a random UDP port
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	server := &dns.Server{
		PacketConn: pc,
		Handler:    mux,
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	t.Cleanup(func() {
		server.Shutdown()
	})

	return pc.LocalAddr().String()
}

// resolverDialingTo creates a net.Resolver that dials the given DNS server address.
func resolverDialingTo(addr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("udp", addr)
		},
	}
}

func TestStandardDNSResolver_LookupAnsBadge_FoundViaDNS(t *testing.T) {
	// Set up a fake DNS server with _ans-badge TXT records
	addr := startFakeDNS(t, map[string][]string{
		"_ans-badge.test.example.com.": {
			"v=ans-badge1; version=v1.0.0; url=https://tlog.example.com/badge/123",
		},
	})

	r := NewStandardDNSResolver().
		WithResolver(resolverDialingTo(addr)).
		WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("test.example.com")
	result, err := r.LookupAnsBadge(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("LookupAnsBadge() error = %v", err)
	}
	if !result.Found {
		t.Fatal("LookupAnsBadge() Found = false, want true")
	}
	if len(result.Records) != 1 {
		t.Fatalf("LookupAnsBadge() Records length = %d, want 1", len(result.Records))
	}
	if result.Records[0].URL != "https://tlog.example.com/badge/123" {
		t.Errorf("URL = %q, want https://tlog.example.com/badge/123", result.Records[0].URL)
	}
	if result.Records[0].Source != BadgeRecordSourceAnsBadge {
		t.Errorf("Source = %v, want BadgeRecordSourceAnsBadge", result.Records[0].Source)
	}
}

func TestStandardDNSResolver_LookupAnsBadge_FallbackToRaBadge(t *testing.T) {
	// No _ans-badge record, but has _ra-badge
	addr := startFakeDNS(t, map[string][]string{
		"_ra-badge.test.example.com.": {
			"v=ra-badge1; url=https://tlog.example.com/badge/legacy",
		},
	})

	r := NewStandardDNSResolver().
		WithResolver(resolverDialingTo(addr)).
		WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("test.example.com")
	result, err := r.LookupAnsBadge(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("LookupAnsBadge() error = %v", err)
	}
	if !result.Found {
		t.Fatal("LookupAnsBadge() Found = false, want true")
	}
	if result.Records[0].Source != BadgeRecordSourceRaBadge {
		t.Errorf("Source = %v, want BadgeRecordSourceRaBadge", result.Records[0].Source)
	}
}

// startFakeDNSWithDrops is like startFakeDNS but silently drops queries for
// names listed in dropNames. With a short resolver timeout, dropped queries
// surface as net.DNSError{IsTimeout: true} — which is exactly the transient
// failure mode we want to exercise on the production resolver.
func startFakeDNSWithDrops(t *testing.T, txtRecords map[string][]string, dropNames map[string]bool) string {
	t.Helper()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		// If any question is in dropNames, silently drop the packet.
		for _, q := range r.Question {
			if dropNames[q.Name] {
				return
			}
		}

		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		for _, q := range r.Question {
			if q.Qtype == dns.TypeTXT {
				if records, ok := txtRecords[q.Name]; ok {
					for _, txt := range records {
						rr := &dns.TXT{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeTXT,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							Txt: []string{txt},
						}
						m.Answer = append(m.Answer, rr)
					}
				} else {
					m.Rcode = dns.RcodeNameError
				}
			}
		}

		w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { server.Shutdown() })

	return pc.LocalAddr().String()
}

// TestStandardDNSResolver_LookupAnsBadge_FallbackErrorMatrix exercises the
// transient-error branches of LookupAnsBadge against a real net.Resolver
// pointed at a fake DNS server with selective packet drops. Each case
// configures which name(s) the server should drop and what records (if any)
// it should return for the rest.
func TestStandardDNSResolver_LookupAnsBadge_FallbackErrorMatrix(t *testing.T) {
	const fqdnStr = "test.example.com"
	const ansBadgeName = "_ans-badge." + fqdnStr + "."
	const raBadgeName = "_ra-badge." + fqdnStr + "."
	const legacyURL = "https://tlog.example.com/badge/legacy"

	tests := []struct {
		name           string
		txtRecords     map[string][]string
		dropNames      map[string]bool
		wantErr        bool
		wantFound      bool
		wantSource     BadgeRecordSource
		wantURL        string
		wantPrimaryErr bool
	}{
		{
			name: "primary timeout falls back to ra-badge with PrimaryError stamped",
			txtRecords: map[string][]string{
				raBadgeName: {"v=ra-badge1; url=" + legacyURL},
			},
			dropNames:      map[string]bool{ansBadgeName: true},
			wantFound:      true,
			wantSource:     BadgeRecordSourceRaBadge,
			wantURL:        legacyURL,
			wantPrimaryErr: true,
		},
		{
			name:       "primary timeout and ra-badge NXDOMAIN — primary error wins",
			txtRecords: map[string][]string{},
			dropNames:  map[string]bool{ansBadgeName: true},
			wantErr:    true,
		},
		{
			name:       "primary NXDOMAIN and fallback timeout — fallback error surfaces",
			txtRecords: map[string][]string{},
			dropNames:  map[string]bool{raBadgeName: true},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := startFakeDNSWithDrops(t, tt.txtRecords, tt.dropNames)
			r := NewStandardDNSResolver().
				WithResolver(resolverDialingTo(addr)).
				WithTimeout(300 * time.Millisecond)

			fqdn, _ := models.NewFqdn(fqdnStr)
			result, err := r.LookupAnsBadge(context.Background(), fqdn)

			if tt.wantErr {
				if err == nil {
					t.Fatal("LookupAnsBadge() error = nil, want non-nil")
				}
				// In all error cases the surfaced error must be a transient
				// DNS error — never NotFound. Either timeout or
				// LookupFailed is acceptable depending on how the OS
				// classifies the dropped packet.
				var dnsErr *DNSError
				if !errors.As(err, &dnsErr) {
					t.Fatalf("err is not *DNSError: %T", err)
				}
				if dnsErr.Type == DNSErrorNotFound {
					t.Errorf("transient error was downgraded to NotFound: %v", dnsErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LookupAnsBadge() unexpected error: %v", err)
			}
			if result.Found != tt.wantFound {
				t.Fatalf("Found = %v, want %v", result.Found, tt.wantFound)
			}
			if !tt.wantFound {
				return
			}
			if len(result.Records) == 0 {
				t.Fatal("Found=true but no records")
			}
			rec := result.Records[0]
			if rec.Source != tt.wantSource {
				t.Errorf("Source = %v, want %v", rec.Source, tt.wantSource)
			}
			if rec.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", rec.URL, tt.wantURL)
			}
			if tt.wantPrimaryErr && rec.PrimaryError == nil {
				t.Error("PrimaryError = nil, want non-nil (primary errored, fallback used)")
			}
			if !tt.wantPrimaryErr && rec.PrimaryError != nil {
				t.Errorf("PrimaryError = %v, want nil", rec.PrimaryError)
			}
		})
	}
}

func TestStandardDNSResolver_LookupAnsBadge_NotFoundViaDNS(t *testing.T) {
	// No records at all - both _ans-badge and _ra-badge return NXDOMAIN
	addr := startFakeDNS(t, map[string][]string{})

	r := NewStandardDNSResolver().
		WithResolver(resolverDialingTo(addr)).
		WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("unknown.example.com")
	result, err := r.LookupAnsBadge(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("LookupAnsBadge() error = %v", err)
	}
	if result.Found {
		t.Error("LookupAnsBadge() Found = true, want false")
	}
}

func TestStandardDNSResolver_LookupAnsBadge_InvalidTXTRecords(t *testing.T) {
	// TXT records that don't parse as badge records
	addr := startFakeDNS(t, map[string][]string{
		"_ans-badge.test.example.com.": {
			"this is not a badge record",
			"also not valid",
		},
	})

	r := NewStandardDNSResolver().
		WithResolver(resolverDialingTo(addr)).
		WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("test.example.com")
	result, err := r.LookupAnsBadge(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("LookupAnsBadge() error = %v", err)
	}
	// TXT records exist but none parse as badge records
	if result.Found {
		t.Error("LookupAnsBadge() Found = true, want false (unparseable records)")
	}
}

func TestStandardDNSResolver_FindBadgeForVersion_ExactMatch(t *testing.T) {
	addr := startFakeDNS(t, map[string][]string{
		"_ans-badge.test.example.com.": {
			"v=ans-badge1; version=v1.0.0; url=https://tlog.example.com/badge/v1",
			"v=ans-badge1; version=v2.0.0; url=https://tlog.example.com/badge/v2",
		},
	})

	r := NewStandardDNSResolver().
		WithResolver(resolverDialingTo(addr)).
		WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("test.example.com")
	version := models.NewVersion(1, 0, 0)

	record, err := r.FindBadgeForVersion(context.Background(), fqdn, version)
	if err != nil {
		t.Fatalf("FindBadgeForVersion() error = %v", err)
	}
	if record.URL != "https://tlog.example.com/badge/v1" {
		t.Errorf("URL = %q, want v1 badge URL", record.URL)
	}
}

func TestStandardDNSResolver_FindBadgeForVersion_VersionlessFallback(t *testing.T) {
	addr := startFakeDNS(t, map[string][]string{
		"_ans-badge.test.example.com.": {
			"v=ans-badge1; url=https://tlog.example.com/badge/latest",
		},
	})

	r := NewStandardDNSResolver().
		WithResolver(resolverDialingTo(addr)).
		WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("test.example.com")
	version := models.NewVersion(1, 0, 0)

	record, err := r.FindBadgeForVersion(context.Background(), fqdn, version)
	if err != nil {
		t.Fatalf("FindBadgeForVersion() error = %v", err)
	}
	if record.URL != "https://tlog.example.com/badge/latest" {
		t.Errorf("URL = %q, want versionless fallback URL", record.URL)
	}
}

func TestStandardDNSResolver_FindBadgeForVersion_NoMatch(t *testing.T) {
	addr := startFakeDNS(t, map[string][]string{
		"_ans-badge.test.example.com.": {
			"v=ans-badge1; version=v2.0.0; url=https://tlog.example.com/badge/v2",
		},
	})

	r := NewStandardDNSResolver().
		WithResolver(resolverDialingTo(addr)).
		WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("test.example.com")
	version := models.NewVersion(1, 0, 0)

	_, err := r.FindBadgeForVersion(context.Background(), fqdn, version)
	if !errors.Is(err, ErrRecordNotFound) {
		t.Errorf("expected ErrRecordNotFound, got %v", err)
	}
}

func TestStandardDNSResolver_FindBadgeForVersion_NotFound(t *testing.T) {
	addr := startFakeDNS(t, map[string][]string{})

	r := NewStandardDNSResolver().
		WithResolver(resolverDialingTo(addr)).
		WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("notfound.example.com")
	version := models.NewVersion(1, 0, 0)

	_, err := r.FindBadgeForVersion(context.Background(), fqdn, version)
	if !errors.Is(err, ErrRecordNotFound) {
		t.Errorf("expected ErrRecordNotFound, got %v", err)
	}
}

func TestStandardDNSResolver_FindPreferredBadge_HighestVersion(t *testing.T) {
	addr := startFakeDNS(t, map[string][]string{
		"_ans-badge.test.example.com.": {
			"v=ans-badge1; version=v1.0.0; url=https://tlog.example.com/badge/v1",
			"v=ans-badge1; version=v3.0.0; url=https://tlog.example.com/badge/v3",
			"v=ans-badge1; version=v2.0.0; url=https://tlog.example.com/badge/v2",
		},
	})

	r := NewStandardDNSResolver().
		WithResolver(resolverDialingTo(addr)).
		WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("test.example.com")

	record, err := r.FindPreferredBadge(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("FindPreferredBadge() error = %v", err)
	}
	if record.URL != "https://tlog.example.com/badge/v3" {
		t.Errorf("URL = %q, want v3 (highest version)", record.URL)
	}
}

func TestStandardDNSResolver_FindPreferredBadge_NotFound(t *testing.T) {
	addr := startFakeDNS(t, map[string][]string{})

	r := NewStandardDNSResolver().
		WithResolver(resolverDialingTo(addr)).
		WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("notfound.example.com")

	_, err := r.FindPreferredBadge(context.Background(), fqdn)
	if !errors.Is(err, ErrRecordNotFound) {
		t.Errorf("expected ErrRecordNotFound, got %v", err)
	}
}

func TestStandardDNSResolver_FindPreferredBadge_VersionedOverNil(t *testing.T) {
	addr := startFakeDNS(t, map[string][]string{
		"_ans-badge.test.example.com.": {
			"v=ans-badge1; url=https://tlog.example.com/badge/nil",
			"v=ans-badge1; version=v1.0.0; url=https://tlog.example.com/badge/v1",
		},
	})

	r := NewStandardDNSResolver().
		WithResolver(resolverDialingTo(addr)).
		WithTimeout(2 * time.Second)

	fqdn, _ := models.NewFqdn("test.example.com")

	record, err := r.FindPreferredBadge(context.Background(), fqdn)
	if err != nil {
		t.Fatalf("FindPreferredBadge() error = %v", err)
	}
	if record.URL != "https://tlog.example.com/badge/v1" {
		t.Errorf("URL = %q, want versioned badge over nil", record.URL)
	}
}
