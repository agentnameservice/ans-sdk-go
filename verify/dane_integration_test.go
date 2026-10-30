package verify

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/miekg/dns"
)

// startFakeDNSForTLSA starts a local DNS server that responds to TLSA queries.
func startFakeDNSForTLSA(t *testing.T, handler dns.Handler) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	t.Cleanup(func() {
		server.Shutdown()
	})

	return pc.LocalAddr().String()
}

func TestStandardDANEResolver_LookupTLSA_Found(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.AuthenticatedData = true // Simulate DNSSEC-validated response

		for _, q := range r.Question {
			if q.Qtype == dns.TypeTLSA {
				rr := &dns.TLSA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTLSA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Usage:        3, // DANE-EE
					Selector:     1, // SubjectPublicKeyInfo
					MatchingType: 1, // SHA-256
					Certificate:  "ABCDEF1234567890",
				}
				m.Answer = append(m.Answer, rr)
			}
		}

		w.WriteMsg(m)
	})

	addr := startFakeDNSForTLSA(t, mux)

	resolver := NewStandardDANEResolver(
		WithDANEServer(addr),
		WithDANETimeout(2*time.Second),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	result, err := resolver.LookupTLSA(context.Background(), fqdn, 443)
	if err != nil {
		t.Fatalf("LookupTLSA() error = %v", err)
	}
	if !result.Found {
		t.Fatal("LookupTLSA() Found = false, want true")
	}
	if !result.DNSSECValid {
		t.Error("LookupTLSA() DNSSECValid = false, want true")
	}
	if len(result.Records) != 1 {
		t.Fatalf("Records length = %d, want 1", len(result.Records))
	}
	if result.Records[0].Usage != 3 {
		t.Errorf("Usage = %d, want 3", result.Records[0].Usage)
	}
	if result.Records[0].CertHash != "abcdef1234567890" {
		t.Errorf("CertHash = %q, want lowercase hex", result.Records[0].CertHash)
	}
}

func TestStandardDANEResolver_LookupTLSA_NXDOMAIN(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError // NXDOMAIN
		w.WriteMsg(m)
	})

	addr := startFakeDNSForTLSA(t, mux)

	resolver := NewStandardDANEResolver(WithDANEServer(addr), WithDANETimeout(2*time.Second))
	fqdn, _ := models.NewFqdn("notfound.example.com")
	result, err := resolver.LookupTLSA(context.Background(), fqdn, 443)
	if err != nil {
		t.Fatalf("LookupTLSA() error = %v", err)
	}
	if result.Found {
		t.Error("LookupTLSA() Found = true, want false for NXDOMAIN")
	}
}

func TestStandardDANEResolver_LookupTLSA_SERVFAIL(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
	})

	addr := startFakeDNSForTLSA(t, mux)

	resolver := NewStandardDANEResolver(WithDANEServer(addr), WithDANETimeout(2*time.Second))
	fqdn, _ := models.NewFqdn("test.example.com")
	_, err := resolver.LookupTLSA(context.Background(), fqdn, 443)
	if err == nil {
		t.Fatal("expected error for SERVFAIL")
	}
	var daneErr *DANEError
	if !errors.As(err, &daneErr) {
		t.Fatalf("expected *DANEError, got %T", err)
	}
	if daneErr.Type != DANEErrorDNSSECFailed {
		t.Errorf("Type = %v, want DANEErrorDNSSECFailed", daneErr.Type)
	}
}

func TestStandardDANEResolver_LookupTLSA_EmptyAnswer(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		// No answer records, but successful response
		w.WriteMsg(m)
	})

	addr := startFakeDNSForTLSA(t, mux)

	resolver := NewStandardDANEResolver(WithDANEServer(addr), WithDANETimeout(2*time.Second))
	fqdn, _ := models.NewFqdn("test.example.com")
	result, err := resolver.LookupTLSA(context.Background(), fqdn, 443)
	if err != nil {
		t.Fatalf("LookupTLSA() error = %v", err)
	}
	if result.Found {
		t.Error("LookupTLSA() Found = true, want false for empty answer")
	}
}

func TestStandardDANEResolver_LookupTLSA_NonTLSARecords(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		// Return a non-TLSA record (e.g., A record)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("1.2.3.4"),
		})
		w.WriteMsg(m)
	})

	addr := startFakeDNSForTLSA(t, mux)

	resolver := NewStandardDANEResolver(WithDANEServer(addr), WithDANETimeout(2*time.Second))
	fqdn, _ := models.NewFqdn("test.example.com")
	result, err := resolver.LookupTLSA(context.Background(), fqdn, 443)
	if err != nil {
		t.Fatalf("LookupTLSA() error = %v", err)
	}
	if result.Found {
		t.Error("LookupTLSA() Found = true, want false (no TLSA records in answer)")
	}
}

func TestStandardDANEResolver_LookupTLSA_ConnectionError(t *testing.T) {
	// Use an address that nothing is listening on
	resolver := NewStandardDANEResolver(
		WithDANEServer("127.0.0.1:1"), // Port 1 is unlikely to respond
		WithDANETimeout(500*time.Millisecond),
	)

	fqdn, _ := models.NewFqdn("test.example.com")
	_, err := resolver.LookupTLSA(context.Background(), fqdn, 443)
	if err == nil {
		t.Fatal("expected error for connection failure")
	}
	var daneErr *DANEError
	if !errors.As(err, &daneErr) {
		t.Fatalf("expected *DANEError, got %T", err)
	}
	if daneErr.Type != DANEErrorLookupFailed {
		t.Errorf("Type = %v, want DANEErrorLookupFailed", daneErr.Type)
	}
}

func TestStandardDANEResolver_LookupTLSA_ContextDeadline(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		// Delay longer than the context deadline
		time.Sleep(500 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(r)
		w.WriteMsg(m)
	})

	addr := startFakeDNSForTLSA(t, mux)

	resolver := NewStandardDANEResolver(WithDANEServer(addr), WithDANETimeout(5*time.Second))
	fqdn, _ := models.NewFqdn("test.example.com")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := resolver.LookupTLSA(ctx, fqdn, 443)
	if err == nil {
		t.Fatal("expected error for context deadline")
	}
}

func TestStandardDANEResolver_LookupTLSA_MultipleTLSA(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.AuthenticatedData = false // No DNSSEC

		for _, q := range r.Question {
			if q.Qtype == dns.TypeTLSA {
				// DANE-EE record
				m.Answer = append(m.Answer, &dns.TLSA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTLSA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Usage:        3,
					Selector:     1,
					MatchingType: 1,
					Certificate:  "AABBCC",
				})
				// DANE-TA record
				m.Answer = append(m.Answer, &dns.TLSA{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTLSA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Usage:        2,
					Selector:     0,
					MatchingType: 1,
					Certificate:  "DDEEFF",
				})
			}
		}

		w.WriteMsg(m)
	})

	addr := startFakeDNSForTLSA(t, mux)

	resolver := NewStandardDANEResolver(WithDANEServer(addr), WithDANETimeout(2*time.Second))
	fqdn, _ := models.NewFqdn("test.example.com")
	result, err := resolver.LookupTLSA(context.Background(), fqdn, 443)
	if err != nil {
		t.Fatalf("LookupTLSA() error = %v", err)
	}
	if !result.Found {
		t.Fatal("LookupTLSA() Found = false, want true")
	}
	if result.DNSSECValid {
		t.Error("LookupTLSA() DNSSECValid = true, want false (AD not set)")
	}
	if len(result.Records) != 2 {
		t.Fatalf("Records length = %d, want 2", len(result.Records))
	}
}
