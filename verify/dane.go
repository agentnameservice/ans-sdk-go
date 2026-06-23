package verify

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/miekg/dns"
)

// TLSARecord represents a parsed TLSA DNS record.
type TLSARecord struct {
	// Usage is the certificate usage field (DANE-TA=2, DANE-EE=3).
	Usage uint8
	// Selector is the selector field (full cert=0, SubjectPublicKeyInfo=1).
	Selector uint8
	// MatchingType is the matching type (exact=0, SHA-256=1, SHA-512=2).
	MatchingType uint8
	// CertHash is the hex-encoded, lowercase certificate association data.
	CertHash string
}

// TLSALookupResult represents the result of a TLSA DNS lookup.
type TLSALookupResult struct {
	// Found indicates whether any TLSA records were found.
	Found bool
	// Records contains the found TLSA records.
	Records []TLSARecord
	// DNSSECValid indicates whether the response was DNSSEC-validated.
	DNSSECValid bool
}

// DANEOutcomeType represents the type of DANE verification outcome.
type DANEOutcomeType int

const (
	// DANEVerified indicates DANE verification passed (DNSSEC valid, TLSA match).
	DANEVerified DANEOutcomeType = iota
	// DANEMismatch indicates TLSA records exist but no fingerprint matched.
	DANEMismatch
	// DANESkipped indicates DANE was skipped (records exist but no DNSSEC).
	DANESkipped
	// DANEDNSSECFailed indicates DNSSEC validation explicitly failed.
	DANEDNSSECFailed
	// DANENoRecords indicates no TLSA records were found.
	DANENoRecords
	// DANELookupError indicates a DNS lookup error occurred.
	DANELookupError
)

// String returns the string representation of a DANEOutcomeType.
func (t DANEOutcomeType) String() string {
	switch t {
	case DANEVerified:
		return "DANEVerified"
	case DANEMismatch:
		return "DANEMismatch"
	case DANESkipped:
		return "DANESkipped"
	case DANEDNSSECFailed:
		return "DANEDNSSECFailed"
	case DANENoRecords:
		return "DANENoRecords"
	case DANELookupError:
		return "DANELookupError"
	default:
		return "unknown"
	}
}

// DANEOutcome represents the result of a DANE/TLSA verification.
type DANEOutcome struct {
	// Type is the outcome type.
	Type DANEOutcomeType
	// Records contains the TLSA records found (if any).
	Records []TLSARecord
	// Error is the underlying error (if any).
	Error error
}

// IsPass returns true if the DANE outcome does not reject the connection.
// Note: DANELookupError returns false for both IsPass and IsReject — use IsError() to detect it.
func (o *DANEOutcome) IsPass() bool {
	return o.Type == DANEVerified || o.Type == DANESkipped || o.Type == DANENoRecords
}

// IsReject returns true if the DANE outcome should reject the connection.
// Note: DANELookupError returns false for both IsPass and IsReject — use IsError() to detect it.
func (o *DANEOutcome) IsReject() bool {
	return o.Type == DANEMismatch || o.Type == DANEDNSSECFailed
}

// IsError returns true if a DNS lookup error prevented verification.
// When true, the caller should apply their failure policy (fail-open vs fail-closed).
func (o *DANEOutcome) IsError() bool {
	return o.Type == DANELookupError
}

// DANEResolver is the interface for DANE/TLSA DNS resolution.
type DANEResolver interface {
	// LookupTLSA queries TLSA records for the given FQDN and port.
	LookupTLSA(ctx context.Context, fqdn models.Fqdn, port uint16) (TLSALookupResult, error)
}

// DANEVerifier verifies certificates against DANE/TLSA records.
type DANEVerifier struct {
	resolver DANEResolver
}

// NewDANEVerifier creates a new DANEVerifier with the given resolver.
func NewDANEVerifier(resolver DANEResolver) *DANEVerifier {
	return &DANEVerifier{resolver: resolver}
}

// tlsaUsageDANEEE is the DANE-EE (domain-issued certificate) usage type.
const tlsaUsageDANEEE = 3

// Verify performs DANE/TLSA verification for a certificate.
func (d *DANEVerifier) Verify(ctx context.Context, fqdn models.Fqdn, port uint16, cert *CertIdentity) *DANEOutcome {
	if cert == nil {
		return &DANEOutcome{Type: DANELookupError, Error: errors.New("nil certificate identity")}
	}

	result, err := d.resolver.LookupTLSA(ctx, fqdn, port)
	if err != nil {
		var daneErr *DANEError
		if errors.As(err, &daneErr) && daneErr.Type == DANEErrorDNSSECFailed {
			return &DANEOutcome{Type: DANEDNSSECFailed, Error: err}
		}
		return &DANEOutcome{Type: DANELookupError, Error: err}
	}

	if !result.Found {
		return &DANEOutcome{Type: DANENoRecords}
	}

	if !result.DNSSECValid {
		return &DANEOutcome{Type: DANESkipped, Records: result.Records}
	}

	// Compare cert fingerprint against DANE-EE (Usage=3) TLSA records only.
	// NOTE: Selector and MatchingType are not yet checked — a production implementation
	// should compute the appropriate hash for each selector (full cert vs SPKI).
	certHex := strings.ToLower(cert.Fingerprint.ToHex())
	for _, rec := range result.Records {
		if rec.Usage != tlsaUsageDANEEE {
			continue // Only match DANE-EE records; skip DANE-TA, PKIX-TA, PKIX-EE
		}
		// Defensive lowercase: StandardDANEResolver already lowercases, but alternative
		// resolver implementations or mocks may provide mixed-case hashes.
		if strings.ToLower(rec.CertHash) == certHex {
			return &DANEOutcome{Type: DANEVerified, Records: result.Records}
		}
	}

	return &DANEOutcome{Type: DANEMismatch, Records: result.Records}
}

// DANEResolverOption configures a StandardDANEResolver.
type DANEResolverOption func(*StandardDANEResolver)

// WithDANEServer sets the DNS server address for TLSA lookups.
// The server must be a DNSSEC-validating recursive resolver (e.g., 8.8.8.8:53, 1.1.1.1:53)
// for the AuthenticatedData (AD) flag to be meaningful.
func WithDANEServer(server string) DANEResolverOption {
	return func(r *StandardDANEResolver) {
		r.server = server
	}
}

// WithDANETimeout sets the timeout for TLSA DNS lookups.
func WithDANETimeout(timeout time.Duration) DANEResolverOption {
	return func(r *StandardDANEResolver) {
		r.timeout = timeout
	}
}

const (
	defaultDANEServer  = "8.8.8.8:53"
	defaultDANETimeout = 5 * time.Second
	// edns0BufSize is the EDNS0 UDP buffer size for DNSSEC-aware queries.
	edns0BufSize = 4096
)

// StandardDANEResolver performs real DNSSEC-aware TLSA lookups using miekg/dns.
type StandardDANEResolver struct {
	server  string
	timeout time.Duration
}

// NewStandardDANEResolver creates a new StandardDANEResolver with the given options.
func NewStandardDANEResolver(opts ...DANEResolverOption) *StandardDANEResolver {
	r := &StandardDANEResolver{
		server:  defaultDANEServer,
		timeout: defaultDANETimeout,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// LookupTLSA queries TLSA records for the given FQDN and port.
func (r *StandardDANEResolver) LookupTLSA(ctx context.Context, fqdn models.Fqdn, port uint16) (TLSALookupResult, error) {
	tlsaName := fqdn.TlsaName(port) + "."

	msg := new(dns.Msg)
	msg.SetQuestion(tlsaName, dns.TypeTLSA)
	msg.SetEdns0(edns0BufSize, true) // Enable DNSSEC OK flag
	msg.RecursionDesired = true

	client := new(dns.Client)
	client.Timeout = r.timeout

	// Use context deadline if shorter than configured timeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < client.Timeout {
			client.Timeout = remaining
		}
	}

	resp, _, err := client.ExchangeContext(ctx, msg, r.server)
	if err != nil {
		return TLSALookupResult{}, &DANEError{
			Type:   DANEErrorLookupFailed,
			Fqdn:   fqdn.String(),
			Reason: err.Error(),
		}
	}

	// SERVFAIL with DNSSEC requested typically means DNSSEC validation failed
	if resp.Rcode == dns.RcodeServerFailure {
		return TLSALookupResult{}, &DANEError{
			Type:   DANEErrorDNSSECFailed,
			Fqdn:   fqdn.String(),
			Reason: "SERVFAIL response (possible DNSSEC validation failure)",
		}
	}

	// NXDOMAIN or no answer means no TLSA records
	if resp.Rcode == dns.RcodeNameError || len(resp.Answer) == 0 {
		return TLSALookupResult{Found: false}, nil
	}

	// Parse TLSA records from response
	var records []TLSARecord
	for _, rr := range resp.Answer {
		if tlsa, ok := rr.(*dns.TLSA); ok {
			records = append(records, TLSARecord{
				Usage:        tlsa.Usage,
				Selector:     tlsa.Selector,
				MatchingType: tlsa.MatchingType,
				// miekg/dns stores Certificate as a hex string already — just lowercase it.
				CertHash: strings.ToLower(tlsa.Certificate),
			})
		}
	}

	if len(records) == 0 {
		return TLSALookupResult{Found: false}, nil
	}

	return TLSALookupResult{
		Found:       true,
		Records:     records,
		DNSSECValid: resp.AuthenticatedData,
	}, nil
}
