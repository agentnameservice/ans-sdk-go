package verify

import (
	"context"
	"errors"
	"net"
	"sort"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
)

// Default DNS configuration values.
const defaultDNSTimeoutSeconds = 10

// ErrRecordNotFound is returned when no matching badge record is found.
// This is not an error condition - it means the FQDN is not an ANS agent.
var ErrRecordNotFound = errors.New("no matching badge record found")

// StandardDNSResolver implements DNSResolver using Go's net.Resolver.
type StandardDNSResolver struct {
	resolver *net.Resolver
	timeout  time.Duration
}

// NewStandardDNSResolver creates a new StandardDNSResolver with default settings.
func NewStandardDNSResolver() *StandardDNSResolver {
	return &StandardDNSResolver{
		resolver: net.DefaultResolver,
		timeout:  defaultDNSTimeoutSeconds * time.Second,
	}
}

// WithResolver sets a custom net.Resolver.
func (r *StandardDNSResolver) WithResolver(resolver *net.Resolver) *StandardDNSResolver {
	r.resolver = resolver
	return r
}

// WithTimeout sets the lookup timeout.
func (r *StandardDNSResolver) WithTimeout(timeout time.Duration) *StandardDNSResolver {
	r.timeout = timeout
	return r
}

// LookupAnsBadge queries _ans-badge TXT records for an FQDN.
// If _ans-badge returns NXDOMAIN/NotFound, falls back to _ra-badge.
// On hard errors (SERVFAIL/timeout), does NOT fallback.
func (r *StandardDNSResolver) LookupAnsBadge(ctx context.Context, fqdn models.Fqdn) (DNSLookupResult, error) {
	// Try _ans-badge first
	result, err := r.lookupBadgeRecords(ctx, fqdn.AnsBadgeName(), BadgeRecordSourceAnsBadge)
	if err != nil {
		// Hard error — do NOT fallback
		return result, err
	}
	if result.Found {
		return result, nil
	}

	// Fallback to _ra-badge
	return r.lookupBadgeRecords(ctx, fqdn.RaBadgeName(), BadgeRecordSourceRaBadge)
}

// lookupBadgeRecords queries a specific DNS name for badge TXT records.
func (r *StandardDNSResolver) lookupBadgeRecords(ctx context.Context, queryName string, source BadgeRecordSource) (DNSLookupResult, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	txts, err := r.resolver.LookupTXT(ctx, queryName)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return DNSLookupResult{Found: false}, nil
		}
		// Hard error (timeout, SERVFAIL, etc.)
		return r.handleLookupError(err, queryName)
	}

	var records []AnsBadgeRecord
	for _, txt := range txts {
		if record, parseErr := ParseAnsBadgeRecord(txt); parseErr == nil {
			record.Source = source
			records = append(records, *record)
		}
	}

	if len(records) == 0 {
		return DNSLookupResult{Found: false}, nil
	}

	return DNSLookupResult{Found: true, Records: records}, nil
}

// handleLookupError converts net.DNSError to appropriate results.
func (r *StandardDNSResolver) handleLookupError(err error, queryName string) (DNSLookupResult, error) {
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return DNSLookupResult{}, &DNSError{
			Type:   DNSErrorLookupFailed,
			Fqdn:   queryName,
			Reason: err.Error(),
		}
	}

	if dnsErr.IsNotFound {
		return DNSLookupResult{Found: false}, nil
	}

	if dnsErr.IsTimeout {
		return DNSLookupResult{}, &DNSError{Type: DNSErrorTimeout, Fqdn: queryName}
	}

	return DNSLookupResult{}, &DNSError{
		Type:   DNSErrorLookupFailed,
		Fqdn:   queryName,
		Reason: err.Error(),
	}
}

// FindBadgeForVersion finds the badge record matching a specific version.
// Prefers an exact version match; falls back to a versionless record if no exact match exists.
func (r *StandardDNSResolver) FindBadgeForVersion(ctx context.Context, fqdn models.Fqdn, version models.Version) (*AnsBadgeRecord, error) {
	records, err := GetAnsBadgeRecords(ctx, r, fqdn)
	if err != nil {
		if isNotFoundError(err) {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}

	// First pass: exact version match
	for _, record := range records {
		if record.Version != nil && record.Version.Equal(version) {
			return &record, nil
		}
	}

	// Second pass: versionless record as fallback (matches any version)
	for _, record := range records {
		if record.Version == nil {
			return &record, nil
		}
	}

	return nil, ErrRecordNotFound
}

// FindPreferredBadge finds the preferred badge (newest version).
func (r *StandardDNSResolver) FindPreferredBadge(ctx context.Context, fqdn models.Fqdn) (*AnsBadgeRecord, error) {
	records, err := GetAnsBadgeRecords(ctx, r, fqdn)
	if err != nil {
		if isNotFoundError(err) {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}

	if len(records) == 0 {
		return nil, ErrRecordNotFound
	}

	// Sort by version descending (newest first), nil versions go last
	sort.Slice(records, func(i, j int) bool {
		vi := records[i].Version
		vj := records[j].Version

		if vi == nil && vj == nil {
			return false
		}
		if vi == nil {
			return false // nil goes last
		}
		if vj == nil {
			return true // non-nil comes first
		}
		return vi.Compare(*vj) > 0 // Higher version first
	})

	return &records[0], nil
}

// isNotFoundError checks if the error indicates record not found.
func isNotFoundError(err error) bool {
	var dnsErr *DNSError
	return errors.As(err, &dnsErr) && dnsErr.Type == DNSErrorNotFound
}
