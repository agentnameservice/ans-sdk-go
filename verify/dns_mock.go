package verify

import (
	"context"
	"sort"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/models"
)

// MockDNSResolver is a mock DNS resolver for testing.
type MockDNSResolver struct {
	records   map[string][]AnsBadgeRecord
	raRecords map[string][]AnsBadgeRecord
	errors    map[string]error
}

// NewMockDNSResolver creates a new MockDNSResolver.
func NewMockDNSResolver() *MockDNSResolver {
	return &MockDNSResolver{
		records:   make(map[string][]AnsBadgeRecord),
		raRecords: make(map[string][]AnsBadgeRecord),
		errors:    make(map[string]error),
	}
}

// WithRecords adds _ans-badge records for an FQDN.
func (r *MockDNSResolver) WithRecords(fqdn string, records []AnsBadgeRecord) *MockDNSResolver {
	r.records[strings.ToLower(fqdn)] = records
	return r
}

// WithRaBadgeRecords adds _ra-badge (legacy) records for an FQDN.
func (r *MockDNSResolver) WithRaBadgeRecords(fqdn string, records []AnsBadgeRecord) *MockDNSResolver {
	r.raRecords[strings.ToLower(fqdn)] = records
	return r
}

// WithError configures an error for an FQDN.
func (r *MockDNSResolver) WithError(fqdn string, err error) *MockDNSResolver {
	r.errors[strings.ToLower(fqdn)] = err
	return r
}

// LookupAnsBadge queries _ans-badge TXT records for an FQDN.
// If _ans-badge returns no records (not found), falls back to _ra-badge.
// On hard errors (SERVFAIL/timeout), does NOT fallback.
func (r *MockDNSResolver) LookupAnsBadge(_ context.Context, fqdn models.Fqdn) (DNSLookupResult, error) {
	key := strings.ToLower(fqdn.String())

	// Check for configured error first — hard errors do NOT trigger fallback
	if err, ok := r.errors[key]; ok {
		return DNSLookupResult{}, err
	}

	// Try _ans-badge records first
	if records, ok := r.records[key]; ok && len(records) > 0 {
		recordsCopy := make([]AnsBadgeRecord, len(records))
		copy(recordsCopy, records)
		for i := range recordsCopy {
			recordsCopy[i].Source = BadgeRecordSourceAnsBadge
		}
		return DNSLookupResult{Found: true, Records: recordsCopy}, nil
	}

	// Fallback to _ra-badge records
	if raRecords, ok := r.raRecords[key]; ok && len(raRecords) > 0 {
		recordsCopy := make([]AnsBadgeRecord, len(raRecords))
		copy(recordsCopy, raRecords)
		for i := range recordsCopy {
			recordsCopy[i].Source = BadgeRecordSourceRaBadge
		}
		return DNSLookupResult{Found: true, Records: recordsCopy}, nil
	}

	return DNSLookupResult{Found: false}, nil
}

// FindBadgeForVersion finds the badge record matching a specific version.
// Prefers an exact version match; falls back to a versionless record if no exact match exists.
func (r *MockDNSResolver) FindBadgeForVersion(ctx context.Context, fqdn models.Fqdn, version models.Version) (*AnsBadgeRecord, error) {
	result, err := r.LookupAnsBadge(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	if !result.Found {
		return nil, ErrRecordNotFound
	}

	// First pass: exact version match
	for _, record := range result.Records {
		if record.Version != nil && record.Version.Equal(version) {
			return &record, nil
		}
	}

	// Second pass: versionless record as fallback (matches any version)
	for _, record := range result.Records {
		if record.Version == nil {
			return &record, nil
		}
	}

	return nil, ErrRecordNotFound
}

// FindPreferredBadge finds the preferred badge (newest version).
func (r *MockDNSResolver) FindPreferredBadge(ctx context.Context, fqdn models.Fqdn) (*AnsBadgeRecord, error) {
	result, err := r.LookupAnsBadge(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	if !result.Found || len(result.Records) == 0 {
		return nil, ErrRecordNotFound
	}

	records := result.Records

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
