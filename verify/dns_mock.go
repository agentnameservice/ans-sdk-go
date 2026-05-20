package verify

import (
	"context"
	"sort"
	"strings"

	"github.com/godaddy/ans-sdk-go/models"
)

// MockDNSResolver is a mock DNS resolver for testing.
type MockDNSResolver struct {
	records    map[string][]AnsBadgeRecord
	raRecords  map[string][]AnsBadgeRecord
	errors     map[string]error
	primaryErr map[string]error
	raBadgeErr map[string]error
}

// NewMockDNSResolver creates a new MockDNSResolver.
func NewMockDNSResolver() *MockDNSResolver {
	return &MockDNSResolver{
		records:    make(map[string][]AnsBadgeRecord),
		raRecords:  make(map[string][]AnsBadgeRecord),
		errors:     make(map[string]error),
		primaryErr: make(map[string]error),
		raBadgeErr: make(map[string]error),
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

// WithError configures an error returned by both primary and fallback lookups
// for an FQDN. Use WithPrimaryError to inject an error only on the primary
// query (so the fallback can still resolve).
func (r *MockDNSResolver) WithError(fqdn string, err error) *MockDNSResolver {
	r.errors[strings.ToLower(fqdn)] = err
	return r
}

// WithPrimaryError configures an error that the primary _ans-badge lookup
// returns. The fallback _ra-badge lookup is unaffected, allowing tests to
// exercise the "primary errored, fallback succeeded" path.
func (r *MockDNSResolver) WithPrimaryError(fqdn string, err error) *MockDNSResolver {
	r.primaryErr[strings.ToLower(fqdn)] = err
	return r
}

// WithRaBadgeError configures an error that the fallback _ra-badge lookup
// returns. Mirrors WithPrimaryError for the legacy record.
func (r *MockDNSResolver) WithRaBadgeError(fqdn string, err error) *MockDNSResolver {
	r.raBadgeErr[strings.ToLower(fqdn)] = err
	return r
}

// LookupAnsBadge queries _ans-badge TXT records for an FQDN.
//
// Mirrors the production resolver's source-selection rule: _ans-badge wins
// when it returns valid records; otherwise the resolver falls back to
// _ra-badge for any reason (NotFound or transient error). When fallback is
// triggered by a primary error, that error is stamped onto each fallback
// record's PrimaryError field.
func (r *MockDNSResolver) LookupAnsBadge(_ context.Context, fqdn models.Fqdn) (DNSLookupResult, error) {
	key := strings.ToLower(fqdn.String())

	// Whole-lookup error: applied to the primary, fallback also fails the
	// same way — equivalent to a server-side outage hitting both records.
	if err, ok := r.errors[key]; ok {
		return DNSLookupResult{}, err
	}

	// Primary lookup
	primaryErr := r.primaryErr[key]
	if primaryErr == nil {
		if records, ok := r.records[key]; ok && len(records) > 0 {
			primaryRecords := make([]AnsBadgeRecord, len(records))
			copy(primaryRecords, records)
			for i := range primaryRecords {
				primaryRecords[i].Source = BadgeRecordSourceAnsBadge
			}
			return DNSLookupResult{Found: true, Records: primaryRecords}, nil
		}
	}

	// Fallback lookup
	if fbErr, ok := r.raBadgeErr[key]; ok {
		if primaryErr != nil {
			return DNSLookupResult{}, primaryErr
		}
		return DNSLookupResult{}, fbErr
	}
	if raRecords, ok := r.raRecords[key]; ok && len(raRecords) > 0 {
		recordsCopy := make([]AnsBadgeRecord, len(raRecords))
		copy(recordsCopy, raRecords)
		for i := range recordsCopy {
			recordsCopy[i].Source = BadgeRecordSourceRaBadge
			if primaryErr != nil {
				recordsCopy[i].PrimaryError = primaryErr
			}
		}
		return DNSLookupResult{Found: true, Records: recordsCopy}, nil
	}

	if primaryErr != nil {
		return DNSLookupResult{}, primaryErr
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
