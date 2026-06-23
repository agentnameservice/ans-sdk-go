package verify

import (
	"context"

	"github.com/agentnameservice/ans-sdk-go/models"
)

// DNSLookupResult represents the result of a DNS lookup.
type DNSLookupResult struct {
	// Found indicates whether records were found.
	Found bool
	// Records contains the found records (empty if not found).
	Records []AnsBadgeRecord
}

// DNSResolver is the interface for DNS resolution.
type DNSResolver interface {
	// LookupAnsBadge queries _ans-badge TXT records for an FQDN.
	LookupAnsBadge(ctx context.Context, fqdn models.Fqdn) (DNSLookupResult, error)

	// FindBadgeForVersion finds the badge record matching a specific version.
	FindBadgeForVersion(ctx context.Context, fqdn models.Fqdn, version models.Version) (*AnsBadgeRecord, error)

	// FindPreferredBadge finds the preferred badge (newest version).
	FindPreferredBadge(ctx context.Context, fqdn models.Fqdn) (*AnsBadgeRecord, error)
}

// GetAnsBadgeRecords is a convenience method that returns records or error for not found.
func GetAnsBadgeRecords(ctx context.Context, resolver DNSResolver, fqdn models.Fqdn) ([]AnsBadgeRecord, error) {
	result, err := resolver.LookupAnsBadge(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	if !result.Found {
		return nil, &DNSError{Type: DNSErrorNotFound, Fqdn: fqdn.String()}
	}
	return result.Records, nil
}
