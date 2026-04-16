package verify

import (
	"fmt"

	"github.com/godaddy/ans-sdk-go/models"
)

// OutcomeType represents the type of verification outcome.
type OutcomeType int

const (
	// OutcomeVerified indicates verification passed.
	OutcomeVerified OutcomeType = iota
	// OutcomeNotAnsAgent indicates no _ans-badge record found.
	OutcomeNotAnsAgent
	// OutcomeInvalidStatus indicates badge status is invalid for connections.
	OutcomeInvalidStatus
	// OutcomeFingerprintMismatch indicates certificate fingerprint mismatch.
	OutcomeFingerprintMismatch
	// OutcomeHostnameMismatch indicates hostname mismatch.
	OutcomeHostnameMismatch
	// OutcomeAnsNameMismatch indicates ANS name mismatch.
	OutcomeAnsNameMismatch
	// OutcomeDNSError indicates DNS resolution failed.
	OutcomeDNSError
	// OutcomeTlogError indicates transparency log error.
	OutcomeTlogError
	// OutcomeCertError indicates certificate parsing error.
	OutcomeCertError
	// OutcomeFailOpen indicates verification was skipped due to fail-open policy.
	OutcomeFailOpen
	// OutcomeURLValidationError indicates the badge URL failed validation.
	OutcomeURLValidationError
	// OutcomeDANERejection indicates DANE/TLSA verification rejected the certificate.
	OutcomeDANERejection
	// OutcomeScittError indicates a SCITT verification error.
	OutcomeScittError
)

// VerificationTier represents the level of SCITT verification achieved.
type VerificationTier int

const (
	// TierBadgeOnly indicates only badge-based verification was performed.
	TierBadgeOnly VerificationTier = iota
	// TierStatusTokenVerified indicates the status token was cryptographically verified.
	TierStatusTokenVerified
	// TierFullScitt indicates both receipt and status token were cryptographically verified.
	TierFullScitt
)

// String returns a human-readable representation of the verification tier.
func (t VerificationTier) String() string {
	switch t {
	case TierBadgeOnly:
		return "BadgeOnly"
	case TierStatusTokenVerified:
		return "StatusTokenVerified"
	case TierFullScitt:
		return "FullScitt"
	default:
		return fmt.Sprintf("VerificationTier(%d)", int(t))
	}
}

// VerificationOutcome represents the result of a verification operation.
type VerificationOutcome struct {
	// Type is the outcome type.
	Type OutcomeType
	// Tier indicates the SCITT verification level achieved (defaults to TierBadgeOnly).
	Tier VerificationTier
	// Badge is the badge if verification partially completed (may be nil).
	Badge *models.Badge
	// MatchedFingerprint is the fingerprint that matched (for successful verification).
	MatchedFingerprint *CertFingerprint
	// Expected is the expected value for mismatch errors.
	Expected string
	// Actual is the actual value for mismatch errors.
	Actual string
	// Status is the badge status for invalid status errors.
	Status models.BadgeStatus
	// Host is the hostname being verified (for error context).
	Host string
	// Error is the underlying error if any.
	Error error
	// Warnings contains non-fatal warnings (e.g., DEPRECATED badge status).
	Warnings []string
	// DANEOutcome contains the DANE/TLSA verification result (nil if DANE not configured).
	DANEOutcome *DANEOutcome
}

// NewVerifiedOutcome creates a successful verification outcome.
func NewVerifiedOutcome(badge *models.Badge, fingerprint CertFingerprint) *VerificationOutcome {
	return &VerificationOutcome{
		Type:               OutcomeVerified,
		Badge:              badge,
		MatchedFingerprint: &fingerprint,
	}
}

// NewNotAnsAgentOutcome creates a not-ANS-agent outcome.
func NewNotAnsAgentOutcome(host string) *VerificationOutcome {
	return &VerificationOutcome{
		Type: OutcomeNotAnsAgent,
		Host: host,
	}
}

// NewInvalidStatusOutcome creates an invalid status outcome.
func NewInvalidStatusOutcome(badge *models.Badge, status models.BadgeStatus) *VerificationOutcome {
	return &VerificationOutcome{
		Type:   OutcomeInvalidStatus,
		Badge:  badge,
		Status: status,
	}
}

// NewFingerprintMismatchOutcome creates a fingerprint mismatch outcome.
func NewFingerprintMismatchOutcome(badge *models.Badge, expected, actual string) *VerificationOutcome {
	return &VerificationOutcome{
		Type:     OutcomeFingerprintMismatch,
		Badge:    badge,
		Expected: expected,
		Actual:   actual,
	}
}

// NewHostnameMismatchOutcome creates a hostname mismatch outcome.
func NewHostnameMismatchOutcome(badge *models.Badge, expected, actual string) *VerificationOutcome {
	return &VerificationOutcome{
		Type:     OutcomeHostnameMismatch,
		Badge:    badge,
		Expected: expected,
		Actual:   actual,
	}
}

// NewAnsNameMismatchOutcome creates an ANS name mismatch outcome.
func NewAnsNameMismatchOutcome(badge *models.Badge, expected, actual string) *VerificationOutcome {
	return &VerificationOutcome{
		Type:     OutcomeAnsNameMismatch,
		Badge:    badge,
		Expected: expected,
		Actual:   actual,
	}
}

// NewDNSErrorOutcome creates a DNS error outcome.
func NewDNSErrorOutcome(err error) *VerificationOutcome {
	return &VerificationOutcome{
		Type:  OutcomeDNSError,
		Error: err,
	}
}

// NewTlogErrorOutcome creates a transparency log error outcome.
func NewTlogErrorOutcome(err error) *VerificationOutcome {
	return &VerificationOutcome{
		Type:  OutcomeTlogError,
		Error: err,
	}
}

// NewURLValidationErrorOutcome creates a URL validation error outcome.
func NewURLValidationErrorOutcome(err error) *VerificationOutcome {
	return &VerificationOutcome{
		Type:  OutcomeURLValidationError,
		Error: err,
	}
}

// NewFailOpenOutcome creates a fail-open outcome (verification skipped).
func NewFailOpenOutcome(err error) *VerificationOutcome {
	return &VerificationOutcome{
		Type:  OutcomeFailOpen,
		Error: err,
	}
}

// NewDANERejectionOutcome creates a DANE rejection outcome.
func NewDANERejectionOutcome(badge *models.Badge, daneOutcome *DANEOutcome) *VerificationOutcome {
	return &VerificationOutcome{
		Type:        OutcomeDANERejection,
		Badge:       badge,
		Error:       daneOutcome.Error,
		DANEOutcome: daneOutcome,
	}
}

// NewCertErrorOutcome creates a certificate error outcome.
func NewCertErrorOutcome(err error) *VerificationOutcome {
	return &VerificationOutcome{
		Type:  OutcomeCertError,
		Error: err,
	}
}

// NewScittVerifiedOutcome creates a SCITT-verified outcome with the given tier.
func NewScittVerifiedOutcome(badge *models.Badge, fingerprint CertFingerprint, tier VerificationTier) *VerificationOutcome {
	return &VerificationOutcome{
		Type:               OutcomeVerified,
		Tier:               tier,
		Badge:              badge,
		MatchedFingerprint: &fingerprint,
	}
}

// NewScittErrorOutcome creates a SCITT error outcome.
func NewScittErrorOutcome(err error) *VerificationOutcome {
	return &VerificationOutcome{
		Type:  OutcomeScittError,
		Error: err,
	}
}

// IsSuccess returns true if verification was successful or fail-open was applied.
func (o *VerificationOutcome) IsSuccess() bool {
	return o.Type == OutcomeVerified || o.Type == OutcomeFailOpen
}

// IsFailOpen returns true if verification was skipped due to fail-open policy.
func (o *VerificationOutcome) IsFailOpen() bool {
	return o.Type == OutcomeFailOpen
}

// IsNotAnsAgent returns true if the agent is not registered with ANS.
func (o *VerificationOutcome) IsNotAnsAgent() bool {
	return o.Type == OutcomeNotAnsAgent
}

// ToError converts the outcome to an error if verification failed.
func (o *VerificationOutcome) ToError() error {
	switch o.Type {
	case OutcomeVerified, OutcomeFailOpen:
		return nil
	case OutcomeNotAnsAgent:
		// If an underlying error exists, return it directly for better context
		if o.Error != nil {
			return o.Error
		}
		host := o.Host
		if host == "" {
			host = "unknown"
		}
		return &DNSError{Type: DNSErrorNotFound, Fqdn: host}
	case OutcomeInvalidStatus:
		return &VerificationError{
			Type:   VerificationErrorInvalidStatus,
			Actual: string(o.Status),
		}
	case OutcomeFingerprintMismatch:
		return &VerificationError{
			Type:     VerificationErrorFingerprintMismatch,
			Expected: o.Expected,
			Actual:   o.Actual,
		}
	case OutcomeHostnameMismatch:
		return &VerificationError{
			Type:     VerificationErrorHostnameMismatch,
			Expected: o.Expected,
			Actual:   o.Actual,
		}
	case OutcomeAnsNameMismatch:
		return &VerificationError{
			Type:     VerificationErrorAnsNameMismatch,
			Expected: o.Expected,
			Actual:   o.Actual,
		}
	case OutcomeDANERejection:
		return o.Error
	case OutcomeDNSError, OutcomeTlogError, OutcomeCertError, OutcomeURLValidationError, OutcomeScittError:
		return o.Error
	default:
		return o.Error
	}
}
