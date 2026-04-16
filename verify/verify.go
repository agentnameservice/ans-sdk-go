package verify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/godaddy/ans-sdk-go/models"
	"github.com/godaddy/ans-sdk-go/verify/scitt"
)

// applyFailurePolicy applies the configured failure policy when DNS or TLog errors occur.
// For FailClosed, returns the original error outcome.
// For FailOpenWithCache, checks stale cache entries.
// For FailOpen, returns a pass-through outcome.
func applyFailurePolicy(config *verifierConfig, fqdn models.Fqdn, version *models.Version, errorOutcome *VerificationOutcome) *VerificationOutcome {
	switch config.failurePolicy {
	case FailClosed:
		return errorOutcome
	case FailOpenWithCache:
		return applyFailOpenWithCache(config, fqdn, version, errorOutcome)
	case FailOpen:
		return NewFailOpenOutcome(errorOutcome.Error)
	}
	return errorOutcome
}

// applyFailOpenWithCache attempts to use a stale cached badge for fail-open-with-cache policy.
func applyFailOpenWithCache(config *verifierConfig, fqdn models.Fqdn, version *models.Version, errorOutcome *VerificationOutcome) *VerificationOutcome {
	if config.cache == nil {
		return errorOutcome
	}

	maxStale := config.failurePolicyConfig.MaxStaleness
	if version != nil {
		if cached, ok := config.cache.GetStaleByFqdnVersion(fqdn, *version, maxStale); ok {
			return &VerificationOutcome{Type: OutcomeFailOpen, Badge: cached.Badge}
		}
	} else {
		if cached, ok := config.cache.GetStaleByFqdn(fqdn, maxStale); ok {
			return &VerificationOutcome{Type: OutcomeFailOpen, Badge: cached.Badge}
		}
	}
	return errorOutcome
}

// defaultDANEPort is the standard HTTPS port used for DANE/TLSA lookups.
const defaultDANEPort = 443

// verifyDANE performs an optional DANE/TLSA check if a DANEResolver is configured.
// Returns nil if DANE is not configured, passes, or should be skipped.
// Returns an error outcome only if DANE explicitly rejects (mismatch or DNSSEC failure).
func verifyDANE(ctx context.Context, config *verifierConfig, fqdn models.Fqdn, cert *CertIdentity, outcome *VerificationOutcome) *VerificationOutcome {
	if config.daneResolver == nil {
		return nil
	}

	daneVerifier := NewDANEVerifier(config.daneResolver)
	daneOutcome := daneVerifier.Verify(ctx, fqdn, defaultDANEPort, cert)

	if daneOutcome.IsReject() {
		return NewDANERejectionOutcome(outcome.Badge, daneOutcome)
	}

	// DANE passed, skipped, no records, or lookup error — add info to outcome
	if daneOutcome.IsPass() && daneOutcome.Type == DANEVerified {
		outcome.DANEOutcome = daneOutcome
	}

	return nil
}

// validateBadgeURL validates a badge URL against the configured URL validator.
// Returns nil if validation passes or no validator is configured.
func validateBadgeURL(config *verifierConfig, badgeURL string) *VerificationOutcome {
	if config.urlValidator == nil {
		return nil
	}
	if err := config.urlValidator.Validate(badgeURL); err != nil {
		return NewURLValidationErrorOutcome(err)
	}
	return nil
}

// ServerVerifier verifies server certificates against the ANS transparency log.
// Use this when a client wants to verify that a server is a legitimate ANS agent.
type ServerVerifier struct {
	config *verifierConfig
}

// NewServerVerifier creates a new server verifier with the given options.
func NewServerVerifier(opts ...Option) *ServerVerifier {
	config := defaultConfig()
	for _, opt := range opts {
		opt(config)
	}
	return &ServerVerifier{config: config}
}

// Verify verifies a server certificate for the given FQDN.
func (v *ServerVerifier) Verify(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity) *VerificationOutcome {
	log := configLogger(v.config)

	// 1. Check cache first
	if v.config.cache != nil {
		if cached, ok := v.config.cache.GetByFqdn(fqdn); ok {
			log.DebugContext(ctx, "badge verification: cache check",
				slog.String("fqdn", fqdn.String()), slog.Bool("cache_hit", true))
			result := v.verifyWithBadge(cached.Badge, cert, fqdn)
			if result.Type != OutcomeFingerprintMismatch {
				// Cache hit: either success or non-fingerprint failure (hostname, status)
				return result
			}
			// Fingerprint mismatch from cache — may be stale after cert renewal.
			// Fall through to fetch fresh badge.
		} else {
			log.DebugContext(ctx, "badge verification: cache check",
				slog.String("fqdn", fqdn.String()), slog.Bool("cache_hit", false))
		}
	}

	// 2. Fetch badge from DNS + TLog
	badge, outcome := v.fetchBadge(ctx, fqdn)
	if outcome != nil {
		return outcome
	}

	// 3. Cache the badge
	if v.config.cache != nil {
		v.config.cache.Insert(fqdn, badge)
	}

	// 4. Verify against badge
	outcome = v.verifyWithBadge(badge, cert, fqdn)
	if !outcome.IsSuccess() {
		return outcome
	}

	// 5. Optional DANE/TLSA check (can reject even if badge verification passed)
	if rejection := verifyDANE(ctx, v.config, fqdn, cert, outcome); rejection != nil {
		return rejection
	}

	return outcome
}

// Prefetch fetches and caches a badge for an FQDN.
// Returns immediately if a fresh cached entry exists.
func (v *ServerVerifier) Prefetch(ctx context.Context, fqdn models.Fqdn) (*models.Badge, error) {
	// Return cached badge if available and not expired
	if v.config.cache != nil {
		if cached, ok := v.config.cache.GetByFqdn(fqdn); ok {
			return cached.Badge, nil
		}
	}

	badge, outcome := v.fetchBadge(ctx, fqdn)
	if outcome != nil {
		return nil, outcome.ToError()
	}

	if v.config.cache != nil {
		v.config.cache.Insert(fqdn, badge)
	}

	return badge, nil
}

// VerifyWithScitt verifies a server certificate using SCITT receipts and status tokens.
// If headers are empty or nil, delegates to the standard badge-based Verify().
// If SCITT verification encounters a fallback-eligible transport error, falls back to badge.
func (v *ServerVerifier) VerifyWithScitt(ctx context.Context, fqdn models.Fqdn, cert *CertIdentity, headers *scitt.Headers) *VerificationOutcome {
	log := configLogger(v.config)

	// Empty headers → badge path
	if headers == nil || headers.IsEmpty() {
		log.InfoContext(ctx, "VerifyWithScitt: no SCITT headers, falling back to badge",
			slog.String("fqdn", fqdn.String()))
		return v.Verify(ctx, fqdn, cert)
	}

	// Both required per spec
	if !headers.HasBoth() {
		log.WarnContext(ctx, "VerifyWithScitt: partial SCITT headers, rejecting",
			slog.String("fqdn", fqdn.String()),
			slog.Bool("has_receipt", len(headers.Receipt) > 0),
			slog.Bool("has_token", len(headers.StatusToken) > 0))
		return NewScittErrorOutcome(errors.New("both X-SCITT-Receipt and X-ANS-Status-Token headers are required"))
	}

	return verifyWithHeaders(ctx, v.config, fqdn, cert, headers, log,
		func() *VerificationOutcome { return v.Verify(ctx, fqdn, cert) })
}

// fetchBadge fetches a badge from DNS and TLog.
func (v *ServerVerifier) fetchBadge(ctx context.Context, fqdn models.Fqdn) (*models.Badge, *VerificationOutcome) {
	log := configLogger(v.config)

	// DNS lookup
	log.DebugContext(ctx, "fetchBadge: DNS lookup", slog.String("fqdn", fqdn.String()))
	record, err := v.config.dnsResolver.FindPreferredBadge(ctx, fqdn)
	if err != nil {
		// ErrRecordNotFound means not an ANS agent — never apply failure policy
		if errors.Is(err, ErrRecordNotFound) {
			return nil, NewNotAnsAgentOutcome(fqdn.String())
		}
		log.WarnContext(ctx, "fetchBadge: DNS error",
			slog.String("fqdn", fqdn.String()), slog.String("error", err.Error()))
		outcome := NewDNSErrorOutcome(err)
		return nil, applyFailurePolicy(v.config, fqdn, nil, outcome)
	}
	if record == nil {
		return nil, NewNotAnsAgentOutcome(fqdn.String())
	}

	// Validate badge URL before fetching
	if outcome := validateBadgeURL(v.config, record.URL); outcome != nil {
		return nil, outcome
	}

	// Fetch badge from transparency log
	log.DebugContext(ctx, "fetchBadge: fetching badge", slog.String("url", record.URL))
	badge, err := v.config.tlogClient.FetchBadge(ctx, record.URL)
	if err != nil {
		log.WarnContext(ctx, "fetchBadge: TLog error",
			slog.String("url", record.URL), slog.String("error", err.Error()))
		outcome := NewTlogErrorOutcome(err)
		return nil, applyFailurePolicy(v.config, fqdn, nil, outcome)
	}

	return badge, nil
}

// verifyWithBadge verifies a certificate against a badge.
func (v *ServerVerifier) verifyWithBadge(badge *models.Badge, cert *CertIdentity, fqdn models.Fqdn) *VerificationOutcome {
	// Check badge status
	if !badge.Status.IsValidForConnection() {
		return NewInvalidStatusOutcome(badge, badge.Status)
	}

	// Compare server certificate fingerprint
	expectedFP := badge.ServerCertFingerprint()
	if !cert.Fingerprint.Matches(expectedFP) {
		return NewFingerprintMismatchOutcome(badge, expectedFP, cert.Fingerprint.String())
	}

	// Compare hostname
	badgeHost := badge.AgentHost()
	certFqdn := cert.FQDN()

	if !strings.EqualFold(badgeHost, fqdn.String()) {
		return NewHostnameMismatchOutcome(badge, fqdn.String(), badgeHost)
	}

	if certFqdn != nil && !strings.EqualFold(*certFqdn, badgeHost) {
		return NewHostnameMismatchOutcome(badge, badgeHost, *certFqdn)
	}

	outcome := NewVerifiedOutcome(badge, cert.Fingerprint)
	if badge.Status == models.BadgeStatusDeprecated {
		outcome.Warnings = append(outcome.Warnings, "badge status is DEPRECATED")
	}
	return outcome
}

// ClientVerifier verifies mTLS client certificates against the ANS transparency log.
// Use this when a server wants to verify that an mTLS client is a legitimate ANS agent.
type ClientVerifier struct {
	config *verifierConfig
}

// NewClientVerifier creates a new client verifier with the given options.
func NewClientVerifier(opts ...Option) *ClientVerifier {
	config := defaultConfig()
	for _, opt := range opts {
		opt(config)
	}
	return &ClientVerifier{config: config}
}

// Verify verifies an mTLS client certificate.
func (v *ClientVerifier) Verify(ctx context.Context, cert *CertIdentity) *VerificationOutcome {
	// 1. Extract FQDN from cert
	fqdnStr := cert.FQDN()
	if fqdnStr == nil {
		return NewCertErrorOutcome(&VerificationError{Type: VerificationErrorNoCN})
	}

	fqdn, err := models.NewFqdn(*fqdnStr)
	if err != nil {
		return NewCertErrorOutcome(err)
	}

	// 2. Extract ANS name from URI SANs
	ansName := cert.AnsName()
	if ansName == nil {
		return NewCertErrorOutcome(&VerificationError{Type: VerificationErrorNoURISAN})
	}

	// 3. Extract version
	version := ansName.Version

	// 4. Check cache first (by FQDN + version)
	if v.config.cache != nil {
		if cached, ok := v.config.cache.GetByFqdnVersion(fqdn, version); ok {
			return v.verifyWithBadge(cached.Badge, cert, fqdn, ansName)
		}
	}

	// 5. Fetch badge from DNS + TLog (matching version)
	badge, outcome := v.fetchBadge(ctx, fqdn, version)
	if outcome != nil {
		return outcome
	}

	// 6. Cache the badge
	if v.config.cache != nil {
		v.config.cache.InsertForVersion(fqdn, version, badge)
	}

	// 7. Verify against badge
	outcome = v.verifyWithBadge(badge, cert, fqdn, ansName)
	if !outcome.IsSuccess() {
		return outcome
	}

	// 8. Optional DANE/TLSA check (can reject even if badge verification passed)
	if rejection := verifyDANE(ctx, v.config, fqdn, cert, outcome); rejection != nil {
		return rejection
	}

	return outcome
}

// VerifyWithScitt verifies an mTLS client certificate using SCITT receipts and status tokens.
// If headers are empty or nil, delegates to the standard badge-based Verify().
// If SCITT verification encounters a fallback-eligible transport error, falls back to badge.
func (v *ClientVerifier) VerifyWithScitt(ctx context.Context, cert *CertIdentity, headers *scitt.Headers) *VerificationOutcome {
	log := configLogger(v.config)

	// Empty headers → badge path
	if headers == nil || headers.IsEmpty() {
		log.InfoContext(ctx, "VerifyWithScitt: no SCITT headers, falling back to badge")
		return v.Verify(ctx, cert)
	}

	// Both required per spec
	if !headers.HasBoth() {
		log.WarnContext(ctx, "VerifyWithScitt: partial SCITT headers, rejecting",
			slog.Bool("has_receipt", len(headers.Receipt) > 0),
			slog.Bool("has_token", len(headers.StatusToken) > 0))
		return NewScittErrorOutcome(errors.New("both X-SCITT-Receipt and X-ANS-Status-Token headers are required"))
	}

	fqdnStr := cert.FQDN()
	if fqdnStr == nil {
		return NewCertErrorOutcome(&VerificationError{Type: VerificationErrorNoCN})
	}
	fqdn, err := models.NewFqdn(*fqdnStr)
	if err != nil {
		return NewCertErrorOutcome(err)
	}

	return verifyWithHeaders(ctx, v.config, fqdn, cert, headers, log,
		func() *VerificationOutcome { return v.Verify(ctx, cert) })
}

// fetchBadge fetches a badge from DNS and TLog for a specific version.
func (v *ClientVerifier) fetchBadge(ctx context.Context, fqdn models.Fqdn, version models.Version) (*models.Badge, *VerificationOutcome) {
	log := configLogger(v.config)

	// DNS lookup for specific version
	log.DebugContext(ctx, "fetchBadge: DNS lookup", slog.String("fqdn", fqdn.String()))
	record, err := v.config.dnsResolver.FindBadgeForVersion(ctx, fqdn, version)
	if err != nil {
		// ErrRecordNotFound means not an ANS agent — never apply failure policy
		if errors.Is(err, ErrRecordNotFound) {
			return nil, NewNotAnsAgentOutcome(fqdn.String())
		}
		log.WarnContext(ctx, "fetchBadge: DNS error",
			slog.String("fqdn", fqdn.String()), slog.String("error", err.Error()))
		outcome := NewDNSErrorOutcome(err)
		return nil, applyFailurePolicy(v.config, fqdn, &version, outcome)
	}
	if record == nil {
		return nil, NewNotAnsAgentOutcome(fqdn.String())
	}

	// Validate badge URL before fetching
	if outcome := validateBadgeURL(v.config, record.URL); outcome != nil {
		return nil, outcome
	}

	// Fetch badge from transparency log
	log.DebugContext(ctx, "fetchBadge: fetching badge", slog.String("url", record.URL))
	badge, err := v.config.tlogClient.FetchBadge(ctx, record.URL)
	if err != nil {
		log.WarnContext(ctx, "fetchBadge: TLog error",
			slog.String("url", record.URL), slog.String("error", err.Error()))
		outcome := NewTlogErrorOutcome(err)
		return nil, applyFailurePolicy(v.config, fqdn, &version, outcome)
	}

	return badge, nil
}

// verifyWithBadge verifies a client certificate against a badge.
func (v *ClientVerifier) verifyWithBadge(badge *models.Badge, cert *CertIdentity, fqdn models.Fqdn, ansName *AnsName) *VerificationOutcome {
	// Check badge status
	if !badge.Status.IsValidForConnection() {
		return NewInvalidStatusOutcome(badge, badge.Status)
	}

	// Compare identity certificate fingerprint
	expectedFP := badge.IdentityCertFingerprint()
	if !cert.Fingerprint.Matches(expectedFP) {
		return NewFingerprintMismatchOutcome(badge, expectedFP, cert.Fingerprint.String())
	}

	// Compare hostname
	badgeHost := badge.AgentHost()
	if !strings.EqualFold(badgeHost, fqdn.String()) {
		return NewHostnameMismatchOutcome(badge, fqdn.String(), badgeHost)
	}

	// Compare ANS name
	badgeAnsName := badge.AgentName()
	if !strings.EqualFold(badgeAnsName, ansName.String()) {
		return NewAnsNameMismatchOutcome(badge, badgeAnsName, ansName.String())
	}

	outcome := NewVerifiedOutcome(badge, cert.Fingerprint)
	if badge.Status == models.BadgeStatusDeprecated {
		outcome.Warnings = append(outcome.Warnings, "badge status is DEPRECATED")
	}
	return outcome
}

// AnsVerifier is a high-level facade combining server and client verification.
type AnsVerifier struct {
	server *ServerVerifier
	client *ClientVerifier
}

// NewAnsVerifier creates a new ANS verifier with the given options.
// Both server and client verifiers share the same config (including cache).
func NewAnsVerifier(opts ...Option) *AnsVerifier {
	config := defaultConfig()
	for _, opt := range opts {
		opt(config)
	}
	return &AnsVerifier{
		server: &ServerVerifier{config: config},
		client: &ClientVerifier{config: config},
	}
}

// VerifyServer verifies a server certificate for the given FQDN string.
func (v *AnsVerifier) VerifyServer(ctx context.Context, fqdnStr string, cert *CertIdentity) *VerificationOutcome {
	fqdn, err := models.NewFqdn(fqdnStr)
	if err != nil {
		return NewCertErrorOutcome(err)
	}
	return v.server.Verify(ctx, fqdn, cert)
}

// VerifyClient verifies an mTLS client certificate.
func (v *AnsVerifier) VerifyClient(ctx context.Context, cert *CertIdentity) *VerificationOutcome {
	return v.client.Verify(ctx, cert)
}

// VerifyServerWithScitt verifies a server certificate using SCITT headers.
func (v *AnsVerifier) VerifyServerWithScitt(ctx context.Context, fqdnStr string, cert *CertIdentity, headers *scitt.Headers) *VerificationOutcome {
	fqdn, err := models.NewFqdn(fqdnStr)
	if err != nil {
		return NewCertErrorOutcome(err)
	}
	return v.server.VerifyWithScitt(ctx, fqdn, cert, headers)
}

// VerifyClientWithScitt verifies an mTLS client certificate using SCITT headers.
func (v *AnsVerifier) VerifyClientWithScitt(ctx context.Context, cert *CertIdentity, headers *scitt.Headers) *VerificationOutcome {
	return v.client.VerifyWithScitt(ctx, cert, headers)
}

// Prefetch fetches and caches a badge for an FQDN string.
func (v *AnsVerifier) Prefetch(ctx context.Context, fqdnStr string) (*models.Badge, error) {
	fqdn, err := models.NewFqdn(fqdnStr)
	if err != nil {
		return nil, err
	}
	return v.server.Prefetch(ctx, fqdn)
}

// configLogger returns the configured logger or the default.
func configLogger(config *verifierConfig) *slog.Logger {
	if config.logger != nil {
		return config.logger
	}
	return slog.Default()
}

// verifyWithHeaders is the shared SCITT verification logic for both server and client verifiers.
func verifyWithHeaders(
	ctx context.Context,
	config *verifierConfig,
	fqdn models.Fqdn,
	cert *CertIdentity,
	headers *scitt.Headers,
	log *slog.Logger,
	badgeFallback func() *VerificationOutcome,
) *VerificationOutcome {
	keys := config.scittKeyLookup
	if keys == nil {
		log.WarnContext(ctx, "VerifyWithScitt: SCITT headers present but no key lookup configured",
			slog.String("fqdn", fqdn.String()))
		return NewScittErrorOutcome(errors.New("SCITT headers present but no key lookup configured; use WithScittKeyLookup option"))
	}

	log.InfoContext(ctx, "VerifyWithScitt: verifying receipt and status token",
		slog.String("fqdn", fqdn.String()))

	// Verify receipt
	receipt, err := scitt.VerifyReceipt(headers.Receipt, keys)
	if err != nil {
		var transportErr *scitt.TransportError
		if errors.As(err, &transportErr) && transportErr.ShouldFallbackToBadge() {
			log.WarnContext(ctx, "VerifyWithScitt: receipt verification transport error, falling back to badge",
				slog.String("fqdn", fqdn.String()),
				slog.String("error", err.Error()))
			return badgeFallback()
		}
		log.WarnContext(ctx, "VerifyWithScitt: receipt verification failed",
			slog.String("fqdn", fqdn.String()),
			slog.String("error", err.Error()))
		return NewScittErrorOutcome(err)
	}

	// Verify status token
	token, err := scitt.VerifyStatusToken(headers.StatusToken, keys, config.clockSkewTolerance)
	if err != nil {
		var transportErr *scitt.TransportError
		if errors.As(err, &transportErr) && transportErr.ShouldFallbackToBadge() {
			log.WarnContext(ctx, "VerifyWithScitt: token verification transport error, falling back to badge",
				slog.String("fqdn", fqdn.String()),
				slog.String("error", err.Error()))
			return badgeFallback()
		}
		log.WarnContext(ctx, "VerifyWithScitt: status token verification failed",
			slog.String("fqdn", fqdn.String()),
			slog.String("error", err.Error()))
		return NewScittErrorOutcome(err)
	}

	// Check agent status allows connections
	if !token.Payload.Status.IsValidForConnection() {
		return NewScittErrorOutcome(fmt.Errorf("agent status %s does not allow connections", token.Payload.Status))
	}

	// Match certificate fingerprint against token's cert arrays (constant-time)
	fp := cert.Fingerprint.Bytes()
	if !scitt.MatchesServerCert(&token.Payload, fp) && !scitt.MatchesIdentityCert(&token.Payload, fp) {
		return NewScittErrorOutcome(errors.New("certificate fingerprint does not match any cert in status token"))
	}

	log.InfoContext(ctx, "VerifyWithScitt: verification succeeded",
		slog.String("fqdn", fqdn.String()),
		slog.String("tier", "FullScitt"),
		slog.Uint64("tree_size", receipt.TreeSize),
		slog.Uint64("leaf_index", receipt.LeafIndex),
		slog.String("agent_status", string(token.Payload.Status)))

	outcome := &VerificationOutcome{
		Type:               OutcomeVerified,
		Tier:               TierFullScitt,
		MatchedFingerprint: &cert.Fingerprint,
	}
	if token.Payload.Status == scitt.StatusDeprecated {
		outcome.Warnings = append(outcome.Warnings, "agent status is DEPRECATED")
	}
	return outcome
}
