package verify

import (
	"log/slog"
	"time"

	"github.com/godaddy/ans-sdk-go/verify/scitt"
)

// Option configures a verifier.
type Option func(*verifierConfig)

// verifierConfig holds the configuration for verifiers.
type verifierConfig struct {
	dnsResolver         DNSResolver
	tlogClient          TransparencyLogClient
	cache               *BadgeCache
	failurePolicy       FailurePolicy
	failurePolicyConfig FailurePolicyConfig
	urlValidator        *URLValidator
	daneResolver        DANEResolver
	scittKeyLookup      scitt.KeyLookup
	clockSkewTolerance  time.Duration
	logger              *slog.Logger
}

// defaultClockSkewTolerance is the default maximum allowed clock skew (120 seconds).
const defaultClockSkewTolerance = 120 * time.Second

// defaultConfig returns the default verifier configuration.
func defaultConfig() *verifierConfig {
	return &verifierConfig{
		dnsResolver:         NewStandardDNSResolver(),
		tlogClient:          NewHTTPTransparencyLogClient(),
		cache:               nil,
		failurePolicy:       FailClosed,
		failurePolicyConfig: DefaultFailurePolicyConfig(),
		urlValidator:        NewDefaultURLValidator(),
		clockSkewTolerance:  defaultClockSkewTolerance,
	}
}

// WithDNSResolver sets a custom DNS resolver.
func WithDNSResolver(r DNSResolver) Option {
	return func(c *verifierConfig) {
		c.dnsResolver = r
	}
}

// WithTlogClient sets a custom transparency log client.
func WithTlogClient(t TransparencyLogClient) Option {
	return func(c *verifierConfig) {
		c.tlogClient = t
	}
}

// WithCache sets a badge cache.
func WithCache(cache *BadgeCache) Option {
	return func(c *verifierConfig) {
		c.cache = cache
	}
}

// WithCacheConfig creates and sets a badge cache with the given configuration.
func WithCacheConfig(cfg CacheConfig) Option {
	return func(c *verifierConfig) {
		c.cache = NewBadgeCache(cfg)
	}
}

// WithFailurePolicy sets the failure policy for DNS/TLog errors.
//
// NOTE: This policy does NOT apply to SCITT verification failures — a malformed
// or signature-invalid SCITT artifact is always terminal, regardless of FailOpen
// settings, to prevent forgery acceptance. Only DNS and TLog infrastructure
// failures are subject to this policy.
func WithFailurePolicy(policy FailurePolicy) Option {
	return func(c *verifierConfig) {
		c.failurePolicy = policy
	}
}

// WithFailurePolicyConfig sets the failure policy configuration.
func WithFailurePolicyConfig(cfg FailurePolicyConfig) Option {
	return func(c *verifierConfig) {
		c.failurePolicyConfig = cfg
	}
}

// WithTrustedRADomains sets custom trusted RA domains for URL validation.
func WithTrustedRADomains(domains []string) Option {
	return func(c *verifierConfig) {
		c.urlValidator = NewURLValidator(domains)
	}
}

// WithoutURLValidation disables badge URL domain validation.
func WithoutURLValidation() Option {
	return func(c *verifierConfig) {
		c.urlValidator = nil
	}
}

// WithDANEResolver enables DANE/TLSA verification using the given resolver.
// When set, the verifier performs an additional DANE check after badge verification.
// DANE rejection (fingerprint mismatch or DNSSEC failure) overrides a successful badge check.
func WithDANEResolver(d DANEResolver) Option {
	return func(c *verifierConfig) {
		c.daneResolver = d
	}
}

// WithScittKeyLookup enables SCITT verification using the given key store.
// When set, VerifyWithScitt methods can verify SCITT receipts and status tokens.
func WithScittKeyLookup(kl scitt.KeyLookup) Option {
	return func(c *verifierConfig) {
		c.scittKeyLookup = kl
	}
}

// WithClockSkewTolerance sets the maximum allowed clock skew for status token expiry checks.
// Negative values are clamped to 0. Values exceeding 10 minutes are clamped to 10 minutes.
// Default is 120 seconds.
func WithClockSkewTolerance(d time.Duration) Option {
	return func(c *verifierConfig) {
		if d < 0 {
			d = 0
		}
		const maxSkew = 10 * time.Minute
		if d > maxSkew {
			d = maxSkew
		}
		c.clockSkewTolerance = d
	}
}

// WithLogger sets a structured logger for verification operations.
// When nil, slog.Default() is used.
func WithLogger(l *slog.Logger) Option {
	return func(c *verifierConfig) {
		c.logger = l
	}
}
