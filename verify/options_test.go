package verify

import (
	"log/slog"
	"testing"
	"time"

	"github.com/godaddy/ans-sdk-go/verify/scitt"
)

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()

	if cfg.dnsResolver == nil {
		t.Error("expected non-nil dnsResolver")
	}
	if cfg.tlogClient == nil {
		t.Error("expected non-nil tlogClient")
	}
	if cfg.cache != nil {
		t.Error("expected nil cache by default")
	}
	if cfg.failurePolicy != FailClosed {
		t.Errorf("expected FailClosed, got %v", cfg.failurePolicy)
	}
	if cfg.urlValidator == nil {
		t.Error("expected non-nil urlValidator by default")
	}
	if cfg.daneResolver != nil {
		t.Error("expected nil daneResolver by default")
	}
}

func TestWithDNSResolver(t *testing.T) {
	mock := NewMockDNSResolver()
	cfg := defaultConfig()
	WithDNSResolver(mock)(cfg)
	if cfg.dnsResolver != mock {
		t.Error("expected custom DNS resolver to be set")
	}
}

func TestWithTlogClient(t *testing.T) {
	mock := NewMockTransparencyLogClient()
	cfg := defaultConfig()
	WithTlogClient(mock)(cfg)
	if cfg.tlogClient != mock {
		t.Error("expected custom tlog client to be set")
	}
}

func TestWithCache(t *testing.T) {
	cache := NewBadgeCache(DefaultCacheConfig())
	cfg := defaultConfig()
	WithCache(cache)(cfg)
	if cfg.cache != cache {
		t.Error("expected cache to be set")
	}
}

func TestWithCacheConfig(t *testing.T) {
	cfg := defaultConfig()
	WithCacheConfig(DefaultCacheConfig())(cfg)
	if cfg.cache == nil {
		t.Error("expected cache to be created from config")
	}
}

func TestWithFailurePolicy(t *testing.T) {
	cfg := defaultConfig()
	WithFailurePolicy(FailOpen)(cfg)
	if cfg.failurePolicy != FailOpen {
		t.Errorf("expected FailOpen, got %v", cfg.failurePolicy)
	}
}

func TestWithFailurePolicyConfig(t *testing.T) {
	cfg := defaultConfig()
	policyCfg := FailurePolicyConfig{MaxStaleness: 30 * time.Minute}
	WithFailurePolicyConfig(policyCfg)(cfg)
	if cfg.failurePolicyConfig.MaxStaleness != 30*time.Minute {
		t.Errorf("expected MaxStaleness 30m, got %v", cfg.failurePolicyConfig.MaxStaleness)
	}
}

func TestWithTrustedRADomains(t *testing.T) {
	cfg := defaultConfig()
	WithTrustedRADomains([]string{"example.com", "test.com"})(cfg)
	if cfg.urlValidator == nil {
		t.Error("expected urlValidator to be set")
	}
}

func TestWithoutURLValidation(t *testing.T) {
	cfg := defaultConfig()
	WithoutURLValidation()(cfg)
	if cfg.urlValidator != nil {
		t.Error("expected urlValidator to be nil")
	}
}

func TestWithDANEResolver_Option(t *testing.T) {
	mock := NewMockDANEResolver()
	cfg := defaultConfig()
	WithDANEResolver(mock)(cfg)
	if cfg.daneResolver != mock {
		t.Error("expected DANE resolver to be set")
	}
}

func TestWithScittKeyLookup(t *testing.T) {
	store, _ := scitt.NewKeyStore(nil)
	cfg := defaultConfig()
	WithScittKeyLookup(store)(cfg)
	if cfg.scittKeyLookup != store {
		t.Error("expected scitt key lookup to be set")
	}
}

func TestWithClockSkewTolerance(t *testing.T) {
	cfg := defaultConfig()
	WithClockSkewTolerance(5 * time.Minute)(cfg)
	if cfg.clockSkewTolerance != 5*time.Minute {
		t.Errorf("expected 5m, got %v", cfg.clockSkewTolerance)
	}
}

func TestWithLogger(t *testing.T) {
	logger := slog.Default()
	cfg := defaultConfig()
	WithLogger(logger)(cfg)
	if cfg.logger != logger {
		t.Error("expected logger to be set")
	}
}

func TestDefaultClockSkewTolerance(t *testing.T) {
	cfg := defaultConfig()
	if cfg.clockSkewTolerance != 120*time.Second {
		t.Errorf("expected default 120s, got %v", cfg.clockSkewTolerance)
	}
}

func TestDefaultScittKeyLookupNil(t *testing.T) {
	cfg := defaultConfig()
	if cfg.scittKeyLookup != nil {
		t.Error("expected nil scitt key lookup by default")
	}
}
