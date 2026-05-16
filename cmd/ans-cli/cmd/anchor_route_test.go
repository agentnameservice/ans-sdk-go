package cmd

import (
	"strings"
	"testing"

	"github.com/godaddy/ans-sdk-go/models"
)

func TestDecideAnchorAndRoute_LegacyVersionedFQDN(t *testing.T) {
	useV2, anchor, err := decideAnchorAndRoute(registerOptions{
		Version: "1.0.0",
	}, true /* hasIdentityCSR */)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if useV2 {
		t.Error("legacy versioned FQDN should route to V1, got V2")
	}
	if anchor != nil {
		t.Errorf("legacy versioned FQDN should produce no anchor block, got %+v", anchor)
	}
}

func TestDecideAnchorAndRoute_BaseOnlyFQDN(t *testing.T) {
	useV2, anchor, err := decideAnchorAndRoute(registerOptions{}, false /* no CSR */)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !useV2 {
		t.Error("base-only registration should route to V2")
	}
	if anchor != nil {
		t.Errorf("base-only without --anchor-type should produce no anchor block, got %+v", anchor)
	}
}

func TestDecideAnchorAndRoute_DIDAnchor(t *testing.T) {
	useV2, anchor, err := decideAnchorAndRoute(registerOptions{
		AnchorType:  "did",
		AnchorInput: "did:web:agent.example.com",
	}, false)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !useV2 {
		t.Error("DID anchor must route to V2")
	}
	if anchor == nil {
		t.Fatal("DID anchor block must be populated")
	}
	if anchor.AnchorType != models.AnchorTypeDID {
		t.Errorf("AnchorType = %q", anchor.AnchorType)
	}
	if anchor.Input != "did:web:agent.example.com" {
		t.Errorf("Input = %q", anchor.Input)
	}
}

func TestDecideAnchorAndRoute_LEIAnchor(t *testing.T) {
	useV2, anchor, err := decideAnchorAndRoute(registerOptions{
		AnchorType:  "lei",
		AnchorInput: "529900T8BM49AURSDO55",
	}, false)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !useV2 {
		t.Error("LEI anchor must route to V2")
	}
	if anchor == nil || anchor.AnchorType != models.AnchorTypeLEI {
		t.Errorf("LEI anchor block missing or wrong: %+v", anchor)
	}
}

func TestDecideAnchorAndRoute_VersionWithoutCSRRejected(t *testing.T) {
	_, _, err := decideAnchorAndRoute(registerOptions{
		Version: "1.0.0",
	}, false /* no CSR */)
	if err == nil {
		t.Fatal("expected both-or-neither error, got nil")
	}
	if !strings.Contains(err.Error(), "must be supplied together") {
		t.Errorf("error mismatch: %v", err)
	}
}

func TestDecideAnchorAndRoute_CSRWithoutVersionRejected(t *testing.T) {
	_, _, err := decideAnchorAndRoute(registerOptions{
		Version: "",
	}, true /* CSR present */)
	if err == nil {
		t.Fatal("expected both-or-neither error, got nil")
	}
}

func TestDecideAnchorAndRoute_AnchorTypeRequiresAnchorInput(t *testing.T) {
	_, _, err := decideAnchorAndRoute(registerOptions{
		AnchorType: "did",
	}, false)
	if err == nil {
		t.Fatal("expected error for missing --anchor-input")
	}
}

func TestDecideAnchorAndRoute_AnchorInputAloneRejected(t *testing.T) {
	_, _, err := decideAnchorAndRoute(registerOptions{
		AnchorInput: "did:web:agent.example.com",
	}, false)
	if err == nil {
		t.Fatal("expected error for --anchor-input without --anchor-type")
	}
}

func TestDecideAnchorAndRoute_UnknownAnchorTypeRejected(t *testing.T) {
	_, _, err := decideAnchorAndRoute(registerOptions{
		AnchorType:  "spiffe",
		AnchorInput: "spiffe://example.org/foo",
	}, false)
	if err == nil {
		t.Fatal("expected error for unknown anchor type")
	}
	if !strings.Contains(err.Error(), "fqdn, did, or lei") {
		t.Errorf("error mismatch: %v", err)
	}
}

func TestDecideAnchorAndRoute_DIDWithVersionRejected(t *testing.T) {
	// Versioned DID is not yet supported.
	_, _, err := decideAnchorAndRoute(registerOptions{
		Version:     "1.0.0",
		AnchorType:  "did",
		AnchorInput: "did:web:agent.example.com",
	}, true /* with CSR */)
	if err == nil {
		t.Fatal("expected error for DID + version")
	}
	if !strings.Contains(err.Error(), "base-only") {
		t.Errorf("error mismatch: %v", err)
	}
}

func TestDecideAnchorAndRoute_ForceV2(t *testing.T) {
	useV2, _, err := decideAnchorAndRoute(registerOptions{
		Version: "1.0.0",
		UseV2:   true,
	}, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !useV2 {
		t.Error("--v2 should force V2 routing")
	}
}

func TestDecideAnchorAndRoute_FQDNAnchorWithVersionAccepted(t *testing.T) {
	// Explicit FQDN anchor + version is allowed; the FQDN profile
	// retains the X.509 URI SAN binding so versioned registration
	// works there.
	useV2, anchor, err := decideAnchorAndRoute(registerOptions{
		Version:     "1.0.0",
		AnchorType:  "fqdn",
		AnchorInput: "agent.example.com",
	}, true)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !useV2 {
		t.Error("explicit anchor type should route to V2")
	}
	if anchor == nil || anchor.AnchorType != models.AnchorTypeFQDN {
		t.Errorf("FQDN anchor block missing or wrong: %+v", anchor)
	}
}
