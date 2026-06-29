package verify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"

	"github.com/godaddy/ans-sdk-go/models"
)

// fixtureCardJSON is the per-test Trust Card body. Each test computes
// the expected hash from this same body so the SDK's JCS+SHA256
// implementation is the single source of truth — no hardcoded digests
// to drift from the library output.
const fixtureCardJSON = `{"ansName":"ans://v1.0.0.test","version":"1.0.0"}`

// fixtureHashes computes the expected hex + base64url SHA-256 over
// JCS(fixtureCardJSON) using the same library the production
// VerifyCardSHA256 uses. Returns (hex, base64url).
func fixtureHashes(t *testing.T) (string, string) {
	t.Helper()
	canonical, err := jsoncanonicalizer.Transform([]byte(fixtureCardJSON))
	if err != nil {
		t.Fatalf("canonicalize fixture: %v", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]),
		base64.RawURLEncoding.EncodeToString(sum[:])
}

func makeBadgeWithCapHash(hexDigest string) *models.Badge {
	return &models.Badge{
		Payload: models.BadgePayload{Producer: models.Producer{Event: models.AgentEvent{
			Attestations: models.Attestations{
				MetadataHashes: map[string]string{
					models.MetadataHashKeyCapabilitiesHash: hexDigest,
				},
			},
		}}},
	}
}

// TestVerifyCardSHA256_AllThreeAgree is the happy path: the operator
// submitted agentCardContent at registration, published a Consolidated
// Approach SVCB record with card-sha256, and serves the live Trust Card
// at /.well-known/ans/trust-card.json. All three channels commit the
// same digest; AllAgree=true and no findings.
func TestVerifyCardSHA256_AllThreeAgree(t *testing.T) {
	expectedHex, expectedB64 := fixtureHashes(t)
	badge := makeBadgeWithCapHash(expectedHex)
	dnsValue := "1 . alpn=a2a port=443 wk=agent-card.json card-sha256=" + expectedB64

	got, err := VerifyCardSHA256(badge, []byte(fixtureCardJSON), dnsValue)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.AllAgree {
		t.Errorf("AllAgree = false; findings=%v", got.Findings)
	}
	if got.HTLHex != expectedHex || got.HDNSHex != expectedHex || got.HLiveHex != expectedHex {
		t.Errorf("hashes diverge:\n  TL:   %s\n  DNS:  %s\n  Live: %s\n  expected: %s",
			got.HTLHex, got.HDNSHex, got.HLiveHex, expectedHex)
	}
	if len(got.Findings) != 0 {
		t.Errorf("expected no findings; got %v", got.Findings)
	}
}

// TestVerifyCardSHA256_DNSDivergesFromTL covers the zone-edit drift
// failure mode: TL committed one digest at registration but the DNS
// SVCB record now publishes a different one. Operator updated the
// hosted card without re-registering.
func TestVerifyCardSHA256_DNSDivergesFromTL(t *testing.T) {
	expectedHex, _ := fixtureHashes(t)
	wrongB64URL := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	dnsValue := "1 . alpn=a2a card-sha256=" + wrongB64URL

	badge := makeBadgeWithCapHash(expectedHex)
	got, err := VerifyCardSHA256(badge, []byte(fixtureCardJSON), dnsValue)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AllAgree {
		t.Error("AllAgree = true; should detect divergence between DNS and TL")
	}
	if !containsFinding(got.Findings, FindingDNSDivergesFromTL) {
		t.Errorf("expected FindingDNSDivergesFromTL in %v", got.Findings)
	}
}

// TestVerifyCardSHA256_LiveDivergesFromTL covers origin drift: the
// served Trust Card body has changed since registration. AIM should
// flag this as a high-priority integrity finding.
func TestVerifyCardSHA256_LiveDivergesFromTL(t *testing.T) {
	expectedHex, _ := fixtureHashes(t)
	differentLive := []byte(`{"ansName":"ans://v1.0.0.different","version":"2.0.0"}`)

	badge := makeBadgeWithCapHash(expectedHex)
	got, err := VerifyCardSHA256(badge, differentLive, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AllAgree {
		t.Error("AllAgree = true; should detect origin drift")
	}
	if !containsFinding(got.Findings, FindingLiveDiverges) {
		t.Errorf("expected FindingLiveDiverges in %v", got.Findings)
	}
}

// TestVerifyCardSHA256_TLEmptyTOFU covers the TOFU path: operator did
// not submit agentCardContent at registration, so the TL has no
// capabilities_hash. A verifier with the live card and a DNS record
// can still confirm DNS↔live consistency, but TL is uninvolved.
func TestVerifyCardSHA256_TLEmptyTOFU(t *testing.T) {
	_, expectedB64 := fixtureHashes(t)
	dnsValue := "1 . alpn=a2a card-sha256=" + expectedB64
	badge := &models.Badge{} // no MetadataHashes

	got, err := VerifyCardSHA256(badge, []byte(fixtureCardJSON), dnsValue)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsFinding(got.Findings, FindingTLEmpty) {
		t.Errorf("expected FindingTLEmpty in %v", got.Findings)
	}
	// Live and DNS both populated and equal — no divergence finding.
	if containsFinding(got.Findings, FindingLiveDivergesDNS) {
		t.Errorf("did not expect live↔DNS divergence; got %v", got.Findings)
	}
}

// TestVerifyCardSHA256_LegacyAgentNoDNSCommitment covers the
// dnsRecordStyle=legacy path: the operator submitted agentCardContent
// (so TL has the hash) but published the legacy `_ans` TXT shape
// instead of the Consolidated Approach SVCB. No DNS card-sha256 to
// cross-check; verifier still reports TL↔live agreement.
func TestVerifyCardSHA256_LegacyAgentNoDNSCommitment(t *testing.T) {
	expectedHex, _ := fixtureHashes(t)
	badge := makeBadgeWithCapHash(expectedHex)

	got, err := VerifyCardSHA256(badge, []byte(fixtureCardJSON), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !containsFinding(got.Findings, FindingDNSEmpty) {
		t.Errorf("expected FindingDNSEmpty in %v", got.Findings)
	}
	if got.HTLHex != expectedHex || got.HLiveHex != expectedHex {
		t.Errorf("TL/live hashes don't match expected")
	}
}

// TestVerifyCardSHA256_MalformedSVCBValueErrors confirms a producer-
// side mistake (an unparseable card-sha256 SvcParam) surfaces as a
// returned error, not a silent zero result.
func TestVerifyCardSHA256_MalformedSVCBValueErrors(t *testing.T) {
	expectedHex, _ := fixtureHashes(t)
	badge := makeBadgeWithCapHash(expectedHex)
	dnsValue := "1 . alpn=a2a card-sha256=this-is-not-base64url!!!"
	_, err := VerifyCardSHA256(badge, []byte(fixtureCardJSON), dnsValue)
	if err == nil {
		t.Fatal("expected error on malformed SVCB SvcParam, got nil")
	}
	if !strings.Contains(err.Error(), "card-sha256") {
		t.Errorf("error should mention card-sha256; got %q", err)
	}
}

// TestExtractCardSHA256_ToleratesQuotedAndPadded covers minor wire-
// shape variations a real-world operator's tooling might produce:
// quoted SvcParam value, base64 with padding, position in the
// SvcParam list (first, middle, last).
func TestExtractCardSHA256_ToleratesQuotedAndPadded(t *testing.T) {
	expectedHex, expectedB64 := fixtureHashes(t)
	// base64 standard form with padding (URLEncoding accepts trailing =).
	hashWithPadding := expectedB64 + "="
	cases := []struct {
		name string
		in   string
	}{
		{"unquoted_first", "card-sha256=" + expectedB64 + " alpn=a2a"},
		{"unquoted_middle", "alpn=a2a card-sha256=" + expectedB64 + " port=443"},
		{"unquoted_last", "alpn=a2a port=443 card-sha256=" + expectedB64},
		{"quoted", `alpn=a2a card-sha256="` + expectedB64 + `"`},
		{"with_padding", "card-sha256=" + hashWithPadding},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractCardSHA256(tc.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != expectedHex {
				t.Errorf("got %q, want %q", got, expectedHex)
			}
		})
	}
}

func TestVerifyCardSHA256_NilBadgeRejected(t *testing.T) {
	_, err := VerifyCardSHA256(nil, nil, "")
	if err == nil {
		t.Fatal("expected error on nil badge, got nil")
	}
}

func containsFinding(findings []string, want string) bool {
	for _, f := range findings {
		if f == want {
			return true
		}
	}
	return false
}
