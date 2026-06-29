// Package verify — three-way card-hash cross-check (ANS_SPEC.md §4.4.2).
//
// The §4.4.2 cross-check pins agreement between three independent
// commitments to the SHA-256 of an agent's ANS Trust Card body:
//
//   H_tl   = badge.attestations.metadataHashes.capabilitiesHash (hex)
//   H_dns  = SVCB record's `card-sha256=<base64url>` SvcParam
//   H_live = SHA-256(JCS(live Trust Card JSON body))
//
// All three SHOULD match. A divergence at any one channel locates a
// specific failure mode:
//
//   H_dns ≠ H_tl: zone-edit drift (operator updated DNS but not
//                 the registered card, or vice versa)
//   H_live ≠ H_tl: origin-side drift (the served Trust Card body
//                  differs from what was registered)
//   H_live ≠ H_dns: as above with DNS-side anchor
//
// VerifyCardSHA256 reports each channel's value and the set of
// findings; callers decide whether divergence is fatal for their
// trust policy.
package verify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"

	"github.com/godaddy/ans-sdk-go/models"
)

// CrossCheckResult captures the outcome of a §4.4.2 three-way
// cross-check. Each *Hex field is hex-lowercase; "" means the channel
// did not commit a value (operator omitted agentCardContent at
// registration, or did not publish a Consolidated Approach SVCB
// record, etc.). AllAgree is true when every populated channel
// matches; an absent channel does not cause AllAgree=false.
type CrossCheckResult struct {
	HLiveHex string
	HTLHex   string
	HDNSHex  string
	AllAgree bool
	Findings []string
}

// CardHashFinding* constants name the failure modes a verifier might
// surface to a user. Findings are descriptive strings; constants
// exist to keep call-site comparisons stable.
const (
	FindingTLEmpty           = "TL did not seal a capabilities_hash (operator omitted agentCardContent)"
	FindingDNSEmpty          = "DNS did not publish a card-sha256 SvcParam (operator on legacy style or did not publish SVCB)"
	FindingLiveDiverges      = "live Trust Card body hash differs from TL-sealed hash (origin drift)"
	FindingDNSDivergesFromTL = "DNS card-sha256 differs from TL-sealed hash (zone-edit drift)"
	FindingLiveDivergesDNS   = "live Trust Card body hash differs from DNS card-sha256"
)

// VerifyCardSHA256 runs the §4.4.2 three-way cross-check.
//
// badge MUST be non-nil; pass the result of fetching the agent's TL
// badge (e.g., via ans.Client.Badge). liveCardBody is the bytes of
// the Trust Card document the verifier fetched from the agent's
// /.well-known/ans/trust-card.json (or "" if the verifier chose not
// to fetch). dnsSVCBValue is the SVCB record's presentation-form
// value (the part after `<priority> <target>`, e.g.
// `1 . alpn=a2a port=443 wk=agent-card.json card-sha256=CY1lDMb...`),
// or "" if the verifier did not query DNS.
//
// VerifyCardSHA256 never errors when channels are simply absent;
// errors are reserved for malformed input (e.g., a card-sha256
// SvcParam value that won't decode).
func VerifyCardSHA256(badge *models.Badge, liveCardBody []byte, dnsSVCBValue string) (*CrossCheckResult, error) {
	if badge == nil {
		return nil, errors.New("verify: badge is nil")
	}
	out := &CrossCheckResult{}

	out.HTLHex = strings.ToLower(strings.TrimSpace(badge.CapabilitiesHash()))

	if len(liveCardBody) > 0 {
		canonical, err := jsoncanonicalizer.Transform(liveCardBody)
		if err != nil {
			return out, fmt.Errorf("verify: canonicalize live card: %w", err)
		}
		sum := sha256.Sum256(canonical)
		out.HLiveHex = hex.EncodeToString(sum[:])
	}

	if dnsSVCBValue != "" {
		hexFromDNS, err := extractCardSHA256(dnsSVCBValue)
		if err != nil {
			return out, fmt.Errorf("verify: parse SVCB card-sha256: %w", err)
		}
		out.HDNSHex = hexFromDNS
	}

	out.AllAgree, out.Findings = compareHashes(out.HLiveHex, out.HTLHex, out.HDNSHex)
	return out, nil
}

// extractCardSHA256 pulls the `card-sha256=<value>` SvcParam from
// an SVCB presentation-form value and returns its hex-lowercase
// equivalent (decoded from base64url). Returns ("", nil) when the
// SvcParam is absent — that's a "DNS channel didn't commit", not
// an error. Returns ("", err) when the SvcParam is present but the
// value cannot be base64url-decoded (the producer wrote a malformed
// record; the verifier should report this clearly).
func extractCardSHA256(svcbValue string) (string, error) {
	const key = "card-sha256="
	idx := strings.Index(svcbValue, key)
	if idx < 0 {
		return "", nil
	}
	rest := svcbValue[idx+len(key):]
	// Value runs to the next whitespace; SVCB SvcParams are
	// space-separated. Strip surrounding quotes if the producer
	// wrote them (RFC 9460 §2.1 allows quoting, though our RA
	// emits unquoted).
	if end := strings.IndexAny(rest, " \t"); end >= 0 {
		rest = rest[:end]
	}
	rest = strings.Trim(rest, `"`)
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		// Some producers may include padding; tolerate it.
		raw, err = base64.URLEncoding.DecodeString(rest)
		if err != nil {
			return "", fmt.Errorf("base64url decode %q: %w", rest, err)
		}
	}
	return hex.EncodeToString(raw), nil
}

func compareHashes(live, tl, dns string) (bool, []string) {
	var findings []string
	allAgree := true

	switch {
	case tl == "" && dns == "" && live == "":
		// Nothing to compare. Don't claim agreement; nothing was
		// proven. Caller's policy decides whether this is a finding.
		findings = append(findings, FindingTLEmpty, FindingDNSEmpty)
		allAgree = false
	default:
		if tl == "" {
			findings = append(findings, FindingTLEmpty)
		}
		if dns == "" {
			findings = append(findings, FindingDNSEmpty)
		}
		// Pairwise: only flag divergence between channels both populated.
		if live != "" && tl != "" && live != tl {
			findings = append(findings, FindingLiveDiverges)
			allAgree = false
		}
		if dns != "" && tl != "" && dns != tl {
			findings = append(findings, FindingDNSDivergesFromTL)
			allAgree = false
		}
		if live != "" && dns != "" && live != dns {
			findings = append(findings, FindingLiveDivergesDNS)
			allAgree = false
		}
	}
	return allAgree, findings
}
