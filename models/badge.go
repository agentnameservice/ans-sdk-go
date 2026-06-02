package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// BadgeStatus represents the status of a badge in the transparency log.
type BadgeStatus string

const (
	// BadgeStatusActive indicates the agent is registered and in good standing.
	BadgeStatusActive BadgeStatus = "ACTIVE"
	// BadgeStatusWarning indicates the certificate expires within 30 days.
	BadgeStatusWarning BadgeStatus = "WARNING"
	// BadgeStatusDeprecated indicates the agent is superseded by a newer version (grace period).
	BadgeStatusDeprecated BadgeStatus = "DEPRECATED"
	// BadgeStatusExpired indicates the certificate has expired.
	BadgeStatusExpired BadgeStatus = "EXPIRED"
	// BadgeStatusRevoked indicates the registration has been explicitly revoked.
	BadgeStatusRevoked BadgeStatus = "REVOKED"
)

// IsValidForConnection returns true if this status allows establishing connections.
func (s BadgeStatus) IsValidForConnection() bool {
	switch s {
	case BadgeStatusActive, BadgeStatusWarning, BadgeStatusDeprecated:
		return true
	case BadgeStatusExpired, BadgeStatusRevoked:
		return false
	default:
		return false
	}
}

// IsActive returns true if this status indicates the badge is fully active (not deprecated).
func (s BadgeStatus) IsActive() bool {
	switch s {
	case BadgeStatusActive, BadgeStatusWarning:
		return true
	case BadgeStatusDeprecated, BadgeStatusExpired, BadgeStatusRevoked:
		return false
	default:
		return false
	}
}

// ShouldReject returns true if this status indicates the badge should be rejected.
func (s BadgeStatus) ShouldReject() bool {
	switch s {
	case BadgeStatusExpired, BadgeStatusRevoked:
		return true
	case BadgeStatusActive, BadgeStatusWarning, BadgeStatusDeprecated:
		return false
	default:
		return false
	}
}

// Badge represents a full badge response from the Transparency Log API.
type Badge struct {
	Status        BadgeStatus   `json:"status"`
	Payload       BadgePayload  `json:"payload"`
	SchemaVersion SchemaVersion `json:"schemaVersion"`
	Signature     *string       `json:"signature,omitempty"`
	MerkleProof   *MerkleProof  `json:"merkleProof,omitempty"`
}

// AgentName returns the agent's ANS name from the badge.
func (b *Badge) AgentName() string {
	return b.Payload.Producer.Event.ANSName
}

// AgentHost returns the agent's host FQDN from the badge.
func (b *Badge) AgentHost() string {
	return b.Payload.Producer.Event.Agent.Host
}

// AgentVersion returns the agent's version string from the badge.
func (b *Badge) AgentVersion() string {
	return b.Payload.Producer.Event.Agent.Version
}

// ServerCertFingerprint returns the server certificate fingerprint from the badge.
func (b *Badge) ServerCertFingerprint() string {
	if b.Payload.Producer.Event.Attestations.ServerCert == nil {
		return ""
	}
	return b.Payload.Producer.Event.Attestations.ServerCert.Fingerprint
}

// IdentityCertFingerprint returns the identity certificate fingerprint from the badge.
func (b *Badge) IdentityCertFingerprint() string {
	if b.Payload.Producer.Event.Attestations.IdentityCert == nil {
		return ""
	}
	return b.Payload.Producer.Event.Attestations.IdentityCert.Fingerprint
}

// ServerCertFingerprints returns all valid server certificate fingerprints.
// Returns the v2 plural list when populated; falls back to the v1 singular if
// only it is set. Empty slice when neither is populated.
func (b *Badge) ServerCertFingerprints() []string {
	att := b.Payload.Producer.Event.Attestations
	if len(att.ValidServerCerts) > 0 {
		out := make([]string, len(att.ValidServerCerts))
		for i, c := range att.ValidServerCerts {
			out[i] = c.Fingerprint
		}
		return out
	}
	if att.ServerCert != nil {
		return []string{att.ServerCert.Fingerprint}
	}
	return nil
}

// IdentityCertFingerprints returns all valid identity certificate fingerprints,
// with v2-then-v1 fallback semantics matching ServerCertFingerprints.
func (b *Badge) IdentityCertFingerprints() []string {
	att := b.Payload.Producer.Event.Attestations
	if len(att.ValidIdentityCerts) > 0 {
		out := make([]string, len(att.ValidIdentityCerts))
		for i, c := range att.ValidIdentityCerts {
			out[i] = c.Fingerprint
		}
		return out
	}
	if att.IdentityCert != nil {
		return []string{att.IdentityCert.Fingerprint}
	}
	return nil
}

// MatchesServerCert reports whether fp matches any valid server certificate
// fingerprint in the badge. Comparison is case-insensitive, which tolerates the
// common "SHA256:" vs "sha256:" prefix and upper/lower hex differences. It does
// NOT canonicalize the binary fingerprint (hex decoding, length validation);
// for cryptographic-grade comparison parse both sides through the verify
// package's CertFingerprint and use Matches/Equal.
func (b *Badge) MatchesServerCert(fp string) bool {
	for _, candidate := range b.ServerCertFingerprints() {
		if strings.EqualFold(candidate, fp) {
			return true
		}
	}
	return false
}

// MatchesIdentityCert reports whether fp matches any valid identity certificate
// fingerprint in the badge, with the same case-insensitive semantics and caveats
// as MatchesServerCert.
func (b *Badge) MatchesIdentityCert(fp string) bool {
	for _, candidate := range b.IdentityCertFingerprints() {
		if strings.EqualFold(candidate, fp) {
			return true
		}
	}
	return false
}

// AgentID returns the agent's unique ID from the badge.
func (b *Badge) AgentID() string {
	return b.Payload.Producer.Event.ANSID
}

// EventType returns the event type from the badge.
func (b *Badge) EventType() EventType {
	return b.Payload.Producer.Event.EventType
}

// IsValid returns true if the badge is valid for establishing connections.
func (b *Badge) IsValid() bool {
	return b.Status.IsValidForConnection()
}

// BadgePayload contains the producer and signed event.
type BadgePayload struct {
	LogID    string   `json:"logId"`
	Producer Producer `json:"producer"`
}

// Producer contains the agent event and signature.
type Producer struct {
	Event     AgentEvent `json:"event"`
	KeyID     string     `json:"keyId"`
	Signature string     `json:"signature"`
}

// AgentEvent contains all registration/verification details.
type AgentEvent struct {
	ANSID        string       `json:"ansId"`
	ANSName      string       `json:"ansName"`
	EventType    EventType    `json:"eventType"`
	Agent        AgentInfo    `json:"agent"`
	Attestations Attestations `json:"attestations"`
	ExpiresAt    *time.Time   `json:"expiresAt,omitempty"`
	IssuedAt     time.Time    `json:"issuedAt"`
	RAID         string       `json:"raId"`
	Timestamp    time.Time    `json:"timestamp"`
}

// EventType represents badge event types.
type EventType string

const (
	// EventTypeAgentRegistered indicates the agent was initially registered.
	EventTypeAgentRegistered EventType = "AGENT_REGISTERED"
	// EventTypeAgentRenewed indicates agent certificates were renewed.
	EventTypeAgentRenewed EventType = "AGENT_RENEWED"
	// EventTypeAgentDeprecated indicates the agent was superseded by a newer version.
	EventTypeAgentDeprecated EventType = "AGENT_DEPRECATED"
	// EventTypeAgentRevoked indicates the agent registration was revoked.
	EventTypeAgentRevoked EventType = "AGENT_REVOKED"
)

// AgentInfo contains basic agent information.
type AgentInfo struct {
	Host    string `json:"host"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Attestations contains certificate attestations for both v1 and v2 shapes.
//
// v1 shape populates IdentityCert / ServerCert (singular).
// v2 shape populates ValidIdentityCerts / ValidServerCerts (plural).
//
// The dnsRecordsProvisioned wire field carries two historic shapes which
// UnmarshalJSON decodes without erroring:
//   - v1 map shape: a JSON object of name→value strings, decoded into
//     DNSRecordsProvisioned.
//   - v2 array shape: a JSON array of {name,data,type} objects, decoded into
//     DNSRecordsProvisionedV2.
//
// MarshalJSON re-emits whichever shape is populated, so values round-trip
// losslessly. Consumers should prefer DNSRecordsProvisionedV2 and fall back to
// DNSRecordsProvisioned for historical entries.
type Attestations struct {
	DomainValidation   string                 `json:"domainValidation"`
	IdentityCert       *CertAttestationV1     `json:"identityCert,omitempty"`
	ServerCert         *CertAttestationV1     `json:"serverCert,omitempty"`
	ValidIdentityCerts []ValidCertAttestation `json:"validIdentityCerts,omitempty"`
	ValidServerCerts   []ValidCertAttestation `json:"validServerCerts,omitempty"`
	// DNSRecordsProvisioned holds v1 map-shaped DNS provisioning data
	// (name→value). Populated only when the wire value is a JSON object.
	// Managed by (Un)MarshalJSON; the json:"-" tag avoids colliding with
	// DNSRecordsProvisionedV2 on the same wire key.
	DNSRecordsProvisioned map[string]string `json:"-"`
	// DNSRecordsProvisionedV2 holds v2 array-shaped DNS provisioning data.
	// Populated only when the wire value is a JSON array.
	DNSRecordsProvisionedV2 []DNSRecordAttestation `json:"-"`
	MetadataHashes          map[string]string      `json:"metadataHashes,omitempty"`
}

// badgeAttParser parses a raw attestations JSON block into an Attestations value.
// Each schema version has its own implementation; register new versions in
// badgeAttParsers — no other code changes are needed.
type badgeAttParser interface {
	parseAtts(raw json.RawMessage) (Attestations, error)
}

// v1BadgeAttParser handles V1 schema attestations:
// singular identityCert/serverCert plus optional rotation arrays,
// and map-shaped dnsRecordsProvisioned.
type v1BadgeAttParser struct{}

func (v1BadgeAttParser) parseAtts(raw json.RawMessage) (Attestations, error) {
	if len(raw) == 0 {
		return Attestations{}, nil
	}
	var wire struct {
		DomainValidation      string                 `json:"domainValidation"`
		IdentityCert          *CertAttestationV1     `json:"identityCert,omitempty"`
		ServerCert            *CertAttestationV1     `json:"serverCert,omitempty"`
		ValidIdentityCerts    []ValidCertAttestation `json:"validIdentityCerts,omitempty"`
		ValidServerCerts      []ValidCertAttestation `json:"validServerCerts,omitempty"`
		DNSRecordsProvisioned map[string]string      `json:"dnsRecordsProvisioned,omitempty"`
		MetadataHashes        map[string]string      `json:"metadataHashes,omitempty"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return Attestations{}, err
	}
	return Attestations{
		DomainValidation:      wire.DomainValidation,
		IdentityCert:          wire.IdentityCert,
		ServerCert:            wire.ServerCert,
		ValidIdentityCerts:    wire.ValidIdentityCerts,
		ValidServerCerts:      wire.ValidServerCerts,
		DNSRecordsProvisioned: wire.DNSRecordsProvisioned,
		MetadataHashes:        wire.MetadataHashes,
	}, nil
}

// v2BadgeAttParser handles V2 schema attestations:
// plural serverCerts/identityCerts arrays (the "valid" prefix was dropped from V1
// wire names), and array-shaped dnsRecordsProvisioned.
type v2BadgeAttParser struct{}

func (v2BadgeAttParser) parseAtts(raw json.RawMessage) (Attestations, error) {
	if len(raw) == 0 {
		return Attestations{}, nil
	}
	var wire struct {
		DomainValidation      string                 `json:"domainValidation"`
		ServerCerts           []ValidCertAttestation `json:"serverCerts,omitempty"`
		IdentityCerts         []ValidCertAttestation `json:"identityCerts,omitempty"`
		DNSRecordsProvisioned []DNSRecordAttestation `json:"dnsRecordsProvisioned,omitempty"`
		MetadataHashes        map[string]string      `json:"metadataHashes,omitempty"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return Attestations{}, err
	}
	return Attestations{
		DomainValidation:        wire.DomainValidation,
		ValidServerCerts:        wire.ServerCerts,
		ValidIdentityCerts:      wire.IdentityCerts,
		DNSRecordsProvisionedV2: wire.DNSRecordsProvisioned,
		MetadataHashes:          wire.MetadataHashes,
	}, nil
}

// badgeAttParsers maps each schema version to its attestations parser.
// To add future versions: implement badgeAttParser and add an entry here.
var badgeAttParsers = map[SchemaVersion]badgeAttParser{
	SchemaVersionV1: v1BadgeAttParser{},
	SchemaVersionV2: v2BadgeAttParser{},
}

// parserForBadgeAtts returns the parser for the given schema version.
// Unknown or empty versions default to v1 (backward compat with badges
// that predate the schemaVersion field).
func parserForBadgeAtts(sv SchemaVersion) badgeAttParser {
	if p, ok := badgeAttParsers[sv]; ok {
		return p
	}
	return v1BadgeAttParser{}
}

// UnmarshalJSON handles three dual-shape fields in the Attestations wire format:
//
//   - dnsRecordsProvisioned: v1 JSON object (map) or v2 JSON array.
//   - serverCerts / validServerCerts: v2 API emits "serverCerts"; older badges
//     and the SDK fixture use "validServerCerts". Both are decoded into ValidServerCerts.
//   - identityCerts / validIdentityCerts: same aliasing as serverCerts.
func (a *Attestations) UnmarshalJSON(data []byte) error {
	type alias Attestations
	aux := struct {
		*alias
		DNSRecordsProvisioned json.RawMessage `json:"dnsRecordsProvisioned,omitempty"`
		// v2 API wire names — captured separately so they can be merged below.
		ServerCerts   json.RawMessage `json:"serverCerts,omitempty"`
		IdentityCerts json.RawMessage `json:"identityCerts,omitempty"`
	}{alias: (*alias)(a)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// serverCerts/identityCerts: populate ValidServerCerts/ValidIdentityCerts when the
	// canonical "valid*" names produced nothing (i.e. this is a v2-wire-name badge).
	if len(a.ValidServerCerts) == 0 && len(aux.ServerCerts) > 0 {
		if err := json.Unmarshal(aux.ServerCerts, &a.ValidServerCerts); err != nil {
			return err
		}
	}
	if len(a.ValidIdentityCerts) == 0 && len(aux.IdentityCerts) > 0 {
		if err := json.Unmarshal(aux.IdentityCerts, &a.ValidIdentityCerts); err != nil {
			return err
		}
	}

	// dnsRecordsProvisioned: v2 array shape or v1 map shape.
	a.DNSRecordsProvisioned = nil
	a.DNSRecordsProvisionedV2 = nil
	if len(aux.DNSRecordsProvisioned) == 0 {
		return nil
	}
	// Try the v2 array shape first.
	if err := json.Unmarshal(aux.DNSRecordsProvisioned, &a.DNSRecordsProvisionedV2); err == nil {
		return nil
	}
	// Clear partial array residue, then fall back to the v1 map shape.
	a.DNSRecordsProvisionedV2 = nil
	return json.Unmarshal(aux.DNSRecordsProvisioned, &a.DNSRecordsProvisioned)
}

// MarshalJSON re-emits dnsRecordsProvisioned in whichever shape is populated,
// preferring the v2 array. This keeps decode/encode round-trips lossless.
func (a Attestations) MarshalJSON() ([]byte, error) {
	type alias Attestations
	aux := struct {
		alias
		DNSRecordsProvisioned any `json:"dnsRecordsProvisioned,omitempty"`
	}{alias: alias(a)}
	switch {
	case len(a.DNSRecordsProvisionedV2) > 0:
		aux.DNSRecordsProvisioned = a.DNSRecordsProvisionedV2
	case len(a.DNSRecordsProvisioned) > 0:
		aux.DNSRecordsProvisioned = a.DNSRecordsProvisioned
	}
	return json.Marshal(aux)
}

// UnmarshalJSON decodes a Badge from JSON. It reads schemaVersion first and
// dispatches the nested attestations block to the matching badgeAttParser.
// To add V3 support: implement badgeAttParser and register it in badgeAttParsers.
func (b *Badge) UnmarshalJSON(data []byte) error {
	// rawEvent embeds AgentEvent so all its fields are decoded automatically,
	// while overriding the Attestations field with json.RawMessage so we can
	// dispatch parsing to the version-specific parser below.
	type rawEvent struct {
		AgentEvent
		Attestations json.RawMessage `json:"attestations"`
	}
	var raw struct {
		Status        BadgeStatus   `json:"status"`
		SchemaVersion SchemaVersion `json:"schemaVersion"`
		Signature     *string       `json:"signature,omitempty"`
		MerkleProof   *MerkleProof  `json:"merkleProof,omitempty"`
		Payload       struct {
			LogID    string `json:"logId"`
			Producer struct {
				Event     rawEvent `json:"event"`
				KeyID     string   `json:"keyId"`
				Signature string   `json:"signature"`
			} `json:"producer"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	b.Status = raw.Status
	b.SchemaVersion = raw.SchemaVersion
	b.Signature = raw.Signature
	b.MerkleProof = raw.MerkleProof
	b.Payload.LogID = raw.Payload.LogID
	b.Payload.Producer.KeyID = raw.Payload.Producer.KeyID
	b.Payload.Producer.Signature = raw.Payload.Producer.Signature
	// Copy all AgentEvent fields; Attestations is zero here — set below.
	b.Payload.Producer.Event = raw.Payload.Producer.Event.AgentEvent

	atts, err := parserForBadgeAtts(b.SchemaVersion).parseAtts(raw.Payload.Producer.Event.Attestations)
	if err != nil {
		return fmt.Errorf("parse attestations (schemaVersion=%q): %w", b.SchemaVersion, err)
	}
	b.Payload.Producer.Event.Attestations = atts
	return nil
}

// CertAttestationV1 contains certificate fingerprint and type.
type CertAttestationV1 struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
}

// ValidCertAttestation is the v2 cert entry. Includes notAfter for expiry checks.
type ValidCertAttestation struct {
	Fingerprint string     `json:"fingerprint"`
	Type        string     `json:"type"`
	NotAfter    *time.Time `json:"notAfter,omitempty"`
}

// DNSRecordAttestation is the v2 DNS record provisioning attestation shape.
// Carried inside Badge attestations and AttestationsV1 audit payloads.
// Distinct from DNSRecord in agent.go which uses the provisioning-request
// shape with a Value field instead of Data.
type DNSRecordAttestation struct {
	Name string `json:"name"`
	Data string `json:"data"`
	Type string `json:"type"`
}
