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
// The dnsRecordsProvisioned wire field carries two historic shapes:
//   - v1 map shape: a JSON object of name→value strings, decoded into
//     DNSRecordsProvisioned.
//   - v2 array shape: a JSON array of {name,data,type} objects, decoded into
//     DNSRecordsProvisionedV2.
//
// Badge.UnmarshalJSON and Badge.MarshalJSON pick the shape from the badge's
// schemaVersion, so a decoded badge re-encodes losslessly. Consumers should
// prefer DNSRecordsProvisionedV2 and fall back to DNSRecordsProvisioned for
// historical entries.
type Attestations struct {
	DomainValidation   string                 `json:"domainValidation"`
	IdentityCert       *CertAttestationV1     `json:"identityCert,omitempty"`
	ServerCert         *CertAttestationV1     `json:"serverCert,omitempty"`
	ValidIdentityCerts []ValidCertAttestation `json:"validIdentityCerts,omitempty"`
	ValidServerCerts   []ValidCertAttestation `json:"validServerCerts,omitempty"`
	// DNSRecordsProvisioned holds v1 map-shaped DNS provisioning data
	// (name→value). Populated by default decoding for standalone
	// Attestations and by parseV1BadgeAtts when dispatched from Badge.
	DNSRecordsProvisioned map[string]string `json:"dnsRecordsProvisioned,omitempty"`
	// DNSRecordsProvisionedV2 holds v2 array-shaped DNS provisioning data.
	// Populated only by parseV2BadgeAtts via Badge.UnmarshalJSON. The
	// json:"-" tag prevents default decoding from competing with the v1 map
	// field on the same wire key; the marshalers re-emit this shape when set.
	DNSRecordsProvisionedV2 []DNSRecordAttestation `json:"-"`
	MetadataHashes          map[string]string      `json:"metadataHashes,omitempty"`
}

// badgeAttCodec converts the attestations JSON block of one schema version
// to and from Attestations. Register new versions in badgeAttCodecs — no
// other code changes are needed.
type badgeAttCodec struct {
	decode func(raw json.RawMessage) (Attestations, error)
	encode func(a Attestations) ([]byte, error)
}

// parseV1BadgeAtts handles V1 schema attestations: singular identityCert/serverCert
// plus optional rotation arrays, and map-shaped dnsRecordsProvisioned.
func parseV1BadgeAtts(raw json.RawMessage) (Attestations, error) {
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

// parseV2BadgeAtts handles V2 schema attestations: plural serverCerts/identityCerts
// arrays (the "valid" prefix was dropped from V1 wire names), and array-shaped
// dnsRecordsProvisioned.
func parseV2BadgeAtts(raw json.RawMessage) (Attestations, error) {
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

// encodeV1BadgeAtts emits the V1 wire shape via Attestations.MarshalJSON.
func encodeV1BadgeAtts(a Attestations) ([]byte, error) {
	return json.Marshal(a)
}

// encodeV2BadgeAtts emits the V2 wire shape: plural serverCerts/identityCerts
// and array-shaped dnsRecordsProvisioned. A singular V1 cert left on the struct
// is folded into its array so no attested fingerprint is dropped.
func encodeV2BadgeAtts(a Attestations) ([]byte, error) {
	wire := struct {
		DomainValidation      string                 `json:"domainValidation"`
		ServerCerts           []ValidCertAttestation `json:"serverCerts,omitempty"`
		IdentityCerts         []ValidCertAttestation `json:"identityCerts,omitempty"`
		DNSRecordsProvisioned []DNSRecordAttestation `json:"dnsRecordsProvisioned,omitempty"`
		MetadataHashes        map[string]string      `json:"metadataHashes,omitempty"`
	}{
		DomainValidation:      a.DomainValidation,
		ServerCerts:           certsOrSingular(a.ValidServerCerts, a.ServerCert),
		IdentityCerts:         certsOrSingular(a.ValidIdentityCerts, a.IdentityCert),
		DNSRecordsProvisioned: a.DNSRecordsProvisionedV2,
		MetadataHashes:        a.MetadataHashes,
	}
	return json.Marshal(wire)
}

// certsOrSingular returns plural when populated, otherwise single wrapped in a
// one-element slice — the same v2-then-v1 fallback ServerCertFingerprints uses.
func certsOrSingular(plural []ValidCertAttestation, single *CertAttestationV1) []ValidCertAttestation {
	if len(plural) > 0 || single == nil {
		return plural
	}
	return []ValidCertAttestation{{Fingerprint: single.Fingerprint, Type: single.Type}}
}

// badgeAttCodecs maps each schema version to its attestations codec.
// V0 and SchemaVersionUnknown are intentionally absent: V0 predates the Badge
// type and is handled via TransparencyLogV0; Unknown falls back to v1 in
// codecForBadgeAtts.
//
//nolint:exhaustive,gochecknoglobals // V0/Unknown handled by codecForBadgeAtts fallback; registry pattern requires package-level dispatch table
var badgeAttCodecs = map[SchemaVersion]badgeAttCodec{
	SchemaVersionV1: {decode: parseV1BadgeAtts, encode: encodeV1BadgeAtts},
	SchemaVersionV2: {decode: parseV2BadgeAtts, encode: encodeV2BadgeAtts},
}

// codecForBadgeAtts returns the codec for the given schema version.
// Unknown or empty versions default to v1 (backward compat with badges
// that predate the schemaVersion field).
func codecForBadgeAtts(sv SchemaVersion) badgeAttCodec {
	if c, ok := badgeAttCodecs[sv]; ok {
		return c
	}
	return badgeAttCodecs[SchemaVersionV1]
}

// MarshalJSON re-emits dnsRecordsProvisioned in whichever shape is populated,
// preferring the v2 array. This keeps decode/encode round-trips lossless.
// Standalone Attestations decoding goes through default unmarshaling and is
// V1-only; V2-shaped wire bytes should be decoded via Badge.UnmarshalJSON,
// which dispatches through the parser registry.
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

// badgeWire mirrors Badge with the attestations block left raw so the
// schema-version codec can convert it in both directions.
type badgeWire struct {
	Status  BadgeStatus `json:"status"`
	Payload struct {
		LogID    string `json:"logId"`
		Producer struct {
			Event struct {
				AgentEvent
				Attestations json.RawMessage `json:"attestations"`
			} `json:"event"`
			KeyID     string `json:"keyId"`
			Signature string `json:"signature"`
		} `json:"producer"`
	} `json:"payload"`
	SchemaVersion SchemaVersion `json:"schemaVersion"`
	Signature     *string       `json:"signature,omitempty"`
	MerkleProof   *MerkleProof  `json:"merkleProof,omitempty"`
}

// MarshalJSON encodes a Badge with its attestations in the wire shape of
// SchemaVersion, mirroring UnmarshalJSON so a decoded badge re-encodes losslessly.
func (b Badge) MarshalJSON() ([]byte, error) {
	atts, err := codecForBadgeAtts(b.SchemaVersion).encode(b.Payload.Producer.Event.Attestations)
	if err != nil {
		return nil, fmt.Errorf("encode attestations (schemaVersion=%q): %w", b.SchemaVersion, err)
	}

	var raw badgeWire
	raw.Status = b.Status
	raw.SchemaVersion = b.SchemaVersion
	raw.Signature = b.Signature
	raw.MerkleProof = b.MerkleProof
	raw.Payload.LogID = b.Payload.LogID
	raw.Payload.Producer.KeyID = b.Payload.Producer.KeyID
	raw.Payload.Producer.Signature = b.Payload.Producer.Signature
	raw.Payload.Producer.Event.AgentEvent = b.Payload.Producer.Event
	raw.Payload.Producer.Event.Attestations = atts
	return json.Marshal(raw)
}

// UnmarshalJSON decodes a Badge from JSON. It reads schemaVersion first and
// dispatches the nested attestations block to the matching badgeAttCodec.
// To add V3 support: write parseV3BadgeAtts/encodeV3BadgeAtts and register them in badgeAttCodecs.
func (b *Badge) UnmarshalJSON(data []byte) error {
	var raw badgeWire
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

	atts, err := codecForBadgeAtts(b.SchemaVersion).decode(raw.Payload.Producer.Event.Attestations)
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
	Name           string `json:"name"`
	Data           string `json:"data"`
	Type           string `json:"type"`
	DNSSECVerified bool   `json:"dnssecVerified,omitempty"`
}
