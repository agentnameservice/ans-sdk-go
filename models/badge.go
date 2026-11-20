package models

import (
	"encoding/json"
	"fmt"
	"sort"
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
	Status        BadgeStatus  `json:"status"`
	Payload       BadgePayload `json:"payload"`
	SchemaVersion string       `json:"schemaVersion,omitempty"`
	Signature     *string      `json:"signature,omitempty"`
	MerkleProof   *MerkleProof `json:"merkleProof,omitempty"`
}

// MarshalJSON encodes the badge with its attestations in the schema V2 layout,
// the only layout Attestations can express, and stamps schemaVersion to match
// so the output decodes again through UnmarshalJSON.
func (b Badge) MarshalJSON() ([]byte, error) {
	type plain Badge
	out := plain(b)
	out.SchemaVersion = string(SchemaVersionV2)
	return json.Marshal(out)
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

// ServerCertFingerprint returns the first attested server certificate
// fingerprint, or "" when the badge lists none. Prefer ServerCertFingerprints:
// a badge may list several certificates during a rotation window.
func (b *Badge) ServerCertFingerprint() string {
	return firstFingerprint(b.Payload.Producer.Event.Attestations.ServerCerts)
}

// IdentityCertFingerprint returns the first attested identity certificate
// fingerprint, or "" when the badge lists none. Prefer IdentityCertFingerprints.
func (b *Badge) IdentityCertFingerprint() string {
	return firstFingerprint(b.Payload.Producer.Event.Attestations.IdentityCerts)
}

// ServerCertFingerprints returns every attested server certificate fingerprint.
func (b *Badge) ServerCertFingerprints() []string {
	return fingerprints(b.Payload.Producer.Event.Attestations.ServerCerts)
}

// IdentityCertFingerprints returns every attested identity certificate fingerprint.
func (b *Badge) IdentityCertFingerprints() []string {
	return fingerprints(b.Payload.Producer.Event.Attestations.IdentityCerts)
}

func firstFingerprint(certs []AttestedCert) string {
	if len(certs) == 0 {
		return ""
	}
	return certs[0].Fingerprint
}

func fingerprints(certs []AttestedCert) []string {
	if len(certs) == 0 {
		return nil
	}
	out := make([]string, len(certs))
	for i, c := range certs {
		out[i] = c.Fingerprint
	}
	return out
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
	// EventTypeAgentUpdated indicates agent metadata changed without a re-registration.
	EventTypeAgentUpdated EventType = "AGENT_UPDATED"
)

// AgentInfo contains basic agent information.
type AgentInfo struct {
	Host    string `json:"host"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Attestations is the version-neutral view of a badge's attestations.
//
// The Transparency Log has published two attestation layouts. Schema V1 carries
// a singular identityCert/serverCert plus optional validIdentityCerts/
// validServerCerts rotation arrays and a name→value map of DNS records. Schema
// V2 carries identityCerts/serverCerts arrays and an array of typed DNS records.
// Badge.UnmarshalJSON folds either layout into this one shape, so consumers
// never branch on the schema version. Badge.MarshalJSON always emits the V2
// layout.
type Attestations struct {
	DomainValidation      string                 `json:"domainValidation,omitempty"`
	IdentityCerts         []AttestedCert         `json:"identityCerts,omitempty"`
	ServerCerts           []AttestedCert         `json:"serverCerts,omitempty"`
	DNSRecordsProvisioned []DNSRecordAttestation `json:"dnsRecordsProvisioned,omitempty"`
	MetadataHashes        map[string]string      `json:"metadataHashes,omitempty"`
}

// AttestedCert describes one attested certificate. NotAfter is nil when the
// log entry predates expiry attestation.
type AttestedCert struct {
	Fingerprint string     `json:"fingerprint"`
	Type        string     `json:"type"`
	NotAfter    *time.Time `json:"notAfter,omitempty"`
}

// ValidAt reports whether the certificate is not known to have expired at now.
// A missing NotAfter counts as valid: the log did not attest an expiry.
func (c AttestedCert) ValidAt(now time.Time) bool {
	return c.NotAfter == nil || now.Before(*c.NotAfter)
}

// DNSRecordAttestation is one DNS record the RA attests it provisioned for the
// agent. Type is the DNS RR type ("TXT", "TLSA", "HTTPS"); it is empty for
// records folded from the V1 map layout, which did not carry a type.
type DNSRecordAttestation struct {
	Name string `json:"name"`
	Data string `json:"data"`
	Type string `json:"type,omitempty"`
}

// attestationsV1Wire is the schema V1 attestations layout.
type attestationsV1Wire struct {
	DomainValidation      string                  `json:"domainValidation,omitempty"`
	IdentityCert          *CertificateV1          `json:"identityCert,omitempty"`
	ServerCert            *CertificateV1          `json:"serverCert,omitempty"`
	ValidIdentityCerts    []CertificateV1Extended `json:"validIdentityCerts,omitempty"`
	ValidServerCerts      []CertificateV1Extended `json:"validServerCerts,omitempty"`
	DNSRecordsProvisioned map[string]string       `json:"dnsRecordsProvisioned,omitempty"`
	MetadataHashes        map[string]string       `json:"metadataHashes,omitempty"`
}

// toAttestations folds the V1 layout into the neutral shape. The rotation
// array wins when present; otherwise the singular certificate becomes a
// one-element list. Map entries are emitted in key order so the result is
// deterministic.
func (w attestationsV1Wire) toAttestations() Attestations {
	att := Attestations{
		DomainValidation: w.DomainValidation,
		IdentityCerts:    certsV1(w.ValidIdentityCerts, w.IdentityCert),
		ServerCerts:      certsV1(w.ValidServerCerts, w.ServerCert),
		MetadataHashes:   w.MetadataHashes,
	}
	if len(w.DNSRecordsProvisioned) > 0 {
		names := make([]string, 0, len(w.DNSRecordsProvisioned))
		for name := range w.DNSRecordsProvisioned {
			names = append(names, name)
		}
		sort.Strings(names)
		att.DNSRecordsProvisioned = make([]DNSRecordAttestation, len(names))
		for i, name := range names {
			att.DNSRecordsProvisioned[i] = DNSRecordAttestation{Name: name, Data: w.DNSRecordsProvisioned[name]}
		}
	}
	return att
}

func certsV1(plural []CertificateV1Extended, single *CertificateV1) []AttestedCert {
	if len(plural) > 0 {
		out := make([]AttestedCert, len(plural))
		for i, c := range plural {
			out[i] = AttestedCert{Fingerprint: c.Fingerprint, Type: string(c.Type), NotAfter: c.NotAfter}
		}
		return out
	}
	if single != nil {
		return []AttestedCert{{Fingerprint: single.Fingerprint, Type: string(single.Type)}}
	}
	return nil
}

// badgeWire is Badge with the attestations block left raw so the schema
// version can select how it is decoded. Every other field decodes directly.
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
	SchemaVersion string       `json:"schemaVersion,omitempty"`
	Signature     *string      `json:"signature,omitempty"`
	MerkleProof   *MerkleProof `json:"merkleProof,omitempty"`
}

// UnmarshalJSON decodes a badge of schema V1 or V2 into the version-neutral
// Badge. A missing schemaVersion is treated as V1, the layout in use before
// the field existed. Any other version is an error: the SDK must not guess at
// an attestation layout it has not seen.
func (b *Badge) UnmarshalJSON(data []byte) error {
	var raw badgeWire
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	atts, err := decodeAttestations(SchemaVersion(raw.SchemaVersion), raw.Payload.Producer.Event.Attestations)
	if err != nil {
		return err
	}

	b.Status = raw.Status
	b.SchemaVersion = raw.SchemaVersion
	b.Signature = raw.Signature
	b.MerkleProof = raw.MerkleProof
	b.Payload.LogID = raw.Payload.LogID
	b.Payload.Producer.KeyID = raw.Payload.Producer.KeyID
	b.Payload.Producer.Signature = raw.Payload.Producer.Signature
	b.Payload.Producer.Event = raw.Payload.Producer.Event.AgentEvent
	b.Payload.Producer.Event.Attestations = atts
	return nil
}

func decodeAttestations(sv SchemaVersion, raw json.RawMessage) (Attestations, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return Attestations{}, nil
	}
	switch sv {
	case SchemaVersionV1, SchemaVersionUnknown:
		var wire attestationsV1Wire
		if err := json.Unmarshal(raw, &wire); err != nil {
			return Attestations{}, fmt.Errorf("parse V1 attestations: %w", err)
		}
		return wire.toAttestations(), nil
	case SchemaVersionV2:
		var att Attestations
		if err := json.Unmarshal(raw, &att); err != nil {
			return Attestations{}, fmt.Errorf("parse V2 attestations: %w", err)
		}
		return att, nil
	case SchemaVersionV0:
		return Attestations{}, fmt.Errorf("badge schemaVersion %q is not served by the badge endpoint", sv)
	default:
		return Attestations{}, fmt.Errorf("unsupported badge schemaVersion %q", sv)
	}
}
