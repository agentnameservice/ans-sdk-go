package models

import "time"

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
	SchemaVersion string       `json:"schemaVersion"`
	Signature     *string      `json:"signature,omitempty"`
	MerkleProof   *MerkleProof `json:"merkleProof,omitempty"`
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

// MatchesServerCert returns true when fp matches any valid server cert.
func (b *Badge) MatchesServerCert(fp string) bool {
	for _, candidate := range b.ServerCertFingerprints() {
		if candidate == fp {
			return true
		}
	}
	return false
}

// MatchesIdentityCert returns true when fp matches any valid identity cert.
func (b *Badge) MatchesIdentityCert(fp string) bool {
	for _, candidate := range b.IdentityCertFingerprints() {
		if candidate == fp {
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
// DNSRecordsProvisioned is the v2 array shape; the v1 publisher emitted a map
// which the Badge response does not surface.
type Attestations struct {
	DomainValidation      string                  `json:"domainValidation"`
	IdentityCert          *CertAttestationV1      `json:"identityCert,omitempty"`
	ServerCert            *CertAttestationV1      `json:"serverCert,omitempty"`
	ValidIdentityCerts    []ValidCertAttestation  `json:"validIdentityCerts,omitempty"`
	ValidServerCerts      []ValidCertAttestation  `json:"validServerCerts,omitempty"`
	DNSRecordsProvisioned []DNSRecordAttestation  `json:"dnsRecordsProvisioned,omitempty"`
	MetadataHashes        map[string]string       `json:"metadataHashes,omitempty"`
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
// Carried inside Badge attestations and (in Task 5) AttestationsV1 audit
// payloads. Distinct from DNSRecord in agent.go which uses the
// provisioning-request shape with a Value field instead of Data.
type DNSRecordAttestation struct {
	Name string `json:"name"`
	Data string `json:"data"`
	Type string `json:"type"`
}
