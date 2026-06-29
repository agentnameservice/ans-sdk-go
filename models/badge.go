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

// Attestations contains the per-event attestations carried in the
// AGENT_REGISTERED (and other lifecycle) TL events. The struct
// supports both V1 and V2 envelope shapes:
//
//   V1 (legacy): singleton certs (IdentityCert / ServerCert),
//                no metadataHashes, no dnsRecordsProvisioned.
//   V2 (current): array certs (IdentityCerts / ServerCerts),
//                metadataHashes map (carries capabilitiesHash per
//                ANS_SPEC.md §4.4.2), and dnsRecordsProvisioned[].
//
// The deserializer accepts both shapes by pointing optional fields at
// nil/zero; readers SHOULD prefer the V2 array fields when populated
// and fall back to the V1 singletons otherwise. Helper methods on
// Badge present a unified view that hides the choice from callers.
type Attestations struct {
	DomainValidation string `json:"domainValidation"`

	// V1 singleton certs (older envelope shape).
	IdentityCert *CertAttestationV1 `json:"identityCert,omitempty"`
	ServerCert   *CertAttestationV1 `json:"serverCert,omitempty"`

	// V2 array certs (current envelope shape).
	IdentityCerts []CertAttestationV1 `json:"identityCerts,omitempty"`
	ServerCerts   []CertAttestationV1 `json:"serverCerts,omitempty"`

	// MetadataHashes carries SHA-256 hex-lowercase digests of
	// artifacts the operator submitted at registration. Reserved
	// keys (per ANS_SPEC.md §A.1):
	//   "capabilitiesHash" — SHA-256(JCS(agentCardContent)).
	// Absent when the operator did not submit agentCardContent.
	MetadataHashes map[string]string `json:"metadataHashes,omitempty"`

	// DNSRecordsProvisioned attests the records the AHP published
	// for this registration: one entry per `_ans` TXT, SVCB at the
	// agent FQDN, `_ans-badge` TXT, TLSA, and HTTPS RR depending on
	// the registration's dnsRecordStyle. Reuses the request-side
	// DNSRecord shape; clients can render zone-file fragments
	// directly from this slice.
	DNSRecordsProvisioned []DNSRecord `json:"dnsRecordsProvisioned,omitempty"`
}

// CertAttestationV1 contains certificate fingerprint and type.
type CertAttestationV1 struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
}

// MetadataHashKeyCapabilitiesHash is the well-known map key the RA
// uses for the SHA-256(JCS(agentCardContent)) digest in V2 events.
// Constant rather than string-literal at call sites so a typo in
// either the SDK or the RA surfaces as a compile error.
const MetadataHashKeyCapabilitiesHash = "capabilitiesHash"

// CapabilitiesHash returns the SHA-256 digest (hex-lowercase) the RA
// sealed for this badge's agentCardContent, or "" when the operator
// did not submit content (or the badge predates V2 envelope shape).
//
// Pair with verify.VerifyCardSHA256 to run the §4.4.2 three-way
// cross-check against a fetched live Trust Card body and a DNS-side
// SVCB card-sha256 SvcParam.
func (b *Badge) CapabilitiesHash() string {
	if b.Payload.Producer.Event.Attestations.MetadataHashes == nil {
		return ""
	}
	return b.Payload.Producer.Event.Attestations.MetadataHashes[MetadataHashKeyCapabilitiesHash]
}

// DNSRecordsProvisioned returns the records the RA attested as
// provisioned for this badge's registration. Empty when the badge
// predates the V2 envelope shape.
func (b *Badge) DNSRecordsProvisioned() []DNSRecord {
	return b.Payload.Producer.Event.Attestations.DNSRecordsProvisioned
}
