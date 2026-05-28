package models

import (
	"encoding/json"
	"time"
)

// TransparencyLogV1 represents the V1 schema for ANS Transparency Log entries
type TransparencyLogV1 struct {
	LogID    string     `json:"logId"`
	Producer ProducerV1 `json:"producer"`
}

// ProducerV1 represents the producer section of V1 schema
type ProducerV1 struct {
	Event     EventV1 `json:"event"`
	KeyID     string  `json:"keyId"`
	Signature string  `json:"signature"`
}

// EventV1 represents the event structure in V1 schema
type EventV1 struct {
	ANSID                string            `json:"ansId"`
	ANSName              string            `json:"ansName"`
	EventType            EventTypeV1       `json:"eventType"`
	Agent                AgentV1           `json:"agent"`
	Attestations         AttestationsV1    `json:"attestations"`
	ExpiresAt            *time.Time        `json:"expiresAt,omitempty"`
	IssuedAt             time.Time         `json:"issuedAt"`
	RAID                 string            `json:"raId"`
	RenewalStatus        *string           `json:"renewalStatus,omitempty"`
	RevocationReasonCode *RevocationReason `json:"revocationReasonCode,omitempty"`
	RevokedAt            *time.Time        `json:"revokedAt,omitempty"`
	Timestamp            time.Time         `json:"timestamp"`
}

// EventTypeV1 represents the event types in V1 schema
type EventTypeV1 string

const (
	EventTypeV1AgentDeprecated EventTypeV1 = "AGENT_DEPRECATED"
	EventTypeV1AgentRegistered EventTypeV1 = "AGENT_REGISTERED"
	EventTypeV1AgentRenewed    EventTypeV1 = "AGENT_RENEWED"
	EventTypeV1AgentRevoked    EventTypeV1 = "AGENT_REVOKED"
)

// AgentV1 represents the agent information in V1 schema
type AgentV1 struct {
	Host       string  `json:"host"`
	Name       *string `json:"name,omitempty"`
	Version    string  `json:"version"`
	ProviderID *string `json:"providerId,omitempty"`
}

// AttestationsV1 represents the attestations in V1 schema.
//
// The dnsRecordsProvisioned wire field carries two distinct shapes depending on
// the schema version of the producing publisher:
//   - v1 map shape: a JSON object with name→value string pairs. Populated into
//     DNSRecordsProvisioned.
//   - v2 array shape: a JSON array of {name, data, type} objects. Populated into
//     DNSRecordsProvisionedV2.
//
// Consumers should check DNSRecordsProvisionedV2 first; fall back to
// DNSRecordsProvisioned for historical entries.
type AttestationsV1 struct {
	// DNSRecordsProvisioned holds v1 map-shaped DNS provisioning data.
	// Populated from JSON only when the wire value is a JSON object.
	DNSRecordsProvisioned map[string]string `json:"dnsRecordsProvisioned,omitempty"`
	// DNSRecordsProvisionedV2 holds v2 array-shaped DNS provisioning data.
	// Populated from JSON only when the wire value is a JSON array.
	// Not emitted during marshaling (tag json:"-") to avoid collision with
	// the map field's key.
	DNSRecordsProvisionedV2 []DNSRecordAttestation  `json:"-"`
	DomainValidation        *string                 `json:"domainValidation,omitempty"`
	IdentityCert            *CertificateV1          `json:"identityCert,omitempty"`
	MetadataHashes          map[string]string       `json:"metadataHashes,omitempty"`
	ServerCert              *CertificateV1          `json:"serverCert,omitempty"`
	ValidIdentityCerts      []CertificateV1Extended `json:"validIdentityCerts,omitempty"`
	ValidServerCerts        []CertificateV1Extended `json:"validServerCerts,omitempty"`
}

// UnmarshalJSON implements json.Unmarshaler for AttestationsV1. It handles the
// two historic wire shapes for dnsRecordsProvisioned: a JSON object (v1 map) and
// a JSON array of {name,data,type} objects (v2). All other fields are decoded
// with standard semantics.
func (a *AttestationsV1) UnmarshalJSON(data []byte) error {
	type rawAtt struct {
		DNSRecordsProvisioned json.RawMessage         `json:"dnsRecordsProvisioned,omitempty"`
		DomainValidation      *string                 `json:"domainValidation,omitempty"`
		IdentityCert          *CertificateV1          `json:"identityCert,omitempty"`
		MetadataHashes        map[string]string       `json:"metadataHashes,omitempty"`
		ServerCert            *CertificateV1          `json:"serverCert,omitempty"`
		ValidIdentityCerts    []CertificateV1Extended `json:"validIdentityCerts,omitempty"`
		ValidServerCerts      []CertificateV1Extended `json:"validServerCerts,omitempty"`
	}
	var r rawAtt
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	a.DomainValidation = r.DomainValidation
	a.IdentityCert = r.IdentityCert
	a.MetadataHashes = r.MetadataHashes
	a.ServerCert = r.ServerCert
	a.ValidIdentityCerts = r.ValidIdentityCerts
	a.ValidServerCerts = r.ValidServerCerts

	if len(r.DNSRecordsProvisioned) == 0 {
		return nil
	}
	// Try array first (v2 shape).
	a.DNSRecordsProvisionedV2 = nil
	if err := json.Unmarshal(r.DNSRecordsProvisioned, &a.DNSRecordsProvisionedV2); err == nil {
		return nil
	}
	// Clear any partial array residue from the failed attempt, then fall back
	// to map (v1 shape).
	a.DNSRecordsProvisionedV2 = nil
	return json.Unmarshal(r.DNSRecordsProvisioned, &a.DNSRecordsProvisioned)
}

// CertificateV1 represents certificate information in V1 schema
type CertificateV1 struct {
	Fingerprint string   `json:"fingerprint"`
	Type        CertType `json:"type"`
}

// CertificateV1Extended represents certificate information with validity period.
// Used in multi-cert arrays (ValidIdentityCerts, ValidServerCerts).
type CertificateV1Extended struct {
	CertificateV1
	NotAfter *time.Time `json:"notAfter,omitempty"`
}

// CertType represents certificate types
type CertType string

const (
	CertTypeX509DVServer CertType = "X509-DV-SERVER"
	CertTypeX509EVClient CertType = "X509-EV-CLIENT"
	CertTypeX509EVServer CertType = "X509-EV-SERVER"
	CertTypeX509OVClient CertType = "X509-OV-CLIENT"
	CertTypeX509OVServer CertType = "X509-OV-SERVER"
)

// RevocationReason represents RFC 5280 revocation reason codes
type RevocationReason string

const (
	RevocationReasonAACompromise         RevocationReason = "AA_COMPROMISE"
	RevocationReasonAffiliationChanged   RevocationReason = "AFFILIATION_CHANGED"
	RevocationReasonCACompromise         RevocationReason = "CA_COMPROMISE"
	RevocationReasonCertificateHold      RevocationReason = "CERTIFICATE_HOLD"
	RevocationReasonCessationOfOperation RevocationReason = "CESSATION_OF_OPERATION"
	RevocationReasonExpiredCert          RevocationReason = "EXPIRED_CERT"
	RevocationReasonKeyCompromise        RevocationReason = "KEY_COMPROMISE"
	RevocationReasonPrivilegeWithdrawn   RevocationReason = "PRIVILEGE_WITHDRAWN"
	RevocationReasonRemoveFromCRL        RevocationReason = "REMOVE_FROM_CRL"
	RevocationReasonSuperseded           RevocationReason = "SUPERSEDED"
	RevocationReasonUnspecified          RevocationReason = "UNSPECIFIED"
)

// TransparencyLogV0 represents the V0 schema for ANS Transparency Log entries
type TransparencyLogV0 struct {
	LogID    string     `json:"logId"`
	Producer ProducerV0 `json:"producer"`
}

// ProducerV0 represents the producer section of V0 schema
type ProducerV0 struct {
	Event     EventV0 `json:"event"`
	KeyID     string  `json:"keyId"`
	Signature string  `json:"signature"`
}

// EventV0 represents the event structure in V0 schema
type EventV0 struct {
	AgentFQDN string         `json:"agentFqdn"`
	AgentID   string         `json:"agentId"`
	ANSName   string         `json:"ansName"`
	EventType EventTypeV0    `json:"eventType"`
	Protocol  string         `json:"protocol"`
	RABadge   RABadge        `json:"raBadge"`
	Timestamp time.Time      `json:"timestamp"`
	Metadata  *EventMetadata `json:"metadata,omitempty"`
}

// EventTypeV0 represents the event types in V0 schema
type EventTypeV0 string

const (
	EventTypeV0AgentActive         EventTypeV0 = "AGENT_ACTIVE"
	EventTypeV0AgentRevocation     EventTypeV0 = "AGENT_REVOCATION"
	EventTypeV0CertificateExpiring EventTypeV0 = "CERTIFICATE_EXPIRING"
	EventTypeV0CertificateRenewed  EventTypeV0 = "CERTIFICATE_RENEWED"

	// EventTypeV0AgentActiveLower is the lowercase variant of agent_active event type
	EventTypeV0AgentActiveLower         EventTypeV0 = "agent_active"
	EventTypeV0AgentRevocationLower     EventTypeV0 = "agent_revocation"
	EventTypeV0CertificateExpiringLower EventTypeV0 = "certificate_expiring"
	EventTypeV0CertificateRenewedLower  EventTypeV0 = "certificate_renewed"
)

// EventMetadata represents optional metadata in V0 schema
type EventMetadata struct {
	AgentCardURL    *string  `json:"agentCardUrl,omitempty"`
	ANSCapabilities []string `json:"ansCapabilities,omitempty"`
	Description     *string  `json:"description,omitempty"`
	Endpoint        *string  `json:"endpoint,omitempty"`
	RABadgeURL      *string  `json:"raBadgeUrl,omitempty"`
}

// RABadge represents the RA badge in V0 schema
type RABadge struct {
	ANSCapabilitiesHash  *string           `json:"ansCapabilitiesHash,omitempty"`
	Attestations         AttestationsV0    `json:"attestations"`
	BadgeURLStatus       string            `json:"badgeUrlStatus"`
	ExpiresAt            *time.Time        `json:"expiresAt,omitempty"`
	IssuedAt             time.Time         `json:"issuedAt"`
	RAID                 string            `json:"raId"`
	RenewalStatus        *string           `json:"renewalStatus,omitempty"`
	RevocationReasonCode *RevocationReason `json:"revocationReasonCode,omitempty"`
}

// AttestationsV0 represents the attestations in V0 schema
type AttestationsV0 struct {
	ClientCertFingerprint       *string           `json:"clientCertFingerprint,omitempty"`
	CSRSubmission               *string           `json:"csrSubmission,omitempty"`
	DNSRecordsProvisioned       map[string]string `json:"dnsRecordsProvisioned,omitempty"`
	DNSRecordsProvisionedStatus *string           `json:"dnsRecordsProvisionedStatus,omitempty"`
	DNSSECStatus                *string           `json:"dnssecStatus,omitempty"`
	DomainValidation            *string           `json:"domainValidation,omitempty"`
	DomainValidationStatus      *string           `json:"domainValidationStatus,omitempty"`
	IdentityCertType            *string           `json:"identityCertType,omitempty"`
	ProtocolExtensionsVerified  *string           `json:"protocolExtensionsVerified,omitempty"`
	ServerCertFingerprint       *string           `json:"serverCertFingerprint,omitempty"`
	ServerCertType              *string           `json:"serverCertType,omitempty"`
}

// SchemaVersion represents the schema version enum
type SchemaVersion string

const (
	SchemaVersionV0      SchemaVersion = "V0"
	SchemaVersionV1      SchemaVersion = "V1"
	SchemaVersionUnknown SchemaVersion = ""
)
