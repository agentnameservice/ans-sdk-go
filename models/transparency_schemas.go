package models

import "time"

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

// AttestationsV1 represents the attestations in V1 schema. The
// dnsRecordsProvisioned wire field is a JSON object of name→value strings.
// V2 attestations (array DNS, plural cert arrays without the "valid" prefix)
// live on AttestationsV2.
type AttestationsV1 struct {
	DNSRecordsProvisioned map[string]string       `json:"dnsRecordsProvisioned,omitempty"`
	DomainValidation      *string                 `json:"domainValidation,omitempty"`
	IdentityCert          *CertificateV1          `json:"identityCert,omitempty"`
	MetadataHashes        map[string]string       `json:"metadataHashes,omitempty"`
	ServerCert            *CertificateV1          `json:"serverCert,omitempty"`
	ValidIdentityCerts    []CertificateV1Extended `json:"validIdentityCerts,omitempty"`
	ValidServerCerts      []CertificateV1Extended `json:"validServerCerts,omitempty"`
}

// TransparencyLogV2 represents the V2 schema for ANS Transparency Log entries.
// V2 mirrors V1 except for the attestations shape (plural cert arrays without the
// "valid" prefix and array-shaped dnsRecordsProvisioned).
type TransparencyLogV2 struct {
	LogID    string     `json:"logId"`
	Producer ProducerV2 `json:"producer"`
}

// ProducerV2 represents the producer section of V2 schema
type ProducerV2 struct {
	Event     EventV2 `json:"event"`
	KeyID     string  `json:"keyId"`
	Signature string  `json:"signature"`
}

// EventV2 represents the event structure in V2 schema. Field set mirrors EventV1;
// only Attestations differs.
type EventV2 struct {
	ANSID                string            `json:"ansId"`
	ANSName              string            `json:"ansName"`
	EventType            EventTypeV2       `json:"eventType"`
	Agent                AgentV2           `json:"agent"`
	Attestations         AttestationsV2    `json:"attestations"`
	ExpiresAt            *time.Time        `json:"expiresAt,omitempty"`
	IssuedAt             time.Time         `json:"issuedAt"`
	RAID                 string            `json:"raId"`
	RenewalStatus        *string           `json:"renewalStatus,omitempty"`
	RevocationReasonCode *RevocationReason `json:"revocationReasonCode,omitempty"`
	RevokedAt            *time.Time        `json:"revokedAt,omitempty"`
	Timestamp            time.Time         `json:"timestamp"`
}

// EventTypeV2 represents the event types in V2 schema (same values as V1).
type EventTypeV2 string

const (
	EventTypeV2AgentDeprecated EventTypeV2 = "AGENT_DEPRECATED"
	EventTypeV2AgentRegistered EventTypeV2 = "AGENT_REGISTERED"
	EventTypeV2AgentRenewed    EventTypeV2 = "AGENT_RENEWED"
	EventTypeV2AgentRevoked    EventTypeV2 = "AGENT_REVOKED"
)

// AgentV2 represents the agent information in V2 schema (same shape as AgentV1).
type AgentV2 struct {
	Host       string  `json:"host"`
	Name       *string `json:"name,omitempty"`
	Version    string  `json:"version"`
	ProviderID *string `json:"providerId,omitempty"`
}

// AttestationsV2 represents the attestations in V2 schema. Wire field names
// match the Badge V2 surface: plural cert arrays (without the V1 "valid"
// prefix) and array-shaped dnsRecordsProvisioned.
type AttestationsV2 struct {
	DomainValidation      *string                 `json:"domainValidation,omitempty"`
	ServerCerts           []CertificateV1Extended `json:"serverCerts,omitempty"`
	IdentityCerts         []CertificateV1Extended `json:"identityCerts,omitempty"`
	DNSRecordsProvisioned []DNSRecordAttestation  `json:"dnsRecordsProvisioned,omitempty"`
	MetadataHashes        map[string]string       `json:"metadataHashes,omitempty"`
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
	SchemaVersionV2      SchemaVersion = "V2"
	SchemaVersionUnknown SchemaVersion = ""
)
