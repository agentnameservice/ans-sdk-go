package scitt

// AgentStatus represents an agent's operational status.
type AgentStatus string

const (
	// StatusActive indicates the agent is active and fully operational.
	StatusActive AgentStatus = "ACTIVE"
	// StatusWarning indicates the agent has warnings but is still operational.
	StatusWarning AgentStatus = "WARNING"
	// StatusDeprecated indicates the agent is deprecated but still allows connections.
	StatusDeprecated AgentStatus = "DEPRECATED"
	// StatusExpired indicates the agent's registration has expired (terminal).
	StatusExpired AgentStatus = "EXPIRED"
	// StatusRevoked indicates the agent's registration has been revoked (terminal).
	StatusRevoked AgentStatus = "REVOKED"
)

// IsValidForConnection returns true if the status allows new connections.
func (s AgentStatus) IsValidForConnection() bool {
	switch s { //nolint:exhaustive // terminal statuses handled by default
	case StatusActive, StatusWarning, StatusDeprecated:
		return true
	default:
		return false
	}
}

// IsTerminal returns true if the status is a terminal state (no recovery).
func (s AgentStatus) IsTerminal() bool {
	switch s { //nolint:exhaustive // connection-valid statuses handled by default
	case StatusExpired, StatusRevoked:
		return true
	default:
		return false
	}
}

// CertType represents the type of certificate.
type CertType string

const (
	// CertTypeX509DVServer is a domain-validated server certificate.
	CertTypeX509DVServer CertType = "x509-dv-server"
	// CertTypeX509OVClient is an organization-validated client certificate.
	CertTypeX509OVClient CertType = "x509-ov-client"
)

// CertEntry is a certificate fingerprint with its type.
type CertEntry struct {
	Fingerprint [32]byte
	CertType    CertType
}

// StatusTokenPayload is the decoded payload of a verified status token.
type StatusTokenPayload struct {
	AgentID            string
	AnsName            string
	Status             AgentStatus
	Iat                int64
	Exp                int64
	ValidIdentityCerts []CertEntry
	ValidServerCerts   []CertEntry
	MetadataHashes     map[string]string
}
