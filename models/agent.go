package models

import (
	"encoding/json"
	"time"
)

// AgentLifecycleStatus is a registration-lifecycle state value accepted by the
// `status` query parameter on GET /v1/agents. Multiple values may be combined
// on a single request; the API defaults to ACTIVE when the parameter is absent.
type AgentLifecycleStatus string

const (
	AgentStatusPendingDNS AgentLifecycleStatus = "PENDING_DNS"
	AgentStatusActive     AgentLifecycleStatus = "ACTIVE"
	AgentStatusDeprecated AgentLifecycleStatus = "DEPRECATED"
	AgentStatusRevoked    AgentLifecycleStatus = "REVOKED"
	AgentStatusAll        AgentLifecycleStatus = "ALL"
)

// IsValidAgentLifecycleStatus reports whether s is a recognised lifecycle
// status value.
func IsValidAgentLifecycleStatus(s AgentLifecycleStatus) bool {
	switch s {
	case AgentStatusPendingDNS, AgentStatusActive, AgentStatusDeprecated,
		AgentStatusRevoked, AgentStatusAll:
		return true
	default:
		return false
	}
}

// AgentProtocol is a protocol filter value accepted by the `protocol` query
// parameter on GET /v1/agents.
type AgentProtocol string

const (
	AgentProtocolA2A     AgentProtocol = "A2A"
	AgentProtocolMCP     AgentProtocol = "MCP"
	AgentProtocolHTTPAPI AgentProtocol = "HTTP-API"
)

// IsValidAgentProtocol reports whether p is a recognised protocol filter value.
func IsValidAgentProtocol(p AgentProtocol) bool {
	switch p {
	case AgentProtocolA2A, AgentProtocolMCP, AgentProtocolHTTPAPI:
		return true
	default:
		return false
	}
}

// AgentEndpoint represents an agent endpoint configuration
type AgentEndpoint struct {
	AgentURL         string          `json:"agentUrl"`
	MetaDataURL      string          `json:"metaDataUrl,omitempty"`
	DocumentationURL string          `json:"documentationUrl,omitempty"`
	Protocol         string          `json:"protocol"`
	Transports       []string        `json:"transports,omitempty"`
	Functions        []AgentFunction `json:"functions,omitempty"`
}

// AgentFunction describes a function provided by an agent endpoint
type AgentFunction struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Tags []string `json:"tags,omitempty"`
}

// AgentRegistrationRequest represents a registration request
type AgentRegistrationRequest struct {
	AgentDisplayName          string          `json:"agentDisplayName"`
	AgentHost                 string          `json:"agentHost"`
	AgentDescription          string          `json:"agentDescription,omitempty"`
	IdentityCSRPEM            string          `json:"identityCsrPEM"`
	ServerCertificatePEM      string          `json:"serverCertificatePEM,omitempty"`
	ServerCertificateChainPEM string          `json:"serverCertificateChainPEM,omitempty"`
	ServerCSRPEM              string          `json:"serverCsrPEM,omitempty"`
	Version                   string          `json:"version"`
	Endpoints                 []AgentEndpoint `json:"endpoints"`

	// AgentCardContent is the optional ANS Trust Card body the
	// operator submits per ANS_SPEC.md §A.1. The RA computes
	// SHA-256 over the JCS-canonical bytes (RFC 8785) and seals
	// the hex-lowercase digest into the AGENT_REGISTERED TL event
	// under attestations.metadataHashes.capabilitiesHash. The same
	// digest re-encoded as base64url appears in the Consolidated
	// Approach SVCB record's card-sha256 SvcParam (§4.4.2 cross-
	// check).
	//
	// Modeled as json.RawMessage so the operator-submitted bytes
	// reach the RA without re-marshaling — JCS canonicalization is
	// byte-precise; any round-trip through map[string]any could
	// shift the digest.
	AgentCardContent json.RawMessage `json:"agentCardContent,omitempty"`

	// DNSRecordStyle selects which DNS record family the RA emits
	// for this registration. Use the DNSRecordStyle* constants:
	//   "consolidated" (default): Consolidated Approach SVCB at the
	//      bare FQDN per ANS_SPEC.md §4.4.2, plus shared records.
	//   "legacy": original `_ans` TXT shape plus shared records
	//      plus an HTTPS RR. Backwards-compatible.
	//   "both": union; the §4.4.2 transition shape.
	//
	// Empty/missing → consolidated (the RA applies the default).
	DNSRecordStyle string `json:"dnsRecordStyle,omitempty"`
}

// DNSRecordStyle constants enumerate the supported values for
// AgentRegistrationRequest.DNSRecordStyle.
const (
	DNSRecordStyleConsolidated = "consolidated"
	DNSRecordStyleLegacy       = "legacy"
	DNSRecordStyleBoth         = "both"
	// DefaultDNSRecordStyle is what the RA applies when the request
	// omits dnsRecordStyle. Pinned to "consolidated" so callers that
	// don't think about the field still get the §4.4.2 SHOULD shape.
	DefaultDNSRecordStyle = DNSRecordStyleConsolidated
)

// DNSRecord type-string constants. The wire format uses uppercase
// strings; these constants prevent typos at call sites.
const (
	DNSRecordTypeTXT   = "TXT"
	DNSRecordTypeTLSA  = "TLSA"
	DNSRecordTypeHTTPS = "HTTPS"
	DNSRecordTypeSVCB  = "SVCB"
)

// RegistrationPending represents a pending registration response
type RegistrationPending struct {
	Status     string          `json:"status"`
	ANSName    string          `json:"ansName"`
	AgentID    string          `json:"agentId,omitempty"`
	Challenges []ChallengeInfo `json:"challenges,omitempty"`
	DNSRecords []DNSRecord     `json:"dnsRecords,omitempty"`
	ExpiresAt  time.Time       `json:"expiresAt,omitempty"`
	Links      []Link          `json:"links,omitempty"`
	NextSteps  []NextStep      `json:"nextSteps"`
}

// ChallengeInfo represents ACME challenge information
type ChallengeInfo struct {
	Type             string            `json:"type"`
	Token            string            `json:"token,omitempty"`
	KeyAuthorization string            `json:"keyAuthorization,omitempty"`
	HTTPPath         string            `json:"httpPath,omitempty"`
	DNSRecord        *DNSRecordDetails `json:"dnsRecord,omitempty"`
	ExpiresAt        time.Time         `json:"expiresAt,omitempty"`
}

// DNSRecordDetails represents DNS record details for ACME challenge
type DNSRecordDetails struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// DNSRecord represents a DNS record to be configured
type DNSRecord struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Purpose  string `json:"purpose,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
	Priority int    `json:"priority,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// NextStep represents a required action
type NextStep struct {
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
	Endpoint    string `json:"endpoint,omitempty"`
}

// Link represents a HATEOAS link
type Link struct {
	Href string `json:"href"`
	Rel  string `json:"rel"`
}

// AgentStatus represents agent status information
// It can unmarshal from either a string (e.g., "ACTIVE") or an object with detailed status
type AgentStatus struct {
	Status         string    `json:"status,omitempty"`
	Phase          string    `json:"phase,omitempty"`
	CreatedAt      time.Time `json:"createdAt,omitempty"`
	UpdatedAt      time.Time `json:"updatedAt,omitempty"`
	ExpiresAt      time.Time `json:"expiresAt,omitempty"`
	PendingSteps   []string  `json:"pendingSteps,omitempty"`
	CompletedSteps []string  `json:"completedSteps,omitempty"`
}

// UnmarshalJSON implements custom unmarshaling to handle both string and object formats
func (a *AgentStatus) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as a simple string first
	var statusString string
	if err := json.Unmarshal(data, &statusString); err == nil {
		a.Status = statusString
		return nil
	}

	// If that fails, unmarshal as an object
	type Alias AgentStatus
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	return json.Unmarshal(data, aux)
}

// AgentDetails represents detailed agent information
type AgentDetails struct {
	AgentID               string               `json:"agentId"`
	AgentDisplayName      string               `json:"agentDisplayName"`
	AgentHost             string               `json:"agentHost"`
	AgentDescription      string               `json:"agentDescription,omitempty"`
	ANSName               string               `json:"ansName"`
	Version               string               `json:"version"`
	AgentStatus           *AgentStatus         `json:"agentStatus,omitempty"`
	Endpoints             []AgentEndpoint      `json:"endpoints"`
	DNSRecords            []DNSRecord          `json:"dnsRecords,omitempty"`
	RegistrationTimestamp time.Time            `json:"registrationTimestamp,omitempty"`
	LastRenewalTimestamp  time.Time            `json:"lastRenewalTimestamp,omitempty"`
	RegistrationPending   *RegistrationPending `json:"registrationPending,omitempty"`
	Links                 []Link               `json:"links,omitempty"`
}

// ChallengeDetails represents detailed challenge information
type ChallengeDetails struct {
	Status     string          `json:"status,omitempty"`
	Challenges []ChallengeInfo `json:"challenges,omitempty"`
	CreatedAt  time.Time       `json:"createdAt,omitempty"`
	ExpiresAt  time.Time       `json:"expiresAt,omitempty"`
}

// AgentSearchResponse represents search results
type AgentSearchResponse struct {
	Agents         []AgentSearchResult `json:"agents"`
	TotalCount     int                 `json:"totalCount"`
	ReturnedCount  int                 `json:"returnedCount"`
	Limit          int                 `json:"limit"`
	Offset         int                 `json:"offset"`
	HasMore        bool                `json:"hasMore"`
	SearchCriteria *SearchCriteria     `json:"searchCriteria,omitempty"`
}

// AgentSearchResult represents a single search result
type AgentSearchResult struct {
	AgentDisplayName      string          `json:"agentDisplayName"`
	AgentHost             string          `json:"agentHost"`
	AgentDescription      string          `json:"agentDescription,omitempty"`
	ANSName               string          `json:"ansName"`
	Version               string          `json:"version"`
	Endpoints             []AgentEndpoint `json:"endpoints"`
	RegistrationTimestamp time.Time       `json:"registrationTimestamp,omitempty"`
	TTL                   int             `json:"ttl,omitempty"`
	Links                 []Link          `json:"links,omitempty"`
}

// SearchCriteria represents search criteria used
type SearchCriteria struct {
	AgentDisplayName string `json:"agentDisplayName,omitempty"`
	AgentHost        string `json:"agentHost,omitempty"`
	Version          string `json:"version,omitempty"`
}
