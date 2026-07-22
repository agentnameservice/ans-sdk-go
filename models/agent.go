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

// DiscoveryProfile names one DNS record family the Registration
// Authority tells the operator to publish for an agent registration.
// Values are the V2 register schema's CONSTANT_CASE enum.
type DiscoveryProfile string

const (
	// DiscoveryProfileANSDNSAID is the DNS-AID-aligned Consolidated
	// Approach (RFC 9460): one SVCB row per protocol endpoint at the
	// bare FQDN plus the `_ans-badge` TXT and TLSA trust records. The
	// server default when discoveryProfiles is omitted.
	DiscoveryProfileANSDNSAID DiscoveryProfile = "ANS_DNSAID"
	// DiscoveryProfileANSTXT is the original `_ans` TXT shape (one row
	// per protocol at `_ans.{fqdn}`) plus an HTTPS RR at the bare FQDN
	// and the same trust records. Opt-in for operators with zone-edit
	// tooling that targets `_ans.{fqdn}`.
	DiscoveryProfileANSTXT DiscoveryProfile = "ANS_TXT"
)

// IsValidDiscoveryProfile reports whether p is a recognised discovery
// profile value.
func IsValidDiscoveryProfile(p DiscoveryProfile) bool {
	switch p {
	case DiscoveryProfileANSDNSAID, DiscoveryProfileANSTXT:
		return true
	default:
		return false
	}
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
	// DiscoveryProfiles is the set of DNS record families the RA tells
	// the operator to publish. V2 API only: the V1 lane ignores the
	// field server-side and always emits the ANS_TXT family, so
	// Client.RegisterAgent rejects a non-empty value on a V1-lane
	// client with ErrBadRequest rather than silently dropping it.
	// Omitted or empty falls back to the server default (ANS_DNSAID).
	// Send both values to publish the union during a transition.
	DiscoveryProfiles []DiscoveryProfile `json:"discoveryProfiles,omitempty"`
}

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
