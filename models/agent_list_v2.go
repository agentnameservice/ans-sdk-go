// Package models holds the wire types the SDK serializes against the
// ANS Registry Authority HTTP API. This file carries the V2 list-shape
// types — distinct from the V1 SearchAgents response (AgentSearchResponse)
// because the V2 list endpoint at GET /v2/ans/agents wraps results
// differently than V1 search and supports cursor pagination rather than
// offset/limit pages.
package models

import "time"

// AgentListV2Response mirrors the V2 spec AgentListResponse shape
// returned by GET /v2/ans/agents. Pagination is cursor-based: callers
// drive subsequent pages by passing the prior NextCursor value into
// the `cursor` query parameter and stop when HasMore is false (or
// NextCursor is nil — the two are kept consistent by the RA).
//
// Distinct from AgentSearchResponse (V1 search). The V1 response uses
// totalCount + offset; the V2 response uses opaque cursors and a
// returnedCount that is always the length of the returned page so
// clients do not need to count for themselves.
type AgentListV2Response struct {
	// Items is the page of agents matching the filter. Empty list is
	// a valid response (filter matched nothing or the cursor pointed
	// past the end).
	Items []AgentListV2Item `json:"items"`

	// ReturnedCount is the length of Items. The RA sends it
	// explicitly so a caller serializing the response across a wire
	// boundary doesn't have to count.
	ReturnedCount int `json:"returnedCount"`

	// Limit is the page size the RA actually applied (the request's
	// `limit` clamped into the server-defined valid range, default 20,
	// max 100).
	Limit int `json:"limit"`

	// NextCursor is the opaque token to pass into the `cursor` query
	// parameter for the next page. Nil when HasMore is false.
	NextCursor *string `json:"nextCursor"`

	// HasMore reports whether further pages exist. A caller can stop
	// driving the cursor as soon as this flips to false.
	HasMore bool `json:"hasMore"`
}

// AgentListV2Item is a single row in the list page. Lighter than
// AgentDetails — no embedded RegistrationPending or DNSRecords block.
// Callers fetch the full detail via GetAgentDetails when they need it.
//
// Version and AnsName are empty strings (not omitted) for §3.2.0
// base-only registrations, where the registrant submitted neither a
// version nor an Identity CSR. AgentHost remains the canonical
// identity field for those rows.
type AgentListV2Item struct {
	AgentID               string          `json:"agentId"`
	AgentDisplayName      string          `json:"agentDisplayName"`
	AgentDescription      string          `json:"agentDescription,omitempty"`
	Version               string          `json:"version"`
	AgentHost             string          `json:"agentHost"`
	AnsName               string          `json:"ansName"`
	Status                string          `json:"status"`
	TTL                   int             `json:"ttl"`
	RegistrationTimestamp time.Time       `json:"registrationTimestamp,omitempty"`
	Endpoints             []AgentEndpoint `json:"endpoints"`
	Links                 []Link          `json:"links"`
}

// IsBaseOnly reports whether this row was registered through the
// §3.2.0 base-only path: no ANSName, no version. Callers that mix
// versioned and base-only agents in the same UI use this rather than
// pattern-matching empty strings.
func (a AgentListV2Item) IsBaseOnly() bool {
	return a.AnsName == "" && a.Version == ""
}
