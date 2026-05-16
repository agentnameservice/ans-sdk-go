package ans

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/godaddy/ans-sdk-go/models"
)

// TestListAgentsV2_WrapperShape pins the SDK's expectation of the
// V2 list response wrapper. The RA returns
// {items, returnedCount, limit, nextCursor, hasMore} — pre-Plan-E
// the SDK had no V2 list method and a hand-built integration test
// tried to decode the wrapper into a bare []Agent slice, which is
// the original "shape mismatch" stall this test prevents from
// recurring.
func TestListAgentsV2_WrapperShape(t *testing.T) {
	t.Parallel()
	cursor := "next-page-cursor"
	wantBody := models.AgentListV2Response{
		Items: []models.AgentListV2Item{
			{
				AgentID:               "11111111-1111-1111-1111-111111111111",
				AgentDisplayName:      "ans-registration",
				AgentDescription:      "Project skill: ans-registration",
				Version:               "",
				AgentHost:             "ans-registration.skills.example.com",
				AnsName:               "",
				Status:                "PENDING_VALIDATION",
				TTL:                   300,
				RegistrationTimestamp: time.Date(2026, 5, 16, 12, 0, 0, 0, time.UTC),
				Endpoints: []models.AgentEndpoint{{
					AgentURL:   "https://ans-registration.skills.example.com/mcp",
					Protocol:   string(models.AgentProtocolMCP),
					Transports: []string{"SSE"},
				}},
				Links: []models.Link{{Rel: "self", Href: "/v2/ans/agents/11111111-1111-1111-1111-111111111111"}},
			},
		},
		ReturnedCount: 1,
		Limit:         20,
		NextCursor:    &cursor,
		HasMore:       true,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/ans/agents" {
			t.Errorf("path: got %q want /v2/ans/agents", r.URL.Path)
		}
		// Confirm the option set serializes into the right query params.
		got := r.URL.Query()
		if got.Get("agentHost") != "ans-registration.skills.example.com" {
			t.Errorf("agentHost: got %q", got.Get("agentHost"))
		}
		if got.Get("limit") != "5" {
			t.Errorf("limit: got %q want 5", got.Get("limit"))
		}
		if got["status"][0] != "PENDING_VALIDATION" {
			t.Errorf("status: got %v", got["status"])
		}
		if got.Get("cursor") != "page-token" {
			t.Errorf("cursor: got %q", got.Get("cursor"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wantBody)
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL), WithJWT("t"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	got, err := client.ListAgentsV2(context.Background(),
		WithListV2Host("ans-registration.skills.example.com"),
		WithListV2Status(models.AgentStatusPendingValidation),
		WithListV2Cursor("page-token"),
		WithListV2Limit(5),
	)
	if err != nil {
		t.Fatalf("ListAgentsV2: %v", err)
	}
	if got.ReturnedCount != 1 {
		t.Errorf("ReturnedCount: got %d want 1", got.ReturnedCount)
	}
	if !got.HasMore {
		t.Errorf("HasMore: got false want true")
	}
	if got.NextCursor == nil || *got.NextCursor != cursor {
		t.Errorf("NextCursor: got %v want %q", got.NextCursor, cursor)
	}
	if len(got.Items) != 1 {
		t.Fatalf("Items: got %d want 1", len(got.Items))
	}
	item := got.Items[0]
	if !item.IsBaseOnly() {
		t.Errorf("IsBaseOnly: expected true for empty AnsName + empty Version")
	}
	if item.AgentHost != "ans-registration.skills.example.com" {
		t.Errorf("AgentHost: got %q", item.AgentHost)
	}
	if item.Status != "PENDING_VALIDATION" {
		t.Errorf("Status: got %q", item.Status)
	}
}

// TestListAgentsV2_NoFilters confirms a zero-option call hits the
// endpoint with no query parameters.
func TestListAgentsV2_NoFilters(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("RawQuery: got %q want empty", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.AgentListV2Response{Items: []models.AgentListV2Item{}, Limit: 20})
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL), WithJWT("t"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got, err := client.ListAgentsV2(context.Background())
	if err != nil {
		t.Fatalf("ListAgentsV2: %v", err)
	}
	if got.HasMore {
		t.Errorf("HasMore: got true want false")
	}
}

// TestListAgentsV2_InvalidStatus surfaces option-validation errors
// before the network call.
func TestListAgentsV2_InvalidStatus(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Errorf("server should not have been called for an option-validation error")
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL), WithJWT("t"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.ListAgentsV2(context.Background(),
		WithListV2Status(models.AgentLifecycleStatus("BOGUS")))
	if err == nil {
		t.Fatalf("ListAgentsV2: expected error for invalid lifecycle status")
	}
}

// Use url.Values implicitly via the option assertions above; keep
// the import alive when the test suite is split.
var _ = url.QueryEscape
