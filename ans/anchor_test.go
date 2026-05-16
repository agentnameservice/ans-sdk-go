package ans

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/godaddy/ans-sdk-go/models"
)

func TestRegisterAgentV2_PathAndPayload(t *testing.T) {
	t.Parallel()
	var capturedPath, capturedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		capturedBody = string(buf[:n])
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.RegistrationPending{
			AgentID: "agent-uuid",
			ANSName: "",
			Status:  "PENDING_VALIDATION",
		})
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL), WithBearerToken("t"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	req := &models.AgentRegistrationRequest{
		AgentDisplayName: "Test",
		AgentHost:        "agent.example.com",
		Endpoints: []models.AgentEndpoint{
			{AgentURL: "https://agent.example.com/mcp", Protocol: "MCP", Transports: []string{"SSE"}},
		},
		Anchor: &models.AnchorRequest{
			AnchorType: models.AnchorTypeDID,
			Input:      "did:web:agent.example.com",
		},
	}
	resp, err := client.RegisterAgentV2(context.Background(), req)
	if err != nil {
		t.Fatalf("RegisterAgentV2: %v", err)
	}
	if resp.AgentID != "agent-uuid" {
		t.Errorf("AgentID = %q", resp.AgentID)
	}
	if capturedPath != "/v2/ans/agents" {
		t.Errorf("path = %q, want /v2/ans/agents", capturedPath)
	}
	if !strings.Contains(capturedBody, `"anchor"`) {
		t.Errorf("body missing anchor block: %s", capturedBody)
	}
	if !strings.Contains(capturedBody, `"anchorType":"did"`) {
		t.Errorf("body missing anchorType=did: %s", capturedBody)
	}
	if !strings.Contains(capturedBody, `"input":"did:web:agent.example.com"`) {
		t.Errorf("body missing did URI: %s", capturedBody)
	}
}

func TestRegisterAgentV2_NilRequestRejected(t *testing.T) {
	t.Parallel()
	client, err := NewClient(WithBaseURL("http://example.invalid"), WithBearerToken("t"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.RegisterAgentV2(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
}

func TestNewDIDWebRegistration_Shape(t *testing.T) {
	t.Parallel()
	endpoints := []models.AgentEndpoint{{AgentURL: "https://agent.example.com/mcp", Protocol: "MCP"}}
	req := NewDIDWebRegistration("Acme", "agent.example.com", "did:web:agent.example.com", endpoints)

	if req.AgentDisplayName != "Acme" {
		t.Errorf("DisplayName = %q", req.AgentDisplayName)
	}
	if req.AgentHost != "agent.example.com" {
		t.Errorf("AgentHost = %q", req.AgentHost)
	}
	if req.Version != "" {
		t.Errorf("Version should be empty for base-only DID, got %q", req.Version)
	}
	if req.IdentityCSRPEM != "" {
		t.Errorf("IdentityCSRPEM should be empty for base-only DID, got non-empty")
	}
	if req.Anchor == nil {
		t.Fatal("Anchor block missing")
	}
	if req.Anchor.AnchorType != models.AnchorTypeDID {
		t.Errorf("AnchorType = %q", req.Anchor.AnchorType)
	}
	if req.Anchor.Input != "did:web:agent.example.com" {
		t.Errorf("Input = %q", req.Anchor.Input)
	}
}

func TestNewLEIRegistration_Shape(t *testing.T) {
	t.Parallel()
	endpoints := []models.AgentEndpoint{{AgentURL: "https://agent.example.com/mcp", Protocol: "MCP"}}
	req := NewLEIRegistration("Acme", "agent.example.com", "529900T8BM49AURSDO55", endpoints)

	if req.Version != "" || req.IdentityCSRPEM != "" {
		t.Error("LEI registration should be base-only (Version + IdentityCSRPEM empty)")
	}
	if req.Anchor == nil || req.Anchor.AnchorType != models.AnchorTypeLEI {
		t.Errorf("Anchor missing or wrong type: %+v", req.Anchor)
	}
	if req.Anchor.Input != "529900T8BM49AURSDO55" {
		t.Errorf("Input = %q", req.Anchor.Input)
	}
}

func TestAgentListV2Item_AnchorPredicates(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		item        models.AgentListV2Item
		wantAnchored bool
		wantDID     bool
		wantLEI     bool
	}{
		{"legacy fqdn-implicit", models.AgentListV2Item{}, false, false, false},
		{"explicit fqdn anchor", models.AgentListV2Item{AnchorType: "fqdn"}, true, false, false},
		{"did anchor", models.AgentListV2Item{AnchorType: "did"}, true, true, false},
		{"lei anchor", models.AgentListV2Item{AnchorType: "lei"}, true, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.item.IsAnchored(); got != c.wantAnchored {
				t.Errorf("IsAnchored = %v, want %v", got, c.wantAnchored)
			}
			if got := c.item.IsDIDAnchor(); got != c.wantDID {
				t.Errorf("IsDIDAnchor = %v, want %v", got, c.wantDID)
			}
			if got := c.item.IsLEIAnchor(); got != c.wantLEI {
				t.Errorf("IsLEIAnchor = %v, want %v", got, c.wantLEI)
			}
		})
	}
}

func TestAgentListV2Response_AnchorRoundTrip(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := models.AgentListV2Response{
			Items: []models.AgentListV2Item{
				{
					AgentID:          "a-1",
					AgentDisplayName: "FQDN agent",
					AgentHost:        "fqdn.example.com",
				},
				{
					AgentID:          "a-2",
					AgentDisplayName: "DID agent",
					AgentHost:        "did-host.example.com",
					AnchorType:       "did",
					AnchorResolvedID: "did:web:did-host.example.com",
				},
				{
					AgentID:          "a-3",
					AgentDisplayName: "LEI agent",
					AgentHost:        "lei-host.example.com",
					AnchorType:       "lei",
					AnchorResolvedID: "529900T8BM49AURSDO55",
				},
			},
			ReturnedCount: 3,
			Limit:         10,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()

	client, err := NewClient(WithBaseURL(srv.URL), WithBearerToken("t"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	page, err := client.ListAgentsV2(context.Background())
	if err != nil {
		t.Fatalf("ListAgentsV2: %v", err)
	}
	if len(page.Items) != 3 {
		t.Fatalf("Items len = %d", len(page.Items))
	}
	if page.Items[0].IsAnchored() {
		t.Error("FQDN-implicit row should not be anchored")
	}
	if !page.Items[1].IsDIDAnchor() {
		t.Error("DID row should be IsDIDAnchor")
	}
	if !page.Items[2].IsLEIAnchor() {
		t.Error("LEI row should be IsLEIAnchor")
	}
	if page.Items[2].AnchorResolvedID != "529900T8BM49AURSDO55" {
		t.Errorf("LEI ResolvedID = %q", page.Items[2].AnchorResolvedID)
	}
}
