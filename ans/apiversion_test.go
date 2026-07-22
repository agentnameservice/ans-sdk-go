package ans

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/models"
)

// TestWithAPIVersion_Validation covers construction-time validation:
// recognised lanes are accepted, anything else is rejected with
// models.ErrBadRequest before a request can be sent to a wrong path.
func TestWithAPIVersion_Validation(t *testing.T) {
	tests := []struct {
		name    string
		version APIVersion
		wantErr bool
	}{
		{name: "v1 accepted", version: APIVersionV1},
		{name: "v2 accepted", version: APIVersionV2},
		{name: "empty rejected", version: APIVersion(""), wantErr: true},
		{name: "uppercase rejected", version: APIVersion("V2"), wantErr: true},
		{name: "garbage rejected", version: APIVersion("v3"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(WithBaseURL("http://example.invalid"), WithJWT("t"), WithAPIVersion(tt.version))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient(WithAPIVersion(%q)) error = %v, wantErr %v", tt.version, err, tt.wantErr)
			}
		})
	}
}

// TestAPIVersion_PathRouting pins the exact path every lane-routed
// method targets on each API version — both lanes, so the V1 paths the
// agentPath refactor rewrote stay pinned for existing users — plus the
// V1-pinned methods whose paths must NOT move when the client is built
// for the V2 lane. The client decodes the shared subset of both lanes'
// response shapes, so the path is the behavioral difference under test.
func TestAPIVersion_PathRouting(t *testing.T) {
	const agentID = "11111111-2222-3333-4444-555555555555"

	tests := []struct {
		name       string
		version    APIVersion
		wantMethod string
		wantPath   string
		body       string // response body; "{}" default
		call       func(ctx context.Context, c *Client) error
	}{
		// ----- lane-routed methods, V1 (default) -----
		{
			name: "register v1", version: APIVersionV1,
			wantMethod: http.MethodPost, wantPath: "/v1/agents/register",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.RegisterAgent(ctx, &models.AgentRegistrationRequest{})
				return err
			},
		},
		{
			name: "details v1", version: APIVersionV1,
			wantMethod: http.MethodGet, wantPath: "/v1/agents/" + agentID,
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetAgentDetails(ctx, agentID)
				return err
			},
		},
		{
			name: "verify-acme v1", version: APIVersionV1,
			wantMethod: http.MethodPost, wantPath: "/v1/agents/" + agentID + "/verify-acme",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.VerifyACME(ctx, agentID)
				return err
			},
		},
		{
			name: "verify-dns v1", version: APIVersionV1,
			wantMethod: http.MethodPost, wantPath: "/v1/agents/" + agentID + "/verify-dns",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.VerifyDNS(ctx, agentID)
				return err
			},
		},
		{
			name: "revoke v1", version: APIVersionV1,
			wantMethod: http.MethodPost, wantPath: "/v1/agents/" + agentID + "/revoke",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.RevokeAgent(ctx, agentID, models.RevocationReasonCessationOfOperation, "")
				return err
			},
		},
		{
			name: "identity certs v1", version: APIVersionV1,
			wantMethod: http.MethodGet, wantPath: "/v1/agents/" + agentID + "/certificates/identity",
			body: "[]",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetIdentityCertificates(ctx, agentID)
				return err
			},
		},
		{
			name: "server certs v1", version: APIVersionV1,
			wantMethod: http.MethodGet, wantPath: "/v1/agents/" + agentID + "/certificates/server",
			body: "[]",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetServerCertificates(ctx, agentID)
				return err
			},
		},
		{
			name: "submit identity csr v1", version: APIVersionV1,
			wantMethod: http.MethodPost, wantPath: "/v1/agents/" + agentID + "/certificates/identity",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.SubmitIdentityCSR(ctx, agentID, "csr-pem")
				return err
			},
		},
		{
			name: "submit server csr v1", version: APIVersionV1,
			wantMethod: http.MethodPost, wantPath: "/v1/agents/" + agentID + "/certificates/server",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.SubmitServerCSR(ctx, agentID, "csr-pem")
				return err
			},
		},
		{
			name: "csr status v1", version: APIVersionV1,
			wantMethod: http.MethodGet, wantPath: "/v1/agents/" + agentID + "/csrs/csr-1/status",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetCSRStatus(ctx, agentID, "csr-1")
				return err
			},
		},
		// ----- lane-routed methods, V2 -----
		{
			name: "register v2", version: APIVersionV2,
			wantMethod: http.MethodPost, wantPath: "/v2/ans/agents",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.RegisterAgent(ctx, &models.AgentRegistrationRequest{})
				return err
			},
		},
		{
			name: "details v2", version: APIVersionV2,
			wantMethod: http.MethodGet, wantPath: "/v2/ans/agents/" + agentID,
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetAgentDetails(ctx, agentID)
				return err
			},
		},
		{
			name: "verify-acme v2", version: APIVersionV2,
			wantMethod: http.MethodPost, wantPath: "/v2/ans/agents/" + agentID + "/verify-acme",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.VerifyACME(ctx, agentID)
				return err
			},
		},
		{
			name: "verify-dns v2", version: APIVersionV2,
			wantMethod: http.MethodPost, wantPath: "/v2/ans/agents/" + agentID + "/verify-dns",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.VerifyDNS(ctx, agentID)
				return err
			},
		},
		{
			name: "identity certs v2", version: APIVersionV2,
			wantMethod: http.MethodGet, wantPath: "/v2/ans/agents/" + agentID + "/certificates/identity",
			body: "[]",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetIdentityCertificates(ctx, agentID)
				return err
			},
		},
		{
			name: "server certs v2", version: APIVersionV2,
			wantMethod: http.MethodGet, wantPath: "/v2/ans/agents/" + agentID + "/certificates/server",
			body: "[]",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetServerCertificates(ctx, agentID)
				return err
			},
		},
		{
			name: "submit identity csr v2", version: APIVersionV2,
			wantMethod: http.MethodPost, wantPath: "/v2/ans/agents/" + agentID + "/certificates/identity",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.SubmitIdentityCSR(ctx, agentID, "csr-pem")
				return err
			},
		},
		{
			name: "submit server csr v2", version: APIVersionV2,
			wantMethod: http.MethodPost, wantPath: "/v2/ans/agents/" + agentID + "/certificates/server",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.SubmitServerCSR(ctx, agentID, "csr-pem")
				return err
			},
		},
		{
			name: "csr status v2", version: APIVersionV2,
			wantMethod: http.MethodGet, wantPath: "/v2/ans/agents/" + agentID + "/csrs/csr-1/status",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetCSRStatus(ctx, agentID, "csr-1")
				return err
			},
		},
		{
			name: "revoke v2", version: APIVersionV2,
			wantMethod: http.MethodPost, wantPath: "/v2/ans/agents/" + agentID + "/revoke",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.RevokeAgent(ctx, agentID, models.RevocationReasonCessationOfOperation, "")
				return err
			},
		},
		// ----- V1-pinned surfaces: paths must not move on the V2 lane -----
		{
			name: "challenge stays v1 on v2 lane", version: APIVersionV2,
			wantMethod: http.MethodGet, wantPath: "/v1/agents/" + agentID + "/challenge",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetChallengeDetails(ctx, agentID)
				return err
			},
		},
		{
			name: "search stays v1 on v2 lane", version: APIVersionV2,
			wantMethod: http.MethodGet, wantPath: "/v1/agents",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.SearchAgents(ctx)
				return err
			},
		},
		{
			name: "events stay v1 on v2 lane", version: APIVersionV2,
			wantMethod: http.MethodGet, wantPath: "/v1/agents/events",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.GetAgentEvents(ctx, 0, "", "")
				return err
			},
		},
		{
			name: "resolution stays v1 on v2 lane", version: APIVersionV2,
			wantMethod: http.MethodPost, wantPath: "/v1/agents/resolution",
			call: func(ctx context.Context, c *Client) error {
				_, err := c.ResolveAgent(ctx, "agent.example.com", "*")
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tt.wantMethod {
					t.Errorf("method: got %s, want %s", r.Method, tt.wantMethod)
				}
				if r.URL.Path != tt.wantPath {
					t.Errorf("path: got %s, want %s", r.URL.Path, tt.wantPath)
				}
				w.Header().Set("Content-Type", "application/json")
				body := tt.body
				if body == "" {
					body = "{}"
				}
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()

			client, err := NewClient(WithBaseURL(server.URL), WithJWT("test-token"), WithAPIVersion(tt.version))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if err := tt.call(context.Background(), client); err != nil {
				t.Fatalf("call: %v", err)
			}
		})
	}
}

// TestRegisterAgent_DiscoveryProfilesSerialization pins the register
// request's wire shape for the discovery-profile surface: the field is
// serialized verbatim when set and absent (not null, not []) when unset,
// because the server treats an omitted field as "use the server default"
// and the request must not look like an explicit choice.
func TestRegisterAgent_DiscoveryProfilesSerialization(t *testing.T) {
	tests := []struct {
		name         string
		profiles     []models.DiscoveryProfile
		wantPresent  bool
		wantProfiles []string
	}{
		{
			name:     "omitted when unset",
			profiles: nil,
		},
		{
			name:         "single profile serialized",
			profiles:     []models.DiscoveryProfile{models.DiscoveryProfileANSDNSAID},
			wantPresent:  true,
			wantProfiles: []string{"ANS_DNSAID"},
		},
		{
			name:         "union preserved in order",
			profiles:     []models.DiscoveryProfile{models.DiscoveryProfileANSDNSAID, models.DiscoveryProfileANSTXT},
			wantPresent:  true,
			wantProfiles: []string{"ANS_DNSAID", "ANS_TXT"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var captured map[string]json.RawMessage
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
					t.Errorf("decode request body: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("{}"))
			}))
			defer server.Close()

			client, err := NewClient(WithBaseURL(server.URL), WithJWT("test-token"), WithAPIVersion(APIVersionV2))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			req := &models.AgentRegistrationRequest{
				AgentDisplayName:  "test",
				AgentHost:         "agent.example.com",
				Version:           "1.0.0",
				DiscoveryProfiles: tt.profiles,
			}
			if _, err := client.RegisterAgent(context.Background(), req); err != nil {
				t.Fatalf("RegisterAgent: %v", err)
			}

			raw, present := captured["discoveryProfiles"]
			if present != tt.wantPresent {
				t.Fatalf("discoveryProfiles present = %v, want %v (body keys: %v)", present, tt.wantPresent, captured)
			}
			if !tt.wantPresent {
				return
			}
			var got []string
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshal discoveryProfiles: %v", err)
			}
			if len(got) != len(tt.wantProfiles) {
				t.Fatalf("profiles: got %v, want %v", got, tt.wantProfiles)
			}
			for i := range got {
				if got[i] != tt.wantProfiles[i] {
					t.Errorf("profiles[%d]: got %q, want %q", i, got[i], tt.wantProfiles[i])
				}
			}
		})
	}
}

// TestRegisterAgent_DiscoveryProfilesRejectedOnV1 pins the SDK-level
// lane guard: DiscoveryProfiles on a V1-lane client is a client-side
// models.ErrBadRequest before any request is sent — the V1 lane would
// ignore the field server-side and silently drop an explicit choice.
func TestRegisterAgent_DiscoveryProfilesRejectedOnV1(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("no HTTP request should be sent when the lane guard rejects")
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL), WithJWT("test-token")) // default V1 lane
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	req := &models.AgentRegistrationRequest{
		AgentDisplayName:  "test",
		AgentHost:         "agent.example.com",
		Version:           "1.0.0",
		DiscoveryProfiles: []models.DiscoveryProfile{models.DiscoveryProfileANSDNSAID},
	}
	_, err = client.RegisterAgent(context.Background(), req)
	if !errors.Is(err, models.ErrBadRequest) {
		t.Fatalf("expected models.ErrBadRequest, got %v", err)
	}
}
