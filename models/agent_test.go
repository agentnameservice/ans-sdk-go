package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAgentStatusUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    AgentStatus
		wantErr bool
	}{
		{
			name:  "simple string status",
			input: `"ACTIVE"`,
			want: AgentStatus{
				Status: "ACTIVE",
			},
			wantErr: false,
		},
		{
			name: "full object status",
			input: `{
				"status": "PENDING",
				"phase": "DNS_VERIFICATION",
				"createdAt": "2024-01-01T00:00:00Z",
				"updatedAt": "2024-01-02T00:00:00Z",
				"pendingSteps": ["VERIFY_DNS", "VERIFY_ACME"],
				"completedSteps": ["SUBMIT_CSR"]
			}`,
			want: AgentStatus{
				Status:         "PENDING",
				Phase:          "DNS_VERIFICATION",
				CreatedAt:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
				UpdatedAt:      time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
				PendingSteps:   []string{"VERIFY_DNS", "VERIFY_ACME"},
				CompletedSteps: []string{"SUBMIT_CSR"},
			},
			wantErr: false,
		},
		{
			name:    "invalid json",
			input:   `{invalid}`,
			want:    AgentStatus{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got AgentStatus
			err := json.Unmarshal([]byte(tt.input), &got)

			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if got.Status != tt.want.Status {
					t.Errorf("Status = %v, want %v", got.Status, tt.want.Status)
				}
				if got.Phase != tt.want.Phase {
					t.Errorf("Phase = %v, want %v", got.Phase, tt.want.Phase)
				}
			}
		})
	}
}

func TestAgentRegistrationRequest_JSON(t *testing.T) {
	req := &AgentRegistrationRequest{
		AgentDisplayName: "Test Agent",
		AgentHost:        "test-agent.example.com",
		AgentDescription: "A test agent",
		Version:          "1.0.0",
		IdentityCSRPEM:   "-----BEGIN CERTIFICATE REQUEST-----\n...",
		Endpoints: []AgentEndpoint{
			{
				AgentURL:   "https://test-agent.example.com/api",
				Protocol:   "HTTP-API",
				Transports: []string{"REST"},
			},
		},
	}

	// Test marshaling
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Test unmarshaling
	var got AgentRegistrationRequest
	err = json.Unmarshal(data, &got)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if got.AgentDisplayName != req.AgentDisplayName {
		t.Errorf("AgentDisplayName = %v, want %v", got.AgentDisplayName, req.AgentDisplayName)
	}
	if got.AgentHost != req.AgentHost {
		t.Errorf("AgentHost = %v, want %v", got.AgentHost, req.AgentHost)
	}
	if len(got.Endpoints) != len(req.Endpoints) {
		t.Errorf("Endpoints length = %v, want %v", len(got.Endpoints), len(req.Endpoints))
	}
}

func TestIsValidAgentLifecycleStatus(t *testing.T) {
	tests := []struct {
		name   string
		status AgentLifecycleStatus
		want   bool
	}{
		{"pending_dns", AgentStatusPendingDNS, true},
		{"active", AgentStatusActive, true},
		{"deprecated", AgentStatusDeprecated, true},
		{"revoked", AgentStatusRevoked, true},
		{"all", AgentStatusAll, true},
		{"empty string", AgentLifecycleStatus(""), false},
		{"unknown value", AgentLifecycleStatus("GARBAGE"), false},
		{"lowercase rejected", AgentLifecycleStatus("active"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidAgentLifecycleStatus(tt.status); got != tt.want {
				t.Errorf("IsValidAgentLifecycleStatus(%q) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestIsValidAgentProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol AgentProtocol
		want     bool
	}{
		{"a2a", AgentProtocolA2A, true},
		{"mcp", AgentProtocolMCP, true},
		{"http-api", AgentProtocolHTTPAPI, true},
		{"empty string", AgentProtocol(""), false},
		{"unknown value", AgentProtocol("GRPC"), false},
		{"lowercase rejected", AgentProtocol("mcp"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidAgentProtocol(tt.protocol); got != tt.want {
				t.Errorf("IsValidAgentProtocol(%q) = %v, want %v", tt.protocol, got, tt.want)
			}
		})
	}
}

// TestIsValidDiscoveryProfile pins the recognised discovery-profile
// enum. Values are CONSTANT_CASE on the wire, matching the V2 register
// schema; anything else — including lowercase — is rejected so a typo'd
// profile fails client-side instead of round-tripping to a server 422.
func TestIsValidDiscoveryProfile(t *testing.T) {
	tests := []struct {
		name    string
		profile DiscoveryProfile
		want    bool
	}{
		{"ans_dnsaid", DiscoveryProfileANSDNSAID, true},
		{"ans_txt", DiscoveryProfileANSTXT, true},
		{"empty string", DiscoveryProfile(""), false},
		{"unknown value", DiscoveryProfile("ANS_SVCB"), false},
		{"lowercase rejected", DiscoveryProfile("ans_dnsaid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidDiscoveryProfile(tt.profile); got != tt.want {
				t.Errorf("IsValidDiscoveryProfile(%q) = %v, want %v", tt.profile, got, tt.want)
			}
		})
	}
}
