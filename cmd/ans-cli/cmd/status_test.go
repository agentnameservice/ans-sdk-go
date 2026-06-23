package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestBuildStatusCmd(t *testing.T) {
	tests := []struct {
		name     string
		checkUse string
	}{
		{
			name:     "command properties",
			checkUse: "status <agentId>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := buildStatusCmd()
			if cmd == nil {
				t.Fatal("buildStatusCmd() returned nil")
			}
			if cmd.Use != tt.checkUse {
				t.Errorf("Use = %q, want %q", cmd.Use, tt.checkUse)
			}
		})
	}
}

func TestPrintAgentDetails(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name   string
		agent  *models.AgentDetails
		checks []string
	}{
		{
			name: "full agent details with output validation",
			agent: &models.AgentDetails{
				AgentID:          "test-agent-123",
				AgentDisplayName: "Test Agent",
				AgentHost:        "test.example.com",
				ANSName:          "ans://v1.0.0.test.example.com",
				Version:          "v1.0.0",
				AgentDescription: "A test agent",
				AgentStatus: &models.AgentStatus{
					Status:         "ACTIVE",
					Phase:          "COMPLETED",
					CompletedSteps: []string{"DNS_VERIFIED", "CERT_ISSUED"},
					PendingSteps:   []string{"RENEWAL"},
				},
				Endpoints: []models.AgentEndpoint{
					{
						AgentURL:   "https://test.example.com/api",
						Protocol:   "MCP",
						Transports: []string{"HTTPS", "SSE"},
						Functions:  []models.AgentFunction{{ID: "fn-1", Name: "test-fn"}},
					},
				},
				DNSRecords: []models.DNSRecord{
					{
						Type:     "TXT",
						Name:     "_ans-badge.test.example.com",
						Value:    "v=ans-badge1",
						Required: true,
						Purpose:  "ANS badge verification",
					},
				},
				Links: []models.Link{
					{Rel: "self", Href: "https://api.example.com/agents/test-agent-123"},
				},
				RegistrationTimestamp: now,
				LastRenewalTimestamp:  now,
			},
			checks: []string{
				"Agent Details", "test-agent-123", "Test Agent",
				"test.example.com", "v1.0.0", "A test agent",
				"Status:", "ACTIVE", "COMPLETED",
				"DNS_VERIFIED", "CERT_ISSUED", "RENEWAL",
				"Endpoints:", "https://test.example.com/api", "MCP",
				"HTTPS", "SSE", "Functions: 1",
				"DNS Records:", "TXT", "_ans-badge",
				"required", "ANS badge verification",
				"Links:", "self",
				"Timestamps:", "Registered:",
			},
		},
		{
			name: "minimal agent details",
			agent: &models.AgentDetails{
				AgentID: "test-id",
			},
			checks: []string{"test-id"},
		},
		{
			name: "agent with nil status",
			agent: &models.AgentDetails{
				AgentID:          "agent-789",
				AgentDisplayName: "No Status Agent",
				AgentHost:        "nostatus.example.com",
				ANSName:          "nostatus.ans.godaddy",
				Version:          "2.0.0",
				AgentStatus:      nil,
			},
			checks: []string{"agent-789"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printAgentDetails(tt.agent)
			})
			for _, check := range tt.checks {
				if !strings.Contains(output, check) {
					t.Errorf("printAgentDetails() output missing %q", check)
				}
			}
		})
	}
}

func TestPrintAgentStatus(t *testing.T) {
	tests := []struct {
		name   string
		status *models.AgentStatus
		expect string
	}{
		{
			name:   "nil status produces no output",
			status: nil,
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printAgentStatus(tt.status)
			})
			if tt.expect == "" && output != "" {
				t.Error("printAgentStatus(nil) should produce no output")
			}
		})
	}
}

func TestPrintEndpoints(t *testing.T) {
	tests := []struct {
		name      string
		endpoints []models.AgentEndpoint
		expect    string
	}{
		{
			name:      "nil endpoints produces no output",
			endpoints: nil,
			expect:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printEndpoints(tt.endpoints)
			})
			if tt.expect == "" && output != "" {
				t.Error("printEndpoints(nil) should produce no output")
			}
		})
	}
}

func TestPrintDNSRecords(t *testing.T) {
	tests := []struct {
		name    string
		records []models.DNSRecord
		expect  string
	}{
		{
			name:    "nil records produces no output",
			records: nil,
			expect:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printDNSRecords(tt.records)
			})
			if tt.expect == "" && output != "" {
				t.Error("printDNSRecords(nil) should produce no output")
			}
		})
	}
}

func TestPrintLinks(t *testing.T) {
	tests := []struct {
		name   string
		links  []models.Link
		expect string
	}{
		{
			name:   "nil links produces no output",
			links:  nil,
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printLinks(tt.links)
			})
			if tt.expect == "" && output != "" {
				t.Error("printLinks(nil) should produce no output")
			}
		})
	}
}

func TestPrintRegistrationPending(t *testing.T) {
	tests := []struct {
		name    string
		pending *models.RegistrationPending
		checks  []string
	}{
		{
			name: "full registration pending",
			pending: &models.RegistrationPending{
				Status:    "PENDING",
				ExpiresAt: time.Now().Add(24 * time.Hour),
				Challenges: []models.ChallengeInfo{
					{
						Type: "DNS-01",
						DNSRecord: &models.DNSRecordDetails{
							Name:  "_acme-challenge.test.example.com",
							Value: "abc123",
						},
					},
				},
				DNSRecords: []models.DNSRecord{
					{
						Type:  "TXT",
						Name:  "_ans-badge",
						Value: "v=ans-badge1",
					},
				},
				NextSteps: []models.NextStep{
					{
						Action:      "VERIFY_DNS",
						Description: "Verify DNS records",
					},
				},
			},
			checks: []string{
				"Registration Pending", "PENDING", "Expires:",
				"Challenges:", "DNS-01", "_acme-challenge",
				"DNS Records:", "TXT", "_ans-badge",
				"Next Steps:", "VERIFY_DNS",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printRegistrationPending(tt.pending)
			})
			for _, check := range tt.checks {
				if !strings.Contains(output, check) {
					t.Errorf("printRegistrationPending() output missing %q", check)
				}
			}
		})
	}
}

func TestCreateClient_Additional(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{
			name: "valid config creates client",
			cfg: &config.Config{
				APIKey:  "key:secret",
				BaseURL: "https://api.test.example.com",
				Verbose: true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := createClient(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("createClient() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && client == nil {
				t.Error("createClient() returned nil client")
			}
		})
	}
}
