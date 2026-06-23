package cmd

import (
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestBuildRegisterCmd(t *testing.T) {
	cmd := buildRegisterCmd()

	if cmd == nil {
		t.Fatal("buildRegisterCmd() returned nil")
	}

	if cmd.Use != "register" {
		t.Errorf("Use = %q, want %q", cmd.Use, "register")
	}

	// Verify required flags
	requiredFlags := []string{"name", "host", "version", "identity-csr", "endpoint-url"}
	for _, flagName := range requiredFlags {
		f := cmd.Flags().Lookup(flagName)
		if f == nil {
			t.Errorf("missing flag %q", flagName)
		}
	}

	// Verify optional flags
	optionalFlags := []string{
		"description", "server-csr", "server-cert",
		"metadata-url", "endpoint-protocol", "endpoint-transports", "function",
	}
	for _, flagName := range optionalFlags {
		if cmd.Flags().Lookup(flagName) == nil {
			t.Errorf("missing optional flag %q", flagName)
		}
	}
}

func TestPrintRegistrationResult(_ *testing.T) {
	result := &models.RegistrationPending{
		Status:    "PENDING",
		ANSName:   "test.ans.godaddy",
		AgentID:   "agent-123",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Challenges: []models.ChallengeInfo{
			{
				Type: "dns-01",
				DNSRecord: &models.DNSRecordDetails{
					Name:  "_acme-challenge.test.example.com",
					Type:  "TXT",
					Value: "challenge-token-123",
				},
			},
			{
				Type:             "http-01",
				HTTPPath:         "/.well-known/acme-challenge/token123",
				KeyAuthorization: "key-auth-value",
			},
		},
		DNSRecords: []models.DNSRecord{
			{
				Name:    "_ans.test.example.com",
				Type:    "TXT",
				Value:   "ans-record-value",
				Purpose: "ANS verification",
			},
		},
		NextSteps: []models.NextStep{
			{
				Action:      "configure-dns",
				Description: "Configure DNS records",
				Endpoint:    "/v1/agents/agent-123/verify-dns",
			},
		},
		Links: []models.Link{
			{
				Rel:  "self",
				Href: "/v1/agents/agent-123",
			},
		},
	}

	// Verify it doesn't panic
	printRegistrationResult(result)
}

func TestPrintRegistrationResultMinimal(_ *testing.T) {
	result := &models.RegistrationPending{
		Status:  "PENDING",
		ANSName: "test.ans.godaddy",
	}

	// Verify it doesn't panic with minimal data
	printRegistrationResult(result)
}

func TestPrintDNSChallengeBanner(t *testing.T) {
	tests := []struct {
		name       string
		challenges []models.ChallengeInfo
	}{
		{
			name:       "no challenges",
			challenges: nil,
		},
		{
			name: "only HTTP challenge (no DNS banner)",
			challenges: []models.ChallengeInfo{
				{
					Type:     "http-01",
					HTTPPath: "/path",
				},
			},
		},
		{
			name: "DNS challenge shows banner",
			challenges: []models.ChallengeInfo{
				{
					Type: "dns-01",
					DNSRecord: &models.DNSRecordDetails{
						Name:  "_acme-challenge.test.example.com",
						Type:  "TXT",
						Value: "token",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			printDNSChallengeBanner(tt.challenges)
		})
	}
}

func TestPrintChallenges(t *testing.T) {
	tests := []struct {
		name       string
		challenges []models.ChallengeInfo
	}{
		{
			name:       "empty challenges",
			challenges: nil,
		},
		{
			name: "single challenge",
			challenges: []models.ChallengeInfo{
				{Type: "dns-01"},
			},
		},
		{
			name: "multiple challenges",
			challenges: []models.ChallengeInfo{
				{Type: "dns-01"},
				{Type: "http-01"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			printChallenges(tt.challenges)
		})
	}
}

func TestPrintDNSRecordsToConfig(t *testing.T) {
	tests := []struct {
		name    string
		records []models.DNSRecord
	}{
		{
			name:    "empty records",
			records: nil,
		},
		{
			name: "with records",
			records: []models.DNSRecord{
				{
					Type:    "TXT",
					Name:    "_ans.test.example.com",
					Value:   "value",
					Purpose: "verification",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			printDNSRecordsToConfig(tt.records)
		})
	}
}

func TestPrintNextSteps(t *testing.T) {
	tests := []struct {
		name  string
		steps []models.NextStep
	}{
		{
			name:  "empty steps",
			steps: nil,
		},
		{
			name: "with steps",
			steps: []models.NextStep{
				{
					Action:      "verify-dns",
					Description: "Verify DNS records",
					Endpoint:    "/v1/agents/123/verify-dns",
				},
				{
					Action:      "verify-acme",
					Description: "Complete ACME challenge",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			printNextSteps(tt.steps)
		})
	}
}

func TestPrintResultLinks(t *testing.T) {
	tests := []struct {
		name  string
		links []models.Link
	}{
		{
			name:  "empty links",
			links: nil,
		},
		{
			name: "with links",
			links: []models.Link{
				{Rel: "self", Href: "/v1/agents/123"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			printResultLinks(tt.links)
		})
	}
}
