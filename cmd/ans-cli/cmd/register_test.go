package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
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

func TestValidateRegistrationParams(t *testing.T) {
	tests := []struct {
		name    string
		p       registerParams
		wantErr bool
		errMsg  string
	}{
		{
			name: "description within limit",
			p:    registerParams{description: strings.Repeat("a", 150)},
		},
		{
			name:    "description too long",
			p:       registerParams{description: strings.Repeat("a", 151)},
			wantErr: true,
			errMsg:  "description exceeds maximum length",
		},
		{
			name: "empty description",
			p:    registerParams{},
		},
		{
			name:    "non-ASCII in description",
			p:       registerParams{description: "smart\xe2\x80\x94agent"},
			wantErr: true,
			errMsg:  "non-ASCII",
		},
		{
			name:    "non-ASCII in name",
			p:       registerParams{name: "My Agent\xe2\x80\x94Beta"},
			wantErr: true,
			errMsg:  "non-ASCII",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRegistrationParams(&tt.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRegistrationParams() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error message %q does not contain %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestValidateRegistrationParamsTags(t *testing.T) {
	tests := []struct {
		name    string
		p       registerParams
		wantErr bool
		errMsg  string
	}{
		{
			name: "function with 5 tags (at limit)",
			p: registerParams{
				functionFlags: []string{"fn1:Search:tag1,tag2,tag3,tag4,tag5"},
			},
		},
		{
			name: "function with 6 tags (over limit)",
			p: registerParams{
				functionFlags: []string{"fn1:Search:tag1,tag2,tag3,tag4,tag5,tag6"},
			},
			wantErr: true,
			errMsg:  "tags",
		},
		{
			name: "multiple functions, one with too many tags",
			p: registerParams{
				functionFlags: []string{
					"fn1:Search:tag1,tag2",
					"fn2:Index:t1,t2,t3,t4,t5,t6",
				},
			},
			wantErr: true,
			errMsg:  "tags",
		},
		{
			name: "function with zero tags",
			p:    registerParams{functionFlags: []string{"fn1:Search"}},
		},
		{
			name: "no functions",
			p:    registerParams{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRegistrationParams(&tt.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRegistrationParams() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error message %q does not contain %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestLintCardFieldsASCII(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{
			name:  "ASCII only string",
			input: `{"name": "My Agent", "description": "test"}`,
		},
		{
			name:    "non-ASCII in string value",
			input:   `{"description": "smart—quote"}`,
			wantErr: true,
			errMsg:  "non-ASCII",
		},
		{
			name:    "em dash in nested field",
			input:   `{"functions": [{"name": "search—fast"}]}`,
			wantErr: true,
			errMsg:  "non-ASCII",
		},
		{
			name:  "numbers and booleans pass",
			input: `{"version": 1, "active": true}`,
		},
		{
			name:  "empty object",
			input: `{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := lintCardFieldsASCII(json.RawMessage(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("lintCardFieldsASCII() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error message %q does not contain %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestPrintResponseErrorDetails(t *testing.T) {
	tests := []struct {
		name     string
		respErr  *models.ResponseError
		wantSubs []string
	}{
		{
			name: "422 with details",
			respErr: &models.ResponseError{
				StatusCode: 422,
				Code:       "VALIDATION_ERROR",
				Message:    "Validation failed",
				Details:    map[string]any{"agentDescription": "must be at most 150 characters"},
			},
			wantSubs: []string{"agentDescription", "150"},
		},
		{
			name: "details map empty",
			respErr: &models.ResponseError{
				StatusCode: 400,
				Details:    map[string]any{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printResponseErrorDetails(&buf, tt.respErr)
			output := buf.String()
			for _, sub := range tt.wantSubs {
				if !strings.Contains(output, sub) {
					t.Errorf("output %q does not contain %q", output, sub)
				}
			}
		})
	}
}
