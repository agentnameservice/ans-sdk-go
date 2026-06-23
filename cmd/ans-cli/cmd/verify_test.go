package cmd

import (
	"testing"

	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestBuildVerifyACMECmd(t *testing.T) {
	cmd := buildVerifyACMECmd()

	if cmd == nil {
		t.Fatal("buildVerifyACMECmd() returned nil")
	}

	if cmd.Use != "verify-acme <agentId>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "verify-acme <agentId>")
	}
}

func TestBuildVerifyDNSCmd(t *testing.T) {
	cmd := buildVerifyDNSCmd()

	if cmd == nil {
		t.Fatal("buildVerifyDNSCmd() returned nil")
	}

	if cmd.Use != "verify-dns <agentId>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "verify-dns <agentId>")
	}
}

func TestPrintACMEResult(t *testing.T) {
	tests := []struct {
		name   string
		result *models.AgentStatus
	}{
		{
			name: "with all fields",
			result: &models.AgentStatus{
				Status: "VERIFYING",
				Phase:  "ACME_VALIDATION",
				PendingSteps: []string{
					"dns-propagation",
					"certificate-issuance",
				},
				CompletedSteps: []string{
					"domain-validation",
				},
			},
		},
		{
			name:   "minimal result",
			result: &models.AgentStatus{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			printACMEResult(tt.result, "agent-123")
		})
	}
}
