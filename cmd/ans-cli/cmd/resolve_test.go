package cmd

import (
	"testing"

	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestBuildResolveCmd(t *testing.T) {
	cmd := buildResolveCmd()

	if cmd == nil {
		t.Fatal("buildResolveCmd() returned nil")
	}

	if cmd.Use != "resolve <host>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "resolve <host>")
	}

	// Verify version flag
	if cmd.Flags().Lookup("version") == nil {
		t.Error("missing flag 'version'")
	}
}

func TestPrintResolveResult(t *testing.T) {
	tests := []struct {
		name    string
		result  *models.AgentCapabilityResponse
		host    string
		version string
	}{
		{
			name: "with links",
			result: &models.AgentCapabilityResponse{
				AnsName: "ans://v1.0.0.test.example.com",
				Links: []models.Link{
					{Rel: "self", Href: "/v1/agents/123"},
					{Rel: "badge", Href: "/v1/agents/123/badge"},
				},
			},
			host:    "test.example.com",
			version: "1.0.0",
		},
		{
			name: "without links",
			result: &models.AgentCapabilityResponse{
				AnsName: "ans://v*.test.example.com",
			},
			host:    "test.example.com",
			version: "*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			printResolveResult(tt.result, tt.host, tt.version)
		})
	}
}
