package cmd

import (
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestBuildRevokeCmd(t *testing.T) {
	cmd := buildRevokeCmd()

	if cmd == nil {
		t.Fatal("buildRevokeCmd() returned nil")
	}

	if cmd.Use != "revoke <agent_id>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "revoke <agent_id>")
	}

	// Verify flags
	if cmd.Flags().Lookup("reason") == nil {
		t.Error("missing flag 'reason'")
	}
	if cmd.Flags().Lookup("comments") == nil {
		t.Error("missing flag 'comments'")
	}
}

func TestPrintRevokeResult(t *testing.T) {
	tests := []struct {
		name   string
		result *models.AgentRevocationResponse
	}{
		{
			name: "with all fields",
			result: &models.AgentRevocationResponse{
				AgentID:   "agent-123",
				AnsName:   "test.ans.godaddy",
				Status:    "REVOKED",
				Reason:    models.RevocationReasonKeyCompromise,
				RevokedAt: time.Now(),
			},
		},
		{
			name: "with zero time",
			result: &models.AgentRevocationResponse{
				AgentID: "agent-456",
				AnsName: "other.ans.godaddy",
				Status:  "REVOKED",
				Reason:  models.RevocationReasonSuperseded,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			printRevokeResult(tt.result)
		})
	}
}
