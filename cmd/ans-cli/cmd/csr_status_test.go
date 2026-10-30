package cmd

import (
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestBuildCsrStatusCmd(t *testing.T) {
	cmd := buildCsrStatusCmd()

	if cmd == nil {
		t.Fatal("buildCsrStatusCmd() returned nil")
	}

	if cmd.Use != "csr-status <agentId> <csrId>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "csr-status <agentId> <csrId>")
	}
}

func TestPrintCsrStatus(t *testing.T) {
	failureReason := "Certificate authority rejected the CSR"

	tests := []struct {
		name   string
		status *models.CsrStatusResponse
	}{
		{
			name: "pending status",
			status: &models.CsrStatusResponse{
				CsrID:       "csr-123",
				Type:        "IDENTITY",
				Status:      csrStatusPending,
				SubmittedAt: time.Now(),
				UpdatedAt:   time.Now(),
			},
		},
		{
			name: "signed status",
			status: &models.CsrStatusResponse{
				CsrID:       "csr-456",
				Type:        "SERVER",
				Status:      csrStatusSigned,
				SubmittedAt: time.Now().Add(-1 * time.Hour),
				UpdatedAt:   time.Now(),
			},
		},
		{
			name: "rejected status with failure reason",
			status: &models.CsrStatusResponse{
				CsrID:         "csr-789",
				Type:          "IDENTITY",
				Status:        csrStatusRejected,
				SubmittedAt:   time.Now().Add(-2 * time.Hour),
				UpdatedAt:     time.Now(),
				FailureReason: &failureReason,
			},
		},
		{
			name: "unknown status",
			status: &models.CsrStatusResponse{
				CsrID:  "csr-000",
				Type:   "IDENTITY",
				Status: "UNKNOWN",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			printCsrStatus(tt.status)
		})
	}
}
