package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/spf13/cobra"
)

const (
	csrStatusPending  = "PENDING"
	csrStatusSigned   = "SIGNED"
	csrStatusRejected = "REJECTED"
)

func buildCsrStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "csr-status <agentId> <csrId>",
		Short: "Check CSR processing status",
		Long:  `Retrieve the current processing status of a Certificate Signing Request (CSR).`,
		Args:  cobra.ExactArgs(RequiredCSRArgs),
		RunE:  runCsrStatus,
	}
}

func runCsrStatus(_ *cobra.Command, args []string) error {
	agentID := args[0]
	csrID := args[1]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.APIKey == "" {
		return errors.New("API key is required. Set --api-key flag or ANS_API_KEY environment variable")
	}

	c, err := createClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()
	result, err := c.GetCSRStatus(ctx, agentID, csrID)
	if err != nil {
		return fmt.Errorf("failed to get CSR status: %w", err)
	}

	if cfg.JSON {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(os.Stdout, string(jsonData))
	} else {
		printCsrStatus(result)
	}

	return nil
}

func printCsrStatus(status *models.CsrStatusResponse) {
	fmt.Fprintln(os.Stdout, "\nCSR Status")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthStandard))
	fmt.Fprintf(os.Stdout, "CSR ID: %s\n", status.CsrID)
	fmt.Fprintf(os.Stdout, "Type:   %s\n", status.Type)
	fmt.Fprintf(os.Stdout, "Status: %s\n", status.Status)

	if !status.SubmittedAt.IsZero() {
		fmt.Fprintf(os.Stdout, "Submitted: %s\n", status.SubmittedAt.Format("2006-01-02 15:04:05 MST"))
	}
	if !status.UpdatedAt.IsZero() {
		fmt.Fprintf(os.Stdout, "Updated: %s\n", status.UpdatedAt.Format("2006-01-02 15:04:05 MST"))
	}

	if status.FailureReason != nil {
		fmt.Fprintf(os.Stdout, "\nFailure Reason: %s\n", *status.FailureReason)
	}

	// Provide guidance based on status
	switch status.Status {
	case csrStatusPending:
		fmt.Fprintln(os.Stdout, "\nThe CSR is being processed. Check back later.")
	case csrStatusSigned:
		fmt.Fprintln(os.Stdout, "\nThe CSR has been signed. Use 'get-identity-certs' or 'get-server-certs' to retrieve the certificate.")
	case csrStatusRejected:
		fmt.Fprintln(os.Stdout, "\nThe CSR was rejected. Please review the failure reason and submit a new CSR.")
	}

	fmt.Fprintln(os.Stdout)
}
