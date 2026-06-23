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

func buildSubmitIdentityCSRCmd() *cobra.Command {
	var submitIdentityCsrFile string

	cmd := &cobra.Command{
		Use:   "submit-identity-csr <agentId>",
		Short: "Submit an identity CSR for an agent",
		Long:  `Submit a Certificate Signing Request (CSR) to obtain a new identity certificate for an agent.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runSubmitIdentityCSRWithParams(args[0], submitIdentityCsrFile)
		},
	}

	cmd.Flags().StringVar(&submitIdentityCsrFile, "csr-file", "", "Path to CSR PEM file (required)")
	_ = cmd.MarkFlagRequired("csr-file")

	return cmd
}

func runSubmitIdentityCSRWithParams(agentID, csrFile string) error {
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

	csrData, err := os.ReadFile(csrFile)
	if err != nil {
		return fmt.Errorf("failed to read CSR file: %w", err)
	}

	ctx := context.Background()
	result, err := c.SubmitIdentityCSR(ctx, agentID, string(csrData))
	if err != nil {
		return fmt.Errorf("failed to submit identity CSR: %w", err)
	}

	if cfg.JSON {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(os.Stdout, string(jsonData))
	} else {
		printCsrSubmissionResult("Identity", result)
	}

	return nil
}

func printCsrSubmissionResult(csrType string, result *models.CsrSubmissionResponse) {
	fmt.Fprintf(os.Stdout, "\n✓ %s CSR Submitted\n", csrType)
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthStandard))
	fmt.Fprintf(os.Stdout, "CSR ID: %s\n", result.CsrID)
	if result.Message != nil {
		fmt.Fprintf(os.Stdout, "Message: %s\n", *result.Message)
	}
	fmt.Fprintln(os.Stdout, "\nUse 'csr-status <agentId> <csrId>' to check the status of your CSR.")
	fmt.Fprintln(os.Stdout)
}
