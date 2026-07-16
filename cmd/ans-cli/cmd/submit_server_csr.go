package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/spf13/cobra"
)

func buildSubmitServerCSRCmd() *cobra.Command {
	var submitServerCsrFile string

	cmd := &cobra.Command{
		Use:   "submit-server-csr <agentId>",
		Short: "Submit a server CSR for an agent",
		Long:  `Submit a Certificate Signing Request (CSR) to obtain a new server certificate for an agent.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runSubmitServerCSRWithParams(args[0], submitServerCsrFile)
		},
	}

	cmd.Flags().StringVar(&submitServerCsrFile, "csr-file", "", "Path to CSR PEM file (required)")
	_ = cmd.MarkFlagRequired("csr-file")

	return cmd
}

func runSubmitServerCSRWithParams(agentID, csrFile string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := cfg.RequireCredentials(); err != nil {
		return err
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
	result, err := c.SubmitServerCSR(ctx, agentID, string(csrData))
	if err != nil {
		return fmt.Errorf("failed to submit server CSR: %w", err)
	}

	if cfg.JSON {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(os.Stdout, string(jsonData))
	} else {
		printCsrSubmissionResult("Server", result)
	}

	return nil
}
