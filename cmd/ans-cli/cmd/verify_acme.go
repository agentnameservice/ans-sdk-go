package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/spf13/cobra"
)

func buildVerifyACMECmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify-acme <agentId>",
		Short: "Trigger ACME domain validation",
		Long: `Initiates validation of domain control via ACME challenge. Call this after
placing the ACME challenge token at the specified location (DNS or HTTP).`,
		Args: cobra.ExactArgs(1),
		RunE: runVerifyACME,
	}
}

func runVerifyACME(_ *cobra.Command, args []string) error {
	agentID := args[0]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.APIKey == "" {
		return errors.New("API key is required. Set --api-key flag or ANS_API_KEY environment variable")
	}

	// Create client and verify ACME
	c, err := createClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()
	result, err := c.VerifyACME(ctx, agentID)
	if err != nil {
		return fmt.Errorf("ACME verification failed: %w", err)
	}

	// Output result
	if cfg.JSON {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(os.Stdout, string(jsonData))
		return nil
	}

	printACMEResult(result, agentID)
	return nil
}

func printACMEResult(result *models.AgentStatus, agentID string) {
	fmt.Fprintln(os.Stdout, "\n✓ ACME validation triggered successfully")

	if result.Status != "" {
		fmt.Fprintf(os.Stdout, "Status: %s\n", result.Status)
	}
	if result.Phase != "" {
		fmt.Fprintf(os.Stdout, "Phase: %s\n", result.Phase)
	}

	if len(result.PendingSteps) > 0 {
		fmt.Fprintln(os.Stdout, "\nPending steps:")
		for _, step := range result.PendingSteps {
			fmt.Fprintf(os.Stdout, "  • %s\n", step)
		}
	}

	if len(result.CompletedSteps) > 0 {
		fmt.Fprintln(os.Stdout, "\nCompleted steps:")
		for _, step := range result.CompletedSteps {
			fmt.Fprintf(os.Stdout, "  ✓ %s\n", step)
		}
	}

	fmt.Fprintln(os.Stdout, "\nUse 'ans-cli status "+agentID+"' to check current status.")
	fmt.Fprintln(os.Stdout)
}
