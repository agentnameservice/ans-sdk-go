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

func buildRevokeCmd() *cobra.Command {
	var (
		revokeReason   string
		revokeComments string
	)

	cmd := &cobra.Command{
		Use:   "revoke <agent_id>",
		Short: "Revoke an agent registration",
		Long: `Revoke an agent registration, marking it as no longer valid.

Valid revocation reasons (RFC 5280):
  KEY_COMPROMISE          - Private key was compromised
  CESSATION_OF_OPERATION  - Agent is no longer operational
  AFFILIATION_CHANGED     - Agent ownership/affiliation changed
  SUPERSEDED              - Replaced by a newer agent version
  CERTIFICATE_HOLD        - Temporarily suspended
  PRIVILEGE_WITHDRAWN     - Authorization was revoked
  AA_COMPROMISE           - Attribute authority was compromised
  CA_COMPROMISE           - Certificate authority was compromised
  EXPIRED_CERT            - Certificate has expired
  REMOVE_FROM_CRL         - Remove from certificate revocation list
  UNSPECIFIED             - Reason not specified

Examples:
  ans-cli revoke abc123 --reason KEY_COMPROMISE
  ans-cli revoke abc123 --reason SUPERSEDED --comments "Replaced by v2.0.0"`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runRevoke(args[0], revokeReason, revokeComments)
		},
	}

	cmd.Flags().StringVar(&revokeReason, "reason", "", "Revocation reason (required)")
	cmd.Flags().StringVar(&revokeComments, "comments", "", "Additional comments for the revocation")
	_ = cmd.MarkFlagRequired("reason")

	return cmd
}

func runRevoke(agentID, reason, comments string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.APIKey == "" {
		return errors.New("API key is required. Set --api-key flag or ANS_API_KEY environment variable")
	}

	// Validate reason
	revocationReason := models.RevocationReason(strings.ToUpper(reason))
	if !models.IsValidRevocationReason(revocationReason) {
		return fmt.Errorf("invalid revocation reason: %s. See 'ans-cli revoke --help' for valid reasons", reason)
	}

	c, err := createClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()
	result, err := c.RevokeAgent(ctx, agentID, revocationReason, comments)
	if err != nil {
		return fmt.Errorf("failed to revoke agent: %w", err)
	}

	if cfg.JSON {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON output: %w", err)
		}
		fmt.Fprintln(os.Stdout, string(jsonData))
	} else {
		printRevokeResult(result)
	}

	return nil
}

func printRevokeResult(result *models.AgentRevocationResponse) {
	fmt.Fprintln(os.Stdout, "\nAgent Revocation Result")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthWide))

	fmt.Fprintf(os.Stdout, "Agent ID:  %s\n", result.AgentID)
	fmt.Fprintf(os.Stdout, "ANS Name:  %s\n", result.AnsName)
	fmt.Fprintf(os.Stdout, "Status:    %s\n", result.Status)
	fmt.Fprintf(os.Stdout, "Reason:    %s\n", result.Reason)
	if !result.RevokedAt.IsZero() {
		fmt.Fprintf(os.Stdout, "Revoked:   %s\n", result.RevokedAt.Format("2006-01-02 15:04:05 MST"))
	}

	fmt.Fprintln(os.Stdout)
}
