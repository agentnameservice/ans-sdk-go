package cmd

import (
	"context"
	"encoding/json"
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

Revocation reasons the registry accepts:
  KEY_COMPROMISE          - Private key was compromised
  CESSATION_OF_OPERATION  - Agent is no longer operational (use this to cancel a pending registration)
  AFFILIATION_CHANGED     - Agent ownership/affiliation changed
  CERTIFICATE_HOLD        - Temporarily suspended
  PRIVILEGE_WITHDRAWN     - Authorization was revoked
  AA_COMPROMISE           - Attribute authority was compromised

SUPERSEDED is reserved for the registry's own successor-deprecation flow and is
rejected for API callers. To retire a version in favor of a newer one, register
the new version and revoke the old with CESSATION_OF_OPERATION.

Revoking a PENDING (not yet ACTIVE) registration cancels it: no certificate was
sealed and no transparency-log event is written. The name and version become
reusable once the call returns.

Examples:
  ans-cli revoke abc123 --reason KEY_COMPROMISE
  ans-cli revoke abc123 --reason CESSATION_OF_OPERATION --comments "Replaced by v2.0.0"`,
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

	if err := cfg.RequireCredentials(); err != nil {
		return err
	}

	// Validate reason against the set the registry accepts (narrower than the
	// full RFC 5280 enum: SUPERSEDED and the RFC-only codes are rejected server-side).
	revocationReason := models.RevocationReason(strings.ToUpper(reason))
	if !models.IsAPIRevocationReason(revocationReason) {
		return fmt.Errorf("revocation reason %q is not accepted by the registry. See 'ans-cli revoke --help' for accepted reasons", reason)
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
