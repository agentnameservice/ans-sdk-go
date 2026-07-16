package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/spf13/cobra"
)

func buildVerifyDNSCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify-dns <agentId>",
		Short: "Verify DNS records are configured",
		Long: `Verifies that all required DNS records (HTTPS, TLSA, _ans, _ans-badge) have been
configured correctly. This is the final step for external domain registration.`,
		Args: cobra.ExactArgs(1),
		RunE: runVerifyDNS,
	}
}

func runVerifyDNS(_ *cobra.Command, args []string) error {
	agentID := args[0]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := cfg.RequireCredentials(); err != nil {
		return err
	}

	// Create client and verify DNS
	c, err := createClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()
	result, err := c.VerifyDNS(ctx, agentID)
	if err != nil {
		var dnsErr *models.DNSVerificationError
		if errors.As(err, &dnsErr) {
			// Typed DNS error already prefixes "DNS verification failed:"; don't
			// double-prefix. Error output goes to stderr so `verify-dns ... -j | jq`
			// automation that captures stdout doesn't conflate failure envelopes
			// with success-shaped data.
			printDNSVerificationError(os.Stderr, dnsErr, cfg.JSON)
			return err
		}
		return fmt.Errorf("DNS verification failed: %w", err)
	}

	// Output result
	if cfg.JSON {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(os.Stdout, string(jsonData))
	} else {
		fmt.Fprintln(os.Stdout, "\n✓ DNS records verified successfully")
		if result.Status != "" {
			fmt.Fprintf(os.Stdout, "Status: %s\n", result.Status)
		}
		if result.Phase != "" {
			fmt.Fprintf(os.Stdout, "Phase: %s\n", result.Phase)
		}

		if len(result.CompletedSteps) > 0 {
			fmt.Fprintln(os.Stdout, "\nCompleted steps:")
			for _, step := range result.CompletedSteps {
				fmt.Fprintf(os.Stdout, "  ✓ %s\n", step)
			}
		}

		fmt.Fprintln(os.Stdout, "\nAgent registration is now active!")
		fmt.Fprintln(os.Stdout, "Use 'ans-cli status "+agentID+"' to view full details.")
		fmt.Fprintln(os.Stdout)
	}

	return nil
}

// printDNSVerificationError renders a DNSVerificationError. In JSON mode it
// emits the wire-shape struct directly; in text mode it prints two readable
// tables (missing / incorrect) with the fields a user needs to configure DNS.
func printDNSVerificationError(w io.Writer, e *models.DNSVerificationError, asJSON bool) {
	if asJSON {
		jsonData, _ := json.MarshalIndent(e, "", "  ")
		fmt.Fprintln(w, string(jsonData))
		return
	}

	if len(e.MissingRecords) > 0 {
		fmt.Fprintln(w, "\nMissing DNS records (configure these):")
		writeMissingRecordsTable(w, e.MissingRecords)
	}
	if len(e.IncorrectRecords) > 0 {
		fmt.Fprintln(w, "\nIncorrect DNS records (fix these):")
		writeIncorrectRecordsTable(w, e.IncorrectRecords)
	}
}

// tabwriterColumnPadding sets the number of pad spaces between columns.
const tabwriterColumnPadding = 2

func writeMissingRecordsTable(w io.Writer, records []models.DNSRecord) {
	tw := tabwriter.NewWriter(w, 0, 0, tabwriterColumnPadding, ' ', 0)
	fmt.Fprintln(tw, "  NAME\tTYPE\tVALUE\tREQUIRED")
	for _, r := range records {
		required := ""
		if r.Required {
			required = "yes"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", r.Name, r.Type, r.Value, required)
	}
	_ = tw.Flush()
}

func writeIncorrectRecordsTable(w io.Writer, records []models.IncorrectDNSRecord) {
	tw := tabwriter.NewWriter(w, 0, 0, tabwriterColumnPadding, ' ', 0)
	fmt.Fprintln(tw, "  NAME\tTYPE\tEXPECTED\tFOUND")
	for _, ir := range records {
		name := ir.Record.Name
		recType := ir.Record.Type
		// AND (not OR): partial-record metadata still gets rendered as-is so
		// the operator sees whichever field the registry did report. Only when
		// BOTH name and type are missing do we substitute the placeholder, to
		// avoid two blank cells that would mimic the empty-record bug this
		// renderer is closing.
		if name == "" && recType == "" {
			name = "<unknown>"
			recType = "<unknown>"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", name, recType, ir.Expected, ir.Found)
	}
	_ = tw.Flush()
}
