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

func buildStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status <agentId>",
		Short: "Get agent registration status",
		Long:  `Retrieve detailed status and information about a registered agent.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runStatus,
	}
}

func runStatus(_ *cobra.Command, args []string) error {
	agentID := args[0]

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if err := cfg.RequireCredentials(); err != nil {
		return err
	}

	// Create client and get agent details
	c, err := createClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()
	result, err := c.GetAgentDetails(ctx, agentID)
	if err != nil {
		return fmt.Errorf("failed to get agent details: %w", err)
	}

	// Output result
	if cfg.JSON {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(os.Stdout, string(jsonData))
	} else {
		printAgentDetails(result)
	}

	return nil
}

func printAgentDetails(agent *models.AgentDetails) {
	printAgentHeader(agent)
	printAgentStatus(agent.AgentStatus)
	printEndpoints(agent.Endpoints)
	printDNSRecords(agent.DNSRecords)

	if agent.RegistrationPending != nil {
		printRegistrationPending(agent.RegistrationPending)
	}

	printTimestamps(agent)
	printLinks(agent.Links)
	fmt.Fprintln(os.Stdout)
}

func printAgentHeader(agent *models.AgentDetails) {
	fmt.Fprintln(os.Stdout, "\nAgent Details")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthStandard))
	fmt.Fprintf(os.Stdout, "Agent ID:    %s\n", agent.AgentID)
	fmt.Fprintf(os.Stdout, "Name:        %s\n", agent.AgentDisplayName)
	fmt.Fprintf(os.Stdout, "Host:        %s\n", agent.AgentHost)
	fmt.Fprintf(os.Stdout, "ANS Name:    %s\n", agent.ANSName)
	fmt.Fprintf(os.Stdout, "Version:     %s\n", agent.Version)

	if agent.AgentDescription != "" {
		fmt.Fprintf(os.Stdout, "Description: %s\n", agent.AgentDescription)
	}
}

func printAgentStatus(status *models.AgentStatus) {
	if status == nil {
		return
	}

	fmt.Fprintln(os.Stdout, "\nStatus:")
	if status.Status != "" {
		fmt.Fprintf(os.Stdout, "  Current:  %s\n", status.Status)
	}
	if status.Phase != "" {
		fmt.Fprintf(os.Stdout, "  Phase:    %s\n", status.Phase)
	}

	if len(status.CompletedSteps) > 0 {
		fmt.Fprintln(os.Stdout, "  Completed:")
		for _, step := range status.CompletedSteps {
			fmt.Fprintf(os.Stdout, "    ✓ %s\n", step)
		}
	}

	if len(status.PendingSteps) > 0 {
		fmt.Fprintln(os.Stdout, "  Pending:")
		for _, step := range status.PendingSteps {
			fmt.Fprintf(os.Stdout, "    • %s\n", step)
		}
	}
}

func printEndpoints(endpoints []models.AgentEndpoint) {
	if len(endpoints) == 0 {
		return
	}

	fmt.Fprintln(os.Stdout, "\nEndpoints:")
	for i, endpoint := range endpoints {
		fmt.Fprintf(os.Stdout, "  %d. %s (%s)\n", i+1, endpoint.AgentURL, endpoint.Protocol)
		if len(endpoint.Transports) > 0 {
			fmt.Fprintf(os.Stdout, "     Transports: %s\n", strings.Join(endpoint.Transports, ", "))
		}
		if len(endpoint.Functions) > 0 {
			fmt.Fprintf(os.Stdout, "     Functions: %d\n", len(endpoint.Functions))
		}
	}
}

func printDNSRecords(records []models.DNSRecord) {
	if len(records) == 0 {
		return
	}

	fmt.Fprintln(os.Stdout, "\nDNS Records:")
	for _, record := range records {
		required := ""
		if record.Required {
			required = " (required)"
		}
		fmt.Fprintf(os.Stdout, "  %s %s%s\n", record.Type, record.Name, required)
		fmt.Fprintf(os.Stdout, "    Value: %s\n", record.Value)
		if record.Purpose != "" {
			fmt.Fprintf(os.Stdout, "    Purpose: %s\n", record.Purpose)
		}
	}
}

func printTimestamps(agent *models.AgentDetails) {
	fmt.Fprintln(os.Stdout, "\nTimestamps:")
	if !agent.RegistrationTimestamp.IsZero() {
		fmt.Fprintf(os.Stdout, "  Registered: %s\n", agent.RegistrationTimestamp.Format("2006-01-02 15:04:05 MST"))
	}
	if !agent.LastRenewalTimestamp.IsZero() {
		fmt.Fprintf(os.Stdout, "  Last Renewal: %s\n", agent.LastRenewalTimestamp.Format("2006-01-02 15:04:05 MST"))
	}
}

func printLinks(links []models.Link) {
	if len(links) == 0 {
		return
	}

	fmt.Fprintln(os.Stdout, "\nLinks:")
	for _, link := range links {
		fmt.Fprintf(os.Stdout, "  %s: %s\n", link.Rel, link.Href)
	}
}

func printRegistrationPending(pending *models.RegistrationPending) {
	fmt.Fprintln(os.Stdout, "\nRegistration Pending:")
	fmt.Fprintf(os.Stdout, "  Status: %s\n", pending.Status)

	if !pending.ExpiresAt.IsZero() {
		fmt.Fprintf(os.Stdout, "  Expires: %s\n", pending.ExpiresAt.Format("2006-01-02 15:04:05 MST"))
	}

	if len(pending.Challenges) > 0 {
		fmt.Fprintln(os.Stdout, "  Challenges:")
		for _, challenge := range pending.Challenges {
			fmt.Fprintf(os.Stdout, "    Type: %s\n", challenge.Type)
			if challenge.DNSRecord != nil {
				fmt.Fprintf(os.Stdout, "      DNS: %s = %s\n", challenge.DNSRecord.Name, challenge.DNSRecord.Value)
			}
		}
	}

	if len(pending.DNSRecords) > 0 {
		printDNSRecords(pending.DNSRecords)
	}

	if len(pending.NextSteps) > 0 {
		fmt.Fprintln(os.Stdout, "  Next Steps:")
		for _, step := range pending.NextSteps {
			fmt.Fprintf(os.Stdout, "    • %s: %s\n", step.Action, step.Description)
		}
	}
}
