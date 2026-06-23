package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/ans"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/spf13/cobra"
)

// searchParams holds the flag-bound inputs for the `ans-cli search` command.
type searchParams struct {
	name     string
	host     string
	version  string
	protocol string
	statuses []string
	limit    int
	offset   int
}

func buildSearchCmd() *cobra.Command {
	p := &searchParams{}

	cmd := &cobra.Command{
		Use:   "search",
		Short: "Search for registered agents",
		Long: `Search the Agent Name Service registry using flexible criteria such as
agent name, host domain, version ranges, protocol, or lifecycle status.

By default the registry returns only ACTIVE agents. Use --status PENDING_DNS to
find registrations still completing DNS validation, or --status ALL to see
agents in every lifecycle state.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runSearchWithParams(p)
		},
	}

	cmd.Flags().StringVar(&p.name, "name", "", "Agent display name (partial matching supported)")
	cmd.Flags().StringVar(&p.host, "host", "", "Agent host domain (partial matching supported)")
	cmd.Flags().StringVar(&p.version, "version", "", "Agent version (flexible matching supported)")
	cmd.Flags().StringVar(&p.protocol, "protocol", "", "Endpoint protocol filter (A2A, MCP, HTTP-API)")
	cmd.Flags().StringSliceVar(&p.statuses, "status", nil, "Lifecycle status filter, repeatable (PENDING_DNS, ACTIVE, DEPRECATED, REVOKED, ALL)")
	cmd.Flags().IntVar(&p.limit, "limit", DefaultSearchLimit, "Maximum number of results (default: 20, max: 100)")
	cmd.Flags().IntVar(&p.offset, "offset", 0, "Number of results to skip for pagination")

	return cmd
}

func runSearchWithParams(p *searchParams) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.APIKey == "" {
		return errors.New("API key is required. Set --api-key flag or ANS_API_KEY environment variable")
	}

	if p.name == "" && p.host == "" && p.version == "" && p.protocol == "" && len(p.statuses) == 0 {
		return errors.New("at least one search criteria is required (--name, --host, --version, --protocol, or --status)")
	}

	opts := buildSearchOptions(p)

	c, err := createClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	ctx := context.Background()
	result, err := c.SearchAgents(ctx, opts...)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	// Output result
	if cfg.JSON {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(os.Stdout, string(jsonData))
	} else {
		printSearchResults(result)
	}

	return nil
}

// buildSearchOptions converts CLI flag values into ans.SearchOption values.
// Status and protocol strings are uppercased for caller convenience; the SDK
// validates the normalised value against the documented enum.
func buildSearchOptions(p *searchParams) []ans.SearchOption {
	var opts []ans.SearchOption

	if p.name != "" {
		opts = append(opts, ans.WithSearchName(p.name))
	}
	if p.host != "" {
		opts = append(opts, ans.WithSearchHost(p.host))
	}
	if p.version != "" {
		opts = append(opts, ans.WithSearchVersion(p.version))
	}
	if p.protocol != "" {
		opts = append(opts, ans.WithSearchProtocol(models.AgentProtocol(strings.ToUpper(p.protocol))))
	}
	if len(p.statuses) > 0 {
		statuses := make([]models.AgentLifecycleStatus, len(p.statuses))
		for i, s := range p.statuses {
			statuses[i] = models.AgentLifecycleStatus(strings.ToUpper(strings.TrimSpace(s)))
		}
		opts = append(opts, ans.WithSearchStatus(statuses...))
	}
	if p.limit > 0 {
		opts = append(opts, ans.WithSearchLimit(p.limit))
	}
	if p.offset > 0 {
		opts = append(opts, ans.WithSearchOffset(p.offset))
	}

	return opts
}

func printSearchResults(result *models.AgentSearchResponse) {
	printSearchHeader(result)

	if len(result.Agents) == 0 {
		fmt.Fprintln(os.Stdout, "No agents found matching the search criteria.")
		return
	}

	for i, agent := range result.Agents {
		printAgentSummary(i+1, &agent)
		if i < len(result.Agents)-1 {
			fmt.Fprintln(os.Stdout)
		}
	}

	printPaginationHint(result)
	fmt.Fprintln(os.Stdout)
}

func printSearchHeader(result *models.AgentSearchResponse) {
	fmt.Fprintln(os.Stdout, "\nSearch Results")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthWide))
	fmt.Fprintf(os.Stdout, "Total matches: %d | Showing: %d | Limit: %d | Offset: %d | More: %v\n\n",
		result.TotalCount, result.ReturnedCount, result.Limit, result.Offset, result.HasMore)
}

func printAgentSummary(num int, agent *models.AgentSearchResult) {
	fmt.Fprintf(os.Stdout, "%d. %s\n", num, agent.AgentDisplayName)
	fmt.Fprintf(os.Stdout, "   ANS Name: %s\n", agent.ANSName)
	fmt.Fprintf(os.Stdout, "   Host:     %s\n", agent.AgentHost)
	fmt.Fprintf(os.Stdout, "   Version:  %s\n", agent.Version)

	if agent.AgentDescription != "" {
		fmt.Fprintf(os.Stdout, "   Description: %s\n", agent.AgentDescription)
	}

	if len(agent.Endpoints) > 0 {
		protocols := make([]string, len(agent.Endpoints))
		for j, endpoint := range agent.Endpoints {
			protocols[j] = endpoint.Protocol
		}
		fmt.Fprintf(os.Stdout, "   Endpoints: %d (%s)\n", len(agent.Endpoints), strings.Join(protocols, ", "))
	}

	if !agent.RegistrationTimestamp.IsZero() {
		fmt.Fprintf(os.Stdout, "   Registered: %s\n", agent.RegistrationTimestamp.Format("2006-01-02 15:04:05"))
	}

	for _, link := range agent.Links {
		if link.Rel == "agent-details" || link.Rel == "self" {
			fmt.Fprintf(os.Stdout, "   Details: %s\n", link.Href)
			break
		}
	}
}

func printPaginationHint(result *models.AgentSearchResponse) {
	if result.HasMore {
		nextOffset := result.Offset + result.ReturnedCount
		fmt.Fprintf(os.Stdout, "\nMore results available. Use --offset %d to see the next page.\n", nextOffset)
	}
}
