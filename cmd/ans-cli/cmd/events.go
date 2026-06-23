package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/agentnameservice/ans-sdk-go/ans"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/spf13/cobra"
)

func buildEventsCmd() *cobra.Command {
	var (
		eventsLimit        int
		eventsProviderID   string
		eventsLastLogID    string
		eventsFollow       bool
		eventsPollInterval int
	)

	cmd := &cobra.Command{
		Use:   "events",
		Short: "Retrieve paginated ANS events",
		Long: `Retrieve a paginated list of Agent Name Service events for monitoring and auditing.

Use --follow to continuously poll for new events (Ctrl+C to stop).

Examples:
  ans-cli events
  ans-cli events --limit 50
  ans-cli events --follow
  ans-cli events --follow --poll-interval 10`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runEventsWithParams(eventsLimit, eventsProviderID, eventsLastLogID, eventsFollow, eventsPollInterval)
		},
	}

	cmd.Flags().IntVar(&eventsLimit, "limit", DefaultEventsLimit, "Maximum number of events to return (default: 20, max: 200)")
	cmd.Flags().StringVar(&eventsProviderID, "provider-id", "", "Filter events by provider ID")
	cmd.Flags().StringVar(&eventsLastLogID, "last-log-id", "", "Cursor for pagination (use lastLogId from previous response)")
	cmd.Flags().BoolVarP(&eventsFollow, "follow", "f", false, "Continuously poll for new events")
	cmd.Flags().IntVar(&eventsPollInterval, "poll-interval", DefaultPollIntervalSeconds, "Seconds between polls in follow mode (default: 5)")

	return cmd
}

// eventsParams holds parameters for the events command.
type eventsParams struct {
	limit           int
	providerID      string
	lastLogID       string
	follow          bool
	pollIntervalSec int
	cfg             *config.Config
}

func runEventsWithParams(limit int, providerID, lastLogID string, follow bool, pollIntervalSec int) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.APIKey == "" {
		return errors.New("API key is required. Set --api-key flag or ANS_API_KEY environment variable")
	}

	params := &eventsParams{
		limit:           limit,
		providerID:      providerID,
		lastLogID:       lastLogID,
		follow:          follow,
		pollIntervalSec: pollIntervalSec,
		cfg:             cfg,
	}

	return executeEvents(params)
}

func executeEvents(params *eventsParams) error {
	// Validate poll interval when in follow mode to prevent tight loops
	if params.follow && params.pollIntervalSec <= 0 {
		return errors.New("poll-interval must be a positive value when using --follow")
	}

	c, err := createClient(params.cfg)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	var (
		ctx    context.Context
		cancel context.CancelFunc
	)

	if params.follow {
		ctx, cancel = signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	return pollEvents(ctx, c, params)
}

func pollEvents(ctx context.Context, c *ans.Client, params *eventsParams) error {
	pollInterval := time.Duration(params.pollIntervalSec) * time.Second
	currentLastLogID := params.lastLogID

	for {
		result, err := c.GetAgentEvents(ctx, params.limit, params.providerID, currentLastLogID)
		if err != nil {
			// Context cancellation is expected in follow mode (user pressed Ctrl+C)
			if ctx.Err() != nil {
				return nil //nolint:nilerr // Signal-triggered cancellation is a clean exit, not an error
			}
			return fmt.Errorf("failed to get events: %w", err)
		}

		if err := outputEvents(result, params.cfg, params.follow, currentLastLogID == ""); err != nil {
			return err
		}

		if !params.follow {
			return nil
		}

		if result.LastLogID != nil && *result.LastLogID != "" {
			currentLastLogID = *result.LastLogID
		}

		select {
		case <-ctx.Done():
			return nil // Signal-triggered cancellation is a clean exit
		case <-time.After(pollInterval):
		}
	}
}

func outputEvents(result *models.EventPageResponse, cfg *config.Config, follow, isFirstPoll bool) error {
	if cfg.JSON {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON output: %w", err)
		}
		fmt.Fprintln(os.Stdout, string(jsonData))
		return nil
	}

	if follow {
		printEventsStreaming(result, isFirstPoll)
	} else {
		printEvents(result)
	}

	return nil
}

func printEventsStreaming(result *models.EventPageResponse, isFirstPoll bool) {
	if isFirstPoll {
		fmt.Fprintln(os.Stdout, "\nANS Events (streaming)")
		fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthWide))
		fmt.Fprintln(os.Stdout, "Press Ctrl+C to stop")
		fmt.Fprintln(os.Stdout)
	}

	if len(result.Items) == 0 {
		if isFirstPoll {
			fmt.Fprintln(os.Stdout, "Waiting for events...")
		}
		return
	}

	for _, event := range result.Items {
		timestamp := time.Now().Format("15:04:05")
		if !event.CreatedAt.IsZero() {
			timestamp = event.CreatedAt.Format("15:04:05")
		}
		version := event.Version
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
		fmt.Fprintf(os.Stdout, "[%s] %-20s %s (%s)\n",
			timestamp, event.EventType, event.AgentHost, version)
	}
}

func printEvents(result *models.EventPageResponse) {
	fmt.Fprintln(os.Stdout, "\nANS Events")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthWide))

	if len(result.Items) == 0 {
		fmt.Fprintln(os.Stdout, "No events found.")
		fmt.Fprintln(os.Stdout)
		return
	}

	for i, event := range result.Items {
		fmt.Fprintf(os.Stdout, "\n%d. [%s] %s\n", i+1, event.EventType, event.AnsName)
		fmt.Fprintf(os.Stdout, "   Log ID:   %s\n", event.LogID)
		fmt.Fprintf(os.Stdout, "   Agent ID: %s\n", event.AgentID)
		fmt.Fprintf(os.Stdout, "   Host:     %s\n", event.AgentHost)
		fmt.Fprintf(os.Stdout, "   Version:  %s\n", event.Version)

		if event.AgentDisplayName != nil {
			fmt.Fprintf(os.Stdout, "   Name:     %s\n", *event.AgentDisplayName)
		}
		if event.AgentDescription != nil {
			fmt.Fprintf(os.Stdout, "   Description: %s\n", *event.AgentDescription)
		}
		if event.ProviderID != nil {
			fmt.Fprintf(os.Stdout, "   Provider: %s\n", *event.ProviderID)
		}

		if !event.CreatedAt.IsZero() {
			fmt.Fprintf(os.Stdout, "   Created:  %s\n", event.CreatedAt.Format("2006-01-02 15:04:05 MST"))
		}
		if event.ExpiresAt != nil && !event.ExpiresAt.IsZero() {
			fmt.Fprintf(os.Stdout, "   Expires:  %s\n", event.ExpiresAt.Format("2006-01-02 15:04:05 MST"))
		}

		if len(event.Endpoints) > 0 {
			fmt.Fprintf(os.Stdout, "   Endpoints: %d (", len(event.Endpoints))
			protocols := make([]string, len(event.Endpoints))
			for j, endpoint := range event.Endpoints {
				protocols[j] = endpoint.Protocol
			}
			fmt.Fprintf(os.Stdout, "%s)\n", strings.Join(protocols, ", "))
		}
	}

	// Pagination hint
	if result.LastLogID != nil && *result.LastLogID != "" {
		fmt.Fprintf(os.Stdout, "\nMore results may be available. Use --last-log-id %s to see the next page.\n", *result.LastLogID)
	}

	fmt.Fprintln(os.Stdout)
}
