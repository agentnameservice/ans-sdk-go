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

func buildResolveCmd() *cobra.Command {
	var resolveVersion string

	cmd := &cobra.Command{
		Use:   "resolve <host>",
		Short: "Resolve an agent by host and version",
		Long: `Resolve an agent by host domain and optional version pattern.

Version patterns support semver matching:
  - "*"       Match any version (default)
  - "1.0.0"   Exact version match
  - "^1.0.0"  Compatible with 1.x.x (major fixed)
  - "~1.2.3"  Compatible with 1.2.x (minor fixed)

Examples:
  ans-cli resolve myagent.example.com
  ans-cli resolve myagent.example.com --version "^1.0.0"
  ans-cli resolve myagent.example.com --version "2.1.0"`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runResolve(args[0], resolveVersion)
		},
	}

	cmd.Flags().StringVarP(&resolveVersion, "version", "V", "*", "Version pattern to match (default: \"*\" for any)")

	return cmd
}

func runResolve(host, version string) error {
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

	ctx := context.Background()
	result, err := c.ResolveAgent(ctx, host, version)
	if err != nil {
		return fmt.Errorf("failed to resolve agent: %w", err)
	}

	if cfg.JSON {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON output: %w", err)
		}
		fmt.Fprintln(os.Stdout, string(jsonData))
	} else {
		printResolveResult(result, host, version)
	}

	return nil
}

func printResolveResult(result *models.AgentCapabilityResponse, host, version string) {
	fmt.Fprintln(os.Stdout, "\nAgent Resolution Result")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthWide))

	fmt.Fprintf(os.Stdout, "Query:    %s @ %s\n", host, version)
	fmt.Fprintf(os.Stdout, "ANS Name: %s\n", result.AnsName)

	if len(result.Links) > 0 {
		fmt.Fprintln(os.Stdout, "\nLinks:")
		for _, link := range result.Links {
			fmt.Fprintf(os.Stdout, "  %s: %s\n", link.Rel, link.Href)
		}
	}

	fmt.Fprintln(os.Stdout)
}
