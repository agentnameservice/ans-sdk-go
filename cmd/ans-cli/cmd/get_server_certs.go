package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/spf13/cobra"
)

func buildGetServerCertsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get-server-certs <agentId>",
		Short: "List server certificates for an agent",
		Long:  `Retrieve all server certificates associated with an agent.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runGetServerCerts,
	}
}

func runGetServerCerts(_ *cobra.Command, args []string) error {
	agentID := args[0]

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
	certs, err := c.GetServerCertificates(ctx, agentID)
	if err != nil {
		return fmt.Errorf("failed to get server certificates: %w", err)
	}

	if cfg.JSON {
		jsonData, _ := json.MarshalIndent(certs, "", "  ")
		fmt.Fprintln(os.Stdout, string(jsonData))
	} else {
		printCertificates("Server", certs)
	}

	return nil
}
