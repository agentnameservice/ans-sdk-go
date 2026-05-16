package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/godaddy/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/godaddy/ans-sdk-go/models"
	"github.com/spf13/cobra"
)

// registerOptions groups the register subcommand's flag values so the
// argument list of runRegisterWithParams stays manageable as the
// surface grows (Plan A/C/D added several optional fields).
type registerOptions struct {
	Name             string
	Host             string
	Version          string
	Description      string
	IdentityCSR      string
	ServerCSR        string
	ServerCert       string
	EndpointURL      string
	MetaDataURL      string
	EndpointProto    string
	EndpointTrans    []string
	Functions        []string
	AgentCardContent string // path to JSON file (Plan C)
	DNSRecordStyle   string // consolidated|legacy|both (Plan D)
}

func buildRegisterCmd() *cobra.Command {
	var opts registerOptions

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new agent with ANS",
		Long: `Register a new agent with the Agent Name Service by providing agent details,
CSRs for identity and server certificates, and endpoint configuration.

Optional fields:
  --agent-card-content   Path to a JSON file containing the ANS Trust Card
                         body. The RA computes SHA-256(JCS(content)) and seals
                         the digest into the AGENT_REGISTERED Transparency
                         Log event under metadataHashes.capabilitiesHash, per
                         ANS_SPEC.md §A.1. The same digest re-encoded as
                         base64url appears in the Consolidated Approach SVCB
                         record's card-sha256 SvcParam (§4.4.2 cross-check).
  --dns-record-style     Selects which DNS record family the RA tells you to
                         publish. Values:
                           consolidated (default, recommended): one SVCB
                             record per protocol at the bare FQDN per §4.4.2,
                             plus shared records.
                           legacy: original _ans TXT shape plus an HTTPS RR.
                             Backwards-compatible.
                           both: union; the §4.4.2 transition shape.
                         Empty/missing → consolidated.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runRegisterWithOptions(opts)
		},
	}

	cmd.Flags().StringVar(&opts.Name, "name", "", "Agent display name (required)")
	cmd.Flags().StringVar(&opts.Host, "host", "", "Agent host domain (required)")
	cmd.Flags().StringVar(&opts.Version, "version", "", "Agent version in semver format (required)")
	cmd.Flags().StringVar(&opts.Description, "description", "", "Agent description")
	cmd.Flags().StringVar(&opts.IdentityCSR, "identity-csr", "", "Path to identity CSR PEM file (required)")
	cmd.Flags().StringVar(&opts.ServerCSR, "server-csr", "", "Path to server CSR PEM file")
	cmd.Flags().StringVar(&opts.ServerCert, "server-cert", "", "Path to server certificate PEM file (BYOC)")
	cmd.Flags().StringVar(&opts.EndpointURL, "endpoint-url", "", "Agent endpoint URL (required)")
	cmd.Flags().StringVar(&opts.MetaDataURL, "metadata-url", "", "Agent metadata URL (e.g., /.well-known/agent-card.json)")
	cmd.Flags().StringVar(&opts.EndpointProto, "endpoint-protocol", "MCP", "Endpoint protocol (MCP, A2A, HTTP-API)")
	cmd.Flags().StringSliceVar(&opts.EndpointTrans, "endpoint-transports", []string{"STREAMABLE-HTTP"}, "Endpoint transports")
	cmd.Flags().StringArrayVar(&opts.Functions, "function", nil, "Agent function in format 'id:name' or 'id:name:tag1,tag2' (repeatable)")
	cmd.Flags().StringVar(&opts.AgentCardContent, "agent-card-content", "",
		"Path to JSON file containing the ANS Trust Card body (Plan C; §A.1)")
	cmd.Flags().StringVar(&opts.DNSRecordStyle, "dns-record-style", "",
		"DNS record family: consolidated (default) | legacy | both (Plan D; §4.4.2)")

	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("host")
	_ = cmd.MarkFlagRequired("version")
	_ = cmd.MarkFlagRequired("identity-csr")
	_ = cmd.MarkFlagRequired("endpoint-url")

	return cmd
}

// runRegisterWithParams is the legacy positional-argument entry point
// kept alive for callers (tests, external scripts) that predate the
// registerOptions struct introduced for Plan A/C/D fields. New code
// SHOULD use runRegisterWithOptions directly.
func runRegisterWithParams(name, host, version, description, identityCSR, serverCSR, serverCert, endpointURL, metaDataURL, endpointProto string, endpointTrans, functionFlags []string) error {
	return runRegisterWithOptions(registerOptions{
		Name:          name,
		Host:          host,
		Version:       version,
		Description:   description,
		IdentityCSR:   identityCSR,
		ServerCSR:     serverCSR,
		ServerCert:    serverCert,
		EndpointURL:   endpointURL,
		MetaDataURL:   metaDataURL,
		EndpointProto: endpointProto,
		EndpointTrans: endpointTrans,
		Functions:     functionFlags,
	})
}

func runRegisterWithOptions(opts registerOptions) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.APIKey == "" {
		return errors.New("API key is required. Set --api-key flag or ANS_API_KEY environment variable")
	}

	c, err := createClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// Read identity CSR
	identityCSRData, err := os.ReadFile(opts.IdentityCSR)
	if err != nil {
		return fmt.Errorf("failed to read identity CSR file: %w", err)
	}

	// Read server CSR or certificate
	var serverCSRData, serverCertData []byte
	if opts.ServerCert != "" {
		serverCertData, err = os.ReadFile(opts.ServerCert)
		if err != nil {
			return fmt.Errorf("failed to read server certificate file: %w", err)
		}
	} else if opts.ServerCSR != "" {
		serverCSRData, err = os.ReadFile(opts.ServerCSR)
		if err != nil {
			return fmt.Errorf("failed to read server CSR file: %w", err)
		}
	}

	// Parse and validate functions
	functions, err := ParseFunctionFlags(opts.Functions)
	if err != nil {
		return fmt.Errorf("invalid function specification: %w", err)
	}

	// Read agentCardContent body (Plan C / §A.1) if provided. Pass
	// the raw bytes through json.RawMessage so JCS canonicalization
	// at the RA sees exactly what the operator wrote.
	var agentCardContent json.RawMessage
	if opts.AgentCardContent != "" {
		raw, err := os.ReadFile(opts.AgentCardContent)
		if err != nil {
			return fmt.Errorf("failed to read agent-card-content file: %w", err)
		}
		// Sanity-check: must be valid JSON. Catches operator typos
		// before the RA returns 422 INVALID_AGENT_CARD_CONTENT.
		var probe interface{}
		if err := json.Unmarshal(raw, &probe); err != nil {
			return fmt.Errorf("agent-card-content file is not valid JSON: %w", err)
		}
		agentCardContent = json.RawMessage(raw)
	}

	// Validate dnsRecordStyle locally so the operator sees a clear
	// error before the registration round-trip. The RA performs the
	// authoritative check; this is an ergonomics layer.
	if opts.DNSRecordStyle != "" {
		switch opts.DNSRecordStyle {
		case models.DNSRecordStyleConsolidated,
			models.DNSRecordStyleLegacy,
			models.DNSRecordStyleBoth:
			// ok
		default:
			return fmt.Errorf("invalid --dns-record-style %q (want consolidated, legacy, or both)",
				opts.DNSRecordStyle)
		}
	}

	// Build registration request
	req := &models.AgentRegistrationRequest{
		AgentDisplayName: opts.Name,
		AgentHost:        opts.Host,
		AgentDescription: opts.Description,
		Version:          opts.Version,
		IdentityCSRPEM:   string(identityCSRData),
		AgentCardContent: agentCardContent,
		DNSRecordStyle:   opts.DNSRecordStyle,
		Endpoints: []models.AgentEndpoint{
			{
				AgentURL:    opts.EndpointURL,
				MetaDataURL: opts.MetaDataURL,
				Protocol:    opts.EndpointProto,
				Transports:  opts.EndpointTrans,
				Functions:   functions,
			},
		},
	}

	if len(serverCertData) > 0 {
		req.ServerCertificatePEM = string(serverCertData)
	} else if len(serverCSRData) > 0 {
		req.ServerCSRPEM = string(serverCSRData)
	}

	// Register the agent
	ctx := context.Background()
	result, err := c.RegisterAgent(ctx, req)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	// Output result
	if cfg.JSON {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(os.Stdout, string(jsonData))
	} else {
		printRegistrationResult(result)
	}

	return nil
}

func printRegistrationResult(result *models.RegistrationPending) {
	printRegistrationHeader(result)
	printDNSChallengeBanner(result.Challenges)
	printChallenges(result.Challenges)
	printDNSRecordsToConfig(result.DNSRecords)
	printNextSteps(result.NextSteps)
	printResultLinks(result.Links)
	fmt.Fprintln(os.Stdout)
}

func printRegistrationHeader(result *models.RegistrationPending) {
	fmt.Fprintln(os.Stdout, "\n✓ Agent registration submitted")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthStandard))
	fmt.Fprintf(os.Stdout, "Status:  %s\n", result.Status)
	fmt.Fprintf(os.Stdout, "ANSName: %s\n", result.ANSName)
	if result.AgentID != "" {
		fmt.Fprintf(os.Stdout, "Agent ID: %s\n", result.AgentID)
	}
	if !result.ExpiresAt.IsZero() {
		fmt.Fprintf(os.Stdout, "Expires: %s\n", result.ExpiresAt.Format("2006-01-02 15:04:05 MST"))
	}
}

func printDNSChallengeBanner(challenges []models.ChallengeInfo) {
	hasDNSChallenge := false
	for _, challenge := range challenges {
		if challenge.DNSRecord != nil {
			hasDNSChallenge = true
			break
		}
	}

	if !hasDNSChallenge {
		return
	}

	fmt.Fprintln(os.Stdout, "\n"+strings.Repeat("=", SeparatorWidthStandard))
	fmt.Fprintln(os.Stdout, "⚠️  ACTION REQUIRED: Configure DNS TXT Record")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthStandard))

	for _, challenge := range challenges {
		if challenge.DNSRecord != nil {
			fmt.Fprintf(os.Stdout, "\nRecord Type: %s\n", challenge.DNSRecord.Type)
			fmt.Fprintf(os.Stdout, "Record Name: %s\n", challenge.DNSRecord.Name)
			fmt.Fprintf(os.Stdout, "Record Value:\n  %s\n", challenge.DNSRecord.Value)
			fmt.Fprintln(os.Stdout, "\nCopy-paste for DNS provider:")
			fmt.Fprintf(os.Stdout, "  Name:  %s\n", challenge.DNSRecord.Name)
			fmt.Fprintf(os.Stdout, "  Type:  TXT\n")
			fmt.Fprintf(os.Stdout, "  Value: %s\n", challenge.DNSRecord.Value)
			fmt.Fprintf(os.Stdout, "  TTL:   300 (or minimum allowed)\n")
		}
	}
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthStandard))
}

func printChallenges(challenges []models.ChallengeInfo) {
	if len(challenges) == 0 {
		return
	}

	fmt.Fprintln(os.Stdout, "\nACME Challenges:")
	for i, challenge := range challenges {
		if len(challenges) > 1 {
			fmt.Fprintf(os.Stdout, "\n  Challenge %d:\n", i+1)
		}
		fmt.Fprintf(os.Stdout, "  Type: %s\n", challenge.Type)

		if challenge.DNSRecord != nil {
			fmt.Fprintf(os.Stdout, "  DNS Record:\n")
			fmt.Fprintf(os.Stdout, "    Name:  %s\n", challenge.DNSRecord.Name)
			fmt.Fprintf(os.Stdout, "    Type:  %s\n", challenge.DNSRecord.Type)
			fmt.Fprintf(os.Stdout, "    Value: %s\n", challenge.DNSRecord.Value)
		}

		if challenge.HTTPPath != "" {
			fmt.Fprintf(os.Stdout, "  HTTP Path: %s\n", challenge.HTTPPath)
			fmt.Fprintf(os.Stdout, "  Key Authorization: %s\n", challenge.KeyAuthorization)
		}
	}
}

func printDNSRecordsToConfig(records []models.DNSRecord) {
	if len(records) == 0 {
		return
	}

	fmt.Fprintln(os.Stdout, "\nDNS Records to Configure:")
	for _, record := range records {
		fmt.Fprintf(os.Stdout, "  %s %s %s (Purpose: %s)\n", record.Type, record.Name, record.Value, record.Purpose)
	}
}

func printNextSteps(steps []models.NextStep) {
	if len(steps) == 0 {
		return
	}

	fmt.Fprintln(os.Stdout, "\nNext Steps:")
	for i, step := range steps {
		fmt.Fprintf(os.Stdout, "  %d. %s: %s\n", i+1, step.Action, step.Description)
		if step.Endpoint != "" {
			fmt.Fprintf(os.Stdout, "     Endpoint: %s\n", step.Endpoint)
		}
	}
}

func printResultLinks(links []models.Link) {
	if len(links) == 0 {
		return
	}

	fmt.Fprintln(os.Stdout, "\nLinks:")
	for _, link := range links {
		fmt.Fprintf(os.Stdout, "  %s: %s\n", link.Rel, link.Href)
	}
}
