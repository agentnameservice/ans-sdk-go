package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/ans"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/spf13/cobra"
)

func buildRegisterCmd() *cobra.Command {
	var (
		regName              string
		regHost              string
		regVersion           string
		regDescription       string
		regIdentityCSR       string
		regServerCSR         string
		regServerCert        string
		regEndpointURL       string
		regMetaDataURL       string
		regEndpointProto     string
		regEndpointTrans     []string
		regFunctions         []string
		regDiscoveryProfiles []string
	)

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new agent with ANS",
		Long: `Register a new agent with the Agent Name Service by providing agent details,
CSRs for identity and server certificates, and endpoint configuration.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runRegisterWithParams(regName, regHost, regVersion, regDescription,
				regIdentityCSR, regServerCSR, regServerCert,
				regEndpointURL, regMetaDataURL, regEndpointProto, regEndpointTrans, regFunctions,
				regDiscoveryProfiles)
		},
	}

	cmd.Flags().StringVar(&regName, "name", "", "Agent display name (required)")
	cmd.Flags().StringVar(&regHost, "host", "", "Agent host domain (required)")
	cmd.Flags().StringVar(&regVersion, "version", "", "Agent version in semver format (required)")
	cmd.Flags().StringVar(&regDescription, "description", "", "Agent description")
	cmd.Flags().StringVar(&regIdentityCSR, "identity-csr", "", "Path to identity CSR PEM file (required)")
	cmd.Flags().StringVar(&regServerCSR, "server-csr", "", "Path to server CSR PEM file")
	cmd.Flags().StringVar(&regServerCert, "server-cert", "", "Path to server certificate PEM file (BYOC)")
	cmd.Flags().StringVar(&regEndpointURL, "endpoint-url", "", "Agent endpoint URL (required)")
	cmd.Flags().StringVar(&regMetaDataURL, "metadata-url", "", "Agent metadata URL (e.g., /.well-known/agent-card.json)")
	cmd.Flags().StringVar(&regEndpointProto, "endpoint-protocol", "MCP", "Endpoint protocol (MCP, A2A, HTTP-API)")
	cmd.Flags().StringSliceVar(&regEndpointTrans, "endpoint-transports", []string{"STREAMABLE-HTTP"}, "Endpoint transports")
	cmd.Flags().StringArrayVar(&regFunctions, "function", nil, "Agent function in format 'id:name' or 'id:name:tag1,tag2' (repeatable)")
	cmd.Flags().StringSliceVar(&regDiscoveryProfiles, "discovery-profiles", nil,
		"DNS record families the RA asks the operator to publish: ANS_DNSAID, ANS_TXT, or both (requires --api-version v2; omitted = server default ANS_DNSAID)")

	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("host")
	_ = cmd.MarkFlagRequired("version")
	_ = cmd.MarkFlagRequired("identity-csr")
	_ = cmd.MarkFlagRequired("endpoint-url")

	return cmd
}

func runRegisterWithParams(name, host, version, description, identityCSR, serverCSR, serverCert, endpointURL, metaDataURL, endpointProto string, endpointTrans, functionFlags, discoveryProfiles []string) error {
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

	// Read identity CSR
	identityCSRData, err := os.ReadFile(identityCSR)
	if err != nil {
		return fmt.Errorf("failed to read identity CSR file: %w", err)
	}

	// Read server CSR or certificate
	var serverCSRData, serverCertData []byte
	if serverCert != "" {
		serverCertData, err = os.ReadFile(serverCert)
		if err != nil {
			return fmt.Errorf("failed to read server certificate file: %w", err)
		}
	} else if serverCSR != "" {
		serverCSRData, err = os.ReadFile(serverCSR)
		if err != nil {
			return fmt.Errorf("failed to read server CSR file: %w", err)
		}
	}

	// Parse and validate functions
	functions, err := ParseFunctionFlags(functionFlags)
	if err != nil {
		return fmt.Errorf("invalid function specification: %w", err)
	}

	// Validate discovery profiles client-side so a typo fails fast with
	// the valid set instead of round-tripping to a server 422.
	profiles := make([]models.DiscoveryProfile, 0, len(discoveryProfiles))
	for _, p := range discoveryProfiles {
		profile := models.DiscoveryProfile(strings.ToUpper(strings.TrimSpace(p)))
		if !models.IsValidDiscoveryProfile(profile) {
			return fmt.Errorf("invalid discovery profile %q (valid: %s, %s)",
				p, models.DiscoveryProfileANSDNSAID, models.DiscoveryProfileANSTXT)
		}
		profiles = append(profiles, profile)
	}
	// Discovery profiles only take effect on the V2 lane; the V1 lane
	// ignores the field server-side and always emits ANS_TXT. Reject
	// the combination instead of letting a V1 registration silently
	// drop the operator's explicit choice. Empty cfg.APIVersion means
	// the flag default (v1) — config tests bypass flag binding.
	if len(profiles) > 0 {
		apiVersion := cfg.APIVersion
		if apiVersion == "" {
			apiVersion = string(ans.APIVersionV1)
		}
		if apiVersion != string(ans.APIVersionV2) {
			return fmt.Errorf("--discovery-profiles requires --api-version v2 (current: %q)", apiVersion)
		}
	}

	// Build registration request
	req := &models.AgentRegistrationRequest{
		AgentDisplayName: name,
		AgentHost:        host,
		AgentDescription: description,
		Version:          version,
		IdentityCSRPEM:   string(identityCSRData),
		Endpoints: []models.AgentEndpoint{
			{
				AgentURL:    endpointURL,
				MetaDataURL: metaDataURL,
				Protocol:    endpointProto,
				Transports:  endpointTrans,
				Functions:   functions,
			},
		},
	}

	if len(serverCertData) > 0 {
		req.ServerCertificatePEM = string(serverCertData)
	} else if len(serverCSRData) > 0 {
		req.ServerCSRPEM = string(serverCSRData)
	}
	if len(profiles) > 0 {
		req.DiscoveryProfiles = profiles
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
