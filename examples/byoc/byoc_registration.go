//nolint:cyclop,depguard,forbidigo,funlen,gocognit,gosec,mnd // This is an example file demonstrating the BYOC workflow
package main

// BYOC (Bring Your Own Certificate) registration workflow.
//
// BYOC allows you to register an agent with your own server certificate instead of
// having ANS issue one. This is useful when:
//   - You have existing certificates from your organization's PKI
//   - You need certificates with specific attributes or extensions
//   - You want to use certificates from a different Certificate Authority
//
// Requirements:
//   - Identity CSR: ANS always issues the identity certificate (client cert for mTLS)
//   - Server Certificate: Your own DV/OV/EV server certificate with:
//   - Subject CN or SAN matching your agent's host domain
//   - Valid chain to a trusted root CA
//   - Not expired and not revoked
//
// Certificate Format:
//   - PEM-encoded X.509 certificate
//   - Include the full chain (leaf + intermediates) for validation

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/agentnameservice/ans-sdk-go/ans"
	"github.com/agentnameservice/ans-sdk-go/keygen"
	"github.com/agentnameservice/ans-sdk-go/models"
)

func main() {
	// Configuration - replace with your values
	const (
		agentHost        = "myagent.example.com"
		agentName        = "My BYOC Agent"
		agentVersion     = "1.0.0"
		agentDescription = "An agent registered with BYOC workflow"
		endpointURL      = "https://myagent.example.com/api"
		endpointMetaURL  = "https://myagent.example.com/.well-known/agent-card.json"
		endpointProtocol = "MCP"
	)

	// Get API credentials from environment
	apiKey := os.Getenv("ANS_API_KEY")
	apiSecret := os.Getenv("ANS_API_SECRET")
	if apiKey == "" || apiSecret == "" {
		log.Fatal("ANS_API_KEY and ANS_API_SECRET environment variables are required")
	}

	// Step 1: Generate identity key pair and CSR
	// ANS always issues the identity certificate - we just provide the CSR
	fmt.Println("Generating identity key pair and CSR...")
	identityKeyPair, err := keygen.GenerateRSAKeyPairWithPEM(2048, nil)
	if err != nil {
		log.Fatalf("Failed to generate identity key pair: %v", err)
	}

	// In production, you would create a proper CSR with the key
	// For this example, we'll use the CLI's generate-csr command output
	identityCSRPath := os.Getenv("IDENTITY_CSR_PATH")
	if identityCSRPath == "" {
		log.Fatal("IDENTITY_CSR_PATH environment variable is required (path to identity CSR PEM file)")
	}

	identityCSRData, err := os.ReadFile(identityCSRPath)
	if err != nil {
		log.Fatalf("Failed to read identity CSR: %v", err)
	}

	// Step 2: Load your existing server certificate (BYOC)
	// This is the key difference from standard registration
	serverCertPath := os.Getenv("SERVER_CERT_PATH")
	if serverCertPath == "" {
		log.Fatal("SERVER_CERT_PATH environment variable is required (path to your server certificate PEM file)")
	}

	serverCertData, err := os.ReadFile(serverCertPath)
	if err != nil {
		log.Fatalf("Failed to read server certificate: %v", err)
	}

	// Optional: Include certificate chain
	serverChainPath := os.Getenv("SERVER_CHAIN_PATH")
	var serverChainData []byte
	if serverChainPath != "" {
		serverChainData, err = os.ReadFile(serverChainPath)
		if err != nil {
			log.Printf("Warning: Failed to read server chain: %v", err)
		}
	}

	// Step 3: Create ANS client
	fmt.Println("Creating ANS client...")
	client, err := ans.NewClient(
		ans.WithBaseURL("https://api.ote-godaddy.com"), // Use ote for testing
		ans.WithAPIKey(apiKey, apiSecret),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Step 4: Build registration request with BYOC
	fmt.Println("Building BYOC registration request...")
	req := &models.AgentRegistrationRequest{
		AgentDisplayName: agentName,
		AgentHost:        agentHost,
		AgentDescription: agentDescription,
		Version:          agentVersion,
		IdentityCSRPEM:   string(identityCSRData),

		// BYOC: Provide your own server certificate instead of CSR
		ServerCertificatePEM: string(serverCertData),
	}

	// Include chain if available
	if len(serverChainData) > 0 {
		req.ServerCertificateChainPEM = string(serverChainData)
	}

	// Add endpoint configuration — declare the agent's URL, metadata, transports,
	// and the functions it offers (each function may carry tags for discovery).
	req.Endpoints = []models.AgentEndpoint{
		{
			AgentURL:    endpointURL,
			MetaDataURL: endpointMetaURL,
			Protocol:    endpointProtocol,
			Transports:  []string{"STREAMABLE-HTTP"},
			Functions: []models.AgentFunction{
				{
					ID:   "analyze-sentiment",
					Name: "Sentiment Analysis",
					Tags: []string{"nlp", "ml"},
				},
				{
					ID:   "extract-entities",
					Name: "Entity Extraction",
					Tags: []string{"nlp", "ner"},
				},
			},
		},
	}

	// Step 5: Submit registration
	fmt.Println("Submitting BYOC registration...")
	ctx := context.Background()
	result, err := client.RegisterAgent(ctx, req)
	if err != nil {
		log.Fatalf("Registration failed: %v", err)
	}

	// Step 6: Handle registration response
	fmt.Println("\n=== Registration Submitted ===")
	fmt.Printf("Status:   %s\n", result.Status)
	fmt.Printf("ANS Name: %s\n", result.ANSName)
	if result.AgentID != "" {
		fmt.Printf("Agent ID: %s\n", result.AgentID)
	}

	// For BYOC, you still need to complete ACME validation for domain ownership
	if len(result.Challenges) > 0 {
		fmt.Println("\n=== ACME Challenges ===")
		fmt.Println("Complete these challenges to prove domain ownership:")
		for i, challenge := range result.Challenges {
			fmt.Printf("\nChallenge %d: %s\n", i+1, challenge.Type)
			if challenge.DNSRecord != nil {
				fmt.Printf("  DNS Record Name:  %s\n", challenge.DNSRecord.Name)
				fmt.Printf("  DNS Record Type:  %s\n", challenge.DNSRecord.Type)
				fmt.Printf("  DNS Record Value: %s\n", challenge.DNSRecord.Value)
			}
			if challenge.HTTPPath != "" {
				fmt.Printf("  HTTP Path: %s\n", challenge.HTTPPath)
				fmt.Printf("  Key Auth:  %s\n", challenge.KeyAuthorization)
			}
		}
	}

	if len(result.NextSteps) > 0 {
		fmt.Println("\n=== Next Steps ===")
		for i, step := range result.NextSteps {
			fmt.Printf("%d. %s: %s\n", i+1, step.Action, step.Description)
		}
	}

	// Save the identity key for later use with mTLS
	identityKeyPath := "identity.key"
	if err := keygen.SavePrivateKeyPEM(identityKeyPair.PrivateKey, identityKeyPath, nil); err != nil {
		log.Printf("Warning: Failed to save identity key: %v", err)
	} else {
		fmt.Printf("\nIdentity private key saved to: %s\n", identityKeyPath)
		fmt.Println("Keep this key secure - you'll need it for mTLS authentication.")
	}
}
