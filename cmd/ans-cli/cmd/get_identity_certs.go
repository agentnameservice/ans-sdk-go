package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/spf13/cobra"
)

func buildGetIdentityCertsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get-identity-certs <agentId>",
		Short: "List identity certificates for an agent",
		Long:  `Retrieve all identity certificates associated with an agent.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runGetIdentityCerts,
	}
}

func runGetIdentityCerts(_ *cobra.Command, args []string) error {
	agentID := args[0]

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

	ctx := context.Background()
	certs, err := c.GetIdentityCertificates(ctx, agentID)
	if err != nil {
		return fmt.Errorf("failed to get identity certificates: %w", err)
	}

	if cfg.JSON {
		jsonData, _ := json.MarshalIndent(certs, "", "  ")
		fmt.Fprintln(os.Stdout, string(jsonData))
	} else {
		printCertificates("Identity", certs)
	}

	return nil
}

func printCertificates(certType string, certs []models.CertificateResponse) {
	fmt.Fprintf(os.Stdout, "\n%s Certificates\n", certType)
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthStandard))

	if len(certs) == 0 {
		fmt.Fprintf(os.Stdout, "No %s certificates found.\n\n", strings.ToLower(certType))
		return
	}

	for i, cert := range certs {
		fmt.Fprintf(os.Stdout, "\nCertificate %d:\n", i+1)
		fmt.Fprintf(os.Stdout, "  CSR ID: %s\n", cert.CsrID)
		if cert.CertificateSubject != nil {
			fmt.Fprintf(os.Stdout, "  Subject: %s\n", *cert.CertificateSubject)
		}
		if cert.CertificateIssuer != nil {
			fmt.Fprintf(os.Stdout, "  Issuer: %s\n", *cert.CertificateIssuer)
		}
		if cert.CertificateSerialNumber != nil {
			fmt.Fprintf(os.Stdout, "  Serial Number: %s\n", *cert.CertificateSerialNumber)
		}
		if cert.CertificatePublicKeyAlgorithm != nil {
			fmt.Fprintf(os.Stdout, "  Public Key Algorithm: %s\n", *cert.CertificatePublicKeyAlgorithm)
		}
		if cert.CertificateSignatureAlgorithm != nil {
			fmt.Fprintf(os.Stdout, "  Signature Algorithm: %s\n", *cert.CertificateSignatureAlgorithm)
		}
		if !cert.CertificateValidFrom.IsZero() {
			fmt.Fprintf(os.Stdout, "  Valid From: %s\n", cert.CertificateValidFrom.Format("2006-01-02 15:04:05 MST"))
		}
		if !cert.CertificateValidTo.IsZero() {
			fmt.Fprintf(os.Stdout, "  Valid To: %s\n", cert.CertificateValidTo.Format("2006-01-02 15:04:05 MST"))
		}
	}

	fmt.Fprintln(os.Stdout)
}
