package cmd

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/csrvalidation"
	"github.com/agentnameservice/ans-sdk-go/keygen"
	"github.com/spf13/cobra"
)

const (
	keyTypeRSA = "rsa"
	keyTypeEC  = "ec"

	csrTypeIdentity = "identity"
	csrTypeServer   = "server"
	csrTypeBoth     = "both"
)

// generateCSRParams carries the generate-csr command's flag values.
type generateCSRParams struct {
	host, org, country, version, outDir string
	keyType                             string
	keySize                             int
	csrType                             string
}

// keyGenerator produces a fresh private key for one CSR.
type keyGenerator func() (crypto.Signer, error)

// csrJob pairs one CSR to generate with the key generator resolved for it.
type csrJob struct {
	name     string
	newKey   keyGenerator
	keyLabel string
}

func buildGenerateCSRCmd() *cobra.Command {
	var p generateCSRParams

	cmd := &cobra.Command{
		Use:   "generate-csr",
		Short: "Generate identity and server CSRs",
		Long: `Generate key pairs and Certificate Signing Requests (CSRs) for identity
and server certificates. By default the identity CSR uses an EC P-256 key and
the server CSR an RSA key, which is what the ANS registry accepts. Pass
--key-type to force one algorithm for both CSRs and --csr-type to generate
only one of them. Keys the registry would reject are refused before anything
is written.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runGenerateCSR(&p)
		},
	}

	cmd.Flags().StringVar(&p.host, "host", "", "Agent host domain (required)")
	cmd.Flags().StringVar(&p.org, "org", "", "Organization name (required)")
	cmd.Flags().StringVar(&p.version, "version", "", "Agent version for ANS URI (required, e.g., 1.0.0)")
	cmd.Flags().StringVar(&p.country, "country", "US", "Country code (default: US)")
	cmd.Flags().StringVar(&p.outDir, "out-dir", ".", "Output directory for keys and CSRs (default: current directory)")
	cmd.Flags().StringVar(&p.keyType, "key-type", "", "Force one key algorithm for every generated CSR: rsa or ec (unset: EC P-256 for identity, RSA for server)")
	cmd.Flags().IntVar(&p.keySize, "key-size", DefaultRSAKeySize, "RSA key size in bits, minimum 2048; ignored for EC keys (default: 2048)")
	cmd.Flags().StringVar(&p.csrType, "csr-type", DefaultCSRType, "Which CSRs to generate: identity, server, or both (default: both)")

	_ = cmd.MarkFlagRequired("host")
	_ = cmd.MarkFlagRequired("org")
	_ = cmd.MarkFlagRequired("version")

	return cmd
}

func runGenerateCSR(p *generateCSRParams) error {
	jobs, err := planCSRJobs(p)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(p.outDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	fmt.Fprintf(os.Stdout, "Generating CSRs for host: %s\n", p.host)
	fmt.Fprintf(os.Stdout, "Organization: %s\n", p.org)
	fmt.Fprintf(os.Stdout, "Version: %s\n", p.version)
	fmt.Fprintf(os.Stdout, "Country: %s\n\n", p.country)

	ansURI := fmt.Sprintf("ans://v%s.%s", p.version, p.host)

	for _, job := range jobs {
		fmt.Fprintf(os.Stdout, "Generating %s certificate (%s)...\n", job.name, job.keyLabel)
		if err := generateCSR(job.name, p.host, p.org, p.country, ansURI, job.newKey, p.outDir); err != nil {
			return fmt.Errorf("failed to generate %s CSR: %w", job.name, err)
		}
	}

	fmt.Fprintf(os.Stdout, "\n✓ CSRs generated successfully in: %s\n", p.outDir)
	fmt.Fprintln(os.Stdout, "\nFiles created:")
	names := make([]string, 0, len(jobs))
	for _, job := range jobs {
		fmt.Fprintf(os.Stdout, "  - %s.key (%s private key)\n", job.name, job.keyLabel)
		fmt.Fprintf(os.Stdout, "  - %s.csr (CSR for %s certificate)\n", job.name, job.name)
		names = append(names, job.name)
	}
	printGenerateCSRNextSteps(p, names)

	return nil
}

// planCSRJobs resolves every flag into the CSRs to generate and their key
// generators before anything is written, so a bad flag fails with no side effects.
func planCSRJobs(p *generateCSRParams) ([]csrJob, error) {
	names, err := csrNames(p.csrType)
	if err != nil {
		return nil, err
	}
	jobs := make([]csrJob, 0, len(names))
	for _, name := range names {
		keyType := p.keyType
		if keyType == "" {
			keyType = defaultKeyType(name)
		}
		newKey, keyLabel, err := newKeyGenerator(keyType, p.keySize)
		if err != nil {
			return nil, err
		}
		if err := checkRegistryRules(name, keyType, p.keySize); err != nil {
			return nil, err
		}
		jobs = append(jobs, csrJob{name: name, newKey: newKey, keyLabel: keyLabel})
	}
	return jobs, nil
}

// csrNames maps the --csr-type flag value to the CSRs to generate, in output order.
func csrNames(csrType string) ([]string, error) {
	switch strings.ToLower(csrType) {
	case csrTypeBoth:
		return []string{csrTypeIdentity, csrTypeServer}, nil
	case csrTypeIdentity:
		return []string{csrTypeIdentity}, nil
	case csrTypeServer:
		return []string{csrTypeServer}, nil
	default:
		return nil, fmt.Errorf("invalid CSR type %q (valid: %s, %s, %s)", csrType, csrTypeIdentity, csrTypeServer, csrTypeBoth)
	}
}

// defaultKeyType returns the key algorithm used when --key-type is unset: EC for
// the identity CSR and RSA for the server CSR.
func defaultKeyType(csrName string) string {
	if csrName == csrTypeServer {
		return keyTypeRSA
	}
	return keyTypeEC
}

// registryRules returns the registry's intake rules for one CSR type.
func registryRules(csrName string) csrvalidation.Rules {
	if csrName == csrTypeServer {
		return csrvalidation.ServerRules()
	}
	return csrvalidation.IdentityRules()
}

// checkRegistryRules refuses a key the registry would reject for this CSR type,
// so generate-csr never writes a CSR that register or submit-*-csr fails on.
func checkRegistryRules(csrName, keyType string, rsaBits int) error {
	rules := registryRules(csrName)
	accepted := rules.AllowsCurve(csrvalidation.CurveP256)
	if strings.ToLower(keyType) == keyTypeRSA {
		accepted = rules.AllowsRSAKeySize(rsaBits)
	}
	if accepted {
		return nil
	}
	return fmt.Errorf("the registry rejects this key for the %s CSR; it accepts %s (adjust --key-type or --key-size, or use --csr-type to generate only the other CSR)",
		csrName, rules.Describe())
}

func printGenerateCSRNextSteps(p *generateCSRParams, names []string) {
	fmt.Fprintln(os.Stdout, "\nNext steps:")
	if len(names) == 1 {
		fmt.Fprintf(os.Stdout, "  Renew an existing agent's %s certificate using:\n", names[0])
		fmt.Fprintf(os.Stdout, "  ans-cli submit-%s-csr <agentId> --csr-file %s/%s.csr\n", names[0], p.outDir, names[0])
		if names[0] == csrTypeServer {
			return
		}
	}
	fmt.Fprintf(os.Stdout, "  Register your agent using:\n")
	fmt.Fprintf(os.Stdout, "  ans-cli register --name \"My Agent\" --host %s --version %s \\\n", p.host, p.version)
	if len(names) == 1 {
		fmt.Fprintf(os.Stdout, "    --identity-csr %s/identity.csr \\\n", p.outDir)
	} else {
		fmt.Fprintf(os.Stdout, "    --identity-csr %s/identity.csr --server-csr %s/server.csr \\\n", p.outDir, p.outDir)
	}
	fmt.Fprintf(os.Stdout, "    --endpoint-url https://%s/api --endpoint-protocol MCP\n", p.host)
}

// newKeyGenerator resolves --key-type and --key-size into a generator plus a
// display label such as "RSA 2048 bits" or "EC P-256".
func newKeyGenerator(keyType string, rsaBits int) (keyGenerator, string, error) {
	switch strings.ToLower(keyType) {
	case keyTypeRSA:
		if rsaBits < keygen.MinRSAKeySize {
			return nil, "", fmt.Errorf("invalid RSA key size %d (minimum %d bits)", rsaBits, keygen.MinRSAKeySize)
		}
		gen := func() (crypto.Signer, error) { return keygen.GenerateRSAKeyPair(rsaBits) }
		return gen, fmt.Sprintf("RSA %d bits", rsaBits), nil
	case keyTypeEC:
		gen := func() (crypto.Signer, error) { return keygen.GenerateECKeyPair(keygen.CurveP256()) }
		return gen, "EC " + csrvalidation.CurveP256, nil
	default:
		return nil, "", fmt.Errorf("invalid key type %q (valid: %s, %s)", keyType, keyTypeRSA, keyTypeEC)
	}
}

func generateCSR(name, host, org, country, ansURI string, newKey keyGenerator, outDir string) error {
	privateKey, err := newKey()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	uri, err := url.Parse(ansURI)
	if err != nil {
		return fmt.Errorf("failed to parse ANS URI: %w", err)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{org},
			Country:      []string{country},
		},
		DNSNames: []string{host},
		URIs:     []*url.URL{uri},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	if err := keygen.SavePrivateKeyPEM(privateKey, filepath.Join(outDir, name+".key"), nil); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err := os.WriteFile(filepath.Join(outDir, name+".csr"), csrPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CSR: %w", err)
	}

	fmt.Fprintf(os.Stdout, "  ✓ %s.key\n", name)
	fmt.Fprintf(os.Stdout, "  ✓ %s.csr\n", name)

	return nil
}
