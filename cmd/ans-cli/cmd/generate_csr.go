package cmd

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/keygen"
	"github.com/spf13/cobra"
)

const (
	keyTypeRSA = "rsa"
	keyTypeEC  = "ec"

	curveNameP256 = "P-256"
	curveNameP384 = "P-384"
	curveNameP521 = "P-521"

	csrTypeIdentity = "identity"
	csrTypeServer   = "server"
	csrTypeBoth     = "both"
)

// generateCSRParams carries the generate-csr command's flag values.
type generateCSRParams struct {
	host, org, country, version, outDir string
	keyType                             string
	keySize                             int
	curve                               string
	csrType                             string
}

// keyGenerator produces a fresh private key for one CSR.
type keyGenerator func() (crypto.Signer, error)

func buildGenerateCSRCmd() *cobra.Command {
	var p generateCSRParams

	cmd := &cobra.Command{
		Use:   "generate-csr",
		Short: "Generate identity and server CSRs",
		Long: `Generate key pairs and Certificate Signing Requests (CSRs) for identity
and server certificates. By default the identity CSR uses an EC P-256 key and
the server CSR an RSA key, which is what the GoDaddy-operated ANS registry
accepts. Pass --key-type to force one algorithm for both CSRs, and --csr-type
to generate only one of them. The CSRs are PEM-encoded and ready to submit to
a registry.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runGenerateCSR(&p)
		},
	}

	cmd.Flags().StringVar(&p.host, "host", "", "Agent host domain (required)")
	cmd.Flags().StringVar(&p.org, "org", "", "Organization name (required)")
	cmd.Flags().StringVar(&p.version, "version", "", "Agent version for ANS URI (required, e.g., 1.0.0)")
	cmd.Flags().StringVar(&p.country, "country", "US", "Country code (default: US)")
	cmd.Flags().StringVar(&p.outDir, "out-dir", ".", "Output directory for keys and CSRs (default: current directory)")
	cmd.Flags().StringVar(&p.keyType, "key-type", "", "Force one key algorithm for every generated CSR: rsa or ec (unset: EC for identity, RSA for server)")
	cmd.Flags().IntVar(&p.keySize, "key-size", DefaultRSAKeySize, "RSA key size in bits, minimum 2048; ignored for --key-type ec (default: 2048)")
	cmd.Flags().StringVar(&p.curve, "curve", DefaultECCurve, "EC curve for --key-type ec: P-256, P-384, or P-521 (default: P-256)")
	cmd.Flags().StringVar(&p.csrType, "csr-type", DefaultCSRType, "Which CSRs to generate: identity, server, or both (default: both)")

	_ = cmd.MarkFlagRequired("host")
	_ = cmd.MarkFlagRequired("org")
	_ = cmd.MarkFlagRequired("version")

	return cmd
}

// csrJob pairs one CSR to generate with the key generator resolved for it.
type csrJob struct {
	name     string
	newKey   keyGenerator
	keyLabel string
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
	for _, job := range jobs {
		fmt.Fprintf(os.Stdout, "  - %s.key (%s private key)\n", job.name, job.keyLabel)
		fmt.Fprintf(os.Stdout, "  - %s.csr (CSR for %s certificate)\n", job.name, job.name)
	}
	names := make([]string, 0, len(jobs))
	for _, job := range jobs {
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
		newKey, keyLabel, err := newKeyGenerator(keyType, p.keySize, p.curve)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, csrJob{name: name, newKey: newKey, keyLabel: keyLabel})
	}
	return jobs, nil
}

// defaultKeyType returns the key algorithm used when --key-type is unset: EC for
// the identity CSR and RSA for the server CSR.
func defaultKeyType(csrName string) string {
	if csrName == csrTypeServer {
		return keyTypeRSA
	}
	return keyTypeEC
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

// newKeyGenerator resolves the --key-type, --key-size, and --curve flag values
// into a generator plus a display label such as "RSA 2048 bits" or "EC P-256".
func newKeyGenerator(keyType string, rsaBits int, curveName string) (keyGenerator, string, error) {
	switch strings.ToLower(keyType) {
	case keyTypeRSA:
		if rsaBits < keygen.MinRSAKeySize {
			return nil, "", fmt.Errorf("invalid RSA key size %d (minimum %d bits)", rsaBits, keygen.MinRSAKeySize)
		}
		gen := func() (crypto.Signer, error) { return keygen.GenerateRSAKeyPair(rsaBits) }
		return gen, fmt.Sprintf("RSA %d bits", rsaBits), nil
	case keyTypeEC:
		curve, err := curveByName(curveName)
		if err != nil {
			return nil, "", err
		}
		gen := func() (crypto.Signer, error) { return keygen.GenerateECKeyPair(curve) }
		return gen, "EC " + curve.Params().Name, nil
	default:
		return nil, "", fmt.Errorf("invalid key type %q (valid: %s, %s)", keyType, keyTypeRSA, keyTypeEC)
	}
}

// curveByName maps a NIST curve name (case-insensitive) to its implementation.
func curveByName(name string) (elliptic.Curve, error) {
	switch strings.ToUpper(name) {
	case curveNameP256:
		return keygen.CurveP256(), nil
	case curveNameP384:
		return keygen.CurveP384(), nil
	case curveNameP521:
		return keygen.CurveP521(), nil
	default:
		return nil, fmt.Errorf("invalid curve %q (valid: %s, %s, %s)", name, curveNameP256, curveNameP384, curveNameP521)
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
