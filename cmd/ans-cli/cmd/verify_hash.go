package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/godaddy/ans-sdk-go/ans"
	"github.com/godaddy/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/godaddy/ans-sdk-go/models"
	"github.com/godaddy/ans-sdk-go/verify"
	"github.com/spf13/cobra"
)

// buildVerifyHashCmd registers `ans-cli verify-hash <agentId>`. The
// subcommand fetches the agent's TL badge, fetches the live ANS
// Trust Card body from /.well-known/ans/trust-card.json on the
// agent's FQDN, and runs the §4.4.2 three-way cross-check.
//
// Optional --svcb-value flag lets the operator pass a DNS SVCB
// presentation-form value when the SDK doesn't query DNS itself.
// Future versions can resolve the SVCB record automatically.
func buildVerifyHashCmd() *cobra.Command {
	var (
		svcbValue        string
		trustCardURL     string
		insecureCardTLS  bool
	)

	cmd := &cobra.Command{
		Use:   "verify-hash <agentId>",
		Short: "Run the §4.4.2 three-way cross-check against an agent's badge",
		Long: `Fetches the agent's Transparency Log badge, fetches the live ANS Trust
Card body, and compares all available SHA-256 commitments to the card.

Three commitments compared (per ANS_SPEC.md §4.4.2):
  H_tl   — TL-sealed metadataHashes.capabilitiesHash on the AGENT_REGISTERED
           event (hex-lowercase). Empty when the operator did not submit
           agentCardContent at registration.
  H_dns  — Consolidated Approach SVCB record's card-sha256 SvcParam
           (base64url, decoded to hex). Pass via --svcb-value or omit if
           the operator chose dnsRecordStyle=legacy.
  H_live — SHA-256(JCS(/.well-known/ans/trust-card.json body)) on the
           agent's FQDN.

Reports each populated channel's value and any divergence. The verifier
SHOULD refuse the connection when AllAgree is false.

Examples:
  ans-cli verify-hash 51ec1fa7-d8aa-4318-b4fa-7cdbd3e5c05a
  ans-cli verify-hash 51ec1fa7-... --svcb-value '1 . alpn=a2a card-sha256=CY1lDMb...'
  ans-cli verify-hash 51ec1fa7-... --trust-card-url https://agent.webmesh.ai/.well-known/ans/trust-card.json
`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runVerifyHash(args[0], svcbValue, trustCardURL, insecureCardTLS)
		},
	}

	cmd.Flags().StringVar(&svcbValue, "svcb-value", "",
		"SVCB record presentation-form value (e.g., '1 . alpn=a2a card-sha256=...'); omit if not running DNS lookup")
	cmd.Flags().StringVar(&trustCardURL, "trust-card-url", "",
		"Override URL to fetch the live Trust Card; defaults to https://{agentHost}/.well-known/ans/trust-card.json")
	cmd.Flags().BoolVar(&insecureCardTLS, "insecure-card-tls", false,
		"Skip TLS verification when fetching the live Trust Card (testing/local dev only)")

	return cmd
}

func runVerifyHash(agentID, svcbValue, trustCardURL string, insecureCardTLS bool) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	tlClient, err := newTransparencyClientForCLI(cfg)
	if err != nil {
		return fmt.Errorf("failed to create transparency client: %w", err)
	}

	// 1. Fetch the badge from the TL.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tlEntry, err := tlClient.GetAgentTransparencyLog(ctx, agentID)
	if err != nil {
		return fmt.Errorf("fetch transparency log: %w", err)
	}
	badge, err := transparencyLogToBadge(tlEntry)
	if err != nil {
		return err
	}

	// 2. Fetch the live Trust Card body. Skip if the badge has no
	//    agent FQDN (shouldn't happen for an active registration).
	host := badge.AgentHost()
	if host == "" {
		return errors.New("verify-hash: badge has no agent host; cannot locate Trust Card")
	}
	url := trustCardURL
	if url == "" {
		url = fmt.Sprintf("https://%s/.well-known/ans/trust-card.json", host)
	}
	liveBody, err := fetchTrustCardBody(ctx, url, insecureCardTLS)
	if err != nil {
		return fmt.Errorf("fetch live Trust Card from %s: %w", url, err)
	}

	// 3. Run the cross-check.
	result, err := verify.VerifyCardSHA256(badge, liveBody, svcbValue)
	if err != nil {
		return fmt.Errorf("cross-check: %w", err)
	}

	if cfg.JSON {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(os.Stdout, string(out))
		return nil
	}
	printVerifyHashResult(result, agentID, host)
	return nil
}

// fetchTrustCardBody pulls the raw bytes of the Trust Card from the
// agent's well-known path. Returns the raw body so the verifier can
// JCS-canonicalize it byte-for-byte; do not parse and re-marshal.
func fetchTrustCardBody(ctx context.Context, url string, insecureTLS bool) ([]byte, error) {
	transport := &http.Transport{}
	if insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // operator opts in via flag for local dev
	}
	hc := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// newTransparencyClientForCLI mirrors createClient but for the
// transparency-log endpoint. The CLI doesn't have a dedicated TL
// helper; the existing client builders are RA-only.
//
// Reads of the public TL badge endpoint do not require an API key,
// so the auth opt is optional. When present, the CLI's "key:secret"
// form is split the same way createClient handles it.
func newTransparencyClientForCLI(cfg *config.Config) (*ans.TransparencyClient, error) {
	opts := []ans.Option{
		ans.WithBaseURL(cfg.BaseURL),
		ans.WithVerbose(cfg.Verbose),
	}
	if cfg.APIKey != "" {
		parts := strings.SplitN(cfg.APIKey, ":", apiKeyParts)
		if len(parts) == apiKeyParts {
			opts = append(opts, ans.WithAPIKey(parts[0], parts[1]))
		}
	}
	return ans.NewTransparencyClient(opts...)
}

// transparencyLogToBadge converts the loose-typed TransparencyLog
// (Payload is map[string]any in the legacy SDK shape) into the
// V2-aware Badge struct the verify package consumes. We re-marshal
// the Payload map through JSON to deserialize into BadgePayload's
// strongly-typed fields, then synthesize the surrounding Badge.
//
// The round-trip is necessary because the legacy SDK shape kept
// Payload untyped to absorb V1/V2 envelope differences. Plan E's
// Badge.CapabilitiesHash and DNSRecordsProvisioned helpers depend on
// the typed shape.
func transparencyLogToBadge(tl *models.TransparencyLog) (*models.Badge, error) {
	if tl == nil {
		return &models.Badge{}, nil
	}
	payloadJSON, err := json.Marshal(tl.Payload)
	if err != nil {
		return nil, fmt.Errorf("re-marshal TL payload: %w", err)
	}
	var payload models.BadgePayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("decode TL payload into Badge: %w", err)
	}
	var sigPtr *string
	if tl.Signature != "" {
		sig := tl.Signature
		sigPtr = &sig
	}
	return &models.Badge{
		Status:        models.BadgeStatus(tl.Status),
		Payload:       payload,
		SchemaVersion: tl.SchemaVersion,
		Signature:     sigPtr,
		MerkleProof:   tl.MerkleProof,
	}, nil
}

func printVerifyHashResult(r *verify.CrossCheckResult, agentID, host string) {
	fmt.Fprintln(os.Stdout, "\n§4.4.2 three-way cross-check")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthStandard))
	fmt.Fprintf(os.Stdout, "Agent ID: %s\n", agentID)
	fmt.Fprintf(os.Stdout, "Host:     %s\n", host)
	fmt.Fprintln(os.Stdout)
	if r.AllAgree {
		fmt.Fprintln(os.Stdout, "✓ All populated channels agree.")
	} else {
		fmt.Fprintln(os.Stdout, "✗ Channels disagree (or one populated channel is missing).")
	}
	fmt.Fprintln(os.Stdout)
	printHashRow("H_tl   (TL capabilities_hash)", r.HTLHex)
	printHashRow("H_dns  (SVCB card-sha256, hex)", r.HDNSHex)
	printHashRow("H_live (SHA-256 JCS(card body))", r.HLiveHex)
	if len(r.Findings) > 0 {
		fmt.Fprintln(os.Stdout, "\nFindings:")
		for _, f := range r.Findings {
			fmt.Fprintf(os.Stdout, "  - %s\n", f)
		}
	}
}

func printHashRow(label, hexValue string) {
	if hexValue == "" {
		fmt.Fprintf(os.Stdout, "  %-32s  (absent)\n", label)
		return
	}
	fmt.Fprintf(os.Stdout, "  %-32s  %s\n", label, hexValue)
}
