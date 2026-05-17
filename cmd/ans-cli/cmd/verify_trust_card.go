// verify_trust_card.go ships the stapled-receipt verifier that closes
// the offline-verification claim of ANS_SPEC §4.4. The command:
//
//   - Fetches the hosted Trust Card from a URL.
//   - Extracts the embedded SCITT receipt under transparencyReceipt.
//   - Recovers the agent ID from the card body or stapled payload.
//   - Fetches the live receipt from the configured Transparency Log.
//   - Confirms the embedded receipt is byte-equal to the live one.
//
// Three-way card-sha256 cross-channel verification (TL-sealed,
// DNS-published, live-card) is the complementary check and lives in
// `ans-cli verify-hash`. After verify-trust-card confirms the staple
// is fresh, callers can chain into verify-hash to confirm the body
// itself has not drifted from the registered capabilities.
package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/godaddy/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/godaddy/ans-sdk-go/verify/scitt"
	"github.com/spf13/cobra"
)

const (
	verifyTrustCardDefaultTimeout = 15 * time.Second

	statusPass    = "PASS"
	statusFail    = "FAIL"
	statusUnknown = "UNKNOWN"
)

// VerifyTrustCardResult is the per-check outcome the command emits.
// JSON-friendly so callers piping to jq see each check's status,
// evidence, and any failure reason without parsing free text.
type VerifyTrustCardResult struct {
	TrustCardURL          string `json:"trustCardUrl"`
	AgentID               string `json:"agentId,omitempty"`
	StapledReceiptPresent string `json:"stapledReceiptPresent"`
	ReceiptMatchesTL      string `json:"receiptMatchesTL"`
	Reason                string `json:"reason,omitempty"`
	EmbeddedBytes         int    `json:"embeddedBytes,omitempty"`
	LiveBytes             int    `json:"liveBytes,omitempty"`
	Overall               string `json:"overall"`
}

func buildVerifyTrustCardCmd() *cobra.Command {
	var (
		transparencyBaseURL string
		jsonOutput          bool
	)
	cmd := &cobra.Command{
		Use:   "verify-trust-card <trust-card-url>",
		Short: "Verify a hosted Trust Card's stapled SCITT receipt against the live TL",
		Long: `Fetches a hosted Trust Card body, extracts the stapled SCITT receipt,
and confirms it byte-matches the live receipt the Transparency Log serves
for the same agent. Demonstrates the offline-verification claim of
ANS_SPEC §4.4: a verifier reading the hosted Trust Card with the staple
present can validate the registration without contacting the live TL,
provided the stapled bytes match what the TL would serve.

For the complementary three-way card-sha256 cross-channel check
(TL-sealed vs DNS-published vs live-card), use ans-cli verify-hash.

The command extracts the agent ID from the Trust Card body's "agentId"
convenience field, falling back to "transparencyPayload.producer.event.ansId"
when present. Production agents SHOULD include "agentId" at the top level
so verifiers can resolve it without parsing the receipt.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			result := runVerifyTrustCard(args[0], transparencyBaseURL)
			return printVerifyTrustCardResult(result, jsonOutput)
		},
	}
	cmd.Flags().StringVar(&transparencyBaseURL, "transparency-url", "",
		"Transparency log base URL (env: ANS_TRANSPARENCY_URL)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Emit JSON output")
	return cmd
}

func runVerifyTrustCard(trustCardURL, transparencyBaseURL string) *VerifyTrustCardResult {
	r := &VerifyTrustCardResult{
		TrustCardURL:          trustCardURL,
		StapledReceiptPresent: statusUnknown,
		ReceiptMatchesTL:      statusUnknown,
		Overall:               statusUnknown,
	}

	cardBytes, err := fetchTrustCardBytes(trustCardURL)
	if err != nil {
		r.Overall = statusFail
		r.Reason = "fetch trust card: " + err.Error()
		return r
	}

	body := map[string]any{}
	if err := json.Unmarshal(cardBytes, &body); err != nil {
		r.Overall = statusFail
		r.Reason = "decode trust card: " + err.Error()
		return r
	}

	receiptB64, _ := body["transparencyReceipt"].(string)
	if receiptB64 == "" {
		r.StapledReceiptPresent = statusFail
		r.Overall = statusFail
		r.Reason = "trust card has no transparencyReceipt field"
		return r
	}
	r.StapledReceiptPresent = statusPass

	embeddedReceipt, err := base64.StdEncoding.DecodeString(receiptB64)
	if err != nil {
		r.Overall = statusFail
		r.Reason = "decode embedded receipt base64: " + err.Error()
		return r
	}
	r.EmbeddedBytes = len(embeddedReceipt)

	agentID, err := agentIDFromTrustCard(body)
	if err != nil {
		r.Overall = statusFail
		r.Reason = err.Error()
		return r
	}
	r.AgentID = agentID

	tlURL := resolveTransparencyURL(transparencyBaseURL)
	if tlURL == "" {
		r.Overall = statusFail
		r.Reason = "no transparency URL: pass --transparency-url or set ANS_TRANSPARENCY_URL"
		return r
	}

	clientOpts := []scitt.HTTPClientOption{
		scitt.WithTimeout(verifyTrustCardDefaultTimeout),
	}
	// Localhost/loopback Transparency Logs (the demo stack and unit
	// tests) are http; permit that explicitly. Production TLs are
	// https and this branch never triggers.
	if isLoopbackTransparencyURL(tlURL) {
		clientOpts = append(clientOpts, scitt.WithAllowInsecureTransport())
	}
	scittClient, err := scitt.NewHTTPClient(tlURL, clientOpts...)
	if err != nil {
		r.Overall = statusFail
		r.Reason = "build SCITT client: " + err.Error()
		return r
	}
	ctx, cancel := context.WithTimeout(context.Background(), verifyTrustCardDefaultTimeout)
	defer cancel()

	liveReceipt, err := scittClient.FetchReceipt(ctx, agentID)
	if err != nil {
		r.ReceiptMatchesTL = statusFail
		r.Overall = statusFail
		r.Reason = "fetch live receipt: " + err.Error()
		return r
	}
	r.LiveBytes = len(liveReceipt)

	if !bytesEqual(embeddedReceipt, liveReceipt) {
		r.ReceiptMatchesTL = statusFail
		r.Overall = statusFail
		r.Reason = fmt.Sprintf(
			"embedded receipt (%d bytes) does not byte-match live receipt (%d bytes); "+
				"the agent's stapled receipt is stale or has been tampered with",
			len(embeddedReceipt), len(liveReceipt),
		)
		return r
	}
	r.ReceiptMatchesTL = statusPass
	r.Overall = statusPass
	return r
}

func fetchTrustCardBytes(trustCardURL string) ([]byte, error) {
	if _, err := url.Parse(trustCardURL); err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	client := &http.Client{Timeout: verifyTrustCardDefaultTimeout}
	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, trustCardURL, nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("trust card http %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// agentIDFromTrustCard extracts the agentId from a Trust Card body.
// Looks for a top-level convenience field first, then falls back to
// the transparencyPayload's nested ansId. Returns a clear error
// when neither is present so callers know what shape the agent owes
// for offline verification to work.
func agentIDFromTrustCard(body map[string]any) (string, error) {
	if v, ok := body["agentId"].(string); ok && v != "" {
		return v, nil
	}
	if pl, ok := body["transparencyPayload"].(map[string]any); ok {
		if pp, ok := pl["producer"].(map[string]any); ok {
			if ev, ok := pp["event"].(map[string]any); ok {
				if v, ok := ev["ansId"].(string); ok && v != "" {
					return v, nil
				}
			}
		}
	}
	return "", fmt.Errorf(
		"trust card body has no agentId or transparencyPayload.producer.event.ansId; " +
			"production agents SHOULD include agentId at the top level for offline verification",
	)
}

// isLoopbackTransparencyURL returns true when the TL URL points at
// localhost or a loopback IP. Used to opt into insecure transport for
// the demo stack and unit tests without exposing a flag operators
// could misuse against a production endpoint.
func isLoopbackTransparencyURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func resolveTransparencyURL(override string) string {
	if override != "" {
		return override
	}
	if cfg, err := config.Load(); err == nil {
		// config.Config doesn't expose TransparencyURL directly today; the
		// existing verify-hash flow reads ANS_TRANSPARENCY_URL from env.
		// Mirror that here.
		_ = cfg
	}
	return os.Getenv("ANS_TRANSPARENCY_URL")
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func printVerifyTrustCardResult(r *VerifyTrustCardResult, asJSON bool) error {
	if asJSON {
		out, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	} else {
		fmt.Printf("trust card:           %s\n", r.TrustCardURL)
		if r.AgentID != "" {
			fmt.Printf("agent id:             %s\n", r.AgentID)
		}
		fmt.Printf("stapled receipt:      %s\n", r.StapledReceiptPresent)
		fmt.Printf("receipt matches TL:   %s\n", r.ReceiptMatchesTL)
		if r.EmbeddedBytes > 0 {
			fmt.Printf("  embedded:           %d bytes\n", r.EmbeddedBytes)
		}
		if r.LiveBytes > 0 {
			fmt.Printf("  live TL:            %d bytes\n", r.LiveBytes)
		}
		if r.Reason != "" {
			fmt.Printf("reason:               %s\n", r.Reason)
		}
		fmt.Printf("overall:              %s\n", r.Overall)
	}
	if r.Overall != statusPass {
		return fmt.Errorf("verify-trust-card: overall %s", r.Overall)
	}
	return nil
}
