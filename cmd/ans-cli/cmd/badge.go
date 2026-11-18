package cmd

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/ans"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/registries"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/trust"
	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/spf13/cobra"
)

const (
	defaultBadgeAuditLimit   = 10
	maxMetadataHashesDisplay = 20

	transparencyURLEnv = "ANS_TRANSPARENCY_URL"
)

// badgeDeps are the network clients badge uses beyond the JSON API; tests
// inject doubles.
type badgeDeps struct {
	// newTransparencyClient builds the client for the log's JSON API.
	newTransparencyClient func(baseURL string, verbose bool) (*ans.TransparencyClient, error)
	// newCheckpointFetcher builds the client that reads a log's raw signed
	// checkpoint note at {tl}/checkpoint.
	newCheckpointFetcher func(tlOrigin string) (scitt.CheckpointFetcher, error)
}

func defaultBadgeDeps() badgeDeps {
	return badgeDeps{
		newTransparencyClient: func(baseURL string, verbose bool) (*ans.TransparencyClient, error) {
			return ans.NewTransparencyClient(ans.WithBaseURL(baseURL), ans.WithVerbose(verbose))
		},
		newCheckpointFetcher: func(tlOrigin string) (scitt.CheckpointFetcher, error) {
			return scitt.NewHTTPClient(tlOrigin, scitt.WithHTTPClient(httpsOnlyClient()))
		},
	}
}

func buildBadgeCmd() *cobra.Command {
	var (
		badgeAuditTrail     bool
		badgeCheckpoint     bool
		transparencyBaseURL string
	)

	cmd := &cobra.Command{
		Use:   "badge <agentId>",
		Short: "Retrieve transparency log entry for an agent",
		Long: `Retrieve the transparency log entry from the Transparency Log
for a given agent ID. This includes the Merkle proof, payload data, and status.

With --checkpoint, the log's signed checkpoint is also retrieved. When a
registry environment is selected with --registry and its log keys have been
saved with "ans-cli registries fetch-keys", the checkpoint signature is
verified against those keys; otherwise the output says plainly that it was
not verified and why.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return runBadgeWithParams(args[0], badgeAuditTrail, badgeCheckpoint, transparencyBaseURL)
		},
	}

	cmd.Flags().BoolVar(&badgeAuditTrail, "audit", false, "Also retrieve audit trail")
	cmd.Flags().BoolVar(&badgeCheckpoint, "checkpoint", false, "Also retrieve the log checkpoint and verify its signature against saved keys")
	cmd.Flags().StringVar(&transparencyBaseURL, "transparency-url", "", "Transparency log base URL (env: "+transparencyURLEnv+")")

	return cmd
}

func runBadgeWithParams(agentID string, auditTrail, checkpoint bool, transparencyBaseURL string) error {
	return runBadge(agentID, auditTrail, checkpoint, transparencyBaseURL, defaultBadgeDeps())
}

func runBadge(agentID string, auditTrail, checkpoint bool, transparencyBaseURL string, deps badgeDeps) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	baseURL, err := resolveTransparencyURL(transparencyBaseURL, os.Getenv(transparencyURLEnv), cfg.Registry)
	if err != nil {
		return err
	}

	// Create Transparency Log client (no authentication needed - public endpoint)
	c, err := deps.newTransparencyClient(baseURL, cfg.Verbose)
	if err != nil {
		return fmt.Errorf("failed to create transparency client: %w", err)
	}

	ctx := context.Background()

	// Get transparency log entry
	logEntry, err := c.GetAgentTransparencyLog(ctx, agentID)
	if err != nil {
		return fmt.Errorf("failed to retrieve transparency log entry: %w", err)
	}

	var verification *checkpointVerification
	if checkpoint {
		v := verifyCheckpoint(ctx, cfg, baseURL, deps)
		verification = &v
	}

	// Output result
	if cfg.JSON {
		outputBadgeJSON(ctx, c, agentID, logEntry, auditTrail, verification)
		return nil
	}

	outputBadgeHuman(ctx, c, agentID, logEntry, auditTrail, verification)
	return nil
}

// checkpointVerification is the outcome of checking the log's signed
// checkpoint note against the keys saved for the selected registry
// environment. Reason is set whenever Verified is false and says what was
// missing or wrong.
type checkpointVerification struct {
	Verified bool   `json:"verified"`
	Registry string `json:"registry,omitempty"`
	KeyID    string `json:"keyId,omitempty"`
	KeyName  string `json:"keyName,omitempty"`
	Origin   string `json:"origin,omitempty"`
	// Size is meaningful only when Verified; an empty log has size 0.
	Size     uint64 `json:"size"`
	RootHash string `json:"rootHash,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// MatchesJSONView reports whether the log's JSON checkpoint view (the
	// unverified /v1/log/checkpoint response printed beside this) describes
	// the same tree head as the verified note. Nil when the view was not
	// retrieved or the note was not verified.
	MatchesJSONView *bool `json:"matchesJsonView,omitempty"`
}

// bindJSONView compares the verified note to the log's JSON checkpoint view
// so the output never shows an unverified size and root beside a verified
// stamp without saying whether they agree. The view's root hash is accepted
// as hex or base64.
func (v *checkpointVerification) bindJSONView(view *models.CheckpointResponse) {
	if !v.Verified || view == nil {
		return
	}
	same := view.LogSize >= 0 && uint64(view.LogSize) == v.Size && rootHashEqual(view.RootHash, v.RootHash)
	v.MatchesJSONView = &same
}

func rootHashEqual(view, verifiedHex string) bool {
	if strings.EqualFold(view, verifiedHex) {
		return true
	}
	raw, err := base64.StdEncoding.DecodeString(view)
	return err == nil && hex.EncodeToString(raw) == verifiedHex
}

// verifyCheckpoint fetches the raw signed checkpoint note from the selected
// registry environment's log and verifies it against that environment's saved
// keys. It never fetches keys: a missing or stale set is reported, with the
// command that would fix it, rather than filled in.
func verifyCheckpoint(ctx context.Context, cfg *config.Config, tlURL string, deps badgeDeps) checkpointVerification {
	keys, sel, reason := savedCheckpointKeys(cfg, tlURL)
	if keys == nil {
		return checkpointVerification{Reason: reason}
	}
	result := checkpointVerification{Registry: sel.String()}
	fetcher, err := deps.newCheckpointFetcher(sel.Environment.TL)
	if err != nil {
		result.Reason = fmt.Sprintf("cannot read %s/checkpoint: %v", sel.Environment.TL, err)
		return result
	}
	note, err := fetcher.FetchCheckpoint(ctx)
	if err != nil {
		result.Reason = fmt.Sprintf("could not fetch %s/checkpoint: %v", sel.Environment.TL, err)
		return result
	}
	cp, err := scitt.VerifyCheckpoint(note, keys)
	if err != nil {
		result.Reason = fmt.Sprintf("signature did not verify against the %d saved key(s) for %s: %v", keys.Len(), sel, err)
		var sigErr *scitt.SignatureError
		if errors.As(err, &sigErr) && sigErr.Type == scitt.SigErrUnknownKeyID {
			result.Reason += fmt.Sprintf(" (if the log added a key, run: ans-cli registries fetch-keys %s)", sel)
		}
		return result
	}
	result.Verified = true
	result.KeyID = hex.EncodeToString(cp.KeyID[:])
	if key, err := keys.Get(cp.KeyID); err == nil {
		result.KeyName = key.Name
	}
	result.Origin = cp.Origin
	result.Size = cp.Size
	result.RootHash = hex.EncodeToString(cp.RootHash[:])
	return result
}

// savedCheckpointKeys loads the keys saved for the selected registry
// environment when the log being read is that environment's. When it cannot,
// the returned reason says why in terms the user can act on.
func savedCheckpointKeys(cfg *config.Config, tlURL string) (*scitt.KeyStore, *registries.Selected, string) {
	if cfg.Registry == "" {
		return nil, nil, "no registry environment selected; saved log keys are kept per registry environment (pass --registry <id>/<environment> and run ans-cli registries fetch-keys)"
	}
	sel, err := selectRegistry(cfg.Registry)
	if err != nil {
		return nil, nil, err.Error()
	}
	if !strings.EqualFold(strings.TrimRight(tlURL, "/"), sel.Environment.TL) {
		return nil, nil, fmt.Sprintf("transparency log URL %s overrides the %s log %s; saved keys are bound to that log", tlURL, sel, sel.Environment.TL)
	}
	store, err := trust.NewStore(cfg.ConfigDir)
	if err != nil {
		return nil, nil, err.Error()
	}
	keys, err := store.LoadKeys(trustScope(sel))
	if err != nil {
		if errors.Is(err, trust.ErrNoSavedKeys) {
			return nil, nil, fmt.Sprintf("no saved log keys for %s; run: ans-cli registries fetch-keys %s", sel, sel)
		}
		return nil, nil, err.Error()
	}
	lookup, err := trust.Lookup(keys)
	if err != nil {
		return nil, nil, err.Error()
	}
	return lookup, &sel, ""
}

// resolveTransparencyURL applies the TL URL precedence: --transparency-url,
// ANS_TRANSPARENCY_URL, then the --registry <id>/<environment> entry.
func resolveTransparencyURL(flagValue, envValue, registryID string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if envValue != "" {
		return envValue, nil
	}
	urls, err := resolveRegistryURLs(registryID)
	if err != nil {
		return "", err
	}
	if urls.tl != "" {
		return urls.tl, nil
	}
	return "", fmt.Errorf("no transparency log URL configured: pass --transparency-url, set %s, or pick a known registry with --registry <id>/<environment> (see `ans-cli registries`)", transparencyURLEnv)
}

func outputBadgeJSON(ctx context.Context, c *ans.TransparencyClient, agentID string, logEntry *models.TransparencyLog, auditTrail bool, verification *checkpointVerification) {
	result := map[string]any{"transparencyLog": logEntry}
	var warnings []string
	checkpoint := verification != nil

	if auditTrail {
		params := &models.AgentAuditParams{Limit: defaultBadgeAuditLimit, Offset: 0}
		if audit, auditErr := c.GetAgentTransparencyLogAudit(ctx, agentID, params); auditErr != nil {
			warning := fmt.Sprintf("failed to retrieve audit trail: %v", auditErr)
			fmt.Fprintln(os.Stderr, "Warning: "+warning)
			warnings = append(warnings, warning)
		} else {
			result["audit"] = audit
		}
	}

	if checkpoint {
		if checkpointData, checkpointErr := c.GetCheckpoint(ctx); checkpointErr != nil {
			warning := fmt.Sprintf("failed to retrieve checkpoint: %v", checkpointErr)
			fmt.Fprintln(os.Stderr, "Warning: "+warning)
			warnings = append(warnings, warning)
		} else {
			result["checkpoint"] = checkpointData
			verification.bindJSONView(checkpointData)
		}
		result["checkpointVerification"] = verification
		if warning := verification.warning(); warning != "" {
			fmt.Fprintln(os.Stderr, "Warning: "+warning)
			warnings = append(warnings, warning)
		}
	}

	if len(warnings) > 0 {
		result["warnings"] = warnings
	}

	jsonData, _ := json.MarshalIndent(result, "", "  ")
	fmt.Fprintln(os.Stdout, string(jsonData))
}

func outputBadgeHuman(ctx context.Context, c *ans.TransparencyClient, agentID string, logEntry *models.TransparencyLog, auditTrail bool, verification *checkpointVerification) {
	printTransparencyLog(logEntry)

	if auditTrail {
		params := &models.AgentAuditParams{Limit: defaultBadgeAuditLimit, Offset: 0}
		if audit, auditErr := c.GetAgentTransparencyLogAudit(ctx, agentID, params); auditErr != nil {
			fmt.Fprintf(os.Stdout, "\n⚠️  Failed to retrieve audit trail: %v\n", auditErr)
		} else {
			fmt.Fprintln(os.Stdout)
			printAuditTrail(audit)
		}
	}

	if verification != nil {
		if checkpointData, checkpointErr := c.GetCheckpoint(ctx); checkpointErr != nil {
			fmt.Fprintf(os.Stdout, "\n⚠️  Failed to retrieve checkpoint: %v\n", checkpointErr)
		} else {
			fmt.Fprintln(os.Stdout)
			printCheckpoint(checkpointData)
			verification.bindJSONView(checkpointData)
		}
		printCheckpointVerification(verification)
	}
}

// warning returns the line a caller should surface when the checkpoint is not
// fully verified, or empty when it is.
func (v *checkpointVerification) warning() string {
	switch {
	case !v.Verified:
		return "checkpoint signature not verified: " + v.Reason
	case v.MatchesJSONView != nil && !*v.MatchesJSONView:
		return "the log's JSON checkpoint view describes a different tree head than the verified signed note"
	default:
		return ""
	}
}

func printCheckpointVerification(v *checkpointVerification) {
	if !v.Verified {
		fmt.Fprintf(os.Stdout, "\n⚠️  Checkpoint signature NOT verified: %s\n", v.Reason)
		return
	}
	fmt.Fprintf(os.Stdout, "\n✅ Checkpoint signature verified against saved key %s (%s) for %s\n", v.KeyID, v.KeyName, v.Registry)
	fmt.Fprintf(os.Stdout, "   Origin: %s  Size: %d  Root: %s\n", v.Origin, v.Size, truncateHash(v.RootHash))
	switch {
	case v.MatchesJSONView == nil:
	case *v.MatchesJSONView:
		fmt.Fprintln(os.Stdout, "   The JSON checkpoint view above describes this same tree head.")
	default:
		fmt.Fprintln(os.Stdout, "   ⚠️  The JSON checkpoint view above describes a DIFFERENT tree head; only the signed note was verified.")
	}
	fmt.Fprintln(os.Stdout, "   This proves the log signed this tree head with a key you saved. It does not prove the head extends earlier heads, that other clients see the same head, or anything about the log entry above, whose inclusion proof is not checked here.")
}

func printTransparencyLog(logEntry *models.TransparencyLog) {
	fmt.Fprintln(os.Stdout, "\n🏅 Transparency Log Entry")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthWide))

	if logEntry.Status != "" {
		fmt.Fprintf(os.Stdout, "Status: %s\n", logEntry.Status)
	}

	if logEntry.SchemaVersion != "" {
		fmt.Fprintf(os.Stdout, "Schema Version: %s\n", logEntry.SchemaVersion)
	} else if logEntry.IsV0() {
		fmt.Fprintf(os.Stdout, "Schema Version: V0 (default)\n")
	}

	if logEntry.Payload != nil {
		printPayload(logEntry)
	}

	if logEntry.MerkleProof != nil {
		printMerkleProof(logEntry.MerkleProof)
	}

	if logEntry.Signature != "" {
		fmt.Fprintf(os.Stdout, "\n🔏 Signature:      %s\n", truncateHash(logEntry.Signature))
	}

	fmt.Fprintln(os.Stdout)
}

func printMerkleProof(proof *models.MerkleProof) {
	fmt.Fprintln(os.Stdout, "\n🌳 Merkle Proof:")
	fmt.Fprintf(os.Stdout, "  Tree Version:    %d\n", proof.TreeVersion)
	fmt.Fprintf(os.Stdout, "  Tree Size:       %d\n", proof.TreeSize)
	if proof.LeafIndex != nil {
		fmt.Fprintf(os.Stdout, "  Leaf Index:      %d\n", *proof.LeafIndex)
	}
	if proof.LeafHash != "" {
		fmt.Fprintf(os.Stdout, "  Leaf Hash:       %s\n", truncateHash(proof.LeafHash))
	}
	if proof.RootHash != "" {
		fmt.Fprintf(os.Stdout, "  Root Hash:       %s\n", truncateHash(proof.RootHash))
	}
	if len(proof.Path) > 0 {
		fmt.Fprintf(os.Stdout, "  Proof Path:      %d nodes\n", len(proof.Path))
	}
	if proof.RootSignature != "" {
		fmt.Fprintf(os.Stdout, "  Root Signature:  %s\n", truncateHash(proof.RootSignature))
	}
}

func printPayload(logEntry *models.TransparencyLog) {
	fmt.Fprintln(os.Stdout, "\n📄 Event Payload:")

	// Use strongly-typed payload if available
	switch {
	case logEntry.IsV1() && logEntry.GetV1Payload() != nil:
		printV1Payload(logEntry.GetV1Payload())
	case logEntry.IsV0() && logEntry.GetV0Payload() != nil:
		printV0Payload(logEntry.GetV0Payload())
	default:
		// Fallback to raw payload for unknown schemas
		printRawPayload(logEntry.Payload)
	}
}

func printV1Payload(v1 *models.TransparencyLogV1) {
	fmt.Fprintf(os.Stdout, "  Schema:          V1\n")
	fmt.Fprintf(os.Stdout, "  Log ID:          %s\n", v1.LogID)

	event := v1.Producer.Event
	fmt.Fprintf(os.Stdout, "  ANS ID:          %s\n", event.ANSID)
	fmt.Fprintf(os.Stdout, "  ANS Name:        %s\n", event.ANSName)
	fmt.Fprintf(os.Stdout, "  Event Type:      %s\n", event.EventType)
	fmt.Fprintf(os.Stdout, "  RA ID:           %s\n", event.RAID)
	fmt.Fprintf(os.Stdout, "  Timestamp:       %s\n", event.Timestamp.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(os.Stdout, "  Issued At:       %s\n", event.IssuedAt.Format("2006-01-02 15:04:05 MST"))

	if event.ExpiresAt != nil {
		fmt.Fprintf(os.Stdout, "  Expires At:      %s\n", event.ExpiresAt.Format("2006-01-02 15:04:05 MST"))
	}
	if event.RevokedAt != nil {
		fmt.Fprintf(os.Stdout, "  Revoked At:      %s\n", event.RevokedAt.Format("2006-01-02 15:04:05 MST"))
	}
	if event.RenewalStatus != nil {
		fmt.Fprintf(os.Stdout, "  Renewal Status:  %s\n", *event.RenewalStatus)
	}
	if event.RevocationReasonCode != nil {
		fmt.Fprintf(os.Stdout, "  Revocation Code: %s\n", *event.RevocationReasonCode)
	}

	// Agent info
	fmt.Fprintln(os.Stdout, "\n  Agent Info:")
	fmt.Fprintf(os.Stdout, "    Host:          %s\n", event.Agent.Host)
	fmt.Fprintf(os.Stdout, "    Version:       %s\n", event.Agent.Version)
	if event.Agent.Name != nil {
		fmt.Fprintf(os.Stdout, "    Name:          %s\n", *event.Agent.Name)
	}
	if event.Agent.ProviderID != nil {
		fmt.Fprintf(os.Stdout, "    Provider ID:   %s\n", *event.Agent.ProviderID)
	}

	// Attestations
	printV1Attestations(&event.Attestations)

	// Signature info
	fmt.Fprintln(os.Stdout, "\n  Signature Info:")
	fmt.Fprintf(os.Stdout, "    Key ID:        %s\n", v1.Producer.KeyID)
	fmt.Fprintf(os.Stdout, "    Signature:     %s\n", truncateHash(v1.Producer.Signature))
}

func printV0Payload(v0 *models.TransparencyLogV0) {
	fmt.Fprintf(os.Stdout, "  Schema:          V0\n")
	fmt.Fprintf(os.Stdout, "  Log ID:          %s\n", v0.LogID)

	event := v0.Producer.Event
	fmt.Fprintf(os.Stdout, "  Agent FQDN:      %s\n", event.AgentFQDN)
	fmt.Fprintf(os.Stdout, "  Agent ID:        %s\n", event.AgentID)
	fmt.Fprintf(os.Stdout, "  ANS Name:        %s\n", event.ANSName)
	fmt.Fprintf(os.Stdout, "  Event Type:      %s\n", event.EventType)
	fmt.Fprintf(os.Stdout, "  Protocol:        %s\n", event.Protocol)
	fmt.Fprintf(os.Stdout, "  Timestamp:       %s\n", event.Timestamp.Format("2006-01-02 15:04:05 MST"))

	// Metadata if present
	if event.Metadata != nil {
		printEventMetadata(event.Metadata)
	}

	// RA Badge
	badge := event.RABadge
	fmt.Fprintln(os.Stdout, "\n  RA Badge:")
	fmt.Fprintf(os.Stdout, "    RA ID:         %s\n", badge.RAID)
	fmt.Fprintf(os.Stdout, "    Badge Status:  %s\n", badge.BadgeURLStatus)
	fmt.Fprintf(os.Stdout, "    Issued At:     %s\n", badge.IssuedAt.Format("2006-01-02 15:04:05 MST"))
	if badge.ExpiresAt != nil {
		fmt.Fprintf(os.Stdout, "    Expires At:    %s\n", badge.ExpiresAt.Format("2006-01-02 15:04:05 MST"))
	}
	if badge.RenewalStatus != nil {
		fmt.Fprintf(os.Stdout, "    Renewal:       %s\n", *badge.RenewalStatus)
	}
	if badge.RevocationReasonCode != nil {
		fmt.Fprintf(os.Stdout, "    Revocation:    %s\n", *badge.RevocationReasonCode)
	}

	// Attestations
	printV0Attestations(&badge.Attestations)

	// Signature info
	fmt.Fprintln(os.Stdout, "\n  Signature Info:")
	fmt.Fprintf(os.Stdout, "    Key ID:        %s\n", v0.Producer.KeyID)
	fmt.Fprintf(os.Stdout, "    Signature:     %s\n", truncateHash(v0.Producer.Signature))
}

func printEventMetadata(metadata *models.EventMetadata) {
	fmt.Fprintln(os.Stdout, "\n  Metadata:")
	if metadata.Description != nil {
		fmt.Fprintf(os.Stdout, "    Description:   %s\n", *metadata.Description)
	}
	if metadata.Endpoint != nil {
		fmt.Fprintf(os.Stdout, "    Endpoint:      %s\n", *metadata.Endpoint)
	}
	if metadata.AgentCardURL != nil {
		fmt.Fprintf(os.Stdout, "    Agent Card:    %s\n", *metadata.AgentCardURL)
	}
	if metadata.RABadgeURL != nil {
		fmt.Fprintf(os.Stdout, "    RA Badge URL:  %s\n", *metadata.RABadgeURL)
	}
	if len(metadata.ANSCapabilities) > 0 {
		fmt.Fprintf(os.Stdout, "    Capabilities:  %v\n", metadata.ANSCapabilities)
	}
}

func printV1Attestations(att *models.AttestationsV1) {
	fmt.Fprintln(os.Stdout, "\n🔐 Attestations:")

	if att.DomainValidation != nil {
		fmt.Fprintf(os.Stdout, "  Domain Validation: %s\n", *att.DomainValidation)
	}

	if att.IdentityCert != nil {
		fmt.Fprintln(os.Stdout, "  Identity Certificate:")
		fmt.Fprintf(os.Stdout, "    Type:          %s\n", att.IdentityCert.Type)
		fmt.Fprintf(os.Stdout, "    Fingerprint:   %s\n", att.IdentityCert.Fingerprint)
	}

	if att.ServerCert != nil {
		fmt.Fprintln(os.Stdout, "  Server Certificate:")
		fmt.Fprintf(os.Stdout, "    Type:          %s\n", att.ServerCert.Type)
		fmt.Fprintf(os.Stdout, "    Fingerprint:   %s\n", att.ServerCert.Fingerprint)
	}

	if len(att.DNSRecordsProvisioned) > 0 {
		fmt.Fprintln(os.Stdout, "  DNS Records Provisioned:")
		keys := make([]string, 0, len(att.DNSRecordsProvisioned))
		for k := range att.DNSRecordsProvisioned {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(os.Stdout, "    %s: %s\n", k, att.DNSRecordsProvisioned[k])
		}
	}

	if len(att.MetadataHashes) > 0 {
		fmt.Fprintln(os.Stdout, "  Metadata Hashes:")
		keys := make([]string, 0, len(att.MetadataHashes))
		for k := range att.MetadataHashes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i >= maxMetadataHashesDisplay {
				fmt.Fprintf(os.Stdout, "    ... and %d more\n", len(keys)-maxMetadataHashesDisplay)
				break
			}
			fmt.Fprintf(os.Stdout, "    %s: %s\n", k, att.MetadataHashes[k])
		}
	}

	if len(att.ValidIdentityCerts) > 0 {
		fmt.Fprintf(os.Stdout, "  Valid Identity Certs: %d\n", len(att.ValidIdentityCerts))
		for _, cert := range att.ValidIdentityCerts {
			fmt.Fprintf(os.Stdout, "    %s (%s)\n", cert.Fingerprint, cert.Type)
			if cert.NotAfter != nil {
				fmt.Fprintf(os.Stdout, "      Not After: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
			}
		}
	}

	if len(att.ValidServerCerts) > 0 {
		fmt.Fprintf(os.Stdout, "  Valid Server Certs:   %d\n", len(att.ValidServerCerts))
		for _, cert := range att.ValidServerCerts {
			fmt.Fprintf(os.Stdout, "    %s (%s)\n", cert.Fingerprint, cert.Type)
			if cert.NotAfter != nil {
				fmt.Fprintf(os.Stdout, "      Not After: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
			}
		}
	}
}

func printV0Attestations(att *models.AttestationsV0) {
	fmt.Fprintln(os.Stdout, "\n🔐 Attestations:")

	if att.DomainValidation != nil {
		fmt.Fprintf(os.Stdout, "  Domain Validation:     %s\n", *att.DomainValidation)
	}
	if att.DomainValidationStatus != nil {
		fmt.Fprintf(os.Stdout, "  Validation Status:     %s\n", *att.DomainValidationStatus)
	}
	if att.ClientCertFingerprint != nil {
		fmt.Fprintf(os.Stdout, "  Client Cert:           %s\n", *att.ClientCertFingerprint)
	}
	if att.ServerCertFingerprint != nil {
		fmt.Fprintf(os.Stdout, "  Server Cert:           %s\n", *att.ServerCertFingerprint)
	}
	if att.IdentityCertType != nil {
		fmt.Fprintf(os.Stdout, "  Identity Cert Type:    %s\n", *att.IdentityCertType)
	}
	if att.ServerCertType != nil {
		fmt.Fprintf(os.Stdout, "  Server Cert Type:      %s\n", *att.ServerCertType)
	}
	if att.DNSSECStatus != nil {
		fmt.Fprintf(os.Stdout, "  DNSSEC Status:         %s\n", *att.DNSSECStatus)
	}
	if att.CSRSubmission != nil {
		fmt.Fprintf(os.Stdout, "  CSR Submission:        %s\n", *att.CSRSubmission)
	}
	if att.ProtocolExtensionsVerified != nil {
		fmt.Fprintf(os.Stdout, "  Protocol Extensions:   %s\n", *att.ProtocolExtensionsVerified)
	}

	if len(att.DNSRecordsProvisioned) > 0 {
		fmt.Fprintln(os.Stdout, "  DNS Records Provisioned:")
		keys := make([]string, 0, len(att.DNSRecordsProvisioned))
		for k := range att.DNSRecordsProvisioned {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(os.Stdout, "    %s: %s\n", k, att.DNSRecordsProvisioned[k])
		}
	}
}

func printRawPayload(payload map[string]any) {
	// Fallback to raw payload display for unknown schemas
	fmt.Fprintf(os.Stdout, "  Schema:          Unknown\n")

	// Common fields to display
	if ansName, ok := payload["ansName"].(string); ok {
		fmt.Fprintf(os.Stdout, "  ANS Name:        %s\n", ansName)
	}
	if ansID, ok := payload["ansId"].(string); ok {
		fmt.Fprintf(os.Stdout, "  Agent ID:        %s\n", ansID)
	}
	if eventType, ok := payload["eventType"].(string); ok {
		fmt.Fprintf(os.Stdout, "  Event Type:      %s\n", eventType)
	}
	if raID, ok := payload["raId"].(string); ok {
		fmt.Fprintf(os.Stdout, "  RA ID:           %s\n", raID)
	}
	if timestamp, ok := payload["timestamp"].(string); ok {
		fmt.Fprintf(os.Stdout, "  Timestamp:       %s\n", timestamp)
	}
	if issuedAt, ok := payload["issuedAt"].(string); ok {
		fmt.Fprintf(os.Stdout, "  Issued At:       %s\n", issuedAt)
	}
	if expiresAt, ok := payload["expiresAt"].(string); ok {
		fmt.Fprintf(os.Stdout, "  Expires At:      %s\n", expiresAt)
	}

	// Agent info if present
	if agent, agentOk := payload["agent"].(map[string]any); agentOk {
		printAgentFromPayload(agent)
	}

	// Attestations if present
	if attestations, attOk := payload["attestations"].(map[string]any); attOk {
		printAttestationsFromPayload(attestations)
	}
}

func printAgentFromPayload(agent map[string]any) {
	fmt.Fprintln(os.Stdout, "\n  Agent Info:")
	if host, ok := agent["host"].(string); ok {
		fmt.Fprintf(os.Stdout, "    Host:          %s\n", host)
	}
	if name, ok := agent["name"].(string); ok {
		fmt.Fprintf(os.Stdout, "    Name:          %s\n", name)
	}
	if version, ok := agent["version"].(string); ok {
		fmt.Fprintf(os.Stdout, "    Version:       %s\n", version)
	}
	if providerID, ok := agent["providerId"].(string); ok {
		fmt.Fprintf(os.Stdout, "    Provider ID:   %s\n", providerID)
	}
}

func printAttestationsFromPayload(att map[string]any) {
	fmt.Fprintln(os.Stdout, "\n🔐 Attestations:")

	if domainValidation, ok := att["domainValidation"].(string); ok {
		fmt.Fprintf(os.Stdout, "  Domain Validation: %s\n", domainValidation)
	}

	if identityCert, certOk := att["identityCert"].(map[string]any); certOk {
		printCertFromPayload("Identity Certificate", identityCert)
	}

	if serverCert, certOk := att["serverCert"].(map[string]any); certOk {
		printCertFromPayload("Server Certificate", serverCert)
	}

	if dnsRecords, dnsOk := att["dnsRecordsProvisioned"].(map[string]any); dnsOk && len(dnsRecords) > 0 {
		fmt.Fprintln(os.Stdout, "  DNS Records Provisioned:")
		keys := make([]string, 0, len(dnsRecords))
		for k := range dnsRecords {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(os.Stdout, "    %s: %v\n", k, dnsRecords[k])
		}
	}
}

func printCertFromPayload(certName string, cert map[string]any) {
	fmt.Fprintf(os.Stdout, "  %s:\n", certName)
	if fingerprint, ok := cert["fingerprint"].(string); ok {
		fmt.Fprintf(os.Stdout, "    Fingerprint:   %s\n", fingerprint)
	}
	if certType, ok := cert["type"].(string); ok {
		fmt.Fprintf(os.Stdout, "    Type:          %s\n", certType)
	}
}

func printAuditTrail(audit *models.TransparencyLogAudit) {
	fmt.Fprintln(os.Stdout, "📋 Audit Trail")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthWide))
	fmt.Fprintf(os.Stdout, "Total Records: %d\n\n", len(audit.Records))

	if len(audit.Records) == 0 {
		fmt.Fprintln(os.Stdout, "No audit entries found")
		return
	}

	for i, entry := range audit.Records {
		printAuditEntry(i+1, &entry)
	}
}

func printAuditEntry(index int, entry *models.TransparencyLog) {
	fmt.Fprintf(os.Stdout, "[%d] ", index)
	printAuditEntryPayload(entry)

	if entry.Status != "" {
		fmt.Fprintf(os.Stdout, " (Status: %s)", entry.Status)
	}
	fmt.Fprintln(os.Stdout)

	printAuditEntryProof(entry.MerkleProof)
	fmt.Fprintln(os.Stdout)
}

func printAuditEntryPayload(entry *models.TransparencyLog) {
	switch {
	case entry.IsV1() && entry.GetV1Payload() != nil:
		v1 := entry.GetV1Payload()
		eventType := string(v1.Producer.Event.EventType)
		timestamp := v1.Producer.Event.Timestamp.Format("2006-01-02 15:04:05")
		fmt.Fprintf(os.Stdout, "V1: %s - %s", eventType, timestamp)
	case entry.IsV0() && entry.GetV0Payload() != nil:
		v0 := entry.GetV0Payload()
		eventType := string(v0.Producer.Event.EventType)
		timestamp := v0.Producer.Event.Timestamp.Format("2006-01-02 15:04:05")
		fmt.Fprintf(os.Stdout, "V0: %s - %s", eventType, timestamp)
	default:
		printAuditEntryRawPayload(entry.Payload)
	}
}

func printAuditEntryRawPayload(payload map[string]any) {
	if payload == nil {
		return
	}
	if et, ok := payload["eventType"].(string); ok {
		fmt.Fprintf(os.Stdout, "%s", et)
	}
	if ts, ok := payload["timestamp"].(string); ok {
		fmt.Fprintf(os.Stdout, " - %s", ts)
	}
}

func printAuditEntryProof(proof *models.MerkleProof) {
	if proof == nil {
		return
	}
	if proof.LeafIndex != nil {
		fmt.Fprintf(os.Stdout, "    Leaf Index: %d\n", *proof.LeafIndex)
	}
	if proof.TreeSize > 0 {
		fmt.Fprintf(os.Stdout, "    Tree Size: %d\n", proof.TreeSize)
	}
}

func printCheckpoint(checkpoint *models.CheckpointResponse) {
	fmt.Fprintln(os.Stdout, "🔖 Log Checkpoint (JSON view, as reported by the log)")
	fmt.Fprintln(os.Stdout, strings.Repeat("=", SeparatorWidthWide))
	fmt.Fprintf(os.Stdout, "Log Size:         %d\n", checkpoint.LogSize)
	fmt.Fprintf(os.Stdout, "Root Hash:        %s\n", truncateHash(checkpoint.RootHash))
	if checkpoint.TreeHeight > 0 {
		fmt.Fprintf(os.Stdout, "Tree Height:      %d\n", checkpoint.TreeHeight)
	}
	if checkpoint.OriginName != "" {
		fmt.Fprintf(os.Stdout, "Origin:           %s\n", checkpoint.OriginName)
	}
	if checkpoint.CheckpointFormat != "" {
		fmt.Fprintf(os.Stdout, "Format:           %s\n", checkpoint.CheckpointFormat)
	}

	if len(checkpoint.Signatures) > 0 {
		fmt.Fprintf(os.Stdout, "\nSignatures:       %d (validity as reported by the log, not checked here)\n", len(checkpoint.Signatures))
		for i, sig := range checkpoint.Signatures {
			fmt.Fprintf(os.Stdout, "  [%d] %s - %s (Valid: %v)\n",
				i+1, sig.SignerName, sig.Algorithm, sig.Valid)
		}
	}
}

func truncateHash(hash string) string {
	if len(hash) > MaxHashDisplayLength {
		return hash[:32] + "..." + hash[len(hash)-16:]
	}
	return hash
}
