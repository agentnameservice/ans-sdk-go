//nolint:sloglint // Examples use global logger for simplicity
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/godaddy/ans-sdk-go/ans"
	"github.com/godaddy/ans-sdk-go/models"
)

const defaultAuditLimit = 5

// ExampleTransparencySchemas demonstrates how to work with schema-aware transparency logs.
func ExampleTransparencySchemas() {
	// Create transparency client
	client, err := ans.NewTransparencyClient(
		ans.WithBaseURL("https://transparency.ans.godaddy.com"),
		ans.WithJWT("your-jwt-token"),
	)
	if err != nil {
		slog.Error("failed to create client", "error", err)
		return
	}

	ctx := context.Background()

	// Get transparency log for an agent
	agentID := "6bf2b7a9-1383-4e33-a945-845f34af7526"
	logEntry, err := client.GetAgentTransparencyLog(ctx, agentID)
	if err != nil {
		slog.Error("failed to get transparency log", "error", err)
		return
	}

	// The schema version is automatically detected from the response header
	slog.Info("transparency log retrieved",
		"schemaVersion", logEntry.SchemaVersion,
		"status", logEntry.Status)

	// Access the strongly-typed payload based on schema version
	printLogEntryDetails(logEntry)

	// Get audit trail with schema parsing
	auditParams := &models.AgentAuditParams{
		Limit:  defaultAuditLimit,
		Offset: 0,
	}
	audit, err := client.GetAgentTransparencyLogAudit(ctx, agentID, auditParams)
	if err != nil {
		slog.Warn("failed to get audit trail", "error", err)
		return
	}

	printAuditRecords(audit)
}

func printLogEntryDetails(logEntry *models.TransparencyLog) {
	if logEntry.IsV1() {
		printV1Details(logEntry.GetV1Payload())
		return
	}

	if logEntry.IsV0() {
		printV0Details(logEntry.GetV0Payload())
		return
	}

	// Fallback to raw payload if schema is unknown
	slog.Info("unknown schema - using raw payload", "payload", logEntry.Payload)
}

func printV1Details(v1Payload *models.TransparencyLogV1) {
	if v1Payload == nil {
		return
	}

	slog.Info("V1 schema detected",
		"logID", v1Payload.LogID,
		"eventType", v1Payload.Producer.Event.EventType,
		"ansID", v1Payload.Producer.Event.ANSID,
		"ansName", v1Payload.Producer.Event.ANSName,
		"raID", v1Payload.Producer.Event.RAID)

	// Access agent information
	agent := v1Payload.Producer.Event.Agent
	slog.Info("agent info",
		"host", agent.Host,
		"version", agent.Version)

	// Access attestations
	printV1Attestations(&v1Payload.Producer.Event.Attestations)
}

func printV1Attestations(att *models.AttestationsV1) {
	if att.IdentityCert != nil {
		slog.Info("identity cert",
			"type", att.IdentityCert.Type,
			"fingerprint", att.IdentityCert.Fingerprint)
	}
	if att.ServerCert != nil {
		slog.Info("server cert",
			"type", att.ServerCert.Type,
			"fingerprint", att.ServerCert.Fingerprint)
	}
	if len(att.MetadataHashes) > 0 {
		slog.Info("metadata hashes", "count", len(att.MetadataHashes))
	}
	if len(att.ValidIdentityCerts) > 0 {
		slog.Info("valid identity certs", "count", len(att.ValidIdentityCerts))
	}
	if len(att.ValidServerCerts) > 0 {
		slog.Info("valid server certs", "count", len(att.ValidServerCerts))
	}
}

func printV0Details(v0Payload *models.TransparencyLogV0) {
	if v0Payload == nil {
		return
	}

	slog.Info("V0 schema detected",
		"logID", v0Payload.LogID,
		"eventType", v0Payload.Producer.Event.EventType,
		"agentFQDN", v0Payload.Producer.Event.AgentFQDN,
		"agentID", v0Payload.Producer.Event.AgentID,
		"ansName", v0Payload.Producer.Event.ANSName,
		"protocol", v0Payload.Producer.Event.Protocol)

	// Access RA Badge
	badge := v0Payload.Producer.Event.RABadge
	slog.Info("RA badge",
		"raID", badge.RAID,
		"badgeURLStatus", badge.BadgeURLStatus)

	// Access attestations
	printV0Attestations(&badge.Attestations)
}

func printV0Attestations(att *models.AttestationsV0) {
	if att.ClientCertFingerprint != nil {
		slog.Info("client cert fingerprint", "value", *att.ClientCertFingerprint)
	}
	if att.ServerCertFingerprint != nil {
		slog.Info("server cert fingerprint", "value", *att.ServerCertFingerprint)
	}
}

func printAuditRecords(audit *models.TransparencyLogAudit) {
	slog.Info("audit trail retrieved", "recordCount", len(audit.Records))

	for i, record := range audit.Records {
		printAuditRecord(i, &record)
	}
}

func printAuditRecord(index int, record *models.TransparencyLog) {
	recordNum := index + 1

	if record.IsV1() {
		if v1 := record.GetV1Payload(); v1 != nil {
			slog.Info("audit record",
				"record", recordNum,
				"schema", "V1",
				"eventType", v1.Producer.Event.EventType,
				"timestamp", v1.Producer.Event.Timestamp)
		}
		return
	}

	if record.IsV0() {
		if v0 := record.GetV0Payload(); v0 != nil {
			slog.Info("audit record",
				"record", recordNum,
				"schema", "V0",
				"eventType", v0.Producer.Event.EventType,
				"timestamp", v0.Producer.Event.Timestamp)
		}
	}
}

// ExampleSchemaValidation demonstrates how to validate and work with specific schema versions.
func ExampleSchemaValidation() {
	// You can also work directly with the schema types if you're creating data

	// Create a V1 event
	v1Event := createV1Event()
	slog.Info("created V1 event", "logID", v1Event.LogID, "eventType", v1Event.Producer.Event.EventType)

	// Create a V0 event
	v0Event := createV0Event()
	slog.Info("created V0 event", "logID", v0Event.LogID, "eventType", v0Event.Producer.Event.EventType)

	// Suppress unused warnings
	_ = v1Event
	_ = v0Event
}

func createV1Event() *models.TransparencyLogV1 {
	return &models.TransparencyLogV1{
		LogID: "01936db8-b65e-7e2f-b5e4-d0b5c1234567",
		Producer: models.ProducerV1{
			Event: models.EventV1{
				ANSID:     "6bf2b7a9-1383-4e33-a945-845f34af7526",
				ANSName:   "ans://v1.0.0.agent-0.ai.domain.com",
				EventType: models.EventTypeV1AgentRegistered,
				Agent: models.AgentV1{
					Host:    "agent-0.ai.domain.com",
					Version: "v1.0.0",
				},
				Attestations: models.AttestationsV1{
					DomainValidation: stringPtr("ACME-DNS-01"),
					IdentityCert: &models.CertificateV1{
						Fingerprint: "SHA256:abcdef1234567890",
						Type:        models.CertTypeX509OVClient,
					},
				},
				RAID: "api.godaddy.com",
			},
			KeyID:     "arn:aws:kms:us-east-1:123456789012:key/stub-key",
			Signature: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
		},
	}
}

func createV0Event() *models.TransparencyLogV0 {
	return &models.TransparencyLogV0{
		LogID: "01936db8-b65e-7e2f-b5e4-d0b5c1234568",
		Producer: models.ProducerV0{
			Event: models.EventV0{
				AgentFQDN: "agent-0.capability.provider.domain.com",
				AgentID:   "6bf2b7a9-1383-4e33-a945-845f34af7527",
				ANSName:   "mcp://agent-0.capability.provider.v1.0.0.domain.com",
				EventType: models.EventTypeV0AgentActive,
				Protocol:  "mcp",
				RABadge: models.RABadge{
					BadgeURLStatus: "verified_link",
					RAID:           "api.godaddy.com",
					Attestations: models.AttestationsV0{
						DomainValidation:      stringPtr("acme-dns-01"),
						ClientCertFingerprint: stringPtr("SHA256:fedcba9876543210"),
					},
				},
			},
			KeyID:     "ra1-prod-key-2024-01",
			Signature: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
		},
	}
}

// Helper function to get string pointer.
func stringPtr(s string) *string {
	return &s
}

// demoV2Attestations loads the v2 badge fixture and walks the new plural-cert
// and DNS-record attestation surfaces along with the matcher helpers.
func demoV2Attestations() {
	fixturePath, err := resolveBadgeV2Fixture()
	if err != nil {
		slog.Error("failed to resolve badge fixture path", "error", err)
		return
	}

	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		slog.Error("failed to read badge fixture", "path", fixturePath, "error", err)
		return
	}

	var badge models.Badge
	if err := json.Unmarshal(raw, &badge); err != nil {
		slog.Error("failed to unmarshal badge fixture", "error", err)
		return
	}

	slog.Info("v2 badge loaded",
		"status", badge.Status,
		"ansName", badge.AgentName(),
		"eventType", badge.EventType())

	for i, fp := range badge.ServerCertFingerprints() {
		slog.Info("server cert fingerprint", "index", i, "fingerprint", fp)
	}
	for i, fp := range badge.IdentityCertFingerprints() {
		slog.Info("identity cert fingerprint", "index", i, "fingerprint", fp)
	}

	for _, rec := range badge.Payload.Producer.Event.Attestations.DNSRecordsProvisioned {
		slog.Info("dns record provisioned",
			"name", rec.Name,
			"data", rec.Data,
			"type", rec.Type)
	}

	serverFps := badge.ServerCertFingerprints()
	if len(serverFps) > 0 {
		slog.Info("matches server cert (valid)",
			"fingerprint", serverFps[0],
			"matches", badge.MatchesServerCert(serverFps[0]))
	}
	const bogusFingerprint = "sha256:0000"
	slog.Info("matches server cert (bogus)",
		"fingerprint", bogusFingerprint,
		"matches", badge.MatchesServerCert(bogusFingerprint))

	if hashes := badge.Payload.Producer.Event.Attestations.MetadataHashes; len(hashes) > 0 {
		slog.Info("metadata hashes", "count", len(hashes))
	}
}

// resolveBadgeV2Fixture locates models/testdata/badge-v2.json relative to this
// source file so the demo runs regardless of the caller's working directory.
// The BADGE_V2_FIXTURE env var overrides for ad-hoc runs.
func resolveBadgeV2Fixture() (string, error) {
	if override := os.Getenv("BADGE_V2_FIXTURE"); override != "" {
		return override, nil
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", os.ErrNotExist
	}
	exampleDir := filepath.Dir(thisFile)
	return filepath.Join(exampleDir, "..", "models", "testdata", "badge-v2.json"), nil
}

func main() {
	// Configure structured logging
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(handler))

	// Run the examples
	ExampleTransparencySchemas()
	demoV2Attestations()
}
