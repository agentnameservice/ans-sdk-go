package cmd

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
)

// captureStdout runs fn and returns what was written to os.Stdout.
// The functions under test write directly to os.Stdout via fmt.Print, so
// reassigning os.Stdout is the only way to capture their output in tests.
func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w //nolint:reassign // required to capture stdout from functions that use fmt.Print

	fn()

	w.Close()
	os.Stdout = old //nolint:reassign // restore original stdout

	buf := make([]byte, 16384)
	n, _ := r.Read(buf)
	return string(buf[:n])
}

func TestBuildBadgeCmd(t *testing.T) {
	tests := []struct {
		name      string
		checkUse  string
		flagNames []string
	}{
		{
			name:      "command properties and flags",
			checkUse:  "badge <agentId>",
			flagNames: []string{"audit", "checkpoint", "transparency-url"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := buildBadgeCmd()
			if cmd == nil {
				t.Fatal("buildBadgeCmd() returned nil")
			}
			if cmd.Use != tt.checkUse {
				t.Errorf("Use = %q, want %q", cmd.Use, tt.checkUse)
			}
			for _, flagName := range tt.flagNames {
				if cmd.Flags().Lookup(flagName) == nil {
					t.Errorf("missing flag %q", flagName)
				}
			}
			// Verify the transparency-url flag has a default
			urlFlag := cmd.Flags().Lookup("transparency-url")
			if urlFlag == nil {
				t.Error("Flag 'transparency-url' not found")
			}
		})
	}
}

func TestTruncateHash(t *testing.T) {
	tests := []struct {
		name string
		hash string
		want string
	}{
		{
			name: "short hash unchanged",
			hash: "abcdef",
			want: "abcdef",
		},
		{
			name: "exact max length unchanged",
			hash: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
			want: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl",
		},
		{
			name: "longer than max is truncated",
			hash: "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnop",
			want: "abcdefghijklmnopqrstuvwxyzabcdef...abcdefghijklmnop",
		},
		{
			name: "empty string unchanged",
			hash: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateHash(tt.hash)
			if got != tt.want {
				t.Errorf("truncateHash(%q) = %q, want %q", tt.hash, got, tt.want)
			}
		})
	}
}

func TestPrintTransparencyLog(t *testing.T) {
	v1 := &models.TransparencyLogV1{
		LogID: "test-log-id",
		Producer: models.ProducerV1{
			Event: models.EventV1{
				ANSID:     "test-ans-id",
				ANSName:   "ans://v1.0.0.example.com",
				EventType: models.EventTypeV1AgentRegistered,
			},
		},
	}

	leafIndex := int64(42)

	tests := []struct {
		name     string
		logEntry *models.TransparencyLog
		checks   []string
	}{
		{
			name: "full log entry with V1 payload",
			logEntry: &models.TransparencyLog{
				Status:        "ACTIVE",
				SchemaVersion: string(models.SchemaVersionV1),
				ParsedPayload: v1,
				Payload:       map[string]any{"logId": "test"},
				Signature:     "abc123def456",
				MerkleProof: &models.MerkleProof{
					TreeVersion: 1,
					TreeSize:    100,
					LeafIndex:   &leafIndex,
				},
			},
			checks: []string{"Transparency Log Entry", "ACTIVE", "V1"},
		},
		{
			name: "minimal log entry defaults to V0",
			logEntry: &models.TransparencyLog{
				Payload: map[string]any{"logId": "test"},
			},
			checks: []string{"V0"},
		},
		{
			name:     "minimal log entry without panic",
			logEntry: &models.TransparencyLog{},
			checks:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printTransparencyLog(tt.logEntry)
			})
			for _, check := range tt.checks {
				if !strings.Contains(output, check) {
					t.Errorf("printTransparencyLog() output missing %q", check)
				}
			}
		})
	}
}

func TestPrintCheckpoint(t *testing.T) {
	tests := []struct {
		name       string
		checkpoint *models.CheckpointResponse
		checks     []string
	}{
		{
			name: "checkpoint with multiple signatures",
			checkpoint: &models.CheckpointResponse{
				LogSize:          1000,
				RootHash:         "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
				TreeHeight:       10,
				OriginName:       "test-origin",
				CheckpointFormat: "c2sp-tlog/v1",
				Signatures: []models.CheckpointSignature{
					{
						SignerName: "test-signer",
						Algorithm:  "ES256",
						Valid:      true,
					},
					{
						SignerName: "test-signer-2",
						Algorithm:  "RSA",
						Valid:      false,
					},
				},
			},
			checks: []string{"test-signer-2"},
		},
		{
			name: "checkpoint with single signature",
			checkpoint: &models.CheckpointResponse{
				LogSize:          1000,
				RootHash:         "hash123",
				TreeHeight:       10,
				OriginName:       "test-origin",
				CheckpointFormat: "v1",
				Signatures: []models.CheckpointSignature{
					{
						SignerName: "signer1",
						Algorithm:  "ed25519",
						Valid:      true,
					},
				},
			},
			checks: []string{"signer1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printCheckpoint(tt.checkpoint)
			})
			for _, check := range tt.checks {
				if !strings.Contains(output, check) {
					t.Errorf("printCheckpoint() output missing %q", check)
				}
			}
		})
	}
}

func TestPrintAuditTrail(t *testing.T) {
	v1 := &models.TransparencyLogV1{
		Producer: models.ProducerV1{
			Event: models.EventV1{
				EventType: models.EventTypeV1AgentRegistered,
				Timestamp: time.Now(),
			},
		},
	}

	leafIndex := int64(1)

	tests := []struct {
		name   string
		audit  *models.TransparencyLogAudit
		checks []string
	}{
		{
			name: "empty audit",
			audit: &models.TransparencyLogAudit{
				Records: []models.TransparencyLog{},
			},
			checks: []string{"No audit entries"},
		},
		{
			name: "audit with records",
			audit: &models.TransparencyLogAudit{
				Records: []models.TransparencyLog{
					{
						Status:        "ACTIVE",
						SchemaVersion: string(models.SchemaVersionV1),
						ParsedPayload: v1,
						MerkleProof: &models.MerkleProof{
							LeafIndex: &leafIndex,
							TreeSize:  10,
						},
					},
				},
			},
			checks: []string{"Audit Trail", "Total Records: 1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printAuditTrail(tt.audit)
			})
			for _, check := range tt.checks {
				if !strings.Contains(output, check) {
					t.Errorf("printAuditTrail() output missing %q", check)
				}
			}
		})
	}
}

func TestPrintV1Payload(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)
	revokedAt := now.Add(12 * time.Hour)
	renewalStatus := "PENDING"
	revocationCode := models.RevocationReasonKeyCompromise
	agentName := "Test Agent"
	providerID := "provider-123"
	domainVal := "ACME-DNS-01"

	tests := []struct {
		name   string
		v1     *models.TransparencyLogV1
		checks []string
	}{
		{
			name: "full V1 payload with all fields",
			v1: &models.TransparencyLogV1{
				LogID: "test-log-id",
				Producer: models.ProducerV1{
					KeyID:     "key-123",
					Signature: "sig-456",
					Event: models.EventV1{
						ANSID:                "test-ans-id",
						ANSName:              "ans://v1.0.0.example.com",
						EventType:            models.EventTypeV1AgentRegistered,
						RAID:                 "ra-123",
						Timestamp:            now,
						IssuedAt:             now,
						ExpiresAt:            &expiresAt,
						RevokedAt:            &revokedAt,
						RenewalStatus:        &renewalStatus,
						RevocationReasonCode: &revocationCode,
						Agent: models.AgentV1{
							Host:       "example.com",
							Version:    "v1.0.0",
							Name:       &agentName,
							ProviderID: &providerID,
						},
						Attestations: models.AttestationsV1{
							DomainValidation: &domainVal,
							IdentityCert: &models.CertificateV1{
								Type:        "X509",
								Fingerprint: "SHA256:abc",
							},
							ServerCert: &models.CertificateV1{
								Type:        "X509",
								Fingerprint: "SHA256:def",
							},
							DNSRecordsProvisioned: map[string]string{
								"_ans-badge": "v=ans-badge1",
							},
							MetadataHashes: map[string]string{
								"sha256": "deadbeef1234",
							},
							ValidIdentityCerts: []models.CertificateV1Extended{
								{
									CertificateV1: models.CertificateV1{
										Fingerprint: "SHA256:idcert1",
										Type:        models.CertTypeX509OVClient,
									},
									NotAfter: &expiresAt,
								},
							},
							ValidServerCerts: []models.CertificateV1Extended{
								{
									CertificateV1: models.CertificateV1{
										Fingerprint: "SHA256:srvcert1",
										Type:        models.CertTypeX509DVServer,
									},
								},
							},
						},
					},
				},
			},
			checks: []string{
				"V1", "test-log-id", "test-ans-id", "AGENT_REGISTERED",
				"Expires At", "Revoked At", "Renewal Status", "Revocation Code",
				"Agent Info", "example.com", "v1.0.0", "Test Agent", "provider-123",
				"Attestations", "ACME-DNS-01", "Identity Certificate", "Server Certificate",
				"DNS Records", "Signature Info", "key-123",
				"Metadata Hashes", "deadbeef1234",
				"Valid Identity Certs", "SHA256:idcert1", "Not After",
				"Valid Server Certs", "SHA256:srvcert1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printV1Payload(tt.v1)
			})
			for _, check := range tt.checks {
				if !strings.Contains(output, check) {
					t.Errorf("printV1Payload() output missing %q", check)
				}
			}
		})
	}
}

func TestPrintV0Payload(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)
	renewalStatus := "PENDING"
	revocationCode := models.RevocationReasonKeyCompromise
	description := "Test agent"
	endpoint := "https://example.com"
	agentCardURL := "https://example.com/card"
	raBadgeURL := "https://example.com/badge"
	domainVal := "ACME-DNS-01"
	domainValStatus := "VERIFIED"
	clientCertFP := "SHA256:client"
	serverCertFP := "SHA256:server"
	identityCertType := "X509-OV"
	serverCertType := "X509-DV"
	dnssecStatus := "ENABLED"
	csrSubmission := "APPROVED"
	protocolExtensions := "VERIFIED"

	tests := []struct {
		name   string
		v0     *models.TransparencyLogV0
		checks []string
	}{
		{
			name: "full V0 payload with all fields",
			v0: &models.TransparencyLogV0{
				LogID: "test-log-id",
				Producer: models.ProducerV0{
					KeyID:     "key-123",
					Signature: "sig-456",
					Event: models.EventV0{
						AgentFQDN: "example.com",
						AgentID:   "agent-123",
						ANSName:   "ans://example.com",
						EventType: models.EventTypeV0AgentActive,
						Protocol:  "ANS/1.0",
						Timestamp: now,
						Metadata: &models.EventMetadata{
							Description:     &description,
							Endpoint:        &endpoint,
							AgentCardURL:    &agentCardURL,
							RABadgeURL:      &raBadgeURL,
							ANSCapabilities: []string{"BASIC", "ADVANCED"},
						},
						RABadge: models.RABadge{
							RAID:                 "ra-123",
							BadgeURLStatus:       "ACTIVE",
							IssuedAt:             now,
							ExpiresAt:            &expiresAt,
							RenewalStatus:        &renewalStatus,
							RevocationReasonCode: &revocationCode,
							Attestations: models.AttestationsV0{
								DomainValidation:           &domainVal,
								DomainValidationStatus:     &domainValStatus,
								ClientCertFingerprint:      &clientCertFP,
								ServerCertFingerprint:      &serverCertFP,
								IdentityCertType:           &identityCertType,
								ServerCertType:             &serverCertType,
								DNSSECStatus:               &dnssecStatus,
								CSRSubmission:              &csrSubmission,
								ProtocolExtensionsVerified: &protocolExtensions,
								DNSRecordsProvisioned: map[string]string{
									"_ra-badge": "v=ra-badge1",
								},
							},
						},
					},
				},
			},
			checks: []string{
				"V0", "test-log-id", "example.com", "agent-123", "AGENT_ACTIVE",
				"ANS/1.0", "Metadata", "Test agent", "https://example.com",
				"Agent Card", "RA Badge URL", "Capabilities",
				"RA Badge", "ra-123", "ACTIVE",
				"Attestations", "ACME-DNS-01", "VERIFIED",
				"Client Cert", "Server Cert", "Identity Cert Type",
				"Server Cert Type", "DNSSEC Status", "CSR Submission",
				"Protocol Extensions", "DNS Records",
				"Signature Info", "key-123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printV0Payload(tt.v0)
			})
			for _, check := range tt.checks {
				if !strings.Contains(output, check) {
					t.Errorf("printV0Payload() output missing %q", check)
				}
			}
		})
	}
}

func TestPrintRawPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
		checks  []string
	}{
		{
			name:    "nil payload",
			payload: nil,
			checks:  []string{},
		},
		{
			name: "full payload with all fields",
			payload: map[string]any{
				"ansName":   "ans://v1.0.0.example.com",
				"ansId":     "test-id",
				"eventType": "AGENT_REGISTERED",
				"raId":      "ra-123",
				"timestamp": "2024-01-01T00:00:00Z",
				"issuedAt":  "2024-01-01T00:00:00Z",
				"expiresAt": "2025-01-01T00:00:00Z",
				"agent": map[string]any{
					"host":       "example.com",
					"name":       "Test Agent",
					"version":    "v1.0.0",
					"providerId": "provider-123",
				},
				"attestations": map[string]any{
					"domainValidation": "ACME-DNS-01",
					"identityCert": map[string]any{
						"fingerprint": "SHA256:abc",
						"type":        "X509",
					},
					"serverCert": map[string]any{
						"fingerprint": "SHA256:def",
						"type":        "X509",
					},
					"dnsRecordsProvisioned": map[string]any{
						"_ans-badge": "v=ans-badge1",
					},
				},
			},
			checks: []string{
				"Unknown", "ans://v1.0.0.example.com", "test-id",
				"AGENT_REGISTERED", "ra-123", "2024-01-01T00:00:00Z",
				"Agent Info", "example.com", "Test Agent", "v1.0.0", "provider-123",
				"Attestations", "ACME-DNS-01", "Identity Certificate", "Server Certificate",
				"DNS Records",
			},
		},
		{
			name: "minimal payload",
			payload: map[string]any{
				"ansName": "test.ans.example.com",
			},
			checks: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printRawPayload(tt.payload)
			})
			for _, check := range tt.checks {
				if !strings.Contains(output, check) {
					t.Errorf("printRawPayload() output missing %q", check)
				}
			}
		})
	}
}

func TestPrintPayload(t *testing.T) {
	tests := []struct {
		name     string
		logEntry *models.TransparencyLog
		expect   string
	}{
		{
			name: "V1 payload",
			logEntry: &models.TransparencyLog{
				SchemaVersion: string(models.SchemaVersionV1),
				ParsedPayload: &models.TransparencyLogV1{
					LogID: "test-log-id",
					Producer: models.ProducerV1{
						Event: models.EventV1{
							ANSID:     "test-ans-id",
							ANSName:   "ans://v1.0.0.example.com",
							EventType: models.EventTypeV1AgentRegistered,
						},
					},
				},
			},
			expect: "V1",
		},
		{
			name: "V0 payload",
			logEntry: &models.TransparencyLog{
				SchemaVersion: string(models.SchemaVersionV0),
				ParsedPayload: &models.TransparencyLogV0{
					LogID: "test-log-id",
					Producer: models.ProducerV0{
						Event: models.EventV0{
							AgentFQDN: "example.com",
							AgentID:   "test-agent-id",
							ANSName:   "ans://example.com",
						},
					},
				},
			},
			expect: "V0",
		},
		{
			name: "raw payload for unknown schema",
			logEntry: &models.TransparencyLog{
				SchemaVersion: "UNKNOWN",
				Payload:       map[string]any{"ansName": "test", "eventType": "AGENT_REGISTERED"},
			},
			expect: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printPayload(tt.logEntry)
			})

			if !strings.Contains(output, tt.expect) {
				t.Errorf("printPayload() output does not contain %q: %s", tt.expect, output)
			}
		})
	}
}

func TestPrintAuditEntryPayload(t *testing.T) {
	tests := []struct {
		name   string
		entry  *models.TransparencyLog
		expect string
	}{
		{
			name: "V1 entry",
			entry: &models.TransparencyLog{
				SchemaVersion: string(models.SchemaVersionV1),
				ParsedPayload: &models.TransparencyLogV1{
					Producer: models.ProducerV1{
						Event: models.EventV1{
							EventType: models.EventTypeV1AgentRegistered,
						},
					},
				},
			},
			expect: "V1:",
		},
		{
			name: "V0 entry",
			entry: &models.TransparencyLog{
				SchemaVersion: string(models.SchemaVersionV0),
				ParsedPayload: &models.TransparencyLogV0{
					Producer: models.ProducerV0{
						Event: models.EventV0{
							EventType: models.EventTypeV0AgentActive,
						},
					},
				},
			},
			expect: "V0:",
		},
		{
			name: "raw entry",
			entry: &models.TransparencyLog{
				Payload: map[string]any{
					"eventType": "TEST_EVENT",
					"timestamp": "2024-01-01T00:00:00Z",
				},
			},
			expect: "TEST_EVENT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printAuditEntryPayload(tt.entry)
			})

			if !strings.Contains(output, tt.expect) {
				t.Errorf("printAuditEntryPayload() output does not contain %q: %s", tt.expect, output)
			}
		})
	}
}

func TestPrintAuditEntryRawPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
	}{
		{
			name:    "nil payload does not panic",
			payload: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			captureStdout(func() {
				printAuditEntryRawPayload(tt.payload)
			})
		})
	}
}

func TestPrintMerkleProof(t *testing.T) {
	leafIndex := int64(42)

	tests := []struct {
		name   string
		proof  *models.MerkleProof
		checks []string
	}{
		{
			name: "full proof with all fields",
			proof: &models.MerkleProof{
				TreeVersion:   1,
				TreeSize:      100,
				LeafIndex:     &leafIndex,
				LeafHash:      "abc123",
				RootHash:      "def456",
				Path:          []string{"path1", "path2"},
				RootSignature: "sig789",
			},
			checks: []string{"Merkle Proof", "42"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printMerkleProof(tt.proof)
			})
			for _, check := range tt.checks {
				if !strings.Contains(output, check) {
					t.Errorf("printMerkleProof() output missing %q", check)
				}
			}
		})
	}
}

func TestPrintAuditEntryProof(t *testing.T) {
	leafIndex := int64(5)

	tests := []struct {
		name   string
		proof  *models.MerkleProof
		expect string
	}{
		{
			name:   "nil proof does not panic",
			proof:  nil,
			expect: "",
		},
		{
			name: "proof with data",
			proof: &models.MerkleProof{
				LeafIndex: &leafIndex,
				TreeSize:  10,
			},
			expect: "Leaf Index",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(func() {
				printAuditEntryProof(tt.proof)
			})

			if tt.expect != "" && !strings.Contains(output, tt.expect) {
				t.Errorf("printAuditEntryProof() output missing %q", tt.expect)
			}
		})
	}
}
