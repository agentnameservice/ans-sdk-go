package models

import (
	"encoding/json"
	"testing"
)

func TestBadgeStatus(t *testing.T) {
	tests := []struct {
		name           string
		status         BadgeStatus
		isValidForConn bool
		isActive       bool
		shouldReject   bool
	}{
		{
			name:           "active status",
			status:         BadgeStatusActive,
			isValidForConn: true,
			isActive:       true,
			shouldReject:   false,
		},
		{
			name:           "warning status",
			status:         BadgeStatusWarning,
			isValidForConn: true,
			isActive:       true,
			shouldReject:   false,
		},
		{
			name:           "deprecated status",
			status:         BadgeStatusDeprecated,
			isValidForConn: true,
			isActive:       false,
			shouldReject:   false,
		},
		{
			name:           "expired status",
			status:         BadgeStatusExpired,
			isValidForConn: false,
			isActive:       false,
			shouldReject:   true,
		},
		{
			name:           "revoked status",
			status:         BadgeStatusRevoked,
			isValidForConn: false,
			isActive:       false,
			shouldReject:   true,
		},
		{
			name:           "unknown status",
			status:         BadgeStatus("UNKNOWN"),
			isValidForConn: false,
			isActive:       false,
			shouldReject:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.IsValidForConnection(); got != tt.isValidForConn {
				t.Errorf("IsValidForConnection() = %v, want %v", got, tt.isValidForConn)
			}
			if got := tt.status.IsActive(); got != tt.isActive {
				t.Errorf("IsActive() = %v, want %v", got, tt.isActive)
			}
			if got := tt.status.ShouldReject(); got != tt.shouldReject {
				t.Errorf("ShouldReject() = %v, want %v", got, tt.shouldReject)
			}
		})
	}
}

func TestBadge_Helpers(t *testing.T) {
	badge := &Badge{
		Status:        BadgeStatusActive,
		SchemaVersion: "V1",
		Payload: BadgePayload{
			LogID: "test-log-id",
			Producer: Producer{
				KeyID:     "test-key",
				Signature: "test-sig",
				Event: AgentEvent{
					ANSID:   "test-ans-id",
					ANSName: "ans://v1.0.0.agent.example.com",
					Agent: AgentInfo{
						Host:    "agent.example.com",
						Name:    "Test Agent",
						Version: "v1.0.0",
					},
					Attestations: Attestations{
						DomainValidation: "ACME-DNS-01",
						ServerCert: &CertAttestationV1{
							Fingerprint: "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904",
							Type:        "X509-DV-SERVER",
						},
						IdentityCert: &CertAttestationV1{
							Fingerprint: "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496",
							Type:        "X509-OV-CLIENT",
						},
					},
				},
			},
		},
	}

	t.Run("AgentName", func(t *testing.T) {
		want := "ans://v1.0.0.agent.example.com"
		if got := badge.AgentName(); got != want {
			t.Errorf("AgentName() = %q, want %q", got, want)
		}
	})

	t.Run("AgentHost", func(t *testing.T) {
		want := "agent.example.com"
		if got := badge.AgentHost(); got != want {
			t.Errorf("AgentHost() = %q, want %q", got, want)
		}
	})

	t.Run("AgentVersion", func(t *testing.T) {
		want := "v1.0.0"
		if got := badge.AgentVersion(); got != want {
			t.Errorf("AgentVersion() = %q, want %q", got, want)
		}
	})

	t.Run("ServerCertFingerprint", func(t *testing.T) {
		want := "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904"
		if got := badge.ServerCertFingerprint(); got != want {
			t.Errorf("ServerCertFingerprint() = %q, want %q", got, want)
		}
	})

	t.Run("IdentityCertFingerprint", func(t *testing.T) {
		want := "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496"
		if got := badge.IdentityCertFingerprint(); got != want {
			t.Errorf("IdentityCertFingerprint() = %q, want %q", got, want)
		}
	})

	t.Run("IsValid", func(t *testing.T) {
		if !badge.IsValid() {
			t.Errorf("IsValid() = false, want true")
		}
	})
}

func TestBadge_Helpers_NilCerts(t *testing.T) {
	badge := &Badge{
		Status: BadgeStatusActive,
		Payload: BadgePayload{
			Producer: Producer{
				Event: AgentEvent{
					Attestations: Attestations{},
				},
			},
		},
	}

	t.Run("ServerCertFingerprint with nil cert", func(t *testing.T) {
		if got := badge.ServerCertFingerprint(); got != "" {
			t.Errorf("ServerCertFingerprint() = %q, want empty string", got)
		}
	})

	t.Run("IdentityCertFingerprint with nil cert", func(t *testing.T) {
		if got := badge.IdentityCertFingerprint(); got != "" {
			t.Errorf("IdentityCertFingerprint() = %q, want empty string", got)
		}
	})
}

func TestBadge_AgentID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{
		{
			name: "standard agent ID",
			id:   "test-agent-id",
			want: "test-agent-id",
		},
		{
			name: "empty agent ID",
			id:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			badge := &Badge{
				Payload: BadgePayload{
					Producer: Producer{
						Event: AgentEvent{
							ANSID: tt.id,
						},
					},
				},
			}
			if got := badge.AgentID(); got != tt.want {
				t.Errorf("AgentID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBadge_EventType(t *testing.T) {
	tests := []struct {
		name      string
		eventType EventType
		want      EventType
	}{
		{
			name:      "agent registered",
			eventType: EventTypeAgentRegistered,
			want:      EventTypeAgentRegistered,
		},
		{
			name:      "agent renewed",
			eventType: EventTypeAgentRenewed,
			want:      EventTypeAgentRenewed,
		},
		{
			name:      "agent revoked",
			eventType: EventTypeAgentRevoked,
			want:      EventTypeAgentRevoked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			badge := &Badge{
				Payload: BadgePayload{
					Producer: Producer{
						Event: AgentEvent{
							EventType: tt.eventType,
						},
					},
				},
			}
			if got := badge.EventType(); got != tt.want {
				t.Errorf("EventType() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBadge_CapabilitiesHash_Plan_C covers the V2 envelope path: a
// badge whose AGENT_REGISTERED event was sealed with agentCardContent
// at registration carries the SHA-256(JCS(content)) digest under
// attestations.metadataHashes.capabilitiesHash. Badge.CapabilitiesHash
// surfaces it; absence (V1 envelope or operator omitted content)
// returns "".
func TestBadge_CapabilitiesHash_Plan_C(t *testing.T) {
	const want = "098d650cc6d280dee4c0f47489a75cf17b9bfbbae53051806d4e084108b2ff27"

	t.Run("v2_envelope_with_capabilitiesHash_present", func(t *testing.T) {
		b := &Badge{
			Payload: BadgePayload{
				Producer: Producer{Event: AgentEvent{Attestations: Attestations{
					MetadataHashes: map[string]string{
						MetadataHashKeyCapabilitiesHash: want,
					},
				}}},
			},
		}
		if got := b.CapabilitiesHash(); got != want {
			t.Errorf("CapabilitiesHash() = %q, want %q", got, want)
		}
	})

	t.Run("absent_when_metadataHashes_nil", func(t *testing.T) {
		b := &Badge{}
		if got := b.CapabilitiesHash(); got != "" {
			t.Errorf("CapabilitiesHash() = %q, want empty", got)
		}
	})

	t.Run("absent_when_key_missing_from_map", func(t *testing.T) {
		b := &Badge{
			Payload: BadgePayload{
				Producer: Producer{Event: AgentEvent{Attestations: Attestations{
					MetadataHashes: map[string]string{"someOtherHash": "abc"},
				}}},
			},
		}
		if got := b.CapabilitiesHash(); got != "" {
			t.Errorf("CapabilitiesHash() = %q, want empty (key absent)", got)
		}
	})
}

// TestBadge_DNSRecordsProvisioned_PlanD covers V2 envelopes that
// carry the dnsRecordsProvisioned attestation. Operators inspect
// the slice to render zone-file fragments matching what the RA
// computed for the registration's dnsRecordStyle.
func TestBadge_DNSRecordsProvisioned_PlanD(t *testing.T) {
	records := []DNSRecord{
		{Name: "agent.webmesh.ai", Type: DNSRecordTypeSVCB,
			Value: `1 . alpn=a2a port=443 wk=agent-card.json`,
			Purpose: "DISCOVERY"},
		{Name: "_ans-badge.agent.webmesh.ai", Type: DNSRecordTypeTXT,
			Value: "v=ans-badge1; version=1.0.1; url=...", Purpose: "BADGE"},
	}
	b := &Badge{
		Payload: BadgePayload{
			Producer: Producer{Event: AgentEvent{Attestations: Attestations{
				DNSRecordsProvisioned: records,
			}}},
		},
	}
	got := b.DNSRecordsProvisioned()
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Type != DNSRecordTypeSVCB {
		t.Errorf("got[0].Type = %q, want SVCB", got[0].Type)
	}
}

// TestAttestations_RoundTripV1AndV2 confirms the unified Attestations
// struct deserializes both V1 (legacy: singleton certs, no metadata
// hashes) and V2 (current: array certs, metadataHashes populated)
// envelope shapes without choking. V1 callers continue to read
// IdentityCert/ServerCert; V2 callers read IdentityCerts/ServerCerts
// arrays plus MetadataHashes.
func TestAttestations_RoundTripV1AndV2(t *testing.T) {
	v1 := []byte(`{
		"domainValidation": "ACME-DNS-01",
		"identityCert": {"fingerprint": "SHA256:aaa", "type": "X509-OV-CLIENT"},
		"serverCert":   {"fingerprint": "SHA256:bbb", "type": "X509-DV-SERVER"}
	}`)
	v2 := []byte(`{
		"domainValidation": "ACME-DNS-01",
		"identityCerts": [{"fingerprint": "SHA256:ccc", "type": "X509-OV-CLIENT"}],
		"serverCerts":   [{"fingerprint": "SHA256:ddd", "type": "X509-DV-SERVER"}],
		"metadataHashes": {"capabilitiesHash": "098d650c..."},
		"dnsRecordsProvisioned": [
			{"name": "agent.webmesh.ai", "type": "SVCB", "value": "1 . alpn=a2a port=443"}
		]
	}`)

	t.Run("v1", func(t *testing.T) {
		var a Attestations
		if err := json.Unmarshal(v1, &a); err != nil {
			t.Fatalf("v1 unmarshal: %v", err)
		}
		if a.IdentityCert == nil || a.IdentityCert.Fingerprint != "SHA256:aaa" {
			t.Errorf("v1 identityCert lost: %+v", a.IdentityCert)
		}
		if len(a.IdentityCerts) != 0 || len(a.MetadataHashes) != 0 {
			t.Errorf("v1 envelope must not populate v2-only fields; got %+v", a)
		}
	})

	t.Run("v2", func(t *testing.T) {
		var a Attestations
		if err := json.Unmarshal(v2, &a); err != nil {
			t.Fatalf("v2 unmarshal: %v", err)
		}
		if len(a.IdentityCerts) != 1 || a.IdentityCerts[0].Fingerprint != "SHA256:ccc" {
			t.Errorf("v2 identityCerts not populated: %+v", a.IdentityCerts)
		}
		if got := a.MetadataHashes[MetadataHashKeyCapabilitiesHash]; got != "098d650c..." {
			t.Errorf("v2 capabilitiesHash = %q, want 098d650c...", got)
		}
		if len(a.DNSRecordsProvisioned) != 1 {
			t.Errorf("v2 dnsRecordsProvisioned len = %d, want 1", len(a.DNSRecordsProvisioned))
		}
	})
}
