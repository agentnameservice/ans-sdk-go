package models

import (
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
						ServerCerts:      []AttestedCert{{Fingerprint: "SHA256:e7b64d16f42055d6faf382a43dc35b98be76aba0db145a904b590a034b33b904", Type: "X509-DV-SERVER"}},
						IdentityCerts:    []AttestedCert{{Fingerprint: "SHA256:aebdc9da0c20d6d5e4999a773839095ed050a9d7252bf212056fddc0c38f3496", Type: "X509-OV-CLIENT"}},
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
