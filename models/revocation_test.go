package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestIsValidRevocationReason(t *testing.T) {
	tests := []struct {
		name   string
		reason RevocationReason
		want   bool
	}{
		{
			name:   "KEY_COMPROMISE",
			reason: RevocationReasonKeyCompromise,
			want:   true,
		},
		{
			name:   "CESSATION_OF_OPERATION",
			reason: RevocationReasonCessationOfOperation,
			want:   true,
		},
		{
			name:   "AFFILIATION_CHANGED",
			reason: RevocationReasonAffiliationChanged,
			want:   true,
		},
		{
			name:   "SUPERSEDED",
			reason: RevocationReasonSuperseded,
			want:   true,
		},
		{
			name:   "CERTIFICATE_HOLD",
			reason: RevocationReasonCertificateHold,
			want:   true,
		},
		{
			name:   "PRIVILEGE_WITHDRAWN",
			reason: RevocationReasonPrivilegeWithdrawn,
			want:   true,
		},
		{
			name:   "AA_COMPROMISE",
			reason: RevocationReasonAACompromise,
			want:   true,
		},
		{
			name:   "CA_COMPROMISE",
			reason: RevocationReasonCACompromise,
			want:   true,
		},
		{
			name:   "UNSPECIFIED",
			reason: RevocationReasonUnspecified,
			want:   true,
		},
		{
			name:   "invalid reason",
			reason: RevocationReason("INVALID_REASON"),
			want:   false,
		},
		{
			name:   "empty string",
			reason: RevocationReason(""),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidRevocationReason(tt.reason); got != tt.want {
				t.Errorf("IsValidRevocationReason(%q) = %v, want %v", tt.reason, got, tt.want)
			}
		})
	}
}

func TestIsAPIRevocationReason(t *testing.T) {
	tests := []struct {
		name   string
		reason RevocationReason
		want   bool
	}{
		{name: "KEY_COMPROMISE accepted", reason: RevocationReasonKeyCompromise, want: true},
		{name: "CESSATION_OF_OPERATION accepted", reason: RevocationReasonCessationOfOperation, want: true},
		{name: "AFFILIATION_CHANGED accepted", reason: RevocationReasonAffiliationChanged, want: true},
		{name: "CERTIFICATE_HOLD accepted", reason: RevocationReasonCertificateHold, want: true},
		{name: "PRIVILEGE_WITHDRAWN accepted", reason: RevocationReasonPrivilegeWithdrawn, want: true},
		{name: "AA_COMPROMISE accepted", reason: RevocationReasonAACompromise, want: true},
		// Reserved for the registry's internal successor-deprecation flow.
		{name: "SUPERSEDED rejected", reason: RevocationReasonSuperseded, want: false},
		// RFC-only codes with no registry enum value.
		{name: "CA_COMPROMISE rejected", reason: RevocationReasonCACompromise, want: false},
		{name: "EXPIRED_CERT rejected", reason: RevocationReasonExpiredCert, want: false},
		{name: "REMOVE_FROM_CRL rejected", reason: RevocationReasonRemoveFromCRL, want: false},
		{name: "UNSPECIFIED rejected", reason: RevocationReasonUnspecified, want: false},
		{name: "unknown rejected", reason: RevocationReason("INVALID_REASON"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAPIRevocationReason(tt.reason); got != tt.want {
				t.Errorf("IsAPIRevocationReason(%q) = %v, want %v", tt.reason, got, tt.want)
			}
		})
	}
}

func TestAgentRevocationRequest_JSON(t *testing.T) {
	tests := []struct {
		name     string
		request  AgentRevocationRequest
		wantJSON string
	}{
		{
			name: "basic request",
			request: AgentRevocationRequest{
				Reason: RevocationReasonKeyCompromise,
			},
			wantJSON: `{"reason":"KEY_COMPROMISE"}`,
		},
		{
			name: "request with comments",
			request: AgentRevocationRequest{
				Reason:   RevocationReasonSuperseded,
				Comments: "Replaced by version 2.0.0",
			},
			wantJSON: `{"reason":"SUPERSEDED","comments":"Replaced by version 2.0.0"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.request)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			if string(jsonData) != tt.wantJSON {
				t.Errorf("JSON mismatch:\ngot:  %s\nwant: %s", string(jsonData), tt.wantJSON)
			}
		})
	}
}

func TestAgentRevocationResponse_JSON(t *testing.T) {
	fixedTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	tests := []struct {
		name    string
		jsonStr string
		want    AgentRevocationResponse
	}{
		{
			name:    "full response",
			jsonStr: `{"agentId":"agent-123","ansName":"ans://v1.0.0.myagent.example.com","status":"REVOKED","revokedAt":"2024-01-15T10:30:00Z","reason":"KEY_COMPROMISE"}`,
			want: AgentRevocationResponse{
				AgentID:   "agent-123",
				AnsName:   "ans://v1.0.0.myagent.example.com",
				Status:    "REVOKED",
				RevokedAt: fixedTime,
				Reason:    RevocationReasonKeyCompromise,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got AgentRevocationResponse
			if err := json.Unmarshal([]byte(tt.jsonStr), &got); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			if got.AgentID != tt.want.AgentID {
				t.Errorf("AgentID mismatch: got %q, want %q", got.AgentID, tt.want.AgentID)
			}
			if got.AnsName != tt.want.AnsName {
				t.Errorf("AnsName mismatch: got %q, want %q", got.AnsName, tt.want.AnsName)
			}
			if got.Status != tt.want.Status {
				t.Errorf("Status mismatch: got %q, want %q", got.Status, tt.want.Status)
			}
			if got.Reason != tt.want.Reason {
				t.Errorf("Reason mismatch: got %q, want %q", got.Reason, tt.want.Reason)
			}
		})
	}
}
