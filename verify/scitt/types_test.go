package scitt

import "testing"

func TestAgentStatusIsValidForConnection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   AgentStatus
		expected bool
	}{
		{name: "active", status: StatusActive, expected: true},
		{name: "warning", status: StatusWarning, expected: true},
		{name: "deprecated", status: StatusDeprecated, expected: true},
		{name: "expired", status: StatusExpired, expected: false},
		{name: "revoked", status: StatusRevoked, expected: false},
		{name: "unknown", status: AgentStatus("UNKNOWN"), expected: false},
		{name: "empty", status: AgentStatus(""), expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.status.IsValidForConnection(); got != tt.expected {
				t.Errorf("AgentStatus(%q).IsValidForConnection() = %v, want %v", tt.status, got, tt.expected)
			}
		})
	}
}

func TestAgentStatusIsTerminal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   AgentStatus
		expected bool
	}{
		{name: "active", status: StatusActive, expected: false},
		{name: "warning", status: StatusWarning, expected: false},
		{name: "deprecated", status: StatusDeprecated, expected: false},
		{name: "expired", status: StatusExpired, expected: true},
		{name: "revoked", status: StatusRevoked, expected: true},
		{name: "unknown", status: AgentStatus("UNKNOWN"), expected: false},
		{name: "empty", status: AgentStatus(""), expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.status.IsTerminal(); got != tt.expected {
				t.Errorf("AgentStatus(%q).IsTerminal() = %v, want %v", tt.status, got, tt.expected)
			}
		})
	}
}

func TestCertTypeConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ct       CertType
		expected string
	}{
		{name: "dv server", ct: CertTypeX509DVServer, expected: "x509-dv-server"},
		{name: "ov client", ct: CertTypeX509OVClient, expected: "x509-ov-client"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if string(tt.ct) != tt.expected {
				t.Errorf("CertType = %q, want %q", tt.ct, tt.expected)
			}
		})
	}
}

func TestStatusTokenPayloadZeroValue(t *testing.T) {
	t.Parallel()

	var p StatusTokenPayload
	if p.AgentID != "" {
		t.Error("expected empty AgentID on zero value")
	}
	if p.Status != "" {
		t.Error("expected empty Status on zero value")
	}
	if p.ValidIdentityCerts != nil {
		t.Error("expected nil ValidIdentityCerts on zero value")
	}
	if p.ValidServerCerts != nil {
		t.Error("expected nil ValidServerCerts on zero value")
	}
	if p.MetadataHashes != nil {
		t.Error("expected nil MetadataHashes on zero value")
	}
}
