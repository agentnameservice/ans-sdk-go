package models

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func loadBadgeFixture(t *testing.T, path string) *Badge {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var b Badge
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return &b
}

// TestBadgeUnmarshalNormalizesBothSchemas proves that the V1 fixture (singular
// certs, map DNS) and the V2 fixture (cert arrays, typed DNS records) decode
// into the same version-neutral Attestations shape.
func TestBadgeUnmarshalNormalizesBothSchemas(t *testing.T) {
	notAfterA := time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name          string
		fixture       string
		schemaVersion string
		wantServer    []AttestedCert
		wantIdentity  []AttestedCert
		wantDNS       []DNSRecordAttestation
		wantHashes    map[string]string
	}{
		{
			name:          "V1 singular certs and map DNS",
			fixture:       "testdata/badge-v1.json",
			schemaVersion: "V1",
			wantServer:    []AttestedCert{{Fingerprint: "v1-srv-fp", Type: "X509-DV-SERVER"}},
			wantIdentity:  []AttestedCert{{Fingerprint: "v1-id-fp", Type: "X509-OV-CLIENT"}},
			wantDNS:       []DNSRecordAttestation{{Name: "_ans.agent.example.com", Data: "txt-data"}},
		},
		{
			name:          "V2 cert arrays and typed DNS",
			fixture:       "testdata/badge-v2.json",
			schemaVersion: "V2",
			wantServer: []AttestedCert{
				{Fingerprint: "v2-srv-fp-a", Type: "X509-DV-SERVER", NotAfter: &notAfterA},
				{Fingerprint: "v2-srv-fp-b", Type: "X509-DV-SERVER", NotAfter: ptrTime(time.Date(2027, 8, 1, 0, 0, 0, 0, time.UTC))},
			},
			wantIdentity: []AttestedCert{{Fingerprint: "v2-id-fp-a", Type: "X509-OV-CLIENT", NotAfter: &notAfterA}},
			wantDNS:      []DNSRecordAttestation{{Name: "_ans.agent.example.com", Data: "txt-data", Type: "TXT"}},
			wantHashes:   map[string]string{"agent.json": "sha256-abc"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := loadBadgeFixture(t, tt.fixture)
			if b.SchemaVersion != tt.schemaVersion {
				t.Errorf("SchemaVersion = %q, want %q", b.SchemaVersion, tt.schemaVersion)
			}
			att := b.Payload.Producer.Event.Attestations
			if att.DomainValidation != "ACME-DNS-01" {
				t.Errorf("DomainValidation = %q", att.DomainValidation)
			}
			assertCerts(t, "ServerCerts", att.ServerCerts, tt.wantServer)
			assertCerts(t, "IdentityCerts", att.IdentityCerts, tt.wantIdentity)
			if len(att.DNSRecordsProvisioned) != len(tt.wantDNS) {
				t.Fatalf("DNSRecordsProvisioned = %+v, want %+v", att.DNSRecordsProvisioned, tt.wantDNS)
			}
			for i, rec := range tt.wantDNS {
				if att.DNSRecordsProvisioned[i] != rec {
					t.Errorf("DNSRecordsProvisioned[%d] = %+v, want %+v", i, att.DNSRecordsProvisioned[i], rec)
				}
			}
			if len(tt.wantHashes) > 0 && att.MetadataHashes["agent.json"] != tt.wantHashes["agent.json"] {
				t.Errorf("MetadataHashes = %+v, want %+v", att.MetadataHashes, tt.wantHashes)
			}
		})
	}
}

func assertCerts(t *testing.T, field string, got, want []AttestedCert) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %+v, want %+v", field, got, want)
	}
	for i := range want {
		if got[i].Fingerprint != want[i].Fingerprint || got[i].Type != want[i].Type {
			t.Errorf("%s[%d] = %+v, want %+v", field, i, got[i], want[i])
		}
		switch {
		case want[i].NotAfter == nil && got[i].NotAfter != nil:
			t.Errorf("%s[%d].NotAfter = %v, want nil", field, i, got[i].NotAfter)
		case want[i].NotAfter != nil && (got[i].NotAfter == nil || !got[i].NotAfter.Equal(*want[i].NotAfter)):
			t.Errorf("%s[%d].NotAfter = %v, want %v", field, i, got[i].NotAfter, want[i].NotAfter)
		}
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

// TestBadgeUnmarshalV1Variants covers the V1 layouts the schema allows: the
// rotation arrays override the singular entry, map keys sort deterministically,
// and a missing schemaVersion is read as V1.
func TestBadgeUnmarshalV1Variants(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantServer []string
		wantDNS    []DNSRecordAttestation
	}{
		{
			name: "validServerCerts wins over singular serverCert",
			raw: `{"schemaVersion":"V1","payload":{"producer":{"event":{"attestations":{
				"serverCert":{"fingerprint":"old","type":"X509-DV-SERVER"},
				"validServerCerts":[{"fingerprint":"a","type":"X509-DV-SERVER","notAfter":"2027-01-01T00:00:00Z"},{"fingerprint":"b","type":"X509-DV-SERVER"}]
			}}}}}`,
			wantServer: []string{"a", "b"},
		},
		{
			name:       "missing schemaVersion decodes as V1",
			raw:        `{"payload":{"producer":{"event":{"attestations":{"serverCert":{"fingerprint":"legacy","type":"X509-DV-SERVER"}}}}}}`,
			wantServer: []string{"legacy"},
		},
		{
			name: "map DNS records sort by name",
			raw: `{"schemaVersion":"V1","payload":{"producer":{"event":{"attestations":{
				"dnsRecordsProvisioned":{"_ans-badge.x":"b","_ans.x":"a"}
			}}}}}`,
			wantDNS: []DNSRecordAttestation{{Name: "_ans-badge.x", Data: "b"}, {Name: "_ans.x", Data: "a"}},
		},
		{
			name: "empty attestations object",
			raw:  `{"schemaVersion":"V1","payload":{"producer":{"event":{"attestations":{}}}}}`,
		},
		{
			name: "absent attestations",
			raw:  `{"schemaVersion":"V1","payload":{"producer":{"event":{}}}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Badge
			if err := json.Unmarshal([]byte(tt.raw), &b); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := b.ServerCertFingerprints(); !equalStrings(got, tt.wantServer) {
				t.Errorf("ServerCertFingerprints = %v, want %v", got, tt.wantServer)
			}
			got := b.Payload.Producer.Event.Attestations.DNSRecordsProvisioned
			if len(got) != len(tt.wantDNS) {
				t.Fatalf("DNSRecordsProvisioned = %+v, want %+v", got, tt.wantDNS)
			}
			for i := range tt.wantDNS {
				if got[i] != tt.wantDNS[i] {
					t.Errorf("DNSRecordsProvisioned[%d] = %+v, want %+v", i, got[i], tt.wantDNS[i])
				}
			}
		})
	}
}

func equalStrings(a, b []string) bool {
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

func TestBadgeUnmarshalRejects(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{
			name:    "unknown schemaVersion",
			raw:     `{"schemaVersion":"V3","payload":{"producer":{"event":{"attestations":{"serverCerts":[{"fingerprint":"x","type":"t"}]}}}}}`,
			wantErr: `unsupported badge schemaVersion "V3"`,
		},
		{
			name:    "V0 is not a badge layout",
			raw:     `{"schemaVersion":"V0","payload":{"producer":{"event":{"attestations":{}}}}}`,
			wantErr: `schemaVersion "V0"`,
		},
		{
			name:    "V1 with array DNS",
			raw:     `{"schemaVersion":"V1","payload":{"producer":{"event":{"attestations":{"dnsRecordsProvisioned":[1]}}}}}`,
			wantErr: "parse V1 attestations",
		},
		{
			name:    "V2 with map DNS",
			raw:     `{"schemaVersion":"V2","payload":{"producer":{"event":{"attestations":{"dnsRecordsProvisioned":{"a":"b"}}}}}}`,
			wantErr: "parse V2 attestations",
		},
		{
			name:    "not an object",
			raw:     `[]`,
			wantErr: "cannot unmarshal",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Badge
			err := json.Unmarshal([]byte(tt.raw), &b)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q should contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestBadgeMarshalEmitsV2 proves any badge, whatever schema it was decoded
// from, re-encodes in the V2 layout with schemaVersion stamped to match, and
// decodes again without loss.
func TestBadgeMarshalEmitsV2(t *testing.T) {
	for _, fixture := range []string{"testdata/badge-v1.json", "testdata/badge-v2.json"} {
		t.Run(fixture, func(t *testing.T) {
			in := loadBadgeFixture(t, fixture)
			data, err := json.Marshal(in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			for _, want := range []string{`"schemaVersion":"V2"`, `"serverCerts":[`, `"identityCerts":[`, `"dnsRecordsProvisioned":[`} {
				if !bytes.Contains(data, []byte(want)) {
					t.Errorf("marshaled badge missing %s: %s", want, data)
				}
			}
			for _, reject := range []string{`"validServerCerts"`, `"serverCert":{`, `"identityCert":{`} {
				if bytes.Contains(data, []byte(reject)) {
					t.Errorf("marshaled badge must not contain %s: %s", reject, data)
				}
			}
			var out Badge
			if err := json.Unmarshal(data, &out); err != nil {
				t.Fatalf("unmarshal round trip: %v; json=%s", err, data)
			}
			if !equalStrings(out.ServerCertFingerprints(), in.ServerCertFingerprints()) ||
				!equalStrings(out.IdentityCertFingerprints(), in.IdentityCertFingerprints()) {
				t.Errorf("fingerprints changed across round trip: %s", data)
			}
			if len(out.Payload.Producer.Event.Attestations.DNSRecordsProvisioned) != len(in.Payload.Producer.Event.Attestations.DNSRecordsProvisioned) {
				t.Errorf("DNS records changed across round trip: %s", data)
			}
			if out.Status != in.Status || out.Payload.LogID != in.Payload.LogID || out.AgentHost() != in.AgentHost() {
				t.Errorf("envelope fields changed across round trip: %s", data)
			}
		})
	}
}

func TestBadgeFingerprintAccessors(t *testing.T) {
	tests := []struct {
		name      string
		certs     []AttestedCert
		wantFirst string
		wantAll   []string
	}{
		{name: "none", certs: nil, wantFirst: "", wantAll: nil},
		{name: "one", certs: []AttestedCert{{Fingerprint: "a"}}, wantFirst: "a", wantAll: []string{"a"}},
		{name: "two", certs: []AttestedCert{{Fingerprint: "a"}, {Fingerprint: "b"}}, wantFirst: "a", wantAll: []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Badge{}
			b.Payload.Producer.Event.Attestations.ServerCerts = tt.certs
			b.Payload.Producer.Event.Attestations.IdentityCerts = tt.certs
			if got := b.ServerCertFingerprint(); got != tt.wantFirst {
				t.Errorf("ServerCertFingerprint = %q, want %q", got, tt.wantFirst)
			}
			if got := b.IdentityCertFingerprint(); got != tt.wantFirst {
				t.Errorf("IdentityCertFingerprint = %q, want %q", got, tt.wantFirst)
			}
			if got := b.ServerCertFingerprints(); !equalStrings(got, tt.wantAll) {
				t.Errorf("ServerCertFingerprints = %v, want %v", got, tt.wantAll)
			}
			if got := b.IdentityCertFingerprints(); !equalStrings(got, tt.wantAll) {
				t.Errorf("IdentityCertFingerprints = %v, want %v", got, tt.wantAll)
			}
		})
	}
}

func TestAttestedCertValidAt(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		notAfter *time.Time
		want     bool
	}{
		{name: "no notAfter is valid", notAfter: nil, want: true},
		{name: "future notAfter is valid", notAfter: ptrTime(now.Add(time.Hour)), want: true},
		{name: "past notAfter is invalid", notAfter: ptrTime(now.Add(-time.Second)), want: false},
		{name: "notAfter equal to now is invalid", notAfter: ptrTime(now), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := AttestedCert{Fingerprint: "x", NotAfter: tt.notAfter}
			if got := c.ValidAt(now); got != tt.want {
				t.Errorf("ValidAt = %v, want %v", got, tt.want)
			}
		})
	}
}
