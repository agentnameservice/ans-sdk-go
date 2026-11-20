package models

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestBadgeUnmarshalsV2Shape(t *testing.T) {
	data, err := os.ReadFile("testdata/badge-v2.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var b Badge
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	att := b.Payload.Producer.Event.Attestations
	if len(att.ValidServerCerts) != 2 {
		t.Fatalf("ValidServerCerts: want 2, got %d; attestations=%+v", len(att.ValidServerCerts), att)
	}
	if len(att.ValidIdentityCerts) != 1 {
		t.Fatalf("ValidIdentityCerts: want 1, got %d; attestations=%+v", len(att.ValidIdentityCerts), att)
	}
	if len(att.DNSRecordsProvisionedV2) != 1 {
		t.Fatalf("DNSRecordsProvisionedV2: want 1, got %d; attestations=%+v", len(att.DNSRecordsProvisionedV2), att)
	}
	if att.MetadataHashes["agent.json"] != "sha256-abc" {
		t.Fatalf("MetadataHashes missing or wrong: %+v", att.MetadataHashes)
	}
}

func TestBadgeMatchesServerCertV2(t *testing.T) {
	b := loadBadgeFixture(t, "testdata/badge-v2.json")
	if !b.MatchesServerCert("v2-srv-fp-a") {
		t.Fatal("expected match on first server cert")
	}
	if !b.MatchesServerCert("v2-srv-fp-b") {
		t.Fatal("expected match on second server cert")
	}
	if b.MatchesServerCert("nope") {
		t.Fatal("expected non-match")
	}
}

func TestBadgeMatchesServerCertV1Compat(t *testing.T) {
	b := loadBadgeFixture(t, "testdata/badge-v1.json")
	if !b.MatchesServerCert("v1-srv-fp") {
		t.Fatal("expected match on v1 singular server cert")
	}
	if b.MatchesServerCert("nope") {
		t.Fatal("expected non-match")
	}
}

func TestBadgeMatchesIdentityCertV2(t *testing.T) {
	b := loadBadgeFixture(t, "testdata/badge-v2.json")
	if !b.MatchesIdentityCert("v2-id-fp-a") {
		t.Fatal("expected match on v2 identity cert")
	}
	if b.MatchesIdentityCert("nope") {
		t.Fatal("expected non-match")
	}
}

func TestBadgeMatchesIdentityCertV1Compat(t *testing.T) {
	b := loadBadgeFixture(t, "testdata/badge-v1.json")
	if !b.MatchesIdentityCert("v1-id-fp") {
		t.Fatal("expected match on v1 singular identity cert")
	}
	if b.MatchesIdentityCert("nope") {
		t.Fatal("expected non-match")
	}
}

func TestBadgeServerCertFingerprintsV2(t *testing.T) {
	b := loadBadgeFixture(t, "testdata/badge-v2.json")
	got := b.ServerCertFingerprints()
	if len(got) != 2 || got[0] != "v2-srv-fp-a" || got[1] != "v2-srv-fp-b" {
		t.Fatalf("got %v", got)
	}
}

func TestBadgeServerCertFingerprintsV1Compat(t *testing.T) {
	b := loadBadgeFixture(t, "testdata/badge-v1.json")
	got := b.ServerCertFingerprints()
	if len(got) != 1 || got[0] != "v1-srv-fp" {
		t.Fatalf("got %v", got)
	}
}

func TestBadgeIdentityCertFingerprintsV2(t *testing.T) {
	b := loadBadgeFixture(t, "testdata/badge-v2.json")
	got := b.IdentityCertFingerprints()
	if len(got) != 1 || got[0] != "v2-id-fp-a" {
		t.Fatalf("got %v", got)
	}
}

func TestBadgeIdentityCertFingerprintsV1Compat(t *testing.T) {
	b := loadBadgeFixture(t, "testdata/badge-v1.json")
	got := b.IdentityCertFingerprints()
	if len(got) != 1 || got[0] != "v1-id-fp" {
		t.Fatalf("got %v", got)
	}
}

// TestBadgeAttestationsParsesV1MapDnsRecords proves a Badge response carrying
// the v1 map-shaped dnsRecordsProvisioned no longer fails to parse and lands in
// the map field, leaving the v2 array field empty.
func TestBadgeAttestationsParsesV1MapDnsRecords(t *testing.T) {
	raw := []byte(`{
		"status": "ACTIVE",
		"schemaVersion": "V1",
		"payload": {"logId":"l","producer":{"keyId":"k","signature":"s","event":{
			"ansId":"a","ansName":"ans://example.com/agent","eventType":"AGENT_REGISTERED",
			"agent":{"host":"agent.example.com","name":"Example","version":"1.0.0"},
			"attestations":{
				"domainValidation":"ACME-DNS-01",
				"serverCert":{"fingerprint":"v1-srv-fp","type":"X509-DV-SERVER"},
				"dnsRecordsProvisioned":{"_ans.agent.example.com":"txt-data"}
			},
			"issuedAt":"2026-05-01T00:00:00Z","raId":"r","timestamp":"2026-05-01T00:00:00Z"
		}}}
	}`)
	var b Badge
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal v1-map badge: %v", err)
	}
	att := b.Payload.Producer.Event.Attestations
	if got := att.DNSRecordsProvisioned["_ans.agent.example.com"]; got != "txt-data" {
		t.Fatalf("DNSRecordsProvisioned: want txt-data, got %q; map=%+v", got, att.DNSRecordsProvisioned)
	}
	if len(att.DNSRecordsProvisionedV2) != 0 {
		t.Fatalf("DNSRecordsProvisionedV2: want empty for v1 map shape, got %+v", att.DNSRecordsProvisionedV2)
	}
}

// TestBadgeMatchesServerCertCaseInsensitive proves the matcher tolerates prefix
// and hex case differences rather than requiring exact string equality.
func TestBadgeMatchesServerCertCaseInsensitive(t *testing.T) {
	b := &Badge{}
	b.Payload.Producer.Event.Attestations.ValidServerCerts = []ValidCertAttestation{
		{Fingerprint: "SHA256:ABCDEF", Type: "X509-DV-SERVER"},
	}
	if !b.MatchesServerCert("sha256:abcdef") {
		t.Fatal("expected case-insensitive match")
	}
	if b.MatchesServerCert("sha256:beef") {
		t.Fatal("expected non-match on different fingerprint")
	}
	if b.MatchesIdentityCert("anything") {
		t.Fatal("expected non-match when no identity certs present")
	}
}

// TestAttestationsRoundTripsV1MapDns proves Marshal->Unmarshal preserves the
// V1 map-shaped dnsRecordsProvisioned for standalone Attestations decoding.
// V2 array-DNS round-trip happens through Badge (covered by TestBadgeUnmarshalsV2Shape);
// standalone Attestations decoding is V1-only by design.
func TestAttestationsRoundTripsV1MapDns(t *testing.T) {
	in := Attestations{
		DomainValidation:      "ACME-DNS-01",
		DNSRecordsProvisioned: map[string]string{"_ans.x": "d"},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Attestations
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v; json=%s", err, data)
	}
	if out.DNSRecordsProvisioned["_ans.x"] != "d" {
		t.Fatalf("v1 round-trip lost data: %+v (json=%s)", out, data)
	}
}

// TestBadgeUnmarshalsWireV2CertNames tests the real v2 API wire field names
// "serverCerts" and "identityCerts" (without the "valid" prefix) as emitted by
// the actual transparency log for v2-schema agents.
func TestBadgeUnmarshalsWireV2CertNames(t *testing.T) {
	raw := []byte(`{
		"status": "ACTIVE",
		"schemaVersion": "V2",
		"payload": {"logId":"l","producer":{"keyId":"k","signature":"s","event":{
			"ansId":"a","ansName":"ans://example.com/agent","eventType":"AGENT_REGISTERED",
			"agent":{"host":"agent.example.com","name":"Example","version":"1.0.0"},
			"attestations":{
				"domainValidation":"ACME-DNS-01",
				"serverCerts":[
					{"fingerprint":"wire-srv-fp-a","type":"X509-DV-SERVER","notAfter":"2027-01-01T00:00:00Z"},
					{"fingerprint":"wire-srv-fp-b","type":"X509-DV-SERVER","notAfter":"2027-06-01T00:00:00Z"}
				],
				"identityCerts":[
					{"fingerprint":"wire-id-fp-a","type":"X509-OV-CLIENT","notAfter":"2027-01-01T00:00:00Z"}
				]
			},
			"issuedAt":"2026-05-01T00:00:00Z","raId":"r","timestamp":"2026-05-01T00:00:00Z"
		}}}
	}`)
	var b Badge
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if fps := b.ServerCertFingerprints(); len(fps) != 2 || fps[0] != "wire-srv-fp-a" || fps[1] != "wire-srv-fp-b" {
		t.Fatalf("ServerCertFingerprints: want [wire-srv-fp-a wire-srv-fp-b], got %v", fps)
	}
	if fps := b.IdentityCertFingerprints(); len(fps) != 1 || fps[0] != "wire-id-fp-a" {
		t.Fatalf("IdentityCertFingerprints: want [wire-id-fp-a], got %v", fps)
	}
	if !b.MatchesServerCert("wire-srv-fp-a") {
		t.Fatal("MatchesServerCert: expected match on wire-srv-fp-a")
	}
	if !b.MatchesIdentityCert("wire-id-fp-a") {
		t.Fatal("MatchesIdentityCert: expected match on wire-id-fp-a")
	}
}

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

// TestBadgeMarshalRoundTripsV2 proves a decoded V2 badge re-encodes with V2
// wire names and decodes again without losing certificates or DNS records.
func TestBadgeMarshalRoundTripsV2(t *testing.T) {
	in := loadBadgeFixture(t, "testdata/badge-v2.json")
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"serverCerts"`, `"identityCerts"`, `"dnsRecordsProvisioned":[`} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("marshaled V2 badge missing %s: %s", want, data)
		}
	}
	for _, reject := range []string{`"validServerCerts"`, `"validIdentityCerts"`, `"serverCert"`} {
		if bytes.Contains(data, []byte(reject)) {
			t.Errorf("marshaled V2 badge must not contain %s: %s", reject, data)
		}
	}

	var out Badge
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v; json=%s", err, data)
	}
	if got := out.ServerCertFingerprints(); len(got) != 2 || got[0] != "v2-srv-fp-a" || got[1] != "v2-srv-fp-b" {
		t.Errorf("ServerCertFingerprints after round trip = %v", got)
	}
	if got := out.IdentityCertFingerprints(); len(got) != 1 || got[0] != "v2-id-fp-a" {
		t.Errorf("IdentityCertFingerprints after round trip = %v", got)
	}
	att := out.Payload.Producer.Event.Attestations
	if len(att.DNSRecordsProvisionedV2) != 1 || att.DNSRecordsProvisionedV2[0].Name != "_ans.agent.example.com" {
		t.Errorf("DNSRecordsProvisionedV2 after round trip = %+v", att.DNSRecordsProvisionedV2)
	}
	if att.MetadataHashes["agent.json"] != "sha256-abc" {
		t.Errorf("MetadataHashes after round trip = %+v", att.MetadataHashes)
	}
	if out.SchemaVersion != SchemaVersionV2 || out.Status != BadgeStatusActive || out.Payload.LogID != "log-456" {
		t.Errorf("envelope fields after round trip: version=%q status=%q logId=%q", out.SchemaVersion, out.Status, out.Payload.LogID)
	}
}

// TestBadgeMarshalRoundTripsV1 proves a V1 badge keeps singular certs and the
// map-shaped DNS records across Marshal->Unmarshal.
func TestBadgeMarshalRoundTripsV1(t *testing.T) {
	in := loadBadgeFixture(t, "testdata/badge-v1.json")
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(data, []byte(`"serverCert":{`)) || !bytes.Contains(data, []byte(`"dnsRecordsProvisioned":{`)) {
		t.Errorf("marshaled V1 badge lost V1 wire shape: %s", data)
	}
	var out Badge
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v; json=%s", err, data)
	}
	if got := out.ServerCertFingerprints(); len(got) != 1 || got[0] != "v1-srv-fp" {
		t.Errorf("ServerCertFingerprints after round trip = %v", got)
	}
	if got := out.IdentityCertFingerprints(); len(got) != 1 || got[0] != "v1-id-fp" {
		t.Errorf("IdentityCertFingerprints after round trip = %v", got)
	}
	if out.Payload.Producer.Event.Attestations.DNSRecordsProvisioned["_ans.agent.example.com"] != "txt-data" {
		t.Errorf("DNSRecordsProvisioned after round trip = %+v", out.Payload.Producer.Event.Attestations.DNSRecordsProvisioned)
	}
}

// TestBadgeMarshalV2FoldsSingularCerts proves a V2-tagged badge built with the
// V1 singular cert fields (as older callers do) still emits those certs.
func TestBadgeMarshalV2FoldsSingularCerts(t *testing.T) {
	b := Badge{SchemaVersion: SchemaVersionV2, Status: BadgeStatusActive}
	b.Payload.Producer.Event.Attestations = Attestations{
		ServerCert:   &CertAttestationV1{Fingerprint: "srv", Type: "X509-DV-SERVER"},
		IdentityCert: &CertAttestationV1{Fingerprint: "id", Type: "X509-OV-CLIENT"},
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Badge
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v; json=%s", err, data)
	}
	if got := out.ServerCertFingerprints(); len(got) != 1 || got[0] != "srv" {
		t.Errorf("ServerCertFingerprints = %v; json=%s", got, data)
	}
	if got := out.IdentityCertFingerprints(); len(got) != 1 || got[0] != "id" {
		t.Errorf("IdentityCertFingerprints = %v; json=%s", got, data)
	}
}

// TestBadgeMarshalUnknownVersionUsesV1 proves a badge with no schemaVersion
// encodes and decodes through the V1 codec, matching the decode fallback.
func TestBadgeMarshalUnknownVersionUsesV1(t *testing.T) {
	b := Badge{Status: BadgeStatusActive}
	b.Payload.Producer.Event.Attestations.ServerCert = &CertAttestationV1{Fingerprint: "srv", Type: "X509-DV-SERVER"}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(data, []byte(`"serverCert":{`)) {
		t.Errorf("unknown-version badge should use V1 wire shape: %s", data)
	}
	var out Badge
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := out.ServerCertFingerprint(); got != "srv" {
		t.Errorf("ServerCertFingerprint = %q", got)
	}
}

func TestBadgeUnmarshalRejectsMalformedAttestations(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "V1 array dns in map field",
			raw:  `{"schemaVersion":"V1","payload":{"producer":{"event":{"attestations":{"dnsRecordsProvisioned":[1]}}}}}`,
		},
		{
			name: "V2 map dns in array field",
			raw:  `{"schemaVersion":"V2","payload":{"producer":{"event":{"attestations":{"dnsRecordsProvisioned":{"a":"b"}}}}}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b Badge
			err := json.Unmarshal([]byte(tt.raw), &b)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), "parse attestations") {
				t.Errorf("error should name the attestations stage: %v", err)
			}
		})
	}
}

func TestDNSRecordAttestationDNSSECVerified(t *testing.T) {
	raw := []byte(`{"name":"_443._tcp.agent.example.com","data":"3 1 1 abcd","type":"TLSA","dnssecVerified":true}`)
	var rec DNSRecordAttestation
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !rec.DNSSECVerified {
		t.Fatal("DNSSECVerified should be true")
	}
	data, err := json.Marshal(DNSRecordAttestation{Name: "n", Data: "d", Type: "TXT"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(data, []byte("dnssecVerified")) {
		t.Errorf("false DNSSECVerified must be omitted: %s", data)
	}
}
