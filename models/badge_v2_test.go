package models

import (
	"encoding/json"
	"os"
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
