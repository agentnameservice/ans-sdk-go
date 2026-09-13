package models

import (
	"encoding/json"
	"testing"
)

func TestAttestationsV1ParsesV1DnsRecordsMap(t *testing.T) {
	raw := []byte(`{
		"identityCert": {"fingerprint":"id","type":"X509-OV-CLIENT"},
		"dnsRecordsProvisioned": {"_ans.foo.example": "txt-data"}
	}`)
	var att AttestationsV1
	if err := json.Unmarshal(raw, &att); err != nil {
		t.Fatalf("unmarshal: %v; raw=%s", err, raw)
	}
	if got := att.DNSRecordsProvisioned["_ans.foo.example"]; got != "txt-data" {
		t.Fatalf("DNSRecordsProvisioned[_ans.foo.example]: want txt-data, got %q; map=%+v", got, att.DNSRecordsProvisioned)
	}
}

func TestAttestationsV1ParsesEmptyDnsRecords(t *testing.T) {
	raw := []byte(`{"identityCert": {"fingerprint":"id","type":"X509-OV-CLIENT"}}`)
	var att AttestationsV1
	if err := json.Unmarshal(raw, &att); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(att.DNSRecordsProvisioned) != 0 {
		t.Fatalf("DNSRecordsProvisioned: want empty, got %+v", att.DNSRecordsProvisioned)
	}
}

func TestAttestationsV1RoundTripsMapDnsShape(t *testing.T) {
	in := AttestationsV1{
		DNSRecordsProvisioned: map[string]string{"_ans.x": "d"},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out AttestationsV1
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v; json=%s", err, data)
	}
	if out.DNSRecordsProvisioned["_ans.x"] != "d" {
		t.Fatalf("v1 round-trip lost data: %+v (json=%s)", out, data)
	}
}

func TestAttestationsV2ParsesArrayDnsRecords(t *testing.T) {
	raw := []byte(`{
		"serverCerts":[{"fingerprint":"v2-srv","type":"X509-DV-SERVER"}],
		"identityCerts":[{"fingerprint":"v2-id","type":"X509-OV-CLIENT"}],
		"dnsRecordsProvisioned":[{"name":"_ans.x","data":"d","type":"TXT"}],
		"metadataHashes":{"agent.json":"sha256-abc"}
	}`)
	var att AttestationsV2
	if err := json.Unmarshal(raw, &att); err != nil {
		t.Fatalf("unmarshal: %v; raw=%s", err, raw)
	}
	if len(att.ServerCerts) != 1 || att.ServerCerts[0].Fingerprint != "v2-srv" {
		t.Fatalf("ServerCerts: %+v", att.ServerCerts)
	}
	if len(att.IdentityCerts) != 1 || att.IdentityCerts[0].Fingerprint != "v2-id" {
		t.Fatalf("IdentityCerts: %+v", att.IdentityCerts)
	}
	if len(att.DNSRecordsProvisioned) != 1 || att.DNSRecordsProvisioned[0].Name != "_ans.x" {
		t.Fatalf("DNSRecordsProvisioned: %+v", att.DNSRecordsProvisioned)
	}
	if att.MetadataHashes["agent.json"] != "sha256-abc" {
		t.Fatalf("MetadataHashes: %+v", att.MetadataHashes)
	}
}

func TestAttestationsV2RoundTrips(t *testing.T) {
	in := AttestationsV2{
		ServerCerts: []CertificateV1Extended{
			{CertificateV1: CertificateV1{Fingerprint: "fp-a", Type: CertTypeX509DVServer}},
		},
		DNSRecordsProvisioned: []DNSRecordAttestation{{Name: "_ans.x", Data: "d", Type: "TXT"}},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out AttestationsV2
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v; json=%s", err, data)
	}
	if len(out.ServerCerts) != 1 || out.ServerCerts[0].Fingerprint != "fp-a" {
		t.Fatalf("ServerCerts round-trip: %+v (json=%s)", out, data)
	}
	if len(out.DNSRecordsProvisioned) != 1 || out.DNSRecordsProvisioned[0].Name != "_ans.x" {
		t.Fatalf("DNS round-trip: %+v (json=%s)", out, data)
	}
}
