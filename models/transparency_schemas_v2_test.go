package models

import (
	"encoding/json"
	"testing"
)

func TestAttestationsV1ParsesV2DnsRecordsArray(t *testing.T) {
	raw := []byte(`{
		"validServerCerts": [{"fingerprint":"a","type":"X509-DV-SERVER"}],
		"dnsRecordsProvisioned": [{"name":"_ans.foo.example","data":"x","type":"TXT"}]
	}`)
	var att AttestationsV1
	if err := json.Unmarshal(raw, &att); err != nil {
		t.Fatalf("unmarshal: %v; raw=%s", err, raw)
	}
	if len(att.DNSRecordsProvisionedV2) != 1 {
		t.Fatalf("DNSRecordsProvisionedV2: want 1, got %d; att=%+v", len(att.DNSRecordsProvisionedV2), att)
	}
	if att.DNSRecordsProvisionedV2[0].Name != "_ans.foo.example" {
		t.Fatalf("Name: want _ans.foo.example, got %q", att.DNSRecordsProvisionedV2[0].Name)
	}
}

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
	if len(att.DNSRecordsProvisionedV2) != 0 {
		t.Fatalf("DNSRecordsProvisionedV2: want empty for v1 map shape, got %+v", att.DNSRecordsProvisionedV2)
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
	if len(att.DNSRecordsProvisionedV2) != 0 {
		t.Fatalf("DNSRecordsProvisionedV2: want empty, got %+v", att.DNSRecordsProvisionedV2)
	}
}
