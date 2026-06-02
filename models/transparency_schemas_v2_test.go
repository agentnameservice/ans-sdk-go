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

// TestAttestationsV1RoundTripsMapDnsShape proves Marshal re-emits the V1
// map-shaped dnsRecordsProvisioned so values survive a decode/encode round-trip.
// V2 array DNS round-trips through Badge (version-dispatched), not AttestationsV1.
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
