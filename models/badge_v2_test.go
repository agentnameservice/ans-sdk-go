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
	if len(att.DNSRecordsProvisioned) != 1 {
		t.Fatalf("DNSRecordsProvisioned: want 1, got %d; attestations=%+v", len(att.DNSRecordsProvisioned), att)
	}
	if att.MetadataHashes["agent.json"] != "sha256-abc" {
		t.Fatalf("MetadataHashes missing or wrong: %+v", att.MetadataHashes)
	}
}
