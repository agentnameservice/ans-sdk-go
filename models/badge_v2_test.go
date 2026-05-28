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
