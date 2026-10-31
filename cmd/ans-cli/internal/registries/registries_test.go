package registries

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const fixture = `{
  "schemaVersion": 1,
  "updatedAt": "2026-10-31T00:00:00Z",
  "registries": [
    {
      "id": "example-production",
      "operator": {"name": "Example", "url": "https://example.com", "contact": "mailto:ops@example.com"},
      "environment": "production",
      "state": "usable",
      "since": "2026-01-01",
      "until": null,
      "ra": {"baseUrl": "https://ra.example.com", "apiVersions": ["v1", "v2"], "auth": ["sso-key", "bearer"]},
      "tl": {"baseUrl": "https://tl.example.com", "verificationKeys": ["tl.example.com+01234567+AjBZ"]}
    },
    {
      "id": "example-test",
      "operator": {"name": "Example", "url": "https://example.com", "contact": "mailto:ops@example.com"},
      "environment": "test",
      "state": "pending",
      "since": "2026-01-01",
      "until": null,
      "ra": {"baseUrl": "https://ra.test.example.com", "apiVersions": ["v2"], "auth": ["bearer"]},
      "tl": {"baseUrl": "https://TL.test.example.com", "verificationKeys": ["tl.test.example.com+89abcdef+AjBZ"]}
    },
    {
      "id": "example-old",
      "operator": {"name": "Example", "url": "https://example.com", "contact": "mailto:ops@example.com"},
      "environment": "production",
      "state": "retired",
      "since": "2025-01-01",
      "until": "2025-12-31",
      "ra": {"baseUrl": "https://old.example.com", "apiVersions": ["v1"], "auth": ["sso-key"]},
      "tl": {"baseUrl": "https://tl.old.example.com", "verificationKeys": []}
    }
  ]
}`

func TestParse(t *testing.T) {
	l, err := Parse([]byte(fixture))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := len(l.Registries), 3; got != want {
		t.Fatalf("len = %d, want %d", got, want)
	}
	if got, want := l.IDs(), []string{"example-production", "example-test", "example-old"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("IDs = %v, want %v", got, want)
	}
	if got, want := l.TLDomains(), []string{"tl.example.com"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("TLDomains = %v, want %v (pending and retired excluded)", got, want)
	}
	if got := len(l.Trusted()); got != 1 {
		t.Errorf("Trusted len = %d, want 1", got)
	}
	r, err := l.Get("example-test")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := r.TL.Host(), "tl.test.example.com"; got != want {
		t.Errorf("TL.Host = %q, want %q (lower-cased)", got, want)
	}
	if r.Trusted() {
		t.Error("pending registry reported trusted")
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"not json", `{`, "known-registries"},
		{"schema version", `{"schemaVersion": 2, "registries": []}`, "unsupported schemaVersion 2"},
		{"empty id", `{"schemaVersion": 1, "registries": [{"id": ""}]}`, "empty id"},
		{"duplicate id", `{"schemaVersion": 1, "registries": [
			{"id": "a", "ra": {"baseUrl": "https://r"}, "tl": {"baseUrl": "https://t"}},
			{"id": "a", "ra": {"baseUrl": "https://r"}, "tl": {"baseUrl": "https://t"}}]}`, `duplicate id "a"`},
		{"missing urls", `{"schemaVersion": 1, "registries": [{"id": "a"}]}`, "ra.baseUrl and tl.baseUrl are required"},
		{"tl without host", `{"schemaVersion": 1, "registries": [{"id": "a", "ra": {"baseUrl": "https://r"}, "tl": {"baseUrl": "https://"}}]}`, "has no host"},
		{"tl unparsable", `{"schemaVersion": 1, "registries": [{"id": "a", "ra": {"baseUrl": "https://r"}, "tl": {"baseUrl": "https://%zz"}}]}`, "has no host"},
		{"key name mismatch", `{"schemaVersion": 1, "registries": [{"id": "a", "ra": {"baseUrl": "https://r"}, "tl": {"baseUrl": "https://t.example", "verificationKeys": ["other.example+00000000+AA"]}}]}`, "does not match tl host"},
		{"key without separator", `{"schemaVersion": 1, "registries": [{"id": "a", "ra": {"baseUrl": "https://r"}, "tl": {"baseUrl": "https://t.example", "verificationKeys": ["t.example"]}}]}`, "does not match tl host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestGet(t *testing.T) {
	l, err := Parse([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.Get("nope")
	if !errors.Is(err, ErrUnknownRegistry) {
		t.Fatalf("Get unknown: err = %v, want ErrUnknownRegistry", err)
	}
	if !strings.Contains(err.Error(), "example-production") {
		t.Errorf("error should list known ids, got %q", err)
	}

	var empty List
	if _, err := empty.Get("example-production"); !errors.Is(err, ErrNoRegistries) {
		t.Errorf("empty Get: err = %v, want ErrNoRegistries", err)
	}
	if !empty.Empty() {
		t.Error("empty list not Empty")
	}
}

func TestFromInjected(t *testing.T) {
	l, err := fromInjected("", "")
	if err != nil || !l.Empty() {
		t.Fatalf("no injection: list=%v err=%v, want empty and nil", l, err)
	}

	enc := base64.StdEncoding.EncodeToString([]byte(fixture))
	l, err = fromInjected(enc, "v1.2.3")
	if err != nil {
		t.Fatalf("injected: %v", err)
	}
	if l.SpecRef != "v1.2.3" || len(l.Registries) != 3 {
		t.Errorf("injected list = ref %q, %d entries", l.SpecRef, len(l.Registries))
	}

	if _, err := fromInjected("!!not-base64!!", ""); err == nil || !strings.Contains(err.Error(), "not base64") {
		t.Errorf("bad base64: err = %v", err)
	}
	if _, err := fromInjected(base64.StdEncoding.EncodeToString([]byte(`{"schemaVersion": 9}`)), ""); err == nil {
		t.Error("bad document accepted")
	}
}

func TestKnownDefaultsToEmpty(t *testing.T) {
	l, err := Known()
	if err != nil {
		t.Fatalf("Known: %v", err)
	}
	if !l.Empty() {
		t.Fatal("test binary should carry no injected list")
	}
}
