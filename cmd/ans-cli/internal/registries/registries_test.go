package registries

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const fixture = `{
  "schemaVersion": 1,
  "updatedAt": "2026-11-18T00:00:00Z",
  "registries": [
    {
      "id": "example",
      "operator": "Example",
      "documentation": "https://example.com/docs/ans",
      "environments": {
        "test": {"ra": "https://ra.test.example.com", "tl": "https://tl.test.example.com"},
        "production": {
          "ra": "https://ra.example.com",
          "tl": "https://tl.example.com",
          "identityCa": {"url": "https://example.com/pki/ca-bundle.pem", "sha256": "4a3267581421b6e98470ff3a3c1ee422467facde0e12f22e57248bb56f99c443"}
        }
      }
    },
    {
      "id": "other",
      "operator": "Other",
      "environments": {
        "test": {"ra": "https://ra.other.example:8443", "tl": "https://tl.other.example"}
      }
    }
  ]
}`

func mustParse(t *testing.T) List {
	t.Helper()
	l, err := Parse([]byte(fixture))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return l
}

func TestParse(t *testing.T) {
	l := mustParse(t)
	if got, want := strings.Join(l.IDs(), ","), "example,other"; got != want {
		t.Errorf("IDs = %q, want %q", got, want)
	}
	r, err := l.Get("example")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := strings.Join(r.EnvironmentNames(), ","), "production,test"; got != want {
		t.Errorf("EnvironmentNames = %q, want %q (production first regardless of document order)", got, want)
	}
	if r.Documentation != "https://example.com/docs/ans" || r.Operator != "Example" {
		t.Errorf("operator fields = %q %q", r.Operator, r.Documentation)
	}
	prod := r.Environments[EnvironmentProduction]
	if prod.IdentityCA == nil || prod.IdentityCA.URL != "https://example.com/pki/ca-bundle.pem" || len(prod.IdentityCA.SHA256) != 64 {
		t.Errorf("production identityCa = %+v", prod.IdentityCA)
	}
	if r.Environments[EnvironmentTest].IdentityCA != nil {
		t.Error("test environment should carry no identityCa")
	}
}

func TestParseRejects(t *testing.T) {
	entry := func(body string) string {
		return `{"id": "a", "operator": "A", "environments": {` + body + `}}`
	}
	tests := []struct {
		name string
		body string
		want string
	}{
		{"not json", `{`, "known-registries"},
		{"schema version", `{"schemaVersion": 2, "registries": []}`, "unsupported schemaVersion 2"},
		{"empty id", `{"schemaVersion": 1, "registries": [{"id": ""}]}`, "empty id"},
		{"no registries", `{"schemaVersion": 1, "registries": []}`, "no registries listed"},
		{"id with separator", `{"schemaVersion": 1, "registries": [{"id": "a/b", "operator": "A", "environments": {"test": {"ra": "https://r", "tl": "https://t"}}}]}`, `id "a/b" must match`},
		{"id upper case", `{"schemaVersion": 1, "registries": [{"id": "Ab", "operator": "A", "environments": {"test": {"ra": "https://r", "tl": "https://t"}}}]}`, `id "Ab" must match`},
		{"id leading hyphen", `{"schemaVersion": 1, "registries": [{"id": "-a", "operator": "A", "environments": {"test": {"ra": "https://r", "tl": "https://t"}}}]}`, `id "-a" must match`},
		{"id trailing hyphen", `{"schemaVersion": 1, "registries": [{"id": "a-", "operator": "A", "environments": {"test": {"ra": "https://r", "tl": "https://t"}}}]}`, `id "a-" must match`},
		{"id double hyphen", `{"schemaVersion": 1, "registries": [{"id": "a--b", "operator": "A", "environments": {"test": {"ra": "https://r", "tl": "https://t"}}}]}`, `id "a--b" must match`},
		{"documentation http", `{"schemaVersion": 1, "registries": [{"id": "a", "operator": "A", "documentation": "http://docs.example", "environments": {"test": {"ra": "https://r", "tl": "https://t"}}}]}`, `documentation: "http://docs.example" is not an https URL`},
		{"documentation unparsable", `{"schemaVersion": 1, "registries": [{"id": "a", "operator": "A", "documentation": "https://%zz", "environments": {"test": {"ra": "https://r", "tl": "https://t"}}}]}`, `documentation: "https://%zz"`},
		{"documentation javascript", `{"schemaVersion": 1, "registries": [{"id": "a", "operator": "A", "documentation": "javascript:alert(1)", "environments": {"test": {"ra": "https://r", "tl": "https://t"}}}]}`, "documentation:"},
		{"identityCa url http", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"ra": "https://r", "tl": "https://t", "identityCa": {"url": "http://x.example/ca.pem", "sha256": "`+strings.Repeat("a", 64)+`"}}`) + `]}`, `test: identityCa.url: "http://x.example/ca.pem" is not an https URL`},
		{"identityCa sha256 short", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"ra": "https://r", "tl": "https://t", "identityCa": {"url": "https://x.example/ca.pem", "sha256": "`+strings.Repeat("a", 63)+`"}}`) + `]}`, "test: identityCa.sha256"},
		{"identityCa sha256 upper case", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"ra": "https://r", "tl": "https://t", "identityCa": {"url": "https://x.example/ca.pem", "sha256": "`+strings.Repeat("A", 64)+`"}}`) + `]}`, "not 64 lower-case hex digits"},
		{"tl upper-case scheme", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"ra": "https://r", "tl": "HTTPS://t.example"}`) + `]}`, `test: tl: "HTTPS://t.example" is not an https origin`},
		{"environments reported in sorted order", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"ra": "bad", "tl": "https://t"}, "production": {"ra": "bad", "tl": "https://t"}`) + `]}`, `production: ra: "bad"`},
		{"duplicate id", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"ra": "https://r", "tl": "https://t"}`) + `,` + entry(`"test": {"ra": "https://r", "tl": "https://t"}`) + `]}`, `duplicate id "a"`},
		{"missing operator", `{"schemaVersion": 1, "registries": [{"id": "a", "environments": {"test": {"ra": "https://r", "tl": "https://t"}}}]}`, "a: operator is required"},
		{"no environments", `{"schemaVersion": 1, "registries": [{"id": "a", "operator": "A"}]}`, "at least one environment"},
		{"unknown environment", `{"schemaVersion": 1, "registries": [` + entry(`"staging": {"ra": "https://r", "tl": "https://t"}`) + `]}`, `unknown environment "staging"`},
		{"missing ra", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"tl": "https://t"}`) + `]}`, `test: ra: "" is not an https origin`},
		{"ra with path", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"ra": "https://r.example/v1", "tl": "https://t"}`) + `]}`, "test: ra:"},
		{"tl http", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"ra": "https://r", "tl": "http://t.example"}`) + `]}`, `test: tl: "http://t.example" is not an https origin`},
		{"tl without host", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"ra": "https://r", "tl": "https://"}`) + `]}`, "test: tl:"},
		{"tl unparsable", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"ra": "https://r", "tl": "https://%zz"}`) + `]}`, "test: tl:"},
		{"tl with user info", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"ra": "https://r", "tl": "https://u@t.example"}`) + `]}`, "not an https origin"},
		{"tl with trailing slash", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"ra": "https://r", "tl": "https://t.example/"}`) + `]}`, `test: tl: "https://t.example/" is not an https origin`},
		{"tl with empty query", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"ra": "https://r", "tl": "https://t.example?"}`) + `]}`, "test: tl:"},
		{"tl with empty fragment", `{"schemaVersion": 1, "registries": [` + entry(`"test": {"ra": "https://r", "tl": "https://t.example#"}`) + `]}`, "test: tl:"},
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

func TestSelect(t *testing.T) {
	l := mustParse(t)
	tests := []struct {
		name      string
		value     string
		wantRA    string
		wantTL    string
		wantErrIs error
		wantSub   string
	}{
		{name: "production", value: "example/production", wantRA: "https://ra.example.com", wantTL: "https://tl.example.com"},
		{name: "test", value: "example/test", wantRA: "https://ra.test.example.com", wantTL: "https://tl.test.example.com"},
		{name: "port is part of the origin", value: "other/test", wantRA: "https://ra.other.example:8443", wantTL: "https://tl.other.example"},
		{name: "environment required even with one environment", value: "other", wantErrIs: ErrEnvironmentRequired, wantSub: "--registry other/<environment>"},
		{name: "trailing separator", value: "example/", wantErrIs: ErrEnvironmentRequired, wantSub: "production and test"},
		{name: "unknown environment", value: "example/staging", wantErrIs: ErrUnknownEnvironment, wantSub: `"example" runs production and test`},
		{name: "nested separator", value: "example/production/extra", wantErrIs: ErrUnknownEnvironment},
		{name: "unknown registry", value: "nope/production", wantErrIs: ErrUnknownRegistry, wantSub: "example, other"},
		{name: "empty value", value: "", wantErrIs: ErrUnknownRegistry},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sel, err := l.Select(tt.value)
			if tt.wantErrIs != nil {
				if !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("err = %v, want %v", err, tt.wantErrIs)
				}
				if tt.wantSub != "" && !strings.Contains(err.Error(), tt.wantSub) {
					t.Errorf("err %q missing %q", err, tt.wantSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("Select: %v", err)
			}
			if sel.Environment.RA != tt.wantRA || sel.Environment.TL != tt.wantTL {
				t.Errorf("Select = %+v, want ra %q tl %q", sel.Environment, tt.wantRA, tt.wantTL)
			}
			if sel.String() != tt.value {
				t.Errorf("String() = %q, want %q", sel.String(), tt.value)
			}
		})
	}
}

func TestGet(t *testing.T) {
	l := mustParse(t)
	_, err := l.Get("nope")
	if !errors.Is(err, ErrUnknownRegistry) {
		t.Fatalf("Get unknown: err = %v, want ErrUnknownRegistry", err)
	}
	if !strings.Contains(err.Error(), "example, other") {
		t.Errorf("error should list known ids, got %q", err)
	}

	var empty List
	if _, err := empty.Get("example"); !errors.Is(err, ErrNoRegistries) {
		t.Errorf("empty Get: err = %v, want ErrNoRegistries", err)
	}
	if _, err := empty.Select("example/production"); !errors.Is(err, ErrNoRegistries) {
		t.Errorf("empty Select: err = %v, want ErrNoRegistries", err)
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
	if l.SpecRef != "v1.2.3" || len(l.Registries) != 2 {
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
