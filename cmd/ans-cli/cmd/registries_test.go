package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/registries"
)

const registriesFixture = `{
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
      "tl": {"baseUrl": "https://tl.test.example.com", "verificationKeys": []}
    }
  ]
}`

// withFixtureRegistries makes knownRegistries return the fixture for the
// duration of the test, as a release build would after ldflags injection.
func withFixtureRegistries(t *testing.T) {
	t.Helper()
	list, err := registries.Parse([]byte(registriesFixture))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	list.SpecRef = "v9.9.9"
	prev := knownRegistries
	knownRegistries = func() (registries.List, error) { return list, nil }
	t.Cleanup(func() { knownRegistries = prev })
}

func withNoRegistries(t *testing.T) {
	t.Helper()
	prev := knownRegistries
	knownRegistries = func() (registries.List, error) { return registries.List{}, nil }
	t.Cleanup(func() { knownRegistries = prev })
}

func withBrokenRegistries(t *testing.T, err error) {
	t.Helper()
	prev := knownRegistries
	knownRegistries = func() (registries.List, error) { return registries.List{}, err }
	t.Cleanup(func() { knownRegistries = prev })
}

func TestRunRegistries_Table(t *testing.T) {
	withFixtureRegistries(t)
	var out bytes.Buffer
	if err := runRegistries(&out, false); err != nil {
		t.Fatalf("runRegistries: %v", err)
	}
	got := out.String()
	for _, want := range []string{"ans-spec v9.9.9", "example-production", "example-test", "https://ra.example.com", "https://tl.test.example.com", "usable", "pending", "REGISTRATION AUTHORITY"} {
		if !strings.Contains(got, want) {
			t.Errorf("table missing %q:\n%s", want, got)
		}
	}
}

func TestRunRegistries_JSON(t *testing.T) {
	withFixtureRegistries(t)
	var out bytes.Buffer
	if err := runRegistries(&out, true); err != nil {
		t.Fatalf("runRegistries: %v", err)
	}
	var doc struct {
		SpecRef    string `json:"specRef"`
		Registries []struct {
			ID string `json:"id"`
		} `json:"registries"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if doc.SpecRef != "v9.9.9" || len(doc.Registries) != 2 || doc.Registries[0].ID != "example-production" {
		t.Errorf("unexpected JSON: %s", out.String())
	}
}

func TestRunRegistries_EmptyBuild(t *testing.T) {
	withNoRegistries(t)
	var out bytes.Buffer
	if err := runRegistries(&out, false); err != nil {
		t.Fatalf("runRegistries: %v", err)
	}
	if !strings.Contains(out.String(), "no known-registries list") {
		t.Errorf("empty build should explain itself, got %q", out.String())
	}
}

func TestRunRegistries_LoaderError(t *testing.T) {
	boom := errors.New("corrupt injection")
	withBrokenRegistries(t, boom)
	if err := runRegistries(&bytes.Buffer{}, false); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

func TestResolveBaseURL(t *testing.T) {
	withFixtureRegistries(t)
	tests := []struct {
		name      string
		cfg       config.Config
		want      string
		wantErrIs error
		wantSub   string
	}{
		{name: "explicit base URL wins", cfg: config.Config{BaseURL: "https://flag.example", Registry: "example-production"}, want: "https://flag.example"},
		{name: "registry supplies the RA URL", cfg: config.Config{Registry: "example-production"}, want: "https://ra.example.com"},
		{name: "pending registries are still selectable by id", cfg: config.Config{Registry: "example-test"}, want: "https://ra.test.example.com"},
		{name: "unknown registry", cfg: config.Config{Registry: "nope"}, wantErrIs: registries.ErrUnknownRegistry},
		{name: "nothing configured", cfg: config.Config{}, wantErrIs: config.ErrNoBaseURL, wantSub: "--registry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveBaseURL(&tt.cfg)
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
				t.Fatalf("err = %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveBaseURL_NoListInBuild(t *testing.T) {
	withNoRegistries(t)
	_, err := resolveBaseURL(&config.Config{Registry: "example-production"})
	if !errors.Is(err, registries.ErrNoRegistries) {
		t.Fatalf("err = %v, want ErrNoRegistries", err)
	}
	if !strings.Contains(err.Error(), "--base-url") {
		t.Errorf("error should point at --base-url, got %q", err)
	}
}

func TestResolveRegistryURLs_LoaderError(t *testing.T) {
	boom := errors.New("corrupt injection")
	withBrokenRegistries(t, boom)
	if _, err := resolveRegistryURLs("example-production"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

func TestCreateClient_UsesRegistry(t *testing.T) {
	withFixtureRegistries(t)
	client, err := createClient(&config.Config{APIVersion: "v1", Registry: "example-production", APIKey: "k:s"})
	if err != nil {
		t.Fatalf("createClient: %v", err)
	}
	if client == nil {
		t.Fatal("nil client")
	}
}

func TestCreateClient_NoBaseURL(t *testing.T) {
	withNoRegistries(t)
	_, err := createClient(&config.Config{APIVersion: "v1", APIKey: "k:s"})
	if !errors.Is(err, config.ErrNoBaseURL) {
		t.Fatalf("err = %v, want ErrNoBaseURL", err)
	}
}
