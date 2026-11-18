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
  "updatedAt": "2026-11-18T00:00:00Z",
  "registries": [
    {
      "id": "example",
      "operator": "Example",
      "documentation": "https://example.com/docs/ans",
      "environments": {
        "production": {"ra": "https://ra.example.com", "tl": "https://tl.example.com"},
        "test": {"ra": "https://ra.test.example.com", "tl": "https://tl.test.example.com"}
      }
    },
    {
      "id": "other",
      "operator": "Other",
      "environments": {
        "test": {"ra": "https://ra.other.example", "tl": "https://tl.other.example"}
      }
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
	for _, want := range []string{
		"ans-spec v9.9.9",
		"REGISTRY", "OPERATOR", "REGISTRATION AUTHORITY", "TRANSPARENCY LOG",
		"example/production", "example/test", "other/test",
		"https://ra.example.com", "https://tl.test.example.com", "https://tl.other.example",
		"example documentation: https://example.com/docs/ans",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("table missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "other documentation") {
		t.Errorf("entry without documentation should print no documentation line:\n%s", got)
	}
	if prod, test := strings.Index(got, "example/production"), strings.Index(got, "example/test"); prod > test {
		t.Errorf("production should be listed before test:\n%s", got)
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
			ID           string `json:"id"`
			Operator     string `json:"operator"`
			Environments map[string]struct {
				RA string `json:"ra"`
				TL string `json:"tl"`
			} `json:"environments"`
		} `json:"registries"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if doc.SpecRef != "v9.9.9" || len(doc.Registries) != 2 || doc.Registries[0].ID != "example" {
		t.Fatalf("unexpected JSON: %s", out.String())
	}
	if got := doc.Registries[0].Environments["production"].TL; got != "https://tl.example.com" {
		t.Errorf("production tl = %q", got)
	}
}

func TestRunRegistries_EmptyBuild(t *testing.T) {
	withNoRegistries(t)
	tests := []struct {
		name   string
		asJSON bool
	}{
		{name: "table", asJSON: false},
		{name: "json", asJSON: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := runRegistries(&out, tt.asJSON)
			if !errors.Is(err, registries.ErrNoRegistries) {
				t.Fatalf("err = %v, want ErrNoRegistries", err)
			}
			if out.Len() != 0 {
				t.Errorf("empty build must write nothing to stdout, got %q", out.String())
			}
		})
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
		{name: "explicit base URL wins", cfg: config.Config{BaseURL: "https://flag.example", Registry: "example/production"}, want: "https://flag.example"},
		{name: "registry environment supplies the RA URL", cfg: config.Config{Registry: "example/production"}, want: "https://ra.example.com"},
		{name: "test environment", cfg: config.Config{Registry: "example/test"}, want: "https://ra.test.example.com"},
		{name: "environment is required", cfg: config.Config{Registry: "example"}, wantErrIs: registries.ErrEnvironmentRequired, wantSub: "example/<environment>"},
		{name: "unknown environment", cfg: config.Config{Registry: "example/staging"}, wantErrIs: registries.ErrUnknownEnvironment},
		{name: "unknown registry", cfg: config.Config{Registry: "nope/production"}, wantErrIs: registries.ErrUnknownRegistry},
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
	_, err := resolveBaseURL(&config.Config{Registry: "example/production"})
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
	if _, err := resolveRegistryURLs("example/production"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

func TestCreateClient_UsesRegistry(t *testing.T) {
	withFixtureRegistries(t)
	client, err := createClient(&config.Config{APIVersion: "v1", Registry: "example/production", APIKey: "k:s"})
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
