package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/registries"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/trust"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/spf13/viper"
)

// testLogOrigin is the Transparency Log origin of the fixture registry's test
// environment; its keys must be named for its host.
const testLogOrigin = "https://tl.test.example.com"

// logSigner is a generated P-256 log key with the name /root-keys gives it.
type logSigner struct {
	priv *ecdsa.PrivateKey
	kid  [4]byte
	name string
}

func newLogSigner(t *testing.T, name string) *logSigner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	sum := sha256.Sum256(der)
	s := &logSigner{priv: priv, name: name}
	copy(s.kid[:], sum[:4])
	return s
}

func (s *logSigner) rootKeysLine(t *testing.T) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&s.priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return fmt.Sprintf("%s+%x+%s", s.name, s.kid, base64.StdEncoding.EncodeToString(append([]byte{0x02}, der...)))
}

// signedCheckpoint renders a C2SP signed note for origin == the signer's name.
func (s *logSigner) signedCheckpoint(t *testing.T, size uint64) []byte {
	t.Helper()
	var root [32]byte
	body := fmt.Sprintf("%s\n%d\n%s\n", s.name, size, base64.StdEncoding.EncodeToString(root[:]))
	digest := sha256.Sum256([]byte(body))
	sig, err := ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	blob := append(append([]byte{}, s.kid[:]...), sig...)
	return []byte(body + "\n— " + s.name + " " + base64.StdEncoding.EncodeToString(blob) + "\n")
}

// withRegistry installs a one-entry directory whose test environment has the
// given RA, TL, and optional identity CA reference.
func withRegistry(t *testing.T, ca *registries.IdentityCA) registries.Selected {
	t.Helper()
	env := map[string]any{"ra": "https://ra.test.example.com", "tl": testLogOrigin}
	if ca != nil {
		env["identityCa"] = map[string]string{"url": ca.URL, "sha256": ca.SHA256}
	}
	doc, err := json.Marshal(map[string]any{
		"schemaVersion": 1,
		"updatedAt":     "2026-11-18T00:00:00Z",
		"registries": []map[string]any{{
			"id": "example", "operator": "Example",
			"environments": map[string]any{"test": env},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	list, err := registries.Parse(doc)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	prev := knownRegistries
	knownRegistries = func() (registries.List, error) { return list, nil }
	t.Cleanup(func() { knownRegistries = prev })
	sel, err := list.Select("example/test")
	if err != nil {
		t.Fatal(err)
	}
	return sel
}

func testCA(t *testing.T, cn string, isCA bool) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func pemBundle(certs ...*x509.Certificate) []byte {
	out := make([]byte, 0, 2048*len(certs))
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mockDeps(client scitt.Client, httpClient *http.Client) trustDeps {
	return trustDeps{
		newLogClient: func(string) (scitt.Client, error) { return client, nil },
		httpClient:   httpClient,
	}
}

func TestBuildTrustSubcommands(t *testing.T) {
	root := buildRegistriesCmd()
	tests := []struct {
		name  string
		use   string
		flags []string
	}{
		{name: "fetch-keys", use: "fetch-keys <id>/<environment>"},
		{name: "fetch-ca", use: "fetch-ca <id>/<environment>"},
		{name: "trust-roots", use: "trust-roots <id>/<environment> --bundle <file>", flags: []string{"bundle", "only", "replace"}},
		{name: "show", use: "show <id>/<environment>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var found bool
			for _, sub := range root.Commands() {
				if sub.Name() != tt.name {
					continue
				}
				found = true
				if sub.Use != tt.use {
					t.Errorf("Use = %q, want %q", sub.Use, tt.use)
				}
				for _, f := range tt.flags {
					if sub.Flags().Lookup(f) == nil {
						t.Errorf("missing flag %q", f)
					}
				}
			}
			if !found {
				t.Fatalf("registries has no %q subcommand", tt.name)
			}
		})
	}
}

func TestTrustSubcommands_Execute(t *testing.T) {
	signer := newLogSigner(t, "tl.test.example.com")
	ca := testCA(t, "Root", true)
	bundle := writeTemp(t, "ca.pem", pemBundle(ca))

	tests := []struct {
		name    string
		args    []string
		wantErr string
		wantOut string
	}{
		{name: "fetch-keys through cobra", args: []string{"fetch-keys", "example/test"}, wantOut: "Saved 1 new key(s)"},
		{name: "fetch-ca without a reference", args: []string{"fetch-ca", "example/test"}, wantErr: "publishes no identity CA reference"},
		{name: "trust-roots requires --bundle", args: []string{"trust-roots", "example/test"}, wantErr: `required flag(s) "bundle"`},
		{name: "trust-roots through cobra", args: []string{"trust-roots", "example/test", "--bundle", bundle}, wantOut: "1 added"},
		{name: "show through cobra", args: []string{"show", "example/test"}, wantOut: "Transparency Log:       " + testLogOrigin},
		{name: "fetch-keys needs an argument", args: []string{"fetch-keys"}, wantErr: "accepts 1 arg"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withRegistry(t, nil)
			viper.Reset()
			t.Cleanup(viper.Reset)
			viper.Set("config-dir", t.TempDir())
			viper.Set("token", "")
			viper.Set("oauth-token", "")
			viper.Set("oauth-token-env", "")

			deps := mockDeps(scitt.NewMockClient().WithRootKeys([]string{signer.rootKeysLine(t)}), nil)
			cmd := buildRegistriesCmdWithDeps(deps)
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Execute: %v\n%s", err, out.String())
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("output missing %q:\n%s", tt.wantOut, out.String())
			}
		})
	}
}

func TestTrustSubcommands_ConfigLoadError(t *testing.T) {
	withRegistry(t, nil)
	for _, name := range []string{"fetch-keys", "fetch-ca", "trust-roots", "show"} {
		t.Run(name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			viper.Set("token-file", "") // explicitly empty makes config.Load fail
			cmd := buildRegistriesCmd()
			args := []string{name, "example/test"}
			if name == "trust-roots" {
				args = append(args, "--bundle", "x.pem")
			}
			cmd.SetArgs(args)
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "failed to load config") {
				t.Fatalf("err = %v, want config load failure", err)
			}
		})
	}
}

func TestRunFetchKeys(t *testing.T) {
	signer := newLogSigner(t, "tl.test.example.com")
	second := newLogSigner(t, "tl.test.example.com/2")
	renamed := &logSigner{priv: signer.priv, kid: signer.kid, name: "tl.test.example.com/renamed"}

	tests := []struct {
		name      string
		registry  string
		configDir func(t *testing.T) string
		preSaved  []string
		client    scitt.Client
		clientErr error
		asJSON    bool
		wantErr   string
		wantErrIs error
		wantOut   []string
		wantSaved int
	}{
		{
			name:      "first fetch saves every key",
			registry:  "example/test",
			client:    scitt.NewMockClient().WithRootKeys([]string{signer.rootKeysLine(t), second.rootKeysLine(t)}),
			wantOut:   []string{"Fetched 2 key(s) from " + testLogOrigin + "/root-keys", "Saved 2 new key(s) for example/test; 2 saved in total", signer.name, "badge --checkpoint --registry example/test"},
			wantSaved: 2,
		},
		{
			name:      "refresh keeps the saved key the log dropped",
			registry:  "example/test",
			preSaved:  []string{signer.rootKeysLine(t)},
			client:    scitt.NewMockClient().WithRootKeys([]string{second.rootKeysLine(t)}),
			wantOut:   []string{"Saved 1 new key(s) for example/test; 2 saved in total"},
			wantSaved: 2,
		},
		{
			name:     "json",
			registry: "example/test",
			client:   scitt.NewMockClient().WithRootKeys([]string{signer.rootKeysLine(t)}),
			asJSON:   true,
			wantOut:  []string{`"registry": "example/test"`, `"added": 1`, `"keyId": "` + hex.EncodeToString(signer.kid[:]) + `"`},
		},
		{
			name:      "collision is reported and fails without replacing the saved key",
			registry:  "example/test",
			preSaved:  []string{signer.rootKeysLine(t)},
			client:    scitt.NewMockClient().WithRootKeys([]string{renamed.rootKeysLine(t), second.rootKeysLine(t)}),
			wantErrIs: errKeyCollision,
			wantOut:   []string{"Refused key " + hex.EncodeToString(signer.kid[:]), `saved as "tl.test.example.com"`},
			wantSaved: 2,
		},
		{
			name:     "unknown registry",
			registry: "nope/test",
			client:   scitt.NewMockClient(),
			wantErr:  "unknown registry",
		},
		{
			name:      "no config dir",
			registry:  "example/test",
			configDir: func(*testing.T) string { return "" },
			client:    scitt.NewMockClient(),
			wantErrIs: trust.ErrNoConfigDir,
		},
		{
			name:      "log client cannot be built",
			registry:  "example/test",
			clientErr: errors.New("bad origin"),
			wantErr:   "transparency log client: bad origin",
		},
		{
			name:     "fetch fails",
			registry: "example/test",
			client:   scitt.NewMockClient().WithError("root-keys", errors.New("boom")),
			wantErr:  testLogOrigin + "/root-keys: boom",
		},
		{
			name:     "key named for another host is rejected",
			registry: "example/test",
			client:   scitt.NewMockClient().WithRootKeys([]string{newLogSigner(t, "evil.example").rootKeysLine(t)}),
			wantErr:  "does not name the log host",
		},
		{
			name:     "corrupt saved file is reported",
			registry: "example/test",
			preSaved: []string{"garbage"},
			client:   scitt.NewMockClient().WithRootKeys([]string{signer.rootKeysLine(t)}),
			wantErr:  "move the file aside",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withRegistry(t, nil)
			dir := t.TempDir()
			if tt.configDir != nil {
				dir = tt.configDir(t)
			}
			if len(tt.preSaved) > 0 {
				path := filepath.Join(dir, "registries", "example", "test", "tl-keys.txt")
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(strings.Join(tt.preSaved, "\n")+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			deps := mockDeps(tt.client, nil)
			if tt.clientErr != nil {
				deps.newLogClient = func(string) (scitt.Client, error) { return nil, tt.clientErr }
			}
			cfg := &config.Config{Registry: tt.registry, ConfigDir: dir, JSON: tt.asJSON}
			var out bytes.Buffer
			err := runFetchKeys(context.Background(), &out, cfg, tt.registry, deps)
			if tt.wantErr != "" || tt.wantErrIs != nil {
				if err == nil {
					t.Fatalf("expected error, output:\n%s", out.String())
				}
				if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("err = %v, want containing %q", err, tt.wantErr)
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Errorf("err = %v, want Is %v", err, tt.wantErrIs)
				}
			} else if err != nil {
				t.Fatalf("runFetchKeys: %v", err)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output missing %q:\n%s", want, out.String())
				}
			}
			if tt.wantSaved > 0 {
				store, _ := trust.NewStore(dir)
				keys, err := store.LoadKeys(trust.Scope{RegistryID: "example", Environment: "test"})
				if err != nil || len(keys) != tt.wantSaved {
					t.Errorf("saved keys = %d, %v; want %d", len(keys), err, tt.wantSaved)
				}
			}
		})
	}
}

func TestRunFetchCA(t *testing.T) {
	ca1 := testCA(t, "Root 1", true)
	ca2 := testCA(t, "Root 2", true)
	bundle := pemBundle(ca1, ca2)
	sum := sha256.Sum256(bundle)
	goodHash := hex.EncodeToString(sum[:])
	leafBundle := pemBundle(testCA(t, "Leaf", false))
	leafSum := sha256.Sum256(leafBundle)

	mux := http.NewServeMux()
	mux.HandleFunc("/ca.pem", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(bundle) })
	mux.HandleFunc("/leaf.pem", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(leafBundle) })
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	tests := []struct {
		name      string
		ca        *registries.IdentityCA
		configDir string
		asJSON    bool
		wantErr   string
		wantErrIs error
		wantOut   []string
	}{
		{
			name:    "downloads, checks the hash, saves, and does not trust",
			ca:      &registries.IdentityCA{URL: server.URL + "/ca.pem", SHA256: goodHash},
			wantOut: []string{"sha256 matches the directory", "2 CA certificate(s)", "CN=Root 1", "CN=Root 2", "NOT trusted", "registries trust-roots example/test --bundle"},
		},
		{
			name:    "json",
			ca:      &registries.IdentityCA{URL: server.URL + "/ca.pem", SHA256: goodHash},
			asJSON:  true,
			wantOut: []string{`"trusted": false`, `"subject": "CN=Root 1"`, `"sha256": "` + fingerprint(ca1) + `"`},
		},
		{name: "no reference", wantErr: "publishes no identity CA reference"},
		{
			name:      "hash mismatch",
			ca:        &registries.IdentityCA{URL: server.URL + "/ca.pem", SHA256: strings.Repeat("0", 64)},
			wantErrIs: trust.ErrBundleHashMismatch,
		},
		{
			name:    "bundle with a non-CA certificate",
			ca:      &registries.IdentityCA{URL: server.URL + "/leaf.pem", SHA256: hex.EncodeToString(leafSum[:])},
			wantErr: "is not a CA certificate",
		},
		{
			name:      "no config dir",
			ca:        &registries.IdentityCA{URL: server.URL + "/ca.pem", SHA256: goodHash},
			configDir: "-",
			wantErrIs: trust.ErrNoConfigDir,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withRegistry(t, tt.ca)
			dir := t.TempDir()
			if tt.configDir == "-" {
				dir = ""
			}
			cfg := &config.Config{Registry: "example/test", ConfigDir: dir, JSON: tt.asJSON}
			var out bytes.Buffer
			err := runFetchCA(context.Background(), &out, cfg, "example/test", mockDeps(nil, server.Client()))
			if tt.wantErr != "" || tt.wantErrIs != nil {
				if err == nil {
					t.Fatalf("expected error, output:\n%s", out.String())
				}
				if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("err = %v, want containing %q", err, tt.wantErr)
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Errorf("err = %v, want Is %v", err, tt.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("runFetchCA: %v", err)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output missing %q:\n%s", want, out.String())
				}
			}
			store, _ := trust.NewStore(dir)
			scope := trust.Scope{RegistryID: "example", Environment: "test"}
			if _, err := store.LoadRoots(scope); !errors.Is(err, trust.ErrNoTrustedRoots) {
				t.Errorf("fetch-ca must not trust roots: %v", err)
			}
			path, _ := store.BundlePath(scope)
			if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, bundle) {
				t.Errorf("saved bundle differs: %v", err)
			}
		})
	}
	t.Run("unknown registry", func(t *testing.T) {
		withRegistry(t, nil)
		err := runFetchCA(context.Background(), &bytes.Buffer{}, &config.Config{ConfigDir: t.TempDir()}, "nope/test", mockDeps(nil, server.Client()))
		if !errors.Is(err, registries.ErrUnknownRegistry) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestRunTrustRoots(t *testing.T) {
	ca1 := testCA(t, "Root 1", true)
	ca2 := testCA(t, "Root 2", true)
	ca3 := testCA(t, "Root 3", true)
	both := writeTemp(t, "both.pem", pemBundle(ca1, ca2))
	third := writeTemp(t, "third.pem", pemBundle(ca3))
	bad := writeTemp(t, "bad.pem", []byte("not pem"))

	tests := []struct {
		name        string
		pre         []string // bundles trusted first, in order
		opts        trustRootsOptions
		asJSON      bool
		configDir   string
		wantErr     string
		wantErrIs   error
		wantOut     []string
		wantSubject []string
	}{
		{
			name:        "trust a bundle",
			opts:        trustRootsOptions{bundlePath: both},
			wantOut:     []string{"2 added, 0 removed, 2 in total", "CN=Root 1", "CN=Root 2"},
			wantSubject: []string{"CN=Root 1", "CN=Root 2"},
		},
		{
			name:        "only one fingerprint",
			opts:        trustRootsOptions{bundlePath: both, only: []string{"  " + strings.ToUpper(fingerprint(ca2)) + " "}},
			wantOut:     []string{"1 added, 0 removed, 1 in total"},
			wantSubject: []string{"CN=Root 2"},
		},
		{
			name:    "only with a fingerprint not in the bundle",
			opts:    trustRootsOptions{bundlePath: both, only: []string{fingerprint(ca3)}},
			wantErr: "--only " + fingerprint(ca3) + ": no root in the bundle",
		},
		{
			name:        "adding keeps earlier roots",
			pre:         []string{both},
			opts:        trustRootsOptions{bundlePath: third},
			wantOut:     []string{"1 added, 0 removed, 3 in total"},
			wantSubject: []string{"CN=Root 1", "CN=Root 2", "CN=Root 3"},
		},
		{
			name:        "replace drops earlier roots",
			pre:         []string{both},
			opts:        trustRootsOptions{bundlePath: third, replace: true},
			wantOut:     []string{"1 added, 2 removed, 1 in total"},
			wantSubject: []string{"CN=Root 3"},
		},
		{
			name:    "json",
			opts:    trustRootsOptions{bundlePath: third},
			asJSON:  true,
			wantOut: []string{`"added": 1`, `"subject": "CN=Root 3"`},
		},
		{name: "missing bundle file", opts: trustRootsOptions{bundlePath: filepath.Join(t.TempDir(), "none.pem")}, wantErr: "--bundle:"},
		{name: "bundle is not PEM", opts: trustRootsOptions{bundlePath: bad}, wantErr: "--bundle " + bad + ": bundle holds no certificate"},
		{name: "no config dir", opts: trustRootsOptions{bundlePath: both}, configDir: "-", wantErrIs: trust.ErrNoConfigDir},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withRegistry(t, nil)
			dir := t.TempDir()
			if tt.configDir == "-" {
				dir = ""
			}
			cfg := &config.Config{Registry: "example/test", ConfigDir: dir, JSON: tt.asJSON}
			for _, p := range tt.pre {
				if err := runTrustRoots(&bytes.Buffer{}, cfg, "example/test", trustRootsOptions{bundlePath: p}); err != nil {
					t.Fatalf("pre-trust %s: %v", p, err)
				}
			}
			var out bytes.Buffer
			err := runTrustRoots(&out, cfg, "example/test", tt.opts)
			if tt.wantErr != "" || tt.wantErrIs != nil {
				if err == nil {
					t.Fatalf("expected error, output:\n%s", out.String())
				}
				if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("err = %v, want containing %q", err, tt.wantErr)
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Errorf("err = %v, want Is %v", err, tt.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("runTrustRoots: %v", err)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output missing %q:\n%s", want, out.String())
				}
			}
			if tt.wantSubject != nil {
				store, _ := trust.NewStore(dir)
				roots, err := store.LoadRoots(trust.Scope{RegistryID: "example", Environment: "test"})
				if err != nil {
					t.Fatal(err)
				}
				got := make([]string, len(roots))
				for i, r := range roots {
					got[i] = r.Cert.Subject.String()
				}
				if strings.Join(got, ",") != strings.Join(tt.wantSubject, ",") {
					t.Errorf("trusted = %v, want %v", got, tt.wantSubject)
				}
			}
		})
	}
	t.Run("unknown registry", func(t *testing.T) {
		withRegistry(t, nil)
		err := runTrustRoots(&bytes.Buffer{}, &config.Config{ConfigDir: t.TempDir()}, "nope/test", trustRootsOptions{bundlePath: both})
		if !errors.Is(err, registries.ErrUnknownRegistry) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestRunShowRegistry(t *testing.T) {
	signer := newLogSigner(t, "tl.test.example.com")
	ca := testCA(t, "Root", true)
	ref := &registries.IdentityCA{URL: "https://example.com/ca.pem", SHA256: strings.Repeat("a", 64)}

	tests := []struct {
		name      string
		ca        *registries.IdentityCA
		setup     func(t *testing.T, dir string)
		configDir string
		asJSON    bool
		wantErr   string
		wantOut   []string
		notOut    []string
	}{
		{
			name:    "nothing saved",
			ca:      ref,
			wantOut: []string{"Registry:               example/test (Example)", "Transparency Log:       " + testLogOrigin, "a reference, not a trust anchor", "Saved transparency log keys: none", "fetch-keys example/test", "Trusted CA roots: none", "trust-roots example/test --bundle"},
		},
		{
			name:    "no identity CA published",
			wantOut: []string{"Identity CA bundle:     none published"},
		},
		{
			name:      "no config dir",
			configDir: "-",
			wantOut:   []string{"Saved transparency log keys: none (no configuration directory", "Trusted CA roots: none (no configuration directory"},
			notOut:    []string{"Configuration:"},
		},
		{
			name: "keys and roots saved",
			setup: func(t *testing.T, dir string) {
				store, _ := trust.NewStore(dir)
				scope := trust.Scope{RegistryID: "example", Environment: "test"}
				keys, err := trust.ValidateKeyLines("tl.test.example.com", []string{signer.rootKeysLine(t)})
				if err != nil {
					t.Fatal(err)
				}
				if _, saveErr := store.SaveKeys(scope, keys); saveErr != nil {
					t.Fatal(saveErr)
				}
				roots, err := trust.ParseCABundle(pemBundle(ca))
				if err != nil {
					t.Fatal(err)
				}
				if _, trustErr := store.TrustRoots(scope, roots, false); trustErr != nil {
					t.Fatal(trustErr)
				}
			},
			wantOut: []string{"Saved transparency log keys: 1", hex.EncodeToString(signer.kid[:]) + "  tl.test.example.com", "Trusted CA roots: 1", "CN=Root (expires"},
		},
		{
			name:   "json with nothing saved has empty arrays",
			asJSON: true,
			wantOut: []string{
				`"registry": "example/test"`, `"savedKeys": []`, `"trustedRoots": []`,
			},
		},
		{
			name: "corrupt keys file is an error",
			setup: func(_ *testing.T, dir string) {
				path := filepath.Join(dir, "registries", "example", "test", "tl-keys.txt")
				_ = os.MkdirAll(filepath.Dir(path), 0o700)
				_ = os.WriteFile(path, []byte("garbage\n"), 0o600)
			},
			wantErr: "move the file aside",
		},
		{
			name: "corrupt roots file is an error",
			setup: func(_ *testing.T, dir string) {
				path := filepath.Join(dir, "registries", "example", "test", "trusted-roots.pem")
				_ = os.MkdirAll(filepath.Dir(path), 0o700)
				_ = os.WriteFile(path, []byte("garbage\n"), 0o600)
			},
			wantErr: "move the file aside",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withRegistry(t, tt.ca)
			dir := t.TempDir()
			if tt.configDir == "-" {
				dir = ""
			}
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			var out bytes.Buffer
			err := runShowRegistry(&out, &config.Config{ConfigDir: dir, JSON: tt.asJSON}, "example/test")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("runShowRegistry: %v", err)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output missing %q:\n%s", want, out.String())
				}
			}
			for _, not := range tt.notOut {
				if strings.Contains(out.String(), not) {
					t.Errorf("output should not contain %q:\n%s", not, out.String())
				}
			}
		})
	}
	t.Run("unknown registry", func(t *testing.T) {
		withRegistry(t, nil)
		if err := runShowRegistry(&bytes.Buffer{}, &config.Config{}, "nope/test"); !errors.Is(err, registries.ErrUnknownRegistry) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestLogHost(t *testing.T) {
	tests := []struct {
		origin  string
		want    string
		wantErr bool
	}{
		{origin: "https://tl.example.com", want: "tl.example.com"},
		{origin: "https://tl.example.com:8443", want: "tl.example.com"},
		{origin: "https://", wantErr: true},
		{origin: "https://%zz", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			got, err := logHost(tt.origin)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("logHost(%q) = %q, %v; want %q, err=%v", tt.origin, got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestFirstUnexpected(t *testing.T) {
	a, b := errors.New("a"), errors.New("b")
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "nil", err: nil, want: nil},
		{name: "expected sentinel", err: fmt.Errorf("wrap: %w", a), want: nil},
		{name: "unexpected", err: b, want: b},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstUnexpected(tt.err, a); !errors.Is(got, tt.want) || (got == nil) != (tt.want == nil) {
				t.Errorf("firstUnexpected = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultTrustDeps(t *testing.T) {
	deps := defaultTrustDeps()
	if deps.httpClient == nil || deps.httpClient.Timeout != trustHTTPTimeout {
		t.Errorf("httpClient = %+v", deps.httpClient)
	}
	if _, err := deps.newLogClient("https://tl.example.com"); err != nil {
		t.Errorf("https origin: %v", err)
	}
	if _, err := deps.newLogClient("http://tl.example.com"); err == nil {
		t.Error("http origin should be refused")
	}
}

func TestHTTPSOnlyClient(t *testing.T) {
	var hits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits++; w.WriteHeader(http.StatusOK) }))
	defer target.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/to-http", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) })
	mux.HandleFunc("/to-https", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ok", http.StatusFound) })
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", http.StatusFound) })
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	origin := httptest.NewTLSServer(mux)
	defer origin.Close()

	client := httpsOnlyClient()
	client.Transport = origin.Client().Transport

	tests := []struct {
		name    string
		path    string
		wantErr error
		wantSub string
	}{
		{name: "https redirect followed", path: "/to-https"},
		{name: "http redirect refused", path: "/to-http", wantErr: errInsecureRedirect},
		{name: "redirect loop stops", path: "/loop", wantSub: "stopped after 10 redirects"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.Get(origin.URL + tt.path)
			if resp != nil {
				_ = resp.Body.Close()
			}
			if tt.wantErr == nil && tt.wantSub == "" {
				if err != nil || resp.StatusCode != http.StatusOK {
					t.Fatalf("Get = %v, %v", resp, err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want Is %v", err, tt.wantErr)
			}
			if tt.wantSub != "" && !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("err = %v, want containing %q", err, tt.wantSub)
			}
		})
	}
	if hits != 0 {
		t.Errorf("plaintext target was reached %d time(s)", hits)
	}
}
