package cmd

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/ans"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/trust"
	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/spf13/viper"
)

// saveSignerKeys saves the signer's /root-keys line for example/test under dir.
func saveSignerKeys(t *testing.T, dir string, signers ...*logSigner) {
	t.Helper()
	store, err := trust.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	lines := make([]string, len(signers))
	for i, s := range signers {
		lines[i] = s.rootKeysLine(t)
	}
	keys, err := trust.ValidateKeyLines("tl.test.example.com", lines)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveKeys(trust.Scope{RegistryID: "example", Environment: "test"}, keys); err != nil {
		t.Fatal(err)
	}
}

func checkpointDeps(fetcher scitt.CheckpointFetcher, fetcherErr error) badgeDeps {
	deps := defaultBadgeDeps()
	deps.newCheckpointFetcher = func(string) (scitt.CheckpointFetcher, error) { return fetcher, fetcherErr }
	return deps
}

func TestVerifyCheckpoint(t *testing.T) {
	signer := newLogSigner(t, "tl.test.example.com")
	other := newLogSigner(t, "tl.test.example.com")
	note := signer.signedCheckpoint(t, 42)

	tests := []struct {
		name       string
		registry   string
		tlURL      string
		configDir  func(t *testing.T) string
		deps       badgeDeps
		wantOK     bool
		wantReason []string
	}{
		{
			name:     "verified against the saved key",
			registry: "example/test",
			tlURL:    testLogOrigin,
			configDir: func(t *testing.T) string {
				dir := t.TempDir()
				saveSignerKeys(t, dir, signer)
				return dir
			},
			deps:   checkpointDeps(scitt.NewMockClient().WithCheckpoint(note), nil),
			wantOK: true,
		},
		{
			name:     "verified when an older saved key is retained alongside the signing key",
			registry: "example/test",
			tlURL:    testLogOrigin,
			configDir: func(t *testing.T) string {
				dir := t.TempDir()
				saveSignerKeys(t, dir, other, signer)
				return dir
			},
			deps:   checkpointDeps(scitt.NewMockClient().WithCheckpoint(note), nil),
			wantOK: true,
		},
		{
			name:       "no registry selected",
			tlURL:      testLogOrigin,
			configDir:  func(t *testing.T) string { return t.TempDir() },
			deps:       checkpointDeps(scitt.NewMockClient().WithCheckpoint(note), nil),
			wantReason: []string{"no registry environment selected", "--registry <id>/<environment>"},
		},
		{
			name:       "unknown registry",
			registry:   "nope/test",
			tlURL:      testLogOrigin,
			configDir:  func(t *testing.T) string { return t.TempDir() },
			deps:       checkpointDeps(scitt.NewMockClient().WithCheckpoint(note), nil),
			wantReason: []string{"unknown registry"},
		},
		{
			name:     "transparency URL equal to the registry log up to case and a trailing slash still verifies",
			registry: "example/test",
			tlURL:    "HTTPS://TL.test.example.com/",
			configDir: func(t *testing.T) string {
				dir := t.TempDir()
				saveSignerKeys(t, dir, signer)
				return dir
			},
			deps:   checkpointDeps(scitt.NewMockClient().WithCheckpoint(note), nil),
			wantOK: true,
		},
		{
			name:       "explicit transparency URL overrides the registry log",
			registry:   "example/test",
			tlURL:      "https://other.example",
			configDir:  func(t *testing.T) string { return t.TempDir() },
			deps:       checkpointDeps(scitt.NewMockClient().WithCheckpoint(note), nil),
			wantReason: []string{"https://other.example overrides the example/test log", "saved keys are bound to that log"},
		},
		{
			name:       "no config dir",
			registry:   "example/test",
			tlURL:      testLogOrigin,
			configDir:  func(*testing.T) string { return "" },
			deps:       checkpointDeps(scitt.NewMockClient().WithCheckpoint(note), nil),
			wantReason: []string{"no configuration directory"},
		},
		{
			name:       "no saved keys",
			registry:   "example/test",
			tlURL:      testLogOrigin,
			configDir:  func(t *testing.T) string { return t.TempDir() },
			deps:       checkpointDeps(scitt.NewMockClient().WithCheckpoint(note), nil),
			wantReason: []string{"no saved log keys for example/test", "ans-cli registries fetch-keys example/test"},
		},
		{
			name:     "corrupt saved keys",
			registry: "example/test",
			tlURL:    testLogOrigin,
			configDir: func(t *testing.T) string {
				dir := t.TempDir()
				path := filepath.Join(dir, "registries", "example", "test", "tl-keys.txt")
				_ = os.MkdirAll(filepath.Dir(path), 0o700)
				_ = os.WriteFile(path, []byte("garbage\n"), 0o600)
				return dir
			},
			deps:       checkpointDeps(scitt.NewMockClient().WithCheckpoint(note), nil),
			wantReason: []string{"move the file aside"},
		},
		{
			name:     "fetcher cannot be built",
			registry: "example/test",
			tlURL:    testLogOrigin,
			configDir: func(t *testing.T) string {
				dir := t.TempDir()
				saveSignerKeys(t, dir, signer)
				return dir
			},
			deps:       checkpointDeps(nil, errors.New("bad origin")),
			wantReason: []string{"cannot read " + testLogOrigin + "/checkpoint: bad origin"},
		},
		{
			name:     "checkpoint fetch fails",
			registry: "example/test",
			tlURL:    testLogOrigin,
			configDir: func(t *testing.T) string {
				dir := t.TempDir()
				saveSignerKeys(t, dir, signer)
				return dir
			},
			deps:       checkpointDeps(scitt.NewMockClient().WithError("checkpoint", errors.New("boom")), nil),
			wantReason: []string{"could not fetch " + testLogOrigin + "/checkpoint: boom"},
		},
		{
			name:     "signed by a key that is not saved suggests a refresh",
			registry: "example/test",
			tlURL:    testLogOrigin,
			configDir: func(t *testing.T) string {
				dir := t.TempDir()
				saveSignerKeys(t, dir, other)
				return dir
			},
			deps:       checkpointDeps(scitt.NewMockClient().WithCheckpoint(note), nil),
			wantReason: []string{"did not verify against the 1 saved key(s) for example/test", "run: ans-cli registries fetch-keys example/test"},
		},
		{
			name:     "malformed note",
			registry: "example/test",
			tlURL:    testLogOrigin,
			configDir: func(t *testing.T) string {
				dir := t.TempDir()
				saveSignerKeys(t, dir, signer)
				return dir
			},
			deps:       checkpointDeps(scitt.NewMockClient().WithCheckpoint([]byte("not a note")), nil),
			wantReason: []string{"did not verify"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withRegistry(t, nil)
			cfg := &config.Config{Registry: tt.registry, ConfigDir: tt.configDir(t)}
			got := verifyCheckpoint(context.Background(), cfg, tt.tlURL, tt.deps)
			if got.Verified != tt.wantOK {
				t.Fatalf("Verified = %v, want %v (reason %q)", got.Verified, tt.wantOK, got.Reason)
			}
			if tt.wantOK {
				if got.KeyID != hex.EncodeToString(signer.kid[:]) || got.KeyName != signer.name || got.Origin != signer.name || got.Size != 42 || got.Registry != "example/test" || got.Reason != "" {
					t.Errorf("verification = %+v", got)
				}
				return
			}
			for _, want := range tt.wantReason {
				if !strings.Contains(got.Reason, want) {
					t.Errorf("reason %q missing %q", got.Reason, want)
				}
			}
			if strings.Contains(tt.name, "refresh") && !strings.Contains(got.Reason, "fetch-keys") {
				t.Error("unknown key id should point at fetch-keys")
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }

func TestPrintCheckpointVerification(t *testing.T) {
	verified := checkpointVerification{Verified: true, Registry: "example/test", KeyID: "deadbeef", KeyName: "tl.test.example.com", Origin: "tl.test.example.com", Size: 7, RootHash: strings.Repeat("ab", 32)}
	matching, differing := verified, verified
	matching.MatchesJSONView = boolPtr(true)
	differing.MatchesJSONView = boolPtr(false)
	tests := []struct {
		name    string
		v       checkpointVerification
		want    []string
		notWant []string
	}{
		{
			name:    "verified without a JSON view",
			v:       verified,
			want:    []string{"✅ Checkpoint signature verified against saved key deadbeef (tl.test.example.com) for example/test", "Size: 7", "does not prove the head extends earlier heads", "inclusion proof is not checked here"},
			notWant: []string{"JSON checkpoint view above"},
		},
		{
			name: "verified and the JSON view agrees",
			v:    matching,
			want: []string{"The JSON checkpoint view above describes this same tree head."},
		},
		{
			name: "verified but the JSON view differs",
			v:    differing,
			want: []string{"⚠️  The JSON checkpoint view above describes a DIFFERENT tree head"},
		},
		{
			name: "not verified",
			v:    checkpointVerification{Reason: "no saved log keys"},
			want: []string{"⚠️  Checkpoint signature NOT verified: no saved log keys"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := captureStdout(func() { printCheckpointVerification(&tt.v) })
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q:\n%s", want, out)
				}
			}
			for _, not := range tt.notWant {
				if strings.Contains(out, not) {
					t.Errorf("output should not contain %q:\n%s", not, out)
				}
			}
		})
	}
}

func TestCheckpointVerificationBindJSONView(t *testing.T) {
	var root [32]byte
	root[0] = 0xab
	rootHex := hex.EncodeToString(root[:])
	rootB64 := base64.StdEncoding.EncodeToString(root[:])
	tests := []struct {
		name        string
		v           checkpointVerification
		view        *models.CheckpointResponse
		wantMatches *bool
		wantWarning string
	}{
		{name: "not verified leaves nil", v: checkpointVerification{Reason: "x"}, view: &models.CheckpointResponse{LogSize: 42}, wantWarning: "checkpoint signature not verified: x"},
		{name: "nil view leaves nil", v: checkpointVerification{Verified: true, Size: 42, RootHash: rootHex}},
		{name: "hex root matches", v: checkpointVerification{Verified: true, Size: 42, RootHash: rootHex}, view: &models.CheckpointResponse{LogSize: 42, RootHash: strings.ToUpper(rootHex)}, wantMatches: boolPtr(true)},
		{name: "base64 root matches", v: checkpointVerification{Verified: true, Size: 42, RootHash: rootHex}, view: &models.CheckpointResponse{LogSize: 42, RootHash: rootB64}, wantMatches: boolPtr(true)},
		{name: "size differs", v: checkpointVerification{Verified: true, Size: 42, RootHash: rootHex}, view: &models.CheckpointResponse{LogSize: 43, RootHash: rootHex}, wantMatches: boolPtr(false), wantWarning: "different tree head"},
		{name: "root differs", v: checkpointVerification{Verified: true, Size: 42, RootHash: rootHex}, view: &models.CheckpointResponse{LogSize: 42, RootHash: "abc"}, wantMatches: boolPtr(false), wantWarning: "different tree head"},
		{name: "negative size never matches", v: checkpointVerification{Verified: true, Size: 42, RootHash: rootHex}, view: &models.CheckpointResponse{LogSize: -1, RootHash: rootHex}, wantMatches: boolPtr(false), wantWarning: "different tree head"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := tt.v
			v.bindJSONView(tt.view)
			switch {
			case tt.wantMatches == nil && v.MatchesJSONView != nil:
				t.Errorf("MatchesJSONView = %v, want nil", *v.MatchesJSONView)
			case tt.wantMatches != nil && (v.MatchesJSONView == nil || *v.MatchesJSONView != *tt.wantMatches):
				t.Errorf("MatchesJSONView = %v, want %v", v.MatchesJSONView, *tt.wantMatches)
			}
			if got := v.warning(); !strings.Contains(got, tt.wantWarning) || (tt.wantWarning == "" && got != "") {
				t.Errorf("warning() = %q, want containing %q", got, tt.wantWarning)
			}
		})
	}
}

// TestRunBadge_CheckpointVerification drives badge end to end: the
// JSON API comes from an httptest server, the raw signed note from a mock, and
// the saved keys from a temp config directory selected through --registry.
func TestRunBadge_CheckpointVerification(t *testing.T) {
	signer := newLogSigner(t, "tl.test.example.com")
	note := signer.signedCheckpoint(t, 42)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/agents/agent-123":
			_ = json.NewEncoder(w).Encode(models.TransparencyLog{Status: "ACTIVE", Payload: map[string]any{"logId": "test"}})
		case "/v1/log/checkpoint":
			_ = json.NewEncoder(w).Encode(models.CheckpointResponse{LogSize: 42, RootHash: strings.Repeat("00", 32)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// The registry's TL origin is what verifyCheckpoint compares against and
	// what the fetcher is asked for; the JSON API client is pointed at the
	// test server regardless.
	deps := checkpointDeps(scitt.NewMockClient().WithCheckpoint(note), nil)
	deps.newTransparencyClient = func(_ string, verbose bool) (*ans.TransparencyClient, error) {
		return ans.NewTransparencyClient(ans.WithBaseURL(server.URL), ans.WithVerbose(verbose))
	}

	tests := []struct {
		name     string
		saveKeys bool
		asJSON   bool
		wantOut  []string
		wantErr  []string // stderr
	}{
		{
			name:     "human output verified and bound to the JSON view",
			saveKeys: true,
			wantOut:  []string{"Log Checkpoint (JSON view, as reported by the log)", "✅ Checkpoint signature verified against saved key " + hex.EncodeToString(signer.kid[:]), "describes this same tree head"},
		},
		{
			name:    "human output says plainly when it cannot verify",
			wantOut: []string{"⚠️  Checkpoint signature NOT verified: no saved log keys for example/test"},
		},
		{
			name:     "json verified",
			saveKeys: true,
			asJSON:   true,
			wantOut:  []string{`"checkpointVerification"`, `"verified": true`, `"keyId": "` + hex.EncodeToString(signer.kid[:]) + `"`, `"size": 42`, `"matchesJsonView": true`},
		},
		{
			name:    "json unverified carries the reason and a warning",
			asJSON:  true,
			wantOut: []string{`"verified": false`, `"reason": "no saved log keys for example/test`, `"warnings"`},
			wantErr: []string{"Warning: checkpoint signature not verified"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withRegistry(t, nil)
			dir := t.TempDir()
			if tt.saveKeys {
				saveSignerKeys(t, dir, signer)
			}
			setupViperForTest(t, "")
			viper.Set("registry", "example/test")
			viper.Set("config-dir", dir)
			viper.Set("json", tt.asJSON)
			t.Setenv("ANS_TRANSPARENCY_URL", "")

			var err error
			stdout, stderr := captureOutput(t, func() {
				err = runBadge("agent-123", false, true, "", deps)
			})
			if err != nil {
				t.Fatalf("runBadge: %v\n%s", err, stdout)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout missing %q:\n%s", want, stdout)
				}
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr missing %q:\n%s", want, stderr)
				}
			}
		})
	}
}

func TestDefaultBadgeDeps(t *testing.T) {
	deps := defaultBadgeDeps()
	if _, err := deps.newTransparencyClient("https://tl.example.com", false); err != nil {
		t.Errorf("newTransparencyClient: %v", err)
	}
	if _, err := deps.newTransparencyClient("", false); err == nil {
		t.Error("empty base URL should be refused")
	}
	if _, err := deps.newCheckpointFetcher("https://tl.example.com"); err != nil {
		t.Errorf("https origin: %v", err)
	}
	if _, err := deps.newCheckpointFetcher("http://tl.example.com"); err == nil {
		t.Error("http origin should be refused")
	}
}

func TestRunBadge_Failures(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) badgeDeps
		wantErr string
	}{
		{
			name: "config cannot load",
			setup: func(*testing.T) badgeDeps {
				viper.Set("token-file", "")
				return defaultBadgeDeps()
			},
			wantErr: "failed to load config",
		},
		{
			name: "transparency client cannot be built",
			setup: func(*testing.T) badgeDeps {
				deps := defaultBadgeDeps()
				deps.newTransparencyClient = func(string, bool) (*ans.TransparencyClient, error) { return nil, errors.New("boom") }
				return deps
			},
			wantErr: "failed to create transparency client: boom",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupViperForTest(t, "")
			t.Setenv("ANS_TRANSPARENCY_URL", "")
			deps := tt.setup(t)
			err := runBadge("agent-123", false, false, "https://tl.example.com", deps)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
