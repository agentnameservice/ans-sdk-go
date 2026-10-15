package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/spf13/viper"
)

func TestBuildRootCmd(t *testing.T) {
	cmd := buildRootCmd()

	if cmd == nil {
		t.Fatal("buildRootCmd() returned nil")
	}

	if cmd.Use != "ans-cli" {
		t.Errorf("Use = %q, want %q", cmd.Use, "ans-cli")
	}

	// Verify all subcommands are registered
	expectedSubcommands := []string{
		"badge",
		"csr-status",
		"events",
		"generate-csr",
		"get-identity-certs",
		"get-server-certs",
		"register",
		"resolve",
		"revoke",
		"search",
		"status",
		"submit-identity-csr",
		"submit-server-csr",
		"verify-acme",
		"verify-dns",
	}

	subCmds := cmd.Commands()
	subCmdNames := make(map[string]bool)
	for _, sub := range subCmds {
		subCmdNames[sub.Name()] = true
	}

	for _, expected := range expectedSubcommands {
		if !subCmdNames[expected] {
			t.Errorf("missing subcommand %q", expected)
		}
	}

	// Verify persistent flags exist
	persistentFlags := []string{"api-key", "token", "oauth-token", "base-url", "verbose", "json"}
	for _, flagName := range persistentFlags {
		if cmd.PersistentFlags().Lookup(flagName) == nil {
			t.Errorf("missing persistent flag %q", flagName)
		}
	}
}

func TestInitConfig(t *testing.T) {
	// initConfig should not panic; reset viper so the env bindings it
	// registers don't leak a developer's exported ANS_* values into
	// later tests.
	t.Cleanup(func() { viper.Reset() })
	initConfig()
}

func TestRootCmdVersion(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		commit         string
		date           string
		wantSubstrings []string
	}{
		{
			name:           "default ldflag values produce dev version string",
			version:        "dev",
			commit:         "none",
			date:           "unknown",
			wantSubstrings: []string{"dev", "none", "unknown"},
		},
		{
			name:           "release values produce stamped version string",
			version:        "0.1.7",
			commit:         "abc1234",
			date:           "2026-05-01T00:00:00Z",
			wantSubstrings: []string{"0.1.7", "abc1234", "2026-05-01T00:00:00Z"},
		},
	}

	origVersion, origCommit, origDate := version, commit, date
	t.Cleanup(func() {
		version, commit, date = origVersion, origCommit, origDate
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, commit, date = tt.version, tt.commit, tt.date

			cmd := buildRootCmd()
			if cmd.Version == "" {
				t.Fatal("rootCmd.Version is empty")
			}

			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetArgs([]string{"--version"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("--version returned error: %v", err)
			}

			got := out.String()
			for _, sub := range tt.wantSubstrings {
				if !strings.Contains(got, sub) {
					t.Errorf("--version output missing %q\noutput: %s", sub, got)
				}
			}
		})
	}
}

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "no args shows help without error",
			args:    []string{},
			wantErr: false,
		},
		{
			name:    "unknown command returns error",
			args:    []string{"nonexistent-command"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run() builds a fresh root command each call, so
			// we call it directly — but we can't inject args into Run().
			// Instead test via the extracted buildRootCmd + Execute pattern.
			cmd := buildRootCmd()
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRootCmdTokenFlags pins the user-facing contract for the bearer-token
// credential: --token is the advertised flag and its help names both token
// kinds users actually hold, while --oauth-token survives only as a hidden
// alias so existing scripts keep working without being recommended.
func TestRootCmdTokenFlags(t *testing.T) {
	t.Cleanup(func() { viper.Reset() })
	cmd := buildRootCmd()

	tokenFlag := cmd.PersistentFlags().Lookup("token")
	if tokenFlag == nil {
		t.Fatal("missing --token flag")
	}
	if tokenFlag.Hidden {
		t.Error("--token must be visible in help")
	}
	for _, want := range []string{"Personal Access Token (PAT)", "OAuth 2.0", "ANS_TOKEN", "--api-key"} {
		if !strings.Contains(tokenFlag.Usage, want) {
			t.Errorf("--token usage = %q, want it to mention %q", tokenFlag.Usage, want)
		}
	}

	legacyFlag := cmd.PersistentFlags().Lookup("oauth-token")
	if legacyFlag == nil {
		t.Fatal("missing deprecated --oauth-token alias")
	}
	if !legacyFlag.Hidden {
		t.Error("--oauth-token must be hidden from help")
	}

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--help returned error: %v", err)
	}
	help := out.String()
	for _, want := range []string{"--token", "ANS_TOKEN", "Personal Access Token (PAT)"} {
		if !strings.Contains(help, want) {
			t.Errorf("--help output missing %q\noutput: %s", want, help)
		}
	}
	for _, notWant := range []string{"--oauth-token", "ANS_OAUTH_TOKEN"} {
		if strings.Contains(help, notWant) {
			t.Errorf("--help output still advertises deprecated name %q\noutput: %s", notWant, help)
		}
	}
}

func TestRootCmdCredentialFlagBindings(t *testing.T) {
	tests := []struct {
		name     string
		flag     string
		viperKey string
	}{
		{name: "--token binds to the token key", flag: "token", viperKey: "token"},
		{name: "--oauth-token keeps binding to the legacy key", flag: "oauth-token", viperKey: "oauth-token"},
		{name: "--api-key binds to the api-key key", flag: "api-key", viperKey: "api-key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(func() { viper.Reset() })
			cmd := buildRootCmd()

			if err := cmd.PersistentFlags().Set(tt.flag, "flag-value"); err != nil {
				t.Fatalf("Set(%q) error = %v", tt.flag, err)
			}
			if got := viper.GetString(tt.viperKey); got != "flag-value" {
				t.Errorf("viper %q = %q, want %q", tt.viperKey, got, "flag-value")
			}
		})
	}
}

// TestRootCmdTokenFlagParsing drives the credential flags through cobra's
// own argument parsing, hidden alias included, and pins the precedence
// contract against an exported ANS_TOKEN: the current name wins and the
// CLI says so.
func TestRootCmdTokenFlagParsing(t *testing.T) {
	tests := []struct {
		name     string
		envToken string
		args     []string
		wantAuth string
		wantNote string // substring of the single expected stderr note; empty means no note
	}{
		{
			name:     "--token authenticates silently",
			args:     []string{"--token", "flag-tok"},
			wantAuth: "Bearer flag-tok",
		},
		{
			name:     "hidden --oauth-token still parses and prints the deprecation note",
			args:     []string{"--oauth-token", "legacy-tok"},
			wantAuth: "Bearer legacy-tok",
			wantNote: "deprecated; use --token or ANS_TOKEN",
		},
		{
			name:     "exported ANS_TOKEN wins over a typed --oauth-token and says so",
			envToken: "env-tok",
			args:     []string{"--oauth-token", "legacy-tok"},
			wantAuth: "Bearer env-tok",
			wantNote: "using --token/ANS_TOKEN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var gotAuth string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				gotAuth = r.Header.Get("Authorization")
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(&models.AgentDetails{AgentID: "agent-123"})
			}))
			defer server.Close()

			viper.Reset()
			t.Cleanup(func() { viper.Reset() })
			// Neutralize a developer's exported credentials; initConfig binds
			// these names when the root command executes.
			t.Setenv("ANS_API_KEY", "")
			t.Setenv("ANS_OAUTH_TOKEN", "")
			t.Setenv("ANS_TOKEN", tt.envToken)

			args := append([]string{"--base-url", server.URL, "status"}, tt.args...)
			args = append(args, "agent-123")

			_, stderr := captureOutput(t, func() {
				cmd := buildRootCmd()
				cmd.SetArgs(args)
				if err := cmd.Execute(); err != nil {
					t.Errorf("Execute(%v) error = %v", args, err)
				}
			})

			mu.Lock()
			gotAuthCopy := gotAuth
			mu.Unlock()
			if gotAuthCopy != tt.wantAuth {
				t.Errorf("Authorization header = %q, want %q", gotAuthCopy, tt.wantAuth)
			}

			assertSingleNote(t, stderr, tt.wantNote)
			for _, secret := range []string{"flag-tok", "legacy-tok", "env-tok"} {
				if strings.Contains(stderr, secret) {
					t.Errorf("stderr leaks a token value: %q", stderr)
				}
			}
		})
	}
}
