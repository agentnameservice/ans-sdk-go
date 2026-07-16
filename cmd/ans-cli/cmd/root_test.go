package cmd

import (
	"bytes"
	"strings"
	"testing"

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
	persistentFlags := []string{"api-key", "oauth-token", "base-url", "verbose", "json"}
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
