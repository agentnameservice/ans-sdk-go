package cmd

import (
	"testing"
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
	persistentFlags := []string{"api-key", "base-url", "verbose", "json"}
	for _, flagName := range persistentFlags {
		if cmd.PersistentFlags().Lookup(flagName) == nil {
			t.Errorf("missing persistent flag %q", flagName)
		}
	}
}

func TestInitConfig(_ *testing.T) {
	// initConfig should not panic
	initConfig()
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

func TestRun_Success(t *testing.T) {
	// Run() itself should succeed for the default (help) case
	err := Run()
	if err != nil {
		t.Errorf("Run() unexpected error: %v", err)
	}
}
