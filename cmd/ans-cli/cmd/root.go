package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Build-time variables, populated by GoReleaser ldflags on tagged releases.
// Defaults are used for `go build` / `go install` and local development.
// Globals are required: `-ldflags -X` can only inject into package-level vars.
//
//nolint:gochecknoglobals // build-time injected via -ldflags
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Run builds and executes the root command, returning any error.
func Run() error {
	rootCmd := buildRootCmd()
	return rootCmd.Execute()
}

// Execute runs the root command and exits on error.
func Execute() {
	if err := Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func buildRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ans-cli",
		Short:   "ANS CLI - Agent Name Service Command Line Tool",
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		Long: `A command-line tool for interacting with the Agent Name Service (ANS).
Use this tool to register agents, verify domain ownership, and search for registered agents.`,
	}

	cobra.OnInitialize(initConfig)

	// Global flags
	cmd.PersistentFlags().String("api-key", "", "API key for authentication (env: ANS_API_KEY; ignored when --oauth-token or ANS_OAUTH_TOKEN is set)")
	cmd.PersistentFlags().String("oauth-token", "", "OAuth 2.0 bearer token for authentication (prefer env: ANS_OAUTH_TOKEN; takes precedence over --api-key)")
	cmd.PersistentFlags().String("base-url", "https://api.ote-godaddy.com", "API base URL (env: ANS_BASE_URL)")
	cmd.PersistentFlags().String("api-version", "v1", "RA API lane for agent lifecycle routes: v1 or v2 (env: ANS_API_VERSION; discovery profiles require v2)")
	cmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")
	cmd.PersistentFlags().BoolP("json", "j", false, "Output in JSON format")

	// Bind flags to viper
	_ = viper.BindPFlag("api-key", cmd.PersistentFlags().Lookup("api-key"))
	_ = viper.BindPFlag("oauth-token", cmd.PersistentFlags().Lookup("oauth-token"))
	_ = viper.BindPFlag("base-url", cmd.PersistentFlags().Lookup("base-url"))
	_ = viper.BindPFlag("api-version", cmd.PersistentFlags().Lookup("api-version"))
	_ = viper.BindPFlag("verbose", cmd.PersistentFlags().Lookup("verbose"))
	_ = viper.BindPFlag("json", cmd.PersistentFlags().Lookup("json"))

	// Add all subcommands
	cmd.AddCommand(
		buildBadgeCmd(),
		buildCsrStatusCmd(),
		buildEventsCmd(),
		buildGenerateCSRCmd(),
		buildGetIdentityCertsCmd(),
		buildGetServerCertsCmd(),
		buildRegisterCmd(),
		buildResolveCmd(),
		buildRevokeCmd(),
		buildSearchCmd(),
		buildStatusCmd(),
		buildSubmitIdentityCSRCmd(),
		buildSubmitServerCSRCmd(),
		buildVerifyACMECmd(),
		buildVerifyDNSCmd(),
	)

	return cmd
}

func initConfig() {
	// Environment variable support
	viper.SetEnvPrefix("ANS")

	// Explicitly bind environment variables (handles hyphenated flag names)
	_ = viper.BindEnv("api-key", "ANS_API_KEY")
	_ = viper.BindEnv("oauth-token", "ANS_OAUTH_TOKEN")
	_ = viper.BindEnv("base-url", "ANS_BASE_URL")
	_ = viper.BindEnv("api-version", "ANS_API_VERSION")

	viper.AutomaticEnv()
}
