package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Config represents application configuration
type Config struct {
	BaseURL string
	APIKey  string //nolint:gosec // G117 - config struct field definition, not logged
	// Token is the bearer credential — a Personal Access Token or an OAuth 2.0
	// access token — sent verbatim as "Authorization: Bearer <token>".
	Token string
	// TokenFromDeprecatedName reports that Token came from the deprecated
	// --oauth-token flag or ANS_OAUTH_TOKEN variable, so the CLI can print a
	// one-line migration note.
	TokenFromDeprecatedName bool
	// DeprecatedTokenIgnored reports that ANS_OAUTH_TOKEN was also exported
	// with a different value and lost to ANS_TOKEN, so the CLI can say which
	// credential it is using.
	DeprecatedTokenIgnored bool
	APIVersion             string
	Verbose                bool
	JSON                   bool
}

// Load loads configuration from flags and the environment. The bearer token
// is resolved from the first of: --token-file (a path, or "-" for stdin),
// the deprecated --oauth-token flag, ANS_TOKEN, the deprecated
// ANS_OAUTH_TOKEN. Explicit flags therefore always beat environment
// variables, and the current names beat the deprecated ones within each
// layer. Reading --token-file is the only I/O; its failure is returned.
func Load() (*Config, error) {
	return load(os.Stdin)
}

func load(stdin io.Reader) (*Config, error) {
	cfg := &Config{
		BaseURL: viper.GetString("base-url"),
		APIKey:  viper.GetString("api-key"),
		// Normalized here so "V2" from env plumbing selects the lane;
		// value validation happens in cmd.createClient where the SDK
		// option can reject with proper guidance.
		APIVersion: strings.ToLower(strings.TrimSpace(viper.GetString("api-version"))),
		Verbose:    viper.GetBool("verbose"),
		JSON:       viper.GetBool("json"),
	}

	// Default the API version exactly once, here: an explicit
	// `--api-version ""`, a whitespace-only ANS_API_VERSION, and test
	// setups that bypass flag binding all normalize to the V1 lane
	// instead of silently bypassing validation downstream.
	if cfg.APIVersion == "" {
		cfg.APIVersion = "v1"
	}

	if err := cfg.resolveToken(stdin); err != nil {
		return nil, err
	}

	return cfg, nil
}

// resolveToken applies the precedence documented on Load. The deprecated
// flag and variable are bound to separate viper keys ("oauth-token" is the
// flag, "oauth-token-env" is ANS_OAUTH_TOKEN) so each value's source is known
// without consulting cobra. Values are trimmed at the boundary so a padded or
// whitespace-only token from env plumbing is treated as unset.
func (c *Config) resolveToken(stdin io.Reader) error {
	tokenFile := viper.GetString("token-file")
	// An explicitly empty --token-file is a scripting mistake, typically
	// --token-file "$TOKEN_FILE" with the variable unset. Falling back to an
	// exported credential would run the command under another identity, and
	// could send that credential to whatever --base-url the script targets.
	if viper.IsSet("token-file") && strings.TrimSpace(tokenFile) == "" {
		return errors.New(`--token-file: empty path; pass a file, "-" for stdin, or omit the flag to use ANS_TOKEN`)
	}
	legacyFlag := strings.TrimSpace(viper.GetString("oauth-token"))
	envToken := strings.TrimSpace(viper.GetString("token"))
	legacyEnv := strings.TrimSpace(viper.GetString("oauth-token-env"))

	switch {
	case tokenFile != "" && legacyFlag != "":
		return errors.New("--token-file and --oauth-token cannot both be set")
	case tokenFile != "":
		token, err := readTokenFile(tokenFile, stdin)
		if err != nil {
			return err
		}
		c.Token = token
	case legacyFlag != "":
		c.Token = legacyFlag
		c.TokenFromDeprecatedName = true
	case envToken != "":
		c.Token = envToken
		c.DeprecatedTokenIgnored = legacyEnv != "" && legacyEnv != envToken
	case legacyEnv != "":
		c.Token = legacyEnv
		c.TokenFromDeprecatedName = true
	}

	return nil
}

// readTokenFile returns the trimmed contents of path, or of stdin when path
// is "-".
func readTokenFile(path string, stdin io.Reader) (string, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return "", fmt.Errorf("--token-file: %w", err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("--token-file %s: no token found", path)
	}

	return token, nil
}

// ErrNoCredentials is returned when neither a bearer token nor an API key is
// configured. It is the single source of truth for the guidance message —
// cmd.authOption returns it directly for its no-credentials branch.
var ErrNoCredentials = errors.New("a bearer token or API key is required. Set ANS_TOKEN or pass --token-file (Personal Access Token or OAuth 2.0 access token), or set --api-key/ANS_API_KEY (key:secret)")

// RequireCredentials returns ErrNoCredentials when neither a bearer token nor
// an API key is configured. Commands call this before any other validation so
// users get clear guidance instead of a late failure.
func (c *Config) RequireCredentials() error {
	if c.Token == "" && c.APIKey == "" {
		return ErrNoCredentials
	}
	return nil
}
