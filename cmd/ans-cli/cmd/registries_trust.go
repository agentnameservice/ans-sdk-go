package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/registries"
	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/trust"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/spf13/cobra"
)

// trustHTTPTimeout bounds each request the trust commands make.
const trustHTTPTimeout = 30 * time.Second

// errInsecureRedirect reports a redirect away from https. The directory names
// https origins; following a redirect to plaintext would let a network
// attacker answer for the log or the bundle host.
var errInsecureRedirect = errors.New("refusing redirect to a non-https URL")

// httpsOnlyClient returns an HTTP client that follows redirects only to https.
func httpsOnlyClient() *http.Client {
	return &http.Client{
		Timeout: trustHTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("%w: %s", errInsecureRedirect, req.URL.Redacted())
			}
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}
}

const maxRedirects = 10

// errKeyCollision reports that a fetched key was refused because a saved key
// already holds its id under a different name or key material.
var errKeyCollision = errors.New("refused a fetched key whose id is already saved with a different name or key material")

// trustDeps are the network clients the trust commands use; tests inject
// doubles.
type trustDeps struct {
	// newLogClient builds the client that reads a Transparency Log's /root-keys.
	newLogClient func(tlOrigin string) (scitt.Client, error)
	// httpClient downloads an identity CA bundle.
	httpClient *http.Client
}

func defaultTrustDeps() trustDeps {
	return trustDeps{
		newLogClient: func(tlOrigin string) (scitt.Client, error) {
			return scitt.NewHTTPClient(tlOrigin, scitt.WithHTTPClient(httpsOnlyClient()))
		},
		httpClient: httpsOnlyClient(),
	}
}

func buildFetchKeysCmd(deps trustDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "fetch-keys <id>/<environment>",
		Short: "Fetch a registry environment's transparency log keys and save them for offline verification",
		Long: `Fetch the checkpoint signing keys a registry environment's Transparency Log
publishes at {tl}/root-keys, validate them, and save them under the configuration
directory for that registry and environment.

Each line must have the C2SP key shape and carry a key name equal to the log
host (or a path under it); any other line rejects the whole response. Saved keys
are never removed: running the command again appends keys the log has added
and keeps every previously saved key, so receipts and checkpoints signed under
older keys still verify. A fetched key whose id is already saved under a
different name or key material is refused and reported.

Keys are never fetched implicitly. Run this once after choosing a registry
environment and again whenever the log announces a new key.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			return runFetchKeys(cmd.Context(), cmd.OutOrStdout(), cfg, args[0], deps)
		},
	}
}

func buildFetchCACmd(deps trustDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "fetch-ca <id>/<environment>",
		Short: "Download a registry environment's published identity CA bundle without trusting it",
		Long: `Download the identity CA bundle the known-registries directory references for a
registry environment, check its bytes against the published sha256, and save it
under the configuration directory for that registry and environment.

Downloading a bundle does not trust its roots. The command prints each root so
you can decide; "registries trust-roots" is the only step that makes roots
trusted, and running fetch-ca again never changes which roots are trusted.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			return runFetchCA(cmd.Context(), cmd.OutOrStdout(), cfg, args[0], deps)
		},
	}
}

func buildTrustRootsCmd() *cobra.Command {
	var opts trustRootsOptions
	cmd := &cobra.Command{
		Use:   "trust-roots <id>/<environment> --bundle <file>",
		Short: "Explicitly accept CA roots for a registry environment",
		Long: `Record the CA certificates in a PEM bundle as the roots you accept for a
registry environment. This is the only operation that changes trusted roots;
neither fetching the directory's identity CA bundle nor refreshing log keys
does. Trust is scoped: roots accepted for one registry environment say nothing
about another.

By default the roots are added to those already trusted. --only limits the
bundle to the roots with the given SHA-256 fingerprints; --replace makes the
selected roots the whole trusted set, dropping every other root.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			return runTrustRoots(cmd.OutOrStdout(), cfg, args[0], opts)
		},
	}
	cmd.Flags().StringVar(&opts.bundlePath, "bundle", "", "PEM file holding the CA certificates to trust (required); registries fetch-ca saves the published bundle")
	cmd.Flags().StringArrayVar(&opts.only, "only", nil, "Trust only the root with this SHA-256 fingerprint (hex, colons optional); repeatable")
	cmd.Flags().BoolVar(&opts.replace, "replace", false, "Replace the trusted set instead of adding to it")
	_ = cmd.MarkFlagRequired("bundle")
	return cmd
}

func buildShowRegistryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <id>/<environment>",
		Short: "Show a registry environment's endpoints and the trust material saved for it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			return runShowRegistry(cmd.OutOrStdout(), cfg, args[0])
		},
	}
}

type trustRootsOptions struct {
	bundlePath string
	only       []string
	replace    bool
}

// keyView is one saved key as the commands print it.
type keyView struct {
	KeyID string `json:"keyId"`
	Name  string `json:"name"`
}

type collisionView struct {
	KeyID       string `json:"keyId"`
	SavedName   string `json:"savedName"`
	FetchedName string `json:"fetchedName"`
}

type fetchKeysReport struct {
	Registry   string          `json:"registry"`
	LogURL     string          `json:"logUrl"`
	Path       string          `json:"path"`
	Fetched    int             `json:"fetched"`
	Added      int             `json:"added"`
	Total      int             `json:"total"`
	Keys       []keyView       `json:"keys"`
	Collisions []collisionView `json:"collisions,omitempty"`
}

func runFetchKeys(ctx context.Context, w io.Writer, cfg *config.Config, value string, deps trustDeps) error {
	sel, store, err := selectWithStore(cfg, value)
	if err != nil {
		return err
	}
	client, err := deps.newLogClient(sel.Environment.TL)
	if err != nil {
		return fmt.Errorf("transparency log client: %w", err)
	}
	host, err := logHost(sel.Environment.TL)
	if err != nil {
		return err
	}
	keys, err := trust.FetchKeys(ctx, client, host)
	if err != nil {
		return fmt.Errorf("%s: %w", sel.Environment.TL+"/root-keys", err)
	}
	res, err := store.SaveKeys(trustScope(sel), keys)
	if err != nil {
		return err
	}

	report := fetchKeysReport{
		Registry: sel.String(),
		LogURL:   sel.Environment.TL + "/root-keys",
		Path:     res.Path,
		Fetched:  len(keys),
		Added:    res.Added,
		Total:    len(res.Keys),
		Keys:     keyViews(res.Keys),
	}
	for _, c := range res.Collisions {
		report.Collisions = append(report.Collisions, collisionView{KeyID: c.Fetched.KIDHex(), SavedName: c.Saved.Name, FetchedName: c.Fetched.Name})
	}
	if cfg.JSON {
		if err := writeJSON(w, report); err != nil {
			return err
		}
	} else {
		printFetchKeys(w, report)
	}
	if len(report.Collisions) > 0 {
		return fmt.Errorf("%w (%d refused; saved keys were kept)", errKeyCollision, len(report.Collisions))
	}
	return nil
}

func printFetchKeys(w io.Writer, r fetchKeysReport) {
	fmt.Fprintf(w, "Fetched %d key(s) from %s\n", r.Fetched, r.LogURL)
	fmt.Fprintf(w, "Saved %d new key(s) for %s; %d saved in total at %s\n", r.Added, r.Registry, r.Total, r.Path)
	for _, k := range r.Keys {
		fmt.Fprintf(w, "  %s  %s\n", k.KeyID, k.Name)
	}
	for _, c := range r.Collisions {
		fmt.Fprintf(w, "Refused key %s: saved as %q, fetched as %q; the saved key is kept\n", c.KeyID, c.SavedName, c.FetchedName)
	}
	fmt.Fprintf(w, "badge --checkpoint --registry %s now verifies checkpoint signatures against these keys. Run this command again to pick up keys the log adds later.\n", r.Registry)
}

type rootView struct {
	Subject     string    `json:"subject"`
	NotAfter    time.Time `json:"notAfter"`
	Fingerprint string    `json:"sha256"`
}

type fetchCAReport struct {
	Registry string     `json:"registry"`
	URL      string     `json:"url"`
	SHA256   string     `json:"sha256"`
	Path     string     `json:"path"`
	Roots    []rootView `json:"roots"`
	Trusted  bool       `json:"trusted"`
}

func runFetchCA(ctx context.Context, w io.Writer, cfg *config.Config, value string, deps trustDeps) error {
	sel, store, err := selectWithStore(cfg, value)
	if err != nil {
		return err
	}
	ca := sel.Environment.IdentityCA
	if ca == nil {
		return fmt.Errorf("%s publishes no identity CA reference in the known-registries directory", sel)
	}
	data, err := trust.FetchBundle(ctx, deps.httpClient, ca.URL, ca.SHA256)
	if err != nil {
		return err
	}
	roots, err := trust.ParseCABundle(data)
	if err != nil {
		return fmt.Errorf("%s: %w", ca.URL, err)
	}
	path, err := store.SaveBundle(trustScope(sel), data)
	if err != nil {
		return err
	}
	report := fetchCAReport{Registry: sel.String(), URL: ca.URL, SHA256: ca.SHA256, Path: path, Roots: rootViews(roots)}
	if cfg.JSON {
		return writeJSON(w, report)
	}
	fmt.Fprintf(w, "Downloaded %s\n", report.URL)
	fmt.Fprintf(w, "sha256 matches the directory: %s\n", report.SHA256)
	fmt.Fprintf(w, "Saved to %s (%d CA certificate(s)):\n", report.Path, len(roots))
	for _, r := range roots {
		fmt.Fprintf(w, "  %s\n", r.Describe())
	}
	fmt.Fprintf(w, "\nThese roots are NOT trusted. Review them, then accept them for %s with:\n  ans-cli registries trust-roots %s --bundle %s\n", report.Registry, report.Registry, report.Path)
	return nil
}

type trustRootsReport struct {
	Registry string     `json:"registry"`
	Path     string     `json:"path"`
	Added    int        `json:"added"`
	Removed  int        `json:"removed"`
	Roots    []rootView `json:"roots"`
}

func runTrustRoots(w io.Writer, cfg *config.Config, value string, opts trustRootsOptions) error {
	sel, store, err := selectWithStore(cfg, value)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(opts.bundlePath)
	if err != nil {
		return fmt.Errorf("--bundle: %w", err)
	}
	roots, err := trust.ParseCABundle(data)
	if err != nil {
		return fmt.Errorf("--bundle %s: %w", opts.bundlePath, err)
	}
	roots, err = selectRoots(roots, opts.only)
	if err != nil {
		return err
	}
	res, err := store.TrustRoots(trustScope(sel), roots, opts.replace)
	if err != nil {
		return err
	}
	report := trustRootsReport{Registry: sel.String(), Path: res.Path, Added: res.Added, Removed: res.Removed, Roots: rootViews(res.Roots)}
	if cfg.JSON {
		return writeJSON(w, report)
	}
	fmt.Fprintf(w, "Trusted roots for %s: %d added, %d removed, %d in total at %s\n", report.Registry, report.Added, report.Removed, len(report.Roots), report.Path)
	for _, r := range res.Roots {
		fmt.Fprintf(w, "  %s\n", r.Describe())
	}
	return nil
}

// selectRoots keeps the roots whose fingerprints are listed in only; every
// listed fingerprint must match a root. An empty list keeps all roots.
func selectRoots(roots []trust.Root, only []string) ([]trust.Root, error) {
	if len(only) == 0 {
		return roots, nil
	}
	want := make([]string, len(only))
	for i, fp := range only {
		want[i] = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fp), ":", ""))
	}
	kept := make([]trust.Root, 0, len(want))
	for _, r := range roots {
		if slices.Contains(want, r.FingerprintHex()) {
			kept = append(kept, r)
		}
	}
	for _, fp := range want {
		if !slices.ContainsFunc(kept, func(r trust.Root) bool { return r.FingerprintHex() == fp }) {
			return nil, fmt.Errorf("--only %s: no root in the bundle has that fingerprint", fp)
		}
	}
	return kept, nil
}

type showReport struct {
	Registry     string                 `json:"registry"`
	Operator     string                 `json:"operator"`
	RA           string                 `json:"ra"`
	TL           string                 `json:"tl"`
	IdentityCA   *registries.IdentityCA `json:"identityCa,omitempty"`
	ConfigDir    string                 `json:"configDir,omitempty"`
	SavedKeys    []keyView              `json:"savedKeys"`
	TrustedRoots []rootView             `json:"trustedRoots"`
}

func runShowRegistry(w io.Writer, cfg *config.Config, value string) error {
	sel, err := selectRegistry(value)
	if err != nil {
		return err
	}
	report := showReport{
		Registry:     sel.String(),
		Operator:     sel.Registry.Operator,
		RA:           sel.Environment.RA,
		TL:           sel.Environment.TL,
		IdentityCA:   sel.Environment.IdentityCA,
		ConfigDir:    cfg.ConfigDir,
		SavedKeys:    []keyView{},
		TrustedRoots: []rootView{},
	}
	var keysErr, rootsErr error
	if store, err := trust.NewStore(cfg.ConfigDir); err != nil {
		keysErr, rootsErr = err, err
	} else {
		scope := trustScope(sel)
		var keys []trust.Key
		if keys, keysErr = store.LoadKeys(scope); keysErr == nil {
			report.SavedKeys = keyViews(keys)
		}
		var roots []trust.Root
		if roots, rootsErr = store.LoadRoots(scope); rootsErr == nil {
			report.TrustedRoots = rootViews(roots)
		}
	}
	if err := firstUnexpected(keysErr, trust.ErrNoSavedKeys, trust.ErrNoConfigDir); err != nil {
		return err
	}
	if err := firstUnexpected(rootsErr, trust.ErrNoTrustedRoots, trust.ErrNoConfigDir); err != nil {
		return err
	}
	if cfg.JSON {
		return writeJSON(w, report)
	}
	printShow(w, report, keysErr, rootsErr)
	return nil
}

// firstUnexpected returns err unless it is nil or one of the expected
// sentinels, which the caller reports as an absence rather than a failure.
func firstUnexpected(err error, expected ...error) error {
	if err == nil {
		return nil
	}
	for _, e := range expected {
		if errors.Is(err, e) {
			return nil
		}
	}
	return err
}

func printShow(w io.Writer, r showReport, keysErr, rootsErr error) {
	fmt.Fprintf(w, "Registry:               %s (%s)\n", r.Registry, r.Operator)
	fmt.Fprintf(w, "Registration Authority: %s\n", r.RA)
	fmt.Fprintf(w, "Transparency Log:       %s\n", r.TL)
	if r.IdentityCA != nil {
		fmt.Fprintf(w, "Identity CA bundle:     %s\n                        sha256 %s (a reference, not a trust anchor)\n", r.IdentityCA.URL, r.IdentityCA.SHA256)
	} else {
		fmt.Fprintln(w, "Identity CA bundle:     none published")
	}
	if r.ConfigDir != "" {
		fmt.Fprintf(w, "Configuration:          %s\n", r.ConfigDir)
	}
	fmt.Fprintln(w)
	switch {
	case keysErr != nil:
		fmt.Fprintf(w, "Saved transparency log keys: none (%v). Fetch them with: ans-cli registries fetch-keys %s\n", keysErr, r.Registry)
	default:
		fmt.Fprintf(w, "Saved transparency log keys: %d\n", len(r.SavedKeys))
		for _, k := range r.SavedKeys {
			fmt.Fprintf(w, "  %s  %s\n", k.KeyID, k.Name)
		}
	}
	switch {
	case rootsErr != nil:
		fmt.Fprintf(w, "Trusted CA roots: none (%v). Accept roots with: ans-cli registries trust-roots %s --bundle <file>\n", rootsErr, r.Registry)
	default:
		fmt.Fprintf(w, "Trusted CA roots: %d\n", len(r.TrustedRoots))
		for _, root := range r.TrustedRoots {
			fmt.Fprintf(w, "  %s (expires %s, sha256 %s)\n", root.Subject, root.NotAfter.Format(time.RFC3339), root.Fingerprint)
		}
	}
}

// selectWithStore resolves the registry environment and opens the trust
// store, the two things every trust command needs first.
func selectWithStore(cfg *config.Config, value string) (registries.Selected, *trust.Store, error) {
	sel, err := selectRegistry(value)
	if err != nil {
		return registries.Selected{}, nil, err
	}
	store, err := trust.NewStore(cfg.ConfigDir)
	if err != nil {
		return registries.Selected{}, nil, err
	}
	return sel, store, nil
}

// logHost returns the host name a log's keys must be named for.
func logHost(tlOrigin string) (string, error) {
	u, err := url.Parse(tlOrigin)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("transparency log origin %q has no host", tlOrigin)
	}
	return u.Hostname(), nil
}

func keyViews(keys []trust.Key) []keyView {
	out := make([]keyView, len(keys))
	for i, k := range keys {
		out[i] = keyView{KeyID: k.KIDHex(), Name: k.Name}
	}
	return out
}

func rootViews(roots []trust.Root) []rootView {
	out := make([]rootView, len(roots))
	for i, r := range roots {
		out[i] = rootView{Subject: r.Subject(), NotAfter: r.Cert.NotAfter.UTC(), Fingerprint: r.FingerprintHex()}
	}
	return out
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
