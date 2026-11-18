// Package registries exposes the known-registries directory published by the
// ANS specification repository (agentnameservice/ans-spec,
// registries/known-registries.json).
//
// The directory is not stored in this repository. The release build fetches it
// at the ans-spec ref pinned in cmd/ans-cli/ANS_SPEC_REF and injects it through
// the linker (see scripts/fetch-registries.sh and .goreleaser.yaml). A binary
// built with plain `go build` or `go install` carries no directory; Known
// returns an empty List and every lookup fails with ErrNoRegistries so callers
// can tell the user to pass explicit URLs or install a release build.
//
// The directory records endpoints only. It carries no Transparency Log keys
// (each log serves its own at /root-keys) and no trust anchors. Being listed is
// not an endorsement and does not make a registry trusted.
package registries

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
)

// Injected by the release build through -ldflags -X. registriesJSON is the
// base64-encoded known-registries.json; specRef is the ans-spec ref it came from.
//
//nolint:gochecknoglobals // build-time injected via -ldflags
var (
	registriesJSON = ""
	specRef        = ""
)

// ErrNoRegistries reports that this binary was built without the known-registries directory.
var ErrNoRegistries = errors.New("this build carries no known-registries list: pass --base-url (and --transparency-url for badge), or install a release build from https://github.com/agentnameservice/ans-sdk-go/releases")

// ErrUnknownRegistry reports that an id is not in the directory. Use errors.Is;
// the wrapped error names the id and lists the ids that exist.
var ErrUnknownRegistry = errors.New("unknown registry")

// ErrEnvironmentRequired reports a --registry value that names a registry but
// not one of its environments.
var ErrEnvironmentRequired = errors.New("registry environment required")

// ErrUnknownEnvironment reports a --registry value whose environment the
// registry does not run.
var ErrUnknownEnvironment = errors.New("unknown registry environment")

// Environment names the directory may carry.
const (
	EnvironmentProduction = "production"
	EnvironmentTest       = "test"
)

// Separator divides the registry id from the environment in a --registry value.
// The schema's id pattern keeps it out of ids.
const Separator = "/"

const sha256HexLen = 64

func environmentOrder() []string { return []string{EnvironmentProduction, EnvironmentTest} }

// Registry is one entry of known-registries.json: an operator and the
// environments it runs.
type Registry struct {
	ID            string                 `json:"id"`
	Operator      string                 `json:"operator"`
	Documentation string                 `json:"documentation,omitempty"`
	Environments  map[string]Environment `json:"environments"`
}

// Environment is one deployment of a registry: a Registration Authority and
// the Transparency Log it publishes to.
type Environment struct {
	RA         string      `json:"ra"`
	TL         string      `json:"tl"`
	IdentityCA *IdentityCA `json:"identityCa,omitempty"`
}

// IdentityCA says where the operator publishes the CA bundle that issues an
// environment's identity certificates and what its bytes hash to. It is
// informational: fetching the bundle does not make its roots trusted.
type IdentityCA struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// EnvironmentNames returns the registry's environment names in display order,
// production before test.
func (r Registry) EnvironmentNames() []string {
	out := make([]string, 0, len(r.Environments))
	for _, name := range environmentOrder() {
		if _, ok := r.Environments[name]; ok {
			out = append(out, name)
		}
	}
	return out
}

// Selected is the registry environment a --registry <id>/<environment> value names.
type Selected struct {
	Registry    Registry
	Name        string
	Environment Environment
}

// String returns the --registry value that selects this environment.
func (s Selected) String() string { return s.Registry.ID + Separator + s.Name }

// List is the parsed known-registries document.
type List struct {
	SchemaVersion int        `json:"schemaVersion"`
	UpdatedAt     string     `json:"updatedAt"`
	Registries    []Registry `json:"registries"`
	// SpecRef is the ans-spec ref the list was fetched from, when known.
	SpecRef string `json:"-"`
}

// Empty reports whether the list has no entries.
func (l List) Empty() bool { return len(l.Registries) == 0 }

// Get returns the registry with the given id.
func (l List) Get(id string) (Registry, error) {
	if l.Empty() {
		return Registry{}, ErrNoRegistries
	}
	for _, r := range l.Registries {
		if r.ID == id {
			return r, nil
		}
	}
	return Registry{}, fmt.Errorf("%w %q; known ids: %s", ErrUnknownRegistry, id, strings.Join(l.IDs(), ", "))
}

// IDs returns every registry id in list order.
func (l List) IDs() []string {
	ids := make([]string, 0, len(l.Registries))
	for _, r := range l.Registries {
		ids = append(ids, r.ID)
	}
	return ids
}

// Select resolves a --registry value of the form <id>/<environment>. The
// environment is always required, even when the registry runs only one, so a
// command never reaches production by default.
func (l List) Select(value string) (Selected, error) {
	id, name, hasEnv := strings.Cut(value, Separator)
	r, err := l.Get(id)
	if err != nil {
		return Selected{}, err
	}
	runs := strings.Join(r.EnvironmentNames(), " and ")
	if !hasEnv || name == "" {
		return Selected{}, fmt.Errorf("%w: %q runs %s; pass --registry %s%s<environment>", ErrEnvironmentRequired, id, runs, id, Separator)
	}
	env, ok := r.Environments[name]
	if !ok {
		return Selected{}, fmt.Errorf("%w %q: %q runs %s", ErrUnknownEnvironment, name, id, runs)
	}
	return Selected{Registry: r, Name: name, Environment: env}, nil
}

// Parse decodes a known-registries document and checks what the schema
// requires: schemaVersion 1, at least one entry, unique ids matching
// ^[a-z0-9]+(-[a-z0-9]+)*$, a named operator, https documentation and
// identityCa URLs, a 64-digit lower-case hex sha256, and for every environment
// a known name and https origins for the RA and TL. updatedAt is not checked.
func Parse(data []byte) (List, error) {
	var l List
	if err := json.Unmarshal(data, &l); err != nil {
		return List{}, fmt.Errorf("known-registries: %w", err)
	}
	if l.SchemaVersion != 1 {
		return List{}, fmt.Errorf("known-registries: unsupported schemaVersion %d", l.SchemaVersion)
	}
	if len(l.Registries) == 0 {
		return List{}, errors.New("known-registries: no registries listed")
	}
	seen := make(map[string]struct{}, len(l.Registries))
	for _, r := range l.Registries {
		if r.ID == "" {
			return List{}, errors.New("known-registries: entry with empty id")
		}
		if _, dup := seen[r.ID]; dup {
			return List{}, fmt.Errorf("known-registries: duplicate id %q", r.ID)
		}
		seen[r.ID] = struct{}{}
		if err := validateRegistry(r); err != nil {
			return List{}, fmt.Errorf("known-registries: %s: %w", r.ID, err)
		}
	}
	return l, nil
}

func validateRegistry(r Registry) error {
	if err := ValidateID(r.ID); err != nil {
		return err
	}
	if r.Operator == "" {
		return errors.New("operator is required")
	}
	if r.Documentation != "" {
		if err := validateHTTPSURL(r.Documentation); err != nil {
			return fmt.Errorf("documentation: %w", err)
		}
	}
	if len(r.Environments) == 0 {
		return errors.New("at least one environment is required")
	}
	for _, name := range slices.Sorted(maps.Keys(r.Environments)) {
		if !slices.Contains(environmentOrder(), name) {
			return fmt.Errorf("unknown environment %q", name)
		}
		if err := validateEnvironment(r.Environments[name]); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func validateEnvironment(env Environment) error {
	if err := validateOrigin(env.RA); err != nil {
		return fmt.Errorf("ra: %w", err)
	}
	if err := validateOrigin(env.TL); err != nil {
		return fmt.Errorf("tl: %w", err)
	}
	if env.IdentityCA == nil {
		return nil
	}
	if err := validateHTTPSURL(env.IdentityCA.URL); err != nil {
		return fmt.Errorf("identityCa.url: %w", err)
	}
	if !isLowerHex(env.IdentityCA.SHA256, sha256HexLen) {
		return fmt.Errorf("identityCa.sha256 %q is not %d lower-case hex digits", env.IdentityCA.SHA256, sha256HexLen)
	}
	return nil
}

// ValidateID enforces the schema's id pattern ^[a-z0-9]+(-[a-z0-9]+)*$, which
// also makes an id a safe single path segment.
func ValidateID(id string) error {
	if id == "" {
		return errors.New("id must not be empty")
	}
	for i := range len(id) {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0 && i < len(id)-1 && id[i-1] != '-':
		default:
			return fmt.Errorf("id %q must match ^[a-z0-9]+(-[a-z0-9]+)*$", id)
		}
	}
	return nil
}

// validateOrigin accepts an https origin for ra and tl: the literal scheme, a
// host, and nothing else. The raw string is compared because url.Parse drops
// an empty query or fragment and lower-cases the scheme, all of which the
// schema rejects. Unlike the schema it also rejects user info in the authority.
func validateOrigin(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q: %w", raw, err)
	}
	if u.Host == "" || raw != "https://"+u.Host {
		return fmt.Errorf("%q is not an https origin", raw)
	}
	return nil
}

// validateHTTPSURL accepts what the schema's `format: uri` plus `^https://`
// pattern accepts for documentation and identityCa.url.
func validateHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q: %w", raw, err)
	}
	if !strings.HasPrefix(raw, "https://") || u.Host == "" {
		return fmt.Errorf("%q is not an https URL", raw)
	}
	return nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Known returns the directory injected at build time, or an empty List when
// this binary was built without one. A corrupt injected value is a build
// defect and is reported through the returned error rather than hidden.
func Known() (List, error) {
	return fromInjected(registriesJSON, specRef)
}

func fromInjected(encoded, ref string) (List, error) {
	if encoded == "" {
		return List{}, nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return List{}, fmt.Errorf("known-registries: injected value is not base64: %w", err)
	}
	l, err := Parse(raw)
	if err != nil {
		return List{}, err
	}
	l.SpecRef = ref
	return l, nil
}
