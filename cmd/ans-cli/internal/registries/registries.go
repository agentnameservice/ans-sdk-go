// Package registries exposes the known-registries list published by the ANS
// specification repository (agentnameservice/ans-spec, registries/known-registries.json).
//
// The list is not stored in this repository. The release build fetches it at
// the ans-spec ref pinned in cmd/ans-cli/ANS_SPEC_REF and injects it through the
// linker (see scripts/fetch-registries.sh and .goreleaser.yaml). A binary built
// with plain `go build` or `go install` carries no list; Known returns an empty
// List and every lookup fails with ErrNoRegistries so callers can tell the user
// to pass explicit URLs or install a release build.
package registries

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
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

// ErrNoRegistries reports that this binary was built without the known-registries list.
var ErrNoRegistries = errors.New("this build carries no known-registries list: pass --base-url (and --transparency-url for badge), or install a release build from https://github.com/agentnameservice/ans-sdk-go/releases")

// ErrUnknownRegistry reports that an id is not in the list. Use errors.Is; the
// wrapped error names the id and lists the ids that exist.
var ErrUnknownRegistry = errors.New("unknown registry")

// State is a registry's lifecycle state as defined in ans-spec registries/README.md.
type State string

// Lifecycle states.
const (
	StatePending  State = "pending"
	StateUsable   State = "usable"
	StateReadOnly State = "readonly"
	StateRetired  State = "retired"
)

// Registry is one entry of known-registries.json.
type Registry struct {
	ID          string   `json:"id"`
	Operator    Operator `json:"operator"`
	Environment string   `json:"environment"`
	State       State    `json:"state"`
	Since       string   `json:"since"`
	Until       *string  `json:"until"`
	RA          RA       `json:"ra"`
	TL          TL       `json:"tl"`
}

// Operator identifies who runs a registry.
type Operator struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Contact string `json:"contact"`
}

// RA is the registry's Registration Authority.
type RA struct {
	BaseURL     string   `json:"baseUrl"`
	APIVersions []string `json:"apiVersions"`
	Auth        []string `json:"auth"`
}

// TL is the registry's Transparency Log.
type TL struct {
	BaseURL          string   `json:"baseUrl"`
	VerificationKeys []string `json:"verificationKeys"`
}

// Host returns the TL hostname, which is also the checkpoint origin and the
// prefix of every verification key name.
func (t TL) Host() string {
	u, err := url.Parse(t.BaseURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// Trusted reports whether verifiers should trust this registry's log.
func (r Registry) Trusted() bool {
	return r.State == StateUsable || r.State == StateReadOnly
}

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

// Trusted returns the registries whose logs verifiers should trust.
func (l List) Trusted() []Registry {
	var out []Registry
	for _, r := range l.Registries {
		if r.Trusted() {
			out = append(out, r)
		}
	}
	return out
}

// TLDomains returns the TL hosts of the trusted registries.
func (l List) TLDomains() []string {
	trusted := l.Trusted()
	out := make([]string, 0, len(trusted))
	for _, r := range trusted {
		out = append(out, r.TL.Host())
	}
	return out
}

// Parse decodes a known-registries document.
func Parse(data []byte) (List, error) {
	var l List
	if err := json.Unmarshal(data, &l); err != nil {
		return List{}, fmt.Errorf("known-registries: %w", err)
	}
	if l.SchemaVersion != 1 {
		return List{}, fmt.Errorf("known-registries: unsupported schemaVersion %d", l.SchemaVersion)
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
		if r.RA.BaseURL == "" || r.TL.BaseURL == "" {
			return List{}, fmt.Errorf("known-registries: %s: ra.baseUrl and tl.baseUrl are required", r.ID)
		}
		host := r.TL.Host()
		if host == "" {
			return List{}, fmt.Errorf("known-registries: %s: tl.baseUrl %q has no host", r.ID, r.TL.BaseURL)
		}
		for _, k := range r.TL.VerificationKeys {
			name, _, ok := strings.Cut(k, "+")
			if !ok || name != host {
				return List{}, fmt.Errorf("known-registries: %s: verification key name does not match tl host %q", r.ID, host)
			}
		}
	}
	return l, nil
}

// Known returns the list injected at build time, or an empty List when this
// binary was built without one. A corrupt injected value is a build defect
// and is reported through the returned error rather than hidden.
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
