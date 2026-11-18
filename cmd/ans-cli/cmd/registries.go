package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/registries"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// knownRegistries is the directory loader; tests swap it for a fixture.
//
//nolint:gochecknoglobals // swapped by tests, mirrors the ldflags-injected globals in root.go
var knownRegistries = registries.Known

const registriesTablePadding = 2

func buildRegistriesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "registries",
		Short: "List the known public ANS registries built into this binary",
		Long: `List the known public ANS registries built into this binary.

The directory comes from the ANS specification repository
(https://github.com/agentnameservice/ans-spec, registries/known-registries.json)
and is injected when a release is built. Pass --registry <id>/<environment>
to any command to use that environment's Registration Authority and
Transparency Log URLs.

Being listed is not an endorsement and does not make a registry trusted.
No entry is a default, and the directory carries no log keys or trust
anchors.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRegistries(cmd.OutOrStdout(), viper.GetBool("json"))
		},
	}
}

func runRegistries(w io.Writer, asJSON bool) error {
	list, err := knownRegistries()
	if err != nil {
		return err
	}
	if list.Empty() {
		return registries.ErrNoRegistries
	}
	if asJSON {
		return writeRegistriesJSON(w, list)
	}
	return writeRegistriesTable(w, list)
}

func writeRegistriesJSON(w io.Writer, list registries.List) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		SpecRef string `json:"specRef,omitempty"`
		registries.List
	}{SpecRef: list.SpecRef, List: list})
}

func writeRegistriesTable(w io.Writer, list registries.List) error {
	if list.SpecRef != "" {
		fmt.Fprintf(w, "Known registries from ans-spec %s (%s)\n\n", list.SpecRef, list.UpdatedAt)
	}
	tw := tabwriter.NewWriter(w, 0, 0, registriesTablePadding, ' ', 0)
	fmt.Fprintln(tw, "REGISTRY\tOPERATOR\tREGISTRATION AUTHORITY\tTRANSPARENCY LOG")
	for _, r := range list.Registries {
		for _, name := range r.EnvironmentNames() {
			env := r.Environments[name]
			fmt.Fprintf(tw, "%s%s%s\t%s\t%s\t%s\n", r.ID, registries.Separator, name, r.Operator, env.RA, env.TL)
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, r := range list.Registries {
		if r.Documentation != "" {
			fmt.Fprintf(w, "\n%s documentation: %s\n", r.ID, r.Documentation)
		}
	}
	return nil
}

// registryURLs is the pair of base URLs a selected registry environment supplies.
type registryURLs struct {
	ra string
	tl string
}

// resolveRegistryURLs returns the RA and TL base URLs for the configured
// --registry <id>/<environment>, or zero values when no registry is selected.
// An explicit --base-url or --transparency-url always wins over the registry
// entry; that precedence is applied by the callers.
func resolveRegistryURLs(value string) (registryURLs, error) {
	if value == "" {
		return registryURLs{}, nil
	}
	list, err := knownRegistries()
	if err != nil {
		return registryURLs{}, err
	}
	sel, err := list.Select(value)
	if err != nil {
		return registryURLs{}, err
	}
	fmt.Fprintf(os.Stderr, "Using registry %s (%s): RA %s, TL %s\n", sel, sel.Registry.Operator, sel.Environment.RA, sel.Environment.TL)
	return registryURLs{ra: sel.Environment.RA, tl: sel.Environment.TL}, nil
}
