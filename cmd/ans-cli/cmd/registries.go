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

// knownRegistries is the list loader; tests swap it for a fixture.
//
//nolint:gochecknoglobals // swapped by tests, mirrors the ldflags-injected globals in root.go
var knownRegistries = registries.Known

const registriesTablePadding = 2

func buildRegistriesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "registries",
		Short: "List the known public ANS registries built into this binary",
		Long: `List the known public ANS registries built into this binary.

The list comes from the ANS specification repository
(https://github.com/agentnameservice/ans-spec, registries/known-registries.json)
and is injected when a release is built. Pass --registry <id> to any command
to use an entry's Registration Authority and Transparency Log URLs.

Being listed records that an operator met published admission criteria.
It is not an endorsement and no entry is a default.`,
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
	if list.Empty() {
		_, err := fmt.Fprintln(w, registries.ErrNoRegistries.Error())
		return err
	}
	if list.SpecRef != "" {
		fmt.Fprintf(w, "Known registries from ans-spec %s (%s)\n\n", list.SpecRef, list.UpdatedAt)
	}
	tw := tabwriter.NewWriter(w, 0, 0, registriesTablePadding, ' ', 0)
	fmt.Fprintln(tw, "ID\tOPERATOR\tENVIRONMENT\tSTATE\tREGISTRATION AUTHORITY\tTRANSPARENCY LOG")
	for _, r := range list.Registries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Operator.Name, r.Environment, r.State, r.RA.BaseURL, r.TL.BaseURL)
	}
	return tw.Flush()
}

// registryURLs is the pair of base URLs a known-registry entry supplies.
type registryURLs struct {
	ra string
	tl string
}

// resolveRegistryURLs returns the RA and TL base URLs for the configured
// --registry id, or zero values when no registry is selected. An explicit
// --base-url or --transparency-url always wins over the registry entry; that
// precedence is applied by the callers.
func resolveRegistryURLs(id string) (registryURLs, error) {
	if id == "" {
		return registryURLs{}, nil
	}
	list, err := knownRegistries()
	if err != nil {
		return registryURLs{}, err
	}
	r, err := list.Get(id)
	if err != nil {
		return registryURLs{}, err
	}
	fmt.Fprintf(os.Stderr, "Using registry %s (%s, %s)\n", r.ID, r.Operator.Name, r.State)
	return registryURLs{ra: r.RA.BaseURL, tl: r.TL.BaseURL}, nil
}
