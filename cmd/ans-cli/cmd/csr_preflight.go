package cmd

import (
	"fmt"
	"os"

	"github.com/agentnameservice/ans-sdk-go/csrvalidation"
)

// readValidatedCSR reads a PEM CSR file and, unless skipPreflight is set,
// checks it against the registry's intake rules before any network call, so a
// CSR the registry would reject fails locally with the same guidance.
func readValidatedCSR(path string, rules csrvalidation.Rules, label string, skipPreflight bool) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s CSR file: %w", label, err)
	}
	if skipPreflight {
		fmt.Fprintf(os.Stderr, "Warning: skipping preflight validation of the %s CSR (--skip-preflight)\n", label)
		return data, nil
	}
	if _, err := csrvalidation.Validate(data, rules); err != nil {
		return nil, fmt.Errorf("%s CSR failed preflight validation: %w", label, err)
	}
	return data, nil
}
