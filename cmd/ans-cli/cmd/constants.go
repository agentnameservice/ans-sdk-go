package cmd

// Display formatting constants
const (
	// SeparatorWidthStandard is the standard width for separator lines
	SeparatorWidthStandard = 60
	// SeparatorWidthWide is the wide width for separator lines
	SeparatorWidthWide = 80
	// MaxHashDisplayLength is the maximum length for displaying hash values
	MaxHashDisplayLength = 64
)

// Command argument constants
const (
	// RequiredCSRArgs is the number of required arguments for CSR commands
	RequiredCSRArgs = 2
)

// Default values for flags
const (
	// DefaultSearchLimit is the default number of search results
	DefaultSearchLimit = 20
	// DefaultEventsLimit is the default number of events to return
	DefaultEventsLimit = 20
	// DefaultRSAKeySize is the default RSA key size in bits
	DefaultRSAKeySize = 2048
	// DefaultCSRType selects which CSRs generate-csr produces
	DefaultCSRType = csrTypeBoth
	// DefaultPollIntervalSeconds is the default seconds between polls in follow mode
	DefaultPollIntervalSeconds = 5
)
