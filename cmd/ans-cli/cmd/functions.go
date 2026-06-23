package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/models"
)

// Function validation constraints from the API specification
const (
	MaxFunctionIDLength   = 64
	MaxFunctionNameLength = 64
	MaxFunctionTags       = 5
	MaxFunctionTagLength  = 20
)

// Function flag parsing constants
const (
	// minFunctionParts is the minimum number of colon-separated parts (id:name)
	minFunctionParts = 2
	// maxFunctionParts is the maximum number of colon-separated parts (id:name:tags)
	maxFunctionParts = 3
)

// ErrInvalidFunctionFormat indicates the function flag value is malformed
var ErrInvalidFunctionFormat = errors.New("invalid function format: expected 'id:name' or 'id:name:tag1,tag2'")

// ParseFunctionFlag parses a single --function flag value in the format "id:name" or "id:name:tag1,tag2,tag3"
func ParseFunctionFlag(value string) (*models.AgentFunction, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, ErrInvalidFunctionFormat
	}

	// Split on colon, limiting to maxFunctionParts to allow colons in tag values
	parts := strings.SplitN(value, ":", maxFunctionParts)
	if len(parts) < minFunctionParts {
		return nil, ErrInvalidFunctionFormat
	}

	id := strings.TrimSpace(parts[0])
	name := strings.TrimSpace(parts[1])

	if id == "" {
		return nil, errors.New("function ID is required")
	}
	if name == "" {
		return nil, errors.New("function name is required")
	}

	fn := &models.AgentFunction{
		ID:   id,
		Name: name,
	}

	// Parse optional tags (third part)
	if len(parts) == maxFunctionParts && strings.TrimSpace(parts[2]) != "" {
		tagParts := strings.Split(parts[2], ",")
		var tags []string
		for _, t := range tagParts {
			trimmed := strings.TrimSpace(t)
			if trimmed != "" {
				tags = append(tags, trimmed)
			}
		}
		if len(tags) > 0 {
			fn.Tags = tags
		}
	}

	return fn, nil
}

// ValidateFunction validates a single AgentFunction against API constraints
func ValidateFunction(f *models.AgentFunction) error {
	if f == nil {
		return errors.New("function cannot be nil")
	}

	if f.ID == "" {
		return errors.New("function ID is required")
	}
	if len(f.ID) > MaxFunctionIDLength {
		return fmt.Errorf("function ID exceeds maximum length of %d characters", MaxFunctionIDLength)
	}

	if f.Name == "" {
		return errors.New("function name is required")
	}
	if len(f.Name) > MaxFunctionNameLength {
		return fmt.Errorf("function name exceeds maximum length of %d characters", MaxFunctionNameLength)
	}

	if len(f.Tags) > MaxFunctionTags {
		return fmt.Errorf("function tags exceed maximum count of %d", MaxFunctionTags)
	}

	for i, tag := range f.Tags {
		if len(tag) > MaxFunctionTagLength {
			return fmt.Errorf("function tag at index %d exceeds maximum length of %d characters", i, MaxFunctionTagLength)
		}
	}

	return nil
}

// ParseFunctionFlags parses multiple --function flag values and validates them
func ParseFunctionFlags(flags []string) ([]models.AgentFunction, error) {
	if len(flags) == 0 {
		return nil, nil
	}

	functions := make([]models.AgentFunction, 0, len(flags))
	seenIDs := make(map[string]bool)

	for _, flagValue := range flags {
		fn, err := ParseFunctionFlag(flagValue)
		if err != nil {
			return nil, fmt.Errorf("parsing function flag %q: %w", flagValue, err)
		}

		if err := ValidateFunction(fn); err != nil {
			return nil, fmt.Errorf("validating function %q: %w", fn.ID, err)
		}

		if seenIDs[fn.ID] {
			return nil, fmt.Errorf("duplicate function ID: %q", fn.ID)
		}
		seenIDs[fn.ID] = true

		functions = append(functions, *fn)
	}

	return functions, nil
}
