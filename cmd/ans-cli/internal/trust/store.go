// Package trust keeps the trust material a consumer configures for one
// registry environment: the Transparency Log keys saved for offline
// verification and the CA roots the consumer has chosen to accept. Both are
// scoped to a registry id and environment under the CLI's configuration
// directory, so trusting a test environment's roots says nothing about
// production.
//
// Nothing here is populated from the known-registries directory. Keys arrive
// through an explicit fetch that binds each line to the log host, and roots
// only through an explicit trust step; the directory's identityCa reference is
// a pointer to a bundle, never a trust anchor.
package trust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/agentnameservice/ans-sdk-go/cmd/ans-cli/internal/registries"
)

const (
	dirPerm  = 0o700
	filePerm = 0o600

	registriesDir = "registries"
	keysFile      = "tl-keys.txt"
	rootsFile     = "trusted-roots.pem"
)

// ErrNoConfigDir reports that the CLI has nowhere to keep trust material.
var ErrNoConfigDir = errors.New("no configuration directory: pass --config-dir or set ANS_CONFIG_DIR")

// ErrInvalidScope reports a registry id or environment that cannot name a directory.
var ErrInvalidScope = errors.New("invalid trust scope")

// ErrNoSavedKeys reports that no Transparency Log keys have been saved for a scope.
var ErrNoSavedKeys = errors.New("no saved transparency log keys")

// ErrNoTrustedRoots reports that no CA roots have been trusted for a scope.
var ErrNoTrustedRoots = errors.New("no trusted roots configured")

// Scope names the registry environment a piece of trust material belongs to.
type Scope struct {
	RegistryID  string
	Environment string
}

// String returns the <id>/<environment> form.
func (s Scope) String() string { return s.RegistryID + "/" + s.Environment }

// validate holds the id and the environment to the known-registries id
// pattern, so a scope is always a safe pair of path segments.
func (s Scope) validate() error {
	for _, part := range []string{s.RegistryID, s.Environment} {
		if err := registries.ValidateID(part); err != nil {
			return fmt.Errorf("%w %q: %w", ErrInvalidScope, s.String(), err)
		}
	}
	return nil
}

// Store reads and writes trust material under one configuration directory.
type Store struct {
	dir string
}

// NewStore returns a Store rooted at dir, which must not be empty.
func NewStore(dir string) (*Store, error) {
	if dir == "" {
		return nil, ErrNoConfigDir
	}
	return &Store{dir: dir}, nil
}

// KeysPath is where a scope's saved Transparency Log keys live.
func (s *Store) KeysPath(scope Scope) (string, error) { return s.path(scope, keysFile) }

// RootsPath is where a scope's trusted CA roots live.
func (s *Store) RootsPath(scope Scope) (string, error) { return s.path(scope, rootsFile) }

func (s *Store) path(scope Scope, file string) (string, error) {
	if err := scope.validate(); err != nil {
		return "", err
	}
	return filepath.Join(s.dir, registriesDir, scope.RegistryID, scope.Environment, file), nil
}

// writeFile creates the parent directory and replaces path atomically, so a
// failure part-way leaves either the previous file or none.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	tmpName := tmp.Name()
	if err := writeTemp(tmp, data); err != nil {
		_ = os.Remove(tmpName) //nolint:gosec // G703: tmpName was created by os.CreateTemp in the validated scope directory
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil { //nolint:gosec // G703: both paths are under the config directory, built from a validated scope
		_ = os.Remove(tmpName) //nolint:gosec // G703: tmpName was created by os.CreateTemp in the validated scope directory
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeTemp(tmp *os.File, data []byte) error {
	if err := tmp.Chmod(filePerm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	return tmp.Close()
}

// readFile returns the file's bytes, or notFound when it does not exist.
func readFile(path string, notFound error) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, notFound
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}
