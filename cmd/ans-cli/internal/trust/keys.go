package trust

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// Key is one Transparency Log verification key as /root-keys publishes it: the
// C2SP line, the signer name it carries, and the 4-byte key id checkpoints and
// receipts refer to it by.
type Key struct {
	Line string
	Name string
	KID  [4]byte
}

// KIDHex returns the key id as /root-keys and checkpoint signatures spell it.
func (k Key) KIDHex() string { return hex.EncodeToString(k.KID[:]) }

// Collision is a fetched key whose id matches a saved key under a different
// name or key material. The saved key is kept and the fetched line is not
// written, as ANS-6 section 4.5 requires: the first-seen key wins.
type Collision struct {
	Saved   Key
	Fetched Key
}

// KeysResult reports what SaveKeys wrote.
type KeysResult struct {
	Path string
	// Keys is every key now saved for the scope, previously saved keys first.
	Keys []Key
	// Added counts the keys this call saved for the first time.
	Added int
	// Collisions lists fetched keys that were refused because a saved key
	// already holds their id.
	Collisions []Collision
}

// FetchKeys retrieves the log's /root-keys lines through client and validates
// them for logHost. The whole set is rejected when any line is. A transport
// error is returned as the client reported it, for the caller to name the URL.
func FetchKeys(ctx context.Context, client scitt.Client, logHost string) ([]Key, error) {
	lines, err := client.FetchRootKeys(ctx)
	if err != nil {
		return nil, err
	}
	return ValidateKeyLines(logHost, lines)
}

// ValidateKeyLines parses /root-keys lines and binds each to the log host.
// Every line must have the C2SP shape (name, 4-byte key id equal to the
// SHA-256 prefix of the SPKI, P-256 key), carry a name that is the log host or
// a path under it, and not reuse another line's key id. The empty host is
// rejected so a caller cannot skip the binding.
func ValidateKeyLines(logHost string, lines []string) ([]Key, error) {
	if logHost == "" {
		return nil, errors.New("root keys: log host is required to validate key names")
	}
	if len(lines) == 0 {
		return nil, errors.New("root keys: no keys to validate")
	}
	keys := make([]Key, 0, len(lines))
	seen := make(map[[4]byte]int, len(lines))
	for i, line := range lines {
		n := i + 1
		tk, err := scitt.ParseC2SPKey(line)
		if err != nil {
			return nil, fmt.Errorf("root keys line %d: %w", n, err)
		}
		if tk.Name != logHost && !strings.HasPrefix(tk.Name, logHost+"/") {
			return nil, fmt.Errorf("root keys line %d: key name %q does not name the log host %q", n, tk.Name, logHost)
		}
		if first, dup := seen[tk.Kid]; dup {
			return nil, fmt.Errorf("root keys line %d: key id %x already used by line %d", n, tk.Kid, first)
		}
		seen[tk.Kid] = n
		keys = append(keys, Key{Line: line, Name: tk.Name, KID: tk.Kid})
	}
	return keys, nil
}

// SaveKeys merges keys into the scope's saved set. A key already saved with
// the same line is left as it is, and a saved key is never removed or
// replaced, so receipts and checkpoints signed under it keep verifying. A
// fetched key whose id matches a saved key under a different line is reported
// as a Collision and not written; the other new keys still are.
func (s *Store) SaveKeys(scope Scope, keys []Key) (KeysResult, error) {
	path, err := s.KeysPath(scope)
	if err != nil {
		return KeysResult{}, err
	}
	saved, err := s.LoadKeys(scope)
	if err != nil && !errors.Is(err, ErrNoSavedKeys) {
		return KeysResult{}, err
	}
	byKID := make(map[[4]byte]Key, len(saved))
	for _, k := range saved {
		byKID[k.KID] = k
	}

	result := KeysResult{Path: path, Keys: saved}
	for _, k := range keys {
		existing, ok := byKID[k.KID]
		switch {
		case !ok:
			byKID[k.KID] = k
			result.Keys = append(result.Keys, k)
			result.Added++
		case existing.Line != k.Line:
			result.Collisions = append(result.Collisions, Collision{Saved: existing, Fetched: k})
		}
	}
	if result.Added == 0 {
		return result, nil
	}

	var b strings.Builder
	for _, k := range result.Keys {
		b.WriteString(k.Line)
		b.WriteByte('\n')
	}
	if err := writeFile(path, []byte(b.String())); err != nil {
		return KeysResult{}, err
	}
	return result, nil
}

// LoadKeys returns the keys saved for the scope in saved order, or
// ErrNoSavedKeys. A file that no longer parses is reported rather than
// repaired, since repairing would mean dropping a key.
func (s *Store) LoadKeys(scope Scope) ([]Key, error) {
	path, err := s.KeysPath(scope)
	if err != nil {
		return nil, err
	}
	data, err := readFile(path, ErrNoSavedKeys)
	if err != nil {
		if errors.Is(err, ErrNoSavedKeys) {
			return nil, fmt.Errorf("%w for %s", ErrNoSavedKeys, scope)
		}
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	keys := make([]Key, 0, len(lines))
	seen := make(map[[4]byte]struct{}, len(lines))
	for i, line := range lines {
		tk, err := scitt.ParseC2SPKey(line)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w (move the file aside and fetch the keys again)", path, i+1, err)
		}
		if _, dup := seen[tk.Kid]; dup {
			return nil, fmt.Errorf("%s line %d: duplicate key id %x (move the file aside and fetch the keys again)", path, i+1, tk.Kid)
		}
		seen[tk.Kid] = struct{}{}
		keys = append(keys, Key{Line: line, Name: tk.Name, KID: tk.Kid})
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w for %s: %s is empty", ErrNoSavedKeys, scope, path)
	}
	return keys, nil
}

// Lookup builds the key lookup VerifyCheckpoint and VerifyReceipt take from
// saved keys.
func Lookup(keys []Key) (*scitt.KeyStore, error) {
	lines := make([]string, len(keys))
	for i, k := range keys {
		lines[i] = k.Line
	}
	ks, err := scitt.NewKeyStore(lines)
	if err != nil {
		return nil, fmt.Errorf("saved keys: %w", err)
	}
	return ks, nil
}
