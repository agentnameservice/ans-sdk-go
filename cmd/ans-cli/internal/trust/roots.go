package trust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const (
	// maxBundleBytes bounds a fetched CA bundle. The published bundles are a
	// few kilobytes; a megabyte leaves room without letting a hostile server
	// hand the CLI arbitrary input.
	maxBundleBytes = 1 << 20
	bundleFile     = "identity-ca-bundle.pem"
	pemCertificate = "CERTIFICATE"
)

// ErrBundleHashMismatch reports a fetched bundle whose bytes do not hash to
// the value the directory published for it.
var ErrBundleHashMismatch = errors.New("identity CA bundle does not match the published sha256")

// Root is one CA certificate a consumer trusts, or is considering trusting.
type Root struct {
	Cert *x509.Certificate
	// Fingerprint is SHA-256 over the certificate's DER bytes.
	Fingerprint [32]byte
}

// FingerprintHex returns the fingerprint as lower-case hex.
func (r Root) FingerprintHex() string { return hex.EncodeToString(r.Fingerprint[:]) }

// PEM renders the certificate as one PEM block.
func (r Root) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemCertificate, Bytes: r.Cert.Raw})
}

// RootsResult reports what TrustRoots wrote.
type RootsResult struct {
	Path string
	// Roots is every root now trusted for the scope, in file order.
	Roots []Root
	// Added counts the roots this call trusted for the first time.
	Added int
	// Removed counts the previously trusted roots a replace dropped.
	Removed int
}

// ParseCABundle decodes a PEM bundle into CA certificates. Every PEM block
// must be a CERTIFICATE that parses and asserts the CA basic constraint; text
// between blocks, such as comments naming each certificate, is ignored. A
// bundle with no certificate is an error.
func ParseCABundle(data []byte) ([]Root, error) {
	var roots []Root
	seen := make(map[[32]byte]struct{})
	rest := data
	for n := 1; ; n++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemCertificate {
			return nil, fmt.Errorf("bundle block %d is %q, want %s", n, block.Type, pemCertificate)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("bundle block %d: %w", n, err)
		}
		if !cert.IsCA {
			return nil, fmt.Errorf("bundle block %d (%s) is not a CA certificate", n, Root{Cert: cert}.Subject())
		}
		fp := sha256.Sum256(cert.Raw)
		if _, dup := seen[fp]; dup {
			continue
		}
		seen[fp] = struct{}{}
		roots = append(roots, Root{Cert: cert, Fingerprint: fp})
	}
	if len(roots) == 0 {
		return nil, errors.New("bundle holds no certificate")
	}
	return roots, nil
}

// FetchBundle downloads the CA bundle an identityCa reference names and
// checks its bytes against the published sha256. It returns the bytes only
// when they match. Fetching proves nothing about trust: the caller decides
// separately, through TrustRoots, whether to accept any of the roots. The
// client owns the request timeout.
func FetchBundle(ctx context.Context, client *http.Client, bundleURL, sha256Hex string) ([]byte, error) {
	want, err := hex.DecodeString(sha256Hex)
	if err != nil || len(want) != sha256.Size {
		return nil, fmt.Errorf("published sha256 %q is not 64 hex digits", sha256Hex)
	}
	u, err := url.Parse(bundleURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("bundle URL %q is not https", bundleURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bundleURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", bundleURL, err)
	}
	resp, err := client.Do(req) //nolint:gosec // G704: the URL is the https identityCa reference from the known-registries directory, checked above
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", bundleURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", bundleURL, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", bundleURL, err)
	}
	if len(data) > maxBundleBytes {
		return nil, fmt.Errorf("fetch %s: bundle exceeds %d bytes", bundleURL, maxBundleBytes)
	}
	got := sha256.Sum256(data)
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return nil, fmt.Errorf("%w: published %s, fetched %x", ErrBundleHashMismatch, sha256Hex, got)
	}
	return data, nil
}

// BundlePath is where a scope's fetched identity CA bundle is kept. The file
// is a download, not a trust decision; TrustRoots reads from wherever the
// user points it, this path included.
func (s *Store) BundlePath(scope Scope) (string, error) { return s.path(scope, bundleFile) }

// SaveBundle writes a fetched bundle to the scope's bundle path and returns
// that path. It never touches the trusted roots.
func (s *Store) SaveBundle(scope Scope, data []byte) (string, error) {
	path, err := s.BundlePath(scope)
	if err != nil {
		return "", err
	}
	if err := writeFile(path, data); err != nil {
		return "", err
	}
	return path, nil
}

// TrustRoots records roots as accepted for the scope. By default they join
// the roots already trusted, deduplicated by fingerprint; with replace, they
// become the whole trusted set and every other root is dropped. This is the
// only operation that changes which roots a scope trusts.
func (s *Store) TrustRoots(scope Scope, roots []Root, replace bool) (RootsResult, error) {
	path, err := s.RootsPath(scope)
	if err != nil {
		return RootsResult{}, err
	}
	previous, err := s.LoadRoots(scope)
	if err != nil && !errors.Is(err, ErrNoTrustedRoots) {
		return RootsResult{}, err
	}
	wasTrusted := make(map[[32]byte]struct{}, len(previous))
	for _, r := range previous {
		wasTrusted[r.Fingerprint] = struct{}{}
	}

	result := RootsResult{Path: path}
	kept := make(map[[32]byte]struct{}, len(previous)+len(roots))
	if !replace {
		result.Roots = append(result.Roots, previous...)
		for _, r := range previous {
			kept[r.Fingerprint] = struct{}{}
		}
	}
	for _, r := range roots {
		if _, dup := kept[r.Fingerprint]; dup {
			continue
		}
		kept[r.Fingerprint] = struct{}{}
		result.Roots = append(result.Roots, r)
		if _, was := wasTrusted[r.Fingerprint]; !was {
			result.Added++
		}
	}
	for _, r := range previous {
		if _, ok := kept[r.Fingerprint]; !ok {
			result.Removed++
		}
	}
	if result.Added == 0 && result.Removed == 0 {
		return result, nil
	}

	// Only the fingerprint is written beside each block. A certificate's
	// subject is attacker-chosen text and could carry a newline followed by
	// a PEM block, which ParseCABundle would read back as a trusted root.
	var buf bytes.Buffer
	for _, r := range result.Roots {
		fmt.Fprintf(&buf, "# sha256 %s\n", r.FingerprintHex())
		buf.Write(r.PEM())
	}
	if err := writeFile(path, buf.Bytes()); err != nil {
		return RootsResult{}, err
	}
	return result, nil
}

// LoadRoots returns the roots trusted for the scope, or ErrNoTrustedRoots.
func (s *Store) LoadRoots(scope Scope) ([]Root, error) {
	path, err := s.RootsPath(scope)
	if err != nil {
		return nil, err
	}
	data, err := readFile(path, ErrNoTrustedRoots)
	if err != nil {
		if errors.Is(err, ErrNoTrustedRoots) {
			return nil, fmt.Errorf("%w for %s", ErrNoTrustedRoots, scope)
		}
		return nil, err
	}
	roots, err := ParseCABundle(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (move the file aside and trust the roots again)", path, err)
	}
	return roots, nil
}

// Subject returns the certificate subject with control and non-printable
// characters replaced, so attacker-chosen names cannot forge output lines.
func (r Root) Subject() string {
	return strings.Map(func(c rune) rune {
		if unicode.IsPrint(c) {
			return c
		}
		return '?'
	}, r.Cert.Subject.String())
}

// Describe renders one root for display: subject, expiry, and fingerprint.
func (r Root) Describe() string {
	return fmt.Sprintf("%s (expires %s, sha256 %s)", r.Subject(), r.Cert.NotAfter.UTC().Format(time.RFC3339), r.FingerprintHex())
}
