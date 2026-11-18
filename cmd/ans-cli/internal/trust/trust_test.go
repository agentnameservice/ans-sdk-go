package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

var testScope = Scope{RegistryID: "example", Environment: "test"}

// keyLine renders a fresh P-256 key as /root-keys publishes it under name.
func keyLine(t *testing.T, name string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return lineFor(t, name, &priv.PublicKey)
}

func lineFor(t *testing.T, name string, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%s+%x+%s", name, sum[:4], base64.StdEncoding.EncodeToString(append([]byte{0x02}, der...)))
}

func mustKeys(t *testing.T, host string, lines ...string) []Key {
	t.Helper()
	keys, err := ValidateKeyLines(host, lines)
	if err != nil {
		t.Fatalf("ValidateKeyLines: %v", err)
	}
	return keys
}

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

// caCert returns a self-signed CA certificate, or a non-CA leaf when isCA is false.
func caCert(t *testing.T, cn string, isCA bool) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func pemOf(certs ...*x509.Certificate) []byte {
	out := make([]byte, 0, 2048*len(certs))
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

func mustRoots(t *testing.T, certs ...*x509.Certificate) []Root {
	t.Helper()
	roots, err := ParseCABundle(pemOf(certs...))
	if err != nil {
		t.Fatalf("ParseCABundle: %v", err)
	}
	return roots
}

func TestScope(t *testing.T) {
	tests := []struct {
		name  string
		scope Scope
		ok    bool
	}{
		{name: "plain", scope: Scope{"godaddy", "production"}, ok: true},
		{name: "hyphen and digits", scope: Scope{"my-reg2", "test"}, ok: true},
		{name: "double hyphen", scope: Scope{"a--b", "test"}},
		{name: "empty id", scope: Scope{"", "test"}},
		{name: "empty environment", scope: Scope{"x", ""}},
		{name: "upper case", scope: Scope{"X", "test"}},
		{name: "leading hyphen", scope: Scope{"-x", "test"}},
		{name: "trailing hyphen", scope: Scope{"x-", "test"}},
		{name: "path separator", scope: Scope{"a/b", "test"}},
		{name: "dot dot", scope: Scope{"..", "test"}},
		{name: "environment with slash", scope: Scope{"x", "../../etc"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.scope.validate()
			if (err == nil) != tt.ok {
				t.Fatalf("validate(%q) = %v, want ok=%v", tt.scope, err, tt.ok)
			}
			if !tt.ok && !errors.Is(err, ErrInvalidScope) {
				t.Errorf("err = %v, want ErrInvalidScope", err)
			}
			if got, want := tt.scope.String(), tt.scope.RegistryID+"/"+tt.scope.Environment; got != want {
				t.Errorf("String() = %q, want %q", got, want)
			}
		})
	}
}

func TestNewStoreAndPaths(t *testing.T) {
	if _, err := NewStore(""); !errors.Is(err, ErrNoConfigDir) {
		t.Fatalf("NewStore(\"\") err = %v, want ErrNoConfigDir", err)
	}
	s, err := NewStore("/cfg")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	tests := []struct {
		name string
		fn   func(Scope) (string, error)
		want string
	}{
		{"keys", s.KeysPath, filepath.Join("/cfg", "registries", "example", "test", "tl-keys.txt")},
		{"roots", s.RootsPath, filepath.Join("/cfg", "registries", "example", "test", "trusted-roots.pem")},
		{"bundle", s.BundlePath, filepath.Join("/cfg", "registries", "example", "test", "identity-ca-bundle.pem")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fn(testScope)
			if err != nil || got != tt.want {
				t.Errorf("path = %q, %v; want %q", got, err, tt.want)
			}
			if _, err := tt.fn(Scope{"../x", "test"}); !errors.Is(err, ErrInvalidScope) {
				t.Errorf("invalid scope err = %v, want ErrInvalidScope", err)
			}
		})
	}
}

func TestWriteFile(t *testing.T) {
	t.Run("creates parents with private permissions", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "a", "b", "f.txt")
		if err := writeFile(path, []byte("x")); err != nil {
			t.Fatalf("writeFile: %v", err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if info.Mode().Perm() != filePerm {
			t.Errorf("perm = %o, want %o", info.Mode().Perm(), filePerm)
		}
		if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
			t.Errorf("temp file left behind: %v", entries)
		}
	})
	t.Run("parent is a file", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(parent, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := writeFile(filepath.Join(parent, "f.txt"), []byte("x")); err == nil || !strings.Contains(err.Error(), "create") {
			t.Errorf("err = %v, want create error", err)
		}
	})
	t.Run("directory not writable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores directory permissions")
		}
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		if err := writeFile(filepath.Join(dir, "f.txt"), []byte("x")); err == nil || !strings.Contains(err.Error(), "write") {
			t.Errorf("err = %v, want write error", err)
		}
	})
	t.Run("target is a directory", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "f.txt")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writeFile(target, []byte("x")); err == nil {
			t.Error("rename over a directory should fail")
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Errorf("temp file left behind: %v", entries)
		}
	})
	t.Run("closed temp file", func(t *testing.T) {
		tmp, err := os.CreateTemp(t.TempDir(), "x")
		if err != nil {
			t.Fatal(err)
		}
		_ = tmp.Close()
		if err := writeTemp(tmp, []byte("x")); err == nil {
			t.Error("writeTemp on a closed file should fail")
		}
	})
}

func TestReadFile(t *testing.T) {
	sentinel := errors.New("absent")
	dir := t.TempDir()
	if _, err := readFile(filepath.Join(dir, "missing"), sentinel); !errors.Is(err, sentinel) {
		t.Errorf("missing: err = %v, want sentinel", err)
	}
	if _, err := readFile(dir, sentinel); err == nil || errors.Is(err, sentinel) {
		t.Errorf("directory: err = %v, want a read error", err)
	}
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readFile(path, sentinel); err != nil || string(data) != "hi" {
		t.Errorf("readFile = %q, %v", data, err)
	}
}

func TestValidateKeyLines(t *testing.T) {
	const host = "tl.example.com"
	good := keyLine(t, host)
	tests := []struct {
		name    string
		host    string
		lines   []string
		wantErr string
		wantN   int
	}{
		{name: "one key", host: host, lines: []string{good}, wantN: 1},
		{name: "two keys", host: host, lines: []string{good, keyLine(t, host)}, wantN: 2},
		{name: "name may be a path under the host", host: host, lines: []string{keyLine(t, host+"/log-2")}, wantN: 1},
		{name: "empty host", host: "", lines: []string{good}, wantErr: "log host is required"},
		{name: "no lines", host: host, lines: nil, wantErr: "no keys to validate"},
		{name: "malformed line", host: host, lines: []string{good, "not+a+key"}, wantErr: "line 2"},
		{name: "wrong host", host: host, lines: []string{keyLine(t, "evil.example.com")}, wantErr: `does not name the log host "tl.example.com"`},
		{name: "host as a prefix without separator", host: host, lines: []string{keyLine(t, host+".evil.com")}, wantErr: "does not name the log host"},
		{name: "duplicate key id", host: host, lines: []string{good, good}, wantErr: "already used by line 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := ValidateKeyLines(tt.host, tt.lines)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if len(keys) != tt.wantN {
				t.Fatalf("got %d keys, want %d", len(keys), tt.wantN)
			}
			for i, k := range keys {
				if k.Line != tt.lines[i] || !strings.HasPrefix(k.Name, tt.host) || len(k.KIDHex()) != 8 {
					t.Errorf("key %d = %+v", i, k)
				}
			}
		})
	}
}

func TestFetchKeys(t *testing.T) {
	const host = "tl.example.com"
	line := keyLine(t, host)
	tests := []struct {
		name    string
		client  scitt.Client
		wantErr string
	}{
		{name: "ok", client: scitt.NewMockClient().WithRootKeys([]string{line})},
		{name: "transport error", client: scitt.NewMockClient().WithError("root-keys", errors.New("boom")), wantErr: "boom"},
		{name: "wrong host", client: scitt.NewMockClient().WithRootKeys([]string{keyLine(t, "other.example")}), wantErr: "does not name the log host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := FetchKeys(context.Background(), tt.client, host)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || len(keys) != 1 || keys[0].Line != line {
				t.Fatalf("keys = %+v, err = %v", keys, err)
			}
		})
	}
}

func TestSaveAndLoadKeys(t *testing.T) {
	const host = "tl.example.com"
	s := newStore(t)
	first := keyLine(t, host)
	second := keyLine(t, host)

	if _, err := s.LoadKeys(testScope); !errors.Is(err, ErrNoSavedKeys) || !strings.Contains(err.Error(), "example/test") {
		t.Fatalf("LoadKeys before save: %v", err)
	}

	res, err := s.SaveKeys(testScope, mustKeys(t, host, first))
	if err != nil || res.Added != 1 || len(res.Keys) != 1 || len(res.Collisions) != 0 {
		t.Fatalf("first save = %+v, %v", res, err)
	}
	if info, statErr := os.Stat(res.Path); statErr != nil || info.Mode().Perm() != filePerm {
		t.Errorf("saved file: %v %v", info, statErr)
	}

	// Saving the same key again changes nothing on disk: a trailing blank
	// line planted in the file survives, which a rewrite would drop.
	plantSentinel(t, res.Path)
	res, err = s.SaveKeys(testScope, mustKeys(t, host, first))
	if err != nil || res.Added != 0 || len(res.Keys) != 1 {
		t.Fatalf("re-save = %+v, %v", res, err)
	}
	assertSentinel(t, res.Path, true)

	// A refresh that returns only the new key still keeps the old one.
	res, err = s.SaveKeys(testScope, mustKeys(t, host, second))
	if err != nil || res.Added != 1 || len(res.Keys) != 2 || res.Keys[0].Line != first || res.Keys[1].Line != second {
		t.Fatalf("refresh = %+v, %v", res, err)
	}
	loaded, err := s.LoadKeys(testScope)
	if err != nil || len(loaded) != 2 || loaded[0].Line != first || loaded[1].Line != second {
		t.Fatalf("LoadKeys = %+v, %v", loaded, err)
	}

	// A different scope sees nothing.
	if _, otherErr := s.LoadKeys(Scope{"example", "production"}); !errors.Is(otherErr, ErrNoSavedKeys) {
		t.Errorf("other scope: %v", otherErr)
	}

	// Lookup verifies against both.
	ks, err := Lookup(loaded)
	if err != nil || ks.Len() != 2 {
		t.Fatalf("Lookup = %v, %v", ks, err)
	}
	if _, err := ks.Get(loaded[0].KID); err != nil {
		t.Errorf("Get first: %v", err)
	}
	if _, err := Lookup([]Key{{Line: "bad"}}); err == nil {
		t.Error("Lookup of a bad line should fail")
	}
}

func TestSaveKeysCollision(t *testing.T) {
	const host = "tl.example.com"
	s := newStore(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	saved := lineFor(t, host, &priv.PublicKey)
	renamed := lineFor(t, host+"/renamed", &priv.PublicKey) // same kid, different name
	fresh := keyLine(t, host)

	if _, saveErr := s.SaveKeys(testScope, mustKeys(t, host, saved)); saveErr != nil {
		t.Fatal(saveErr)
	}
	res, err := s.SaveKeys(testScope, mustKeys(t, host, renamed, fresh))
	if err != nil {
		t.Fatalf("SaveKeys: %v", err)
	}
	if res.Added != 1 || len(res.Collisions) != 1 || len(res.Keys) != 2 {
		t.Fatalf("result = %+v", res)
	}
	if res.Collisions[0].Saved.Line != saved || res.Collisions[0].Fetched.Line != renamed {
		t.Errorf("collision = %+v", res.Collisions[0])
	}
	loaded, err := s.LoadKeys(testScope)
	if err != nil || len(loaded) != 2 || loaded[0].Line != saved || loaded[1].Line != fresh {
		t.Fatalf("saved key was replaced or lost: %+v %v", loaded, err)
	}

	// A collision alone writes nothing.
	plantSentinel(t, res.Path)
	res, err = s.SaveKeys(testScope, mustKeys(t, host, renamed))
	if err != nil || res.Added != 0 || len(res.Collisions) != 1 {
		t.Fatalf("collision-only = %+v, %v", res, err)
	}
	assertSentinel(t, res.Path, true)
}

// sentinel is appended to a trust file to detect rewrites: both parsers
// ignore blank lines, and a rewrite regenerates the file without them.
const sentinel = "\n\n\n"

func plantSentinel(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(sentinel); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertSentinel(t *testing.T, path string, wantPresent bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.HasSuffix(string(data), sentinel); got != wantPresent {
		t.Errorf("file rewritten=%v, want rewritten=%v", !got, !wantPresent)
	}
}

func TestSaveKeysErrors(t *testing.T) {
	const host = "tl.example.com"
	s := newStore(t)
	key := mustKeys(t, host, keyLine(t, host))
	if _, err := s.SaveKeys(Scope{"bad/", "test"}, key); !errors.Is(err, ErrInvalidScope) {
		t.Errorf("invalid scope: %v", err)
	}
	path, _ := s.KeysPath(testScope)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveKeys(testScope, key); err == nil || !strings.Contains(err.Error(), "move the file aside") {
		t.Errorf("corrupt saved file: %v", err)
	}
}

func TestLoadKeysErrors(t *testing.T) {
	const host = "tl.example.com"
	line := keyLine(t, host)
	tests := []struct {
		name    string
		content string
		wantErr string
		wantIs  error
	}{
		{name: "empty file", content: "\n\n", wantIs: ErrNoSavedKeys, wantErr: "is empty"},
		{name: "corrupt line", content: line + "\nnope\n", wantErr: "line 2"},
		{name: "duplicate kid", content: line + "\n" + line + "\n", wantErr: "duplicate key id"},
		{name: "blank lines and spaces tolerated", content: "\n  " + line + "  \n\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStore(t)
			path, _ := s.KeysPath(testScope)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			keys, err := s.LoadKeys(testScope)
			if tt.wantErr == "" {
				if err != nil || len(keys) != 1 || keys[0].Line != line {
					t.Fatalf("LoadKeys = %+v, %v", keys, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("err = %v, want Is %v", err, tt.wantIs)
			}
		})
	}
	t.Run("invalid scope", func(t *testing.T) {
		if _, err := newStore(t).LoadKeys(Scope{"", ""}); !errors.Is(err, ErrInvalidScope) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		s := newStore(t)
		path, _ := s.KeysPath(testScope)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := s.LoadKeys(testScope); err == nil || errors.Is(err, ErrNoSavedKeys) {
			t.Errorf("err = %v, want a read error", err)
		}
	})
}

func TestParseCABundle(t *testing.T) {
	ca1 := caCert(t, "Root 1", true)
	ca2 := caCert(t, "Root 2", true)
	leaf := caCert(t, "Leaf", false)
	tests := []struct {
		name    string
		data    []byte
		wantN   int
		wantErr string
	}{
		{name: "two roots", data: pemOf(ca1, ca2), wantN: 2},
		{name: "comments between blocks", data: append([]byte("# us-east-1\n"), pemOf(ca1)...), wantN: 1},
		{name: "duplicate collapsed", data: pemOf(ca1, ca1), wantN: 1},
		{name: "empty", data: nil, wantErr: "no certificate"},
		{name: "no pem", data: []byte("hello"), wantErr: "no certificate"},
		{name: "wrong block type", data: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), wantErr: `block 1 is "PRIVATE KEY"`},
		{name: "bad der", data: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}), wantErr: "block 1:"},
		{name: "leaf rejected", data: pemOf(ca1, leaf), wantErr: "block 2 (CN=Leaf) is not a CA"},
		{name: "leaf with control characters in its name", data: pemOf(caCert(t, "Bad\nLeaf", false)), wantErr: "block 1 (CN=Bad?Leaf) is not a CA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roots, err := ParseCABundle(tt.data)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || len(roots) != tt.wantN {
				t.Fatalf("roots = %d, err = %v; want %d", len(roots), err, tt.wantN)
			}
			r := roots[0]
			want := sha256.Sum256(r.Cert.Raw)
			if r.Fingerprint != want || r.FingerprintHex() != hex.EncodeToString(want[:]) {
				t.Errorf("fingerprint mismatch")
			}
			if !strings.Contains(r.Describe(), "CN=Root 1") || !strings.Contains(r.Describe(), r.FingerprintHex()) {
				t.Errorf("Describe = %q", r.Describe())
			}
			if again, err := ParseCABundle(r.PEM()); err != nil || len(again) != 1 || again[0].Fingerprint != r.Fingerprint {
				t.Errorf("PEM round trip failed: %v", err)
			}
		})
	}
}

func TestFetchBundle(t *testing.T) {
	ca := caCert(t, "Root", true)
	bundle := pemOf(ca)
	sum := sha256.Sum256(bundle)
	goodHash := hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/ca.pem", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(bundle) })
	mux.HandleFunc("/big.pem", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(make([]byte, maxBundleBytes+1)) })
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	client := server.Client()

	tests := []struct {
		name    string
		url     string
		hash    string
		client  *http.Client
		wantErr string
		wantIs  error
	}{
		{name: "ok", url: server.URL + "/ca.pem", hash: goodHash, client: client},
		{name: "bad hash encoding", url: server.URL + "/ca.pem", hash: "zz", client: client, wantErr: "not 64 hex digits"},
		{name: "short hash", url: server.URL + "/ca.pem", hash: "abcd", client: client, wantErr: "not 64 hex digits"},
		{name: "http url", url: "http://example.com/ca.pem", hash: goodHash, client: client, wantErr: "is not https"},
		{name: "unparsable url", url: "https://%zz", hash: goodHash, client: client, wantErr: "is not https"},
		{name: "not found", url: server.URL + "/missing.pem", hash: goodHash, client: client, wantErr: "status 404"},
		{name: "too large", url: server.URL + "/big.pem", hash: goodHash, client: client, wantErr: "exceeds"},
		{name: "hash mismatch", url: server.URL + "/ca.pem", hash: strings.Repeat("0", 64), client: client, wantIs: ErrBundleHashMismatch},
		{name: "connection refused", url: "https://127.0.0.1:1/ca.pem", hash: goodHash, client: &http.Client{}, wantErr: "fetch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := FetchBundle(context.Background(), tt.client, tt.url, tt.hash)
			if tt.wantErr != "" || tt.wantIs != nil {
				if err == nil {
					t.Fatal("expected error")
				}
				if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("err = %v, want containing %q", err, tt.wantErr)
				}
				if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
					t.Errorf("err = %v, want Is %v", err, tt.wantIs)
				}
				return
			}
			if err != nil || string(data) != string(bundle) {
				t.Fatalf("FetchBundle = %d bytes, %v", len(data), err)
			}
		})
	}
}

func TestSaveBundle(t *testing.T) {
	s := newStore(t)
	path, err := s.SaveBundle(testScope, []byte("pem"))
	if err != nil {
		t.Fatalf("SaveBundle: %v", err)
	}
	want, _ := s.BundlePath(testScope)
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if data, _ := os.ReadFile(path); string(data) != "pem" {
		t.Errorf("content = %q", data)
	}
	if _, err := s.LoadRoots(testScope); !errors.Is(err, ErrNoTrustedRoots) {
		t.Errorf("saving a bundle must not trust its roots: %v", err)
	}
	if _, err := s.SaveBundle(Scope{"A", "test"}, nil); !errors.Is(err, ErrInvalidScope) {
		t.Errorf("invalid scope: %v", err)
	}
	if _, err := s.SaveBundle(Scope{"example", "production"}, nil); err == nil {
		// A zero-length write succeeds; make sure a failing write is reported.
		t.Log("empty bundle saved")
	}
	s2 := &Store{dir: filepath.Join(t.TempDir(), "f")}
	if err := os.WriteFile(s2.dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.SaveBundle(testScope, []byte("x")); err == nil {
		t.Error("write under a file should fail")
	}
}

func TestTrustRootsAdd(t *testing.T) {
	ca1 := caCert(t, "Root 1", true)
	ca2 := caCert(t, "Root 2", true)
	s := newStore(t)

	if _, err := s.LoadRoots(testScope); !errors.Is(err, ErrNoTrustedRoots) || !strings.Contains(err.Error(), "example/test") {
		t.Fatalf("LoadRoots before trust: %v", err)
	}

	steps := []struct {
		name        string
		roots       []*x509.Certificate
		wantAdded   int
		wantTotal   int
		wantRewrite bool
	}{
		{name: "first root", roots: []*x509.Certificate{ca1}, wantAdded: 1, wantTotal: 1, wantRewrite: true},
		{name: "duplicate plus new", roots: []*x509.Certificate{ca1, ca2}, wantAdded: 1, wantTotal: 2, wantRewrite: true},
		{name: "nothing new", roots: []*x509.Certificate{ca2}, wantAdded: 0, wantTotal: 2},
	}
	for i, st := range steps {
		res, err := s.TrustRoots(testScope, mustRoots(t, st.roots...), false)
		if err != nil || res.Added != st.wantAdded || res.Removed != 0 || len(res.Roots) != st.wantTotal {
			t.Fatalf("%s: result = %+v, %v", st.name, res, err)
		}
		if i > 0 {
			assertSentinel(t, res.Path, !st.wantRewrite)
		}
		plantSentinel(t, res.Path)
	}

	loaded, err := s.LoadRoots(testScope)
	if err != nil || len(loaded) != 2 || !loaded[0].Cert.Equal(ca1) || !loaded[1].Cert.Equal(ca2) {
		t.Fatalf("LoadRoots = %v, %v", loaded, err)
	}
	if _, err := s.LoadRoots(Scope{"example", "production"}); !errors.Is(err, ErrNoTrustedRoots) {
		t.Errorf("other scope: %v", err)
	}
}

func TestTrustRootsReplace(t *testing.T) {
	ca1 := caCert(t, "Root 1", true)
	ca2 := caCert(t, "Root 2", true)
	ca3 := caCert(t, "Root 3", true)
	s := newStore(t)
	if _, err := s.TrustRoots(testScope, mustRoots(t, ca1, ca2), false); err != nil {
		t.Fatal(err)
	}

	res, err := s.TrustRoots(testScope, mustRoots(t, ca2, ca3), true)
	if err != nil || res.Added != 1 || res.Removed != 1 || len(res.Roots) != 2 {
		t.Fatalf("replace = %+v, %v", res, err)
	}
	loaded, err := s.LoadRoots(testScope)
	if err != nil || len(loaded) != 2 || !loaded[0].Cert.Equal(ca2) || !loaded[1].Cert.Equal(ca3) {
		t.Fatalf("after replace = %v, %v", loaded, err)
	}

	res, err = s.TrustRoots(testScope, mustRoots(t, ca3, ca2), true)
	if err != nil || res.Added != 0 || res.Removed != 0 {
		t.Fatalf("same-set replace = %+v, %v", res, err)
	}

	res, err = s.TrustRoots(testScope, mustRoots(t, ca1), true)
	if err != nil || res.Added != 1 || res.Removed != 2 || len(res.Roots) != 1 {
		t.Fatalf("replace with one = %+v, %v", res, err)
	}
	data, _ := os.ReadFile(res.Path)
	if !strings.Contains(string(data), "# sha256 "+mustRoots(t, ca1)[0].FingerprintHex()) || strings.Contains(string(data), "Root") {
		t.Errorf("roots file should carry fingerprints and PEM only:\n%s", data)
	}
}

// TestTrustRootsDoesNotWriteSubjects pins the defence against a CA whose
// subject carries a newline and a PEM block: nothing attacker-chosen is
// written beside the trusted blocks, so reading the file back yields exactly
// the roots that were trusted.
func TestTrustRootsDoesNotWriteSubjects(t *testing.T) {
	hidden := caCert(t, "Hidden", true)
	carrierCN := "Carrier\n" + string(pemOf(hidden)) + "# tail"
	carrier := caCert(t, carrierCN, true)
	s := newStore(t)

	res, err := s.TrustRoots(testScope, mustRoots(t, carrier), false)
	if err != nil || res.Added != 1 {
		t.Fatalf("TrustRoots = %+v, %v", res, err)
	}
	loaded, err := s.LoadRoots(testScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || !loaded[0].Cert.Equal(carrier) {
		t.Fatalf("loaded %d root(s); the hidden certificate must not become trusted", len(loaded))
	}
	if subj := loaded[0].Subject(); strings.ContainsAny(subj, "\n\r") || !strings.Contains(subj, "Carrier?") {
		t.Errorf("Subject() = %q, want control characters replaced", subj)
	}
	if desc := loaded[0].Describe(); strings.Contains(desc, "\n") {
		t.Errorf("Describe() leaks a newline: %q", desc)
	}
}

func TestTrustRootsErrors(t *testing.T) {
	ca := caCert(t, "Root", true)
	s := newStore(t)
	if _, err := s.TrustRoots(Scope{"x", "Prod"}, mustRoots(t, ca), false); !errors.Is(err, ErrInvalidScope) {
		t.Errorf("invalid scope: %v", err)
	}
	path, _ := s.RootsPath(testScope)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TrustRoots(testScope, mustRoots(t, ca), false); err == nil || !strings.Contains(err.Error(), "move the file aside") {
		t.Errorf("corrupt roots file: %v", err)
	}
	if _, err := s.LoadRoots(testScope); err == nil || errors.Is(err, ErrNoTrustedRoots) {
		t.Errorf("corrupt LoadRoots: %v", err)
	}
	if _, err := s.LoadRoots(Scope{"", "test"}); !errors.Is(err, ErrInvalidScope) {
		t.Errorf("LoadRoots invalid scope: %v", err)
	}
	s2 := &Store{dir: filepath.Join(t.TempDir(), "f")}
	if err := os.WriteFile(s2.dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.TrustRoots(testScope, mustRoots(t, ca), false); err == nil {
		t.Error("write under a file should fail")
	}
	if _, err := s2.SaveKeys(testScope, mustKeys(t, "h", keyLine(t, "h"))); err == nil {
		t.Error("key write under a file should fail")
	}
}
