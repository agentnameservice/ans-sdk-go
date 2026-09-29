package scitt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// checkpointSigner is a generated P-256 log key together with the identity a
// verifier pins for it through /root-keys.
type checkpointSigner struct {
	priv *ecdsa.PrivateKey
	kid  [4]byte
	name string
}

func newCheckpointSigner(t *testing.T, name string) *checkpointSigner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	sum := sha256.Sum256(spkiDER(t, &priv.PublicKey))
	var kid [4]byte
	copy(kid[:], sum[:4])
	return &checkpointSigner{priv: priv, kid: kid, name: name}
}

func spkiDER(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	return der
}

// rootKeysLine renders the signer the way the log advertises it at /root-keys:
// <name>+<kid hex>+<base64(0x02 || SPKI-DER)>.
func (s *checkpointSigner) rootKeysLine(t *testing.T) string {
	t.Helper()
	keyBytes := append([]byte{0x02}, spkiDER(t, &s.priv.PublicKey)...)
	return fmt.Sprintf("%s+%x+%s", s.name, s.kid, base64.StdEncoding.EncodeToString(keyBytes))
}

func (s *checkpointSigner) keyStore(t *testing.T) *KeyStore {
	t.Helper()
	ks, err := NewKeyStore([]string{s.rootKeysLine(t)})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return ks
}

// signASN1 signs SHA-256(body) as the log's primary checkpoint signer does.
func (s *checkpointSigner) signASN1(t *testing.T, body []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(body)
	sig, err := ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	return sig
}

// signP1363 signs SHA-256(body) in the fixed-width r||s form.
func (s *checkpointSigner) signP1363(t *testing.T, body []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(body)
	r, sv, err := ecdsa.Sign(rand.Reader, s.priv, digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	sv.FillBytes(out[32:])
	return out
}

// checkpointBody renders the C2SP checkpoint body: origin, decimal size, base64
// root hash, then any extension lines, each newline-terminated.
func checkpointBody(origin string, size uint64, root [32]byte, extensions ...string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%d\n%s\n", origin, size, base64.StdEncoding.EncodeToString(root[:]))
	for _, ext := range extensions {
		b.WriteString(ext)
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// signatureLine renders one note signature line: an em dash, the signer name,
// and base64(kid || sig).
func signatureLine(name string, kid [4]byte, sig []byte) string {
	blob := append(append([]byte{}, kid[:]...), sig...)
	return "— " + name + " " + base64.StdEncoding.EncodeToString(blob) + "\n"
}

// signedNote assembles the body, the blank separator line, and the signature lines.
func signedNote(body []byte, lines ...string) []byte {
	return append(append([]byte{}, body...), []byte("\n"+strings.Join(lines, ""))...)
}

func TestVerifyCheckpoint(t *testing.T) {
	t.Parallel()

	const origin = "log.example"
	root := sha256.Sum256([]byte("root"))
	s := newCheckpointSigner(t, origin)
	other := newCheckpointSigner(t, "other.example")
	keys := s.keyStore(t)

	bothKeys, err := NewKeyStore([]string{s.rootKeysLine(t), other.rootKeysLine(t)})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}

	body := checkpointBody(origin, 42, root)
	validLine := signatureLine(origin, s.kid, s.signASN1(t, body))
	unknownLine := signatureLine(other.name, other.kid, other.signASN1(t, body))
	wrongNameLine := signatureLine("someone.else", s.kid, s.signASN1(t, body))
	// A compact-JWS envelope carrying the same key hash, as the log's additional signer emits.
	jwsLine := signatureLine(origin, s.kid, []byte("eyJhbGciOiJFUzI1NiJ9.eyJvcmlnaW4iOiJsb2cifQ.c2ln"))
	otherJWSLine := signatureLine(other.name, other.kid, []byte("eyJhbGciOiJFUzI1NiJ9.eyJvcmlnaW4iOiJvdGhlciJ9.c2ln"))
	tamperedLine := signatureLine(origin, s.kid, s.signASN1(t, checkpointBody(origin, 41, root)))

	rootB64 := base64.StdEncoding.EncodeToString(root[:])
	rawBody := func(lines ...string) []byte { return []byte(strings.Join(lines, "\n") + "\n") }
	// signRaw signs an arbitrary body so that only the parse stage can reject the note.
	signRaw := func(b []byte) []byte { return signedNote(b, signatureLine(origin, s.kid, s.signASN1(t, b))) }

	extBody := checkpointBody(origin, 42, root, "extension one", "extension two")
	verified := &Checkpoint{Origin: origin, Size: 42, RootHash: root, KeyID: s.kid}

	tests := []struct {
		name        string
		note        []byte
		keys        KeyLookup
		want        *Checkpoint
		wantSigErr  *SignatureErrorType
		wantKid     [4]byte
		wantCPErr   *CheckpointErrorType
		errContains string
	}{
		{
			name: "ASN.1 signature verifies",
			note: signedNote(body, validLine),
			want: verified,
		},
		{
			name: "P1363 signature verifies",
			note: signedNote(body, signatureLine(origin, s.kid, s.signP1363(t, body))),
			want: verified,
		},
		{
			name: "unknown kid after the verifying line is ignored",
			note: signedNote(body, validLine, unknownLine),
			want: verified,
		},
		{
			name: "unknown kid before the verifying line is ignored",
			note: signedNote(body, unknownLine, validLine),
			want: verified,
		},
		{
			name: "same-kid envelope that does not verify is skipped when another line verifies",
			note: signedNote(body, jwsLine, validLine),
			want: verified,
		},
		{
			name: "extension lines are part of the signed body",
			note: signedNote(extBody, signatureLine(origin, s.kid, s.signASN1(t, extBody))),
			want: verified,
		},
		{
			name: "size zero is accepted",
			note: signRaw(checkpointBody(origin, 0, root)),
			want: &Checkpoint{Origin: origin, Size: 0, RootHash: root, KeyID: s.kid},
		},
		{
			name:       "only line has an unknown kid",
			note:       signedNote(body, unknownLine),
			wantSigErr: ptr(SigErrUnknownKeyID),
			wantKid:    other.kid,
		},
		{
			name:       "unknown kid is reported when only an envelope sits under the known key",
			note:       signedNote(body, jwsLine, unknownLine),
			wantSigErr: ptr(SigErrUnknownKeyID),
			wantKid:    other.kid,
		},
		{
			name:       "tampered body",
			note:       signedNote(body, tamperedLine),
			wantSigErr: ptr(SigErrSignatureInvalid),
			wantKid:    s.kid,
		},
		{
			name:        "failing non-envelope line under a known key rejects before a later valid line",
			note:        signedNote(body, tamperedLine, validLine),
			wantSigErr:  ptr(SigErrSignatureInvalid),
			wantKid:     s.kid,
			errContains: "did not verify",
		},
		{
			name:       "failing non-envelope line under a known key rejects despite an unknown line",
			note:       signedNote(body, tamperedLine, unknownLine),
			wantSigErr: ptr(SigErrSignatureInvalid),
			wantKid:    s.kid,
		},
		{
			name:        "same-kid envelope alone does not verify",
			note:        signedNote(body, jwsLine),
			wantSigErr:  ptr(SigErrSignatureInvalid),
			wantKid:     s.kid,
			errContains: "only a JWS envelope",
		},
		{
			name:        "first of two envelope lines under different pinned keys is the one reported",
			note:        signedNote(body, jwsLine, otherJWSLine),
			keys:        bothKeys,
			wantSigErr:  ptr(SigErrSignatureInvalid),
			wantKid:     s.kid,
			errContains: "only a JWS envelope",
		},
		{
			name:        "origin differs from the key name",
			note:        signRaw(checkpointBody("evil.example", 42, root)),
			wantSigErr:  ptr(SigErrIssuerMismatch),
			wantKid:     s.kid,
			errContains: `origin "evil.example"`,
		},
		{
			name:        "signer name differs from the key name",
			note:        signedNote(body, wrongNameLine),
			wantSigErr:  ptr(SigErrIssuerMismatch),
			wantKid:     s.kid,
			errContains: `signer "someone.else"`,
		},
		{
			name:        "wrong-name verifying line rejects before a later correct line",
			note:        signedNote(body, wrongNameLine, validLine),
			wantSigErr:  ptr(SigErrIssuerMismatch),
			wantKid:     s.kid,
			errContains: `signer "someone.else"`,
		},
		{
			name:        "another pinned log's key signs a note carrying this origin",
			note:        signedNote(body, unknownLine),
			keys:        bothKeys,
			wantSigErr:  ptr(SigErrIssuerMismatch),
			wantKid:     other.kid,
			errContains: `origin "log.example" does not match key name "other.example"`,
		},
		{
			name: "two-key store verifies a note from either pinned log",
			note: signedNote(checkpointBody(other.name, 7, root),
				signatureLine(other.name, other.kid, other.signASN1(t, checkpointBody(other.name, 7, root)))),
			keys: bothKeys,
			want: &Checkpoint{Origin: other.name, Size: 7, RootHash: root, KeyID: other.kid},
		},
		{
			name:      "size is not a decimal",
			note:      signRaw(rawBody(origin, "forty-two", rootB64)),
			wantCPErr: ptr(CheckpointErrInvalidSize),
		},
		{
			name:      "size is negative",
			note:      signRaw(rawBody(origin, "-1", rootB64)),
			wantCPErr: ptr(CheckpointErrInvalidSize),
		},
		{
			name:      "size overflows uint64",
			note:      signRaw(rawBody(origin, "18446744073709551616", rootB64)),
			wantCPErr: ptr(CheckpointErrInvalidSize),
		},
		{
			name:      "root hash is not base64",
			note:      signRaw(rawBody(origin, "42", "not*base64")),
			wantCPErr: ptr(CheckpointErrInvalidRootHash),
		},
		{
			name:      "root hash is not 32 bytes",
			note:      signRaw(rawBody(origin, "42", base64.StdEncoding.EncodeToString(root[:31]))),
			wantCPErr: ptr(CheckpointErrInvalidRootHash),
		},
		{
			name:      "empty origin",
			note:      signRaw(rawBody("", "42", rootB64)),
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "fewer than three body lines",
			note:      signRaw(rawBody(origin, "42")),
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "missing blank-line separator",
			note:      append(append([]byte{}, body...), validLine...),
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "NUL byte in the origin",
			note:      signRaw(rawBody("log\x00example", "42", rootB64)),
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "invalid UTF-8 in the origin",
			note:      signRaw(rawBody("log\xffexample", "42", rootB64)),
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "tab in an extension line",
			note:      signRaw(checkpointBody(origin, 42, root, "ext\tline")),
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "CRLF line endings",
			note:      []byte(strings.ReplaceAll(string(signedNote(body, validLine)), "\n", "\r\n")),
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "no signature lines",
			note:      signedNote(body),
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "empty signature line",
			note:      signedNote(body, "\n", validLine),
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "signature line without the em dash",
			note:      signedNote(body, strings.Replace(validLine, "—", "-", 1)),
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "signature line without a name",
			note:      signedNote(body, "— "+base64.StdEncoding.EncodeToString(append(s.kid[:], 1, 2, 3))+"\n"),
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "signature line with invalid base64",
			note:      signedNote(body, "— "+origin+" !!!\n"),
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "signature blob too short for a key hash and signature",
			note:      signedNote(body, "— "+origin+" "+base64.StdEncoding.EncodeToString(s.kid[:])+"\n"),
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "last signature line not newline-terminated",
			note:      []byte(strings.TrimSuffix(string(signedNote(body, validLine)), "\n")),
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "empty note",
			note:      nil,
			wantCPErr: ptr(CheckpointErrMalformed),
		},
		{
			name:      "oversized note",
			note:      make([]byte, MaxCheckpointNoteSize+1),
			wantCPErr: ptr(CheckpointErrOversizedInput),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			lookup := tt.keys
			if lookup == nil {
				lookup = keys
			}
			got, err := VerifyCheckpoint(tt.note, lookup)

			switch {
			case tt.wantSigErr != nil:
				assertSignatureError(t, err, *tt.wantSigErr, tt.wantKid)
			case tt.wantCPErr != nil:
				assertCheckpointError(t, err, *tt.wantCPErr)
			default:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if *got != *tt.want {
					t.Errorf("checkpoint = %+v, want %+v", *got, *tt.want)
				}
				return
			}
			if got != nil {
				t.Errorf("checkpoint = %+v, want nil on error", *got)
			}
			if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error = %q, want containing %q", err.Error(), tt.errContains)
			}
		})
	}
}

// TestVerifyCheckpointAtSizeLimit pins the boundary: a note of exactly
// MaxCheckpointNoteSize bytes is still verified.
func TestVerifyCheckpointAtSizeLimit(t *testing.T) {
	t.Parallel()

	const origin = "log.example"
	root := sha256.Sum256([]byte("root"))
	s := newCheckpointSigner(t, origin)

	// A P1363 signature has a fixed width, so the signature line length is known
	// before the body (and its padding extension line) is signed.
	sigLineLen := len(signatureLine(origin, s.kid, make([]byte, 64)))
	base := checkpointBody(origin, 7, root)
	padLen := MaxCheckpointNoteSize - len(base) - 1 /* extension newline */ - 1 /* separator */ - sigLineLen
	body := checkpointBody(origin, 7, root, strings.Repeat("x", padLen))
	note := signedNote(body, signatureLine(origin, s.kid, s.signP1363(t, body)))
	if len(note) != MaxCheckpointNoteSize {
		t.Fatalf("note is %d bytes, want exactly %d", len(note), MaxCheckpointNoteSize)
	}

	got, err := VerifyCheckpoint(note, s.keyStore(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Size != 7 || got.Origin != origin || got.RootHash != root || got.KeyID != s.kid {
		t.Errorf("checkpoint = %+v", *got)
	}
}

// errLookup is a KeyLookup that fails every Get with a caller-chosen error per kid.
type errLookup map[[4]byte]error

func (l errLookup) Get(kid [4]byte) (*TrustedKey, error) { return nil, l[kid] }

func TestVerifyCheckpointUnknownKeyCause(t *testing.T) {
	t.Parallel()

	const origin = "log.example"
	root := sha256.Sum256([]byte("root"))
	s := newCheckpointSigner(t, origin)
	first := newCheckpointSigner(t, "first.example")
	second := newCheckpointSigner(t, "second.example")
	body := checkpointBody(origin, 42, root)
	note := signedNote(body,
		signatureLine(first.name, first.kid, first.signASN1(t, body)),
		signatureLine(second.name, second.kid, second.signASN1(t, body)))

	errFirst := errors.New("first lookup failed")
	errSecond := errors.New("second lookup failed")

	tests := []struct {
		name          string
		keys          KeyLookup
		wantKid       [4]byte
		wantCauseIs   error
		wantCauseType *SignatureErrorType
	}{
		{
			name:          "key store miss is carried as the cause",
			keys:          s.keyStore(t),
			wantKid:       first.kid,
			wantCauseType: ptr(SigErrUnknownKeyID),
		},
		{
			name:        "first lookup error is kept, not the last",
			keys:        errLookup{first.kid: errFirst, second.kid: errSecond},
			wantKid:     first.kid,
			wantCauseIs: errFirst,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := VerifyCheckpoint(note, tt.keys)
			assertSignatureError(t, err, SigErrUnknownKeyID, tt.wantKid)
			if tt.wantCauseIs != nil && !errors.Is(err, tt.wantCauseIs) {
				t.Errorf("errors.Is(err, cause) = false; err = %v", err)
			}
			if tt.wantCauseType != nil {
				var inner *SignatureError
				if !errors.As(errors.Unwrap(err), &inner) || inner.Type != *tt.wantCauseType || inner.Kid != tt.wantKid {
					t.Errorf("cause = %v, want *SignatureError type %d for kid %x", errors.Unwrap(err), *tt.wantCauseType, tt.wantKid)
				}
			}
		})
	}
}

func TestCheckpointCovers(t *testing.T) {
	t.Parallel()

	root := sha256.Sum256([]byte("root"))
	otherRoot := sha256.Sum256([]byte("other"))
	cp := &Checkpoint{Origin: "log.example", Size: 42, RootHash: root}

	tests := []struct {
		name    string
		receipt *VerifiedReceipt
		wantErr *CheckpointErrorType
	}{
		{
			name:    "same size and root",
			receipt: &VerifiedReceipt{TreeSize: 42, RootHash: root},
		},
		{
			name:    "receipt from a smaller tree",
			receipt: &VerifiedReceipt{TreeSize: 41, RootHash: root},
			wantErr: ptr(CheckpointErrSizeMismatch),
		},
		{
			name:    "receipt from a larger tree",
			receipt: &VerifiedReceipt{TreeSize: 43, RootHash: root},
			wantErr: ptr(CheckpointErrSizeMismatch),
		},
		{
			name:    "same size, different root",
			receipt: &VerifiedReceipt{TreeSize: 42, RootHash: otherRoot},
			wantErr: ptr(CheckpointErrRootMismatch),
		},
		{
			name:    "different size and root reports the size",
			receipt: &VerifiedReceipt{TreeSize: 1, RootHash: otherRoot},
			wantErr: ptr(CheckpointErrSizeMismatch),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := cp.Covers(tt.receipt)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			assertCheckpointError(t, err, *tt.wantErr)
		})
	}
}

func ptr[T any](v T) *T { return &v }

func assertSignatureError(t *testing.T, err error, wantType SignatureErrorType, wantKid [4]byte) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var sigErr *SignatureError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected *SignatureError, got %T: %v", err, err)
	}
	if sigErr.Type != wantType {
		t.Errorf("error type = %d, want %d (%v)", sigErr.Type, wantType, err)
	}
	if sigErr.Kid != wantKid {
		t.Errorf("kid = %x, want %x", sigErr.Kid, wantKid)
	}
}

func assertCheckpointError(t *testing.T, err error, wantType CheckpointErrorType) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var cpErr *CheckpointError
	if !errors.As(err, &cpErr) {
		t.Fatalf("expected *CheckpointError, got %T: %v", err, err)
	}
	if cpErr.Type != wantType {
		t.Errorf("error type = %d, want %d (%v)", cpErr.Type, wantType, err)
	}
}
