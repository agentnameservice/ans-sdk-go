package scitt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxCheckpointNoteSize is the maximum accepted size of a checkpoint note in
// bytes. A checkpoint is a three-line body plus a few signature lines; the bound
// keeps a hostile log from handing a verifier arbitrary amounts of input.
const MaxCheckpointNoteSize = 64 << 10

const (
	// noteSeparator ends the signed body: the body's own trailing newline
	// followed by the blank line that precedes the signature block. The note is
	// split at the first blank line: tlog-checkpoint forbids empty body and
	// extension lines, so a well-formed note has exactly one, and a blank line
	// anywhere else must fail parsing rather than move the boundary.
	noteSeparator = "\n\n"
	// signaturePrefix opens every signature line: U+2014 EM DASH and a space.
	signaturePrefix = "— "
	// jwsHeaderMarker is the base64url of `{"alg":`, the opening bytes of a
	// compact JWS whose protected header starts with alg. The log's additional
	// signer emits such an envelope under the same key hash as its ECDSA line.
	jwsHeaderMarker = "eyJhbGciOi"
	// checkpointBodyLines is the least a checkpoint body holds: origin, tree
	// size, and root hash. Any further lines are extensions.
	checkpointBodyLines = 3
)

// Checkpoint is the verified content of a transparency log's signed checkpoint:
// the tree head the log committed to under a key the caller trusts.
type Checkpoint struct {
	// Origin is the log's unique identifier, the first line of the checkpoint.
	Origin string
	// Size is the number of leaves in the tree the checkpoint commits to.
	Size uint64
	// RootHash is the Merkle tree root over the first Size leaves.
	RootHash [32]byte
	// KeyID is the 4-byte key hash of the trusted key whose signature verified.
	KeyID [4]byte
}

// Covers reports whether the checkpoint is the tree head a receipt's inclusion
// path leads to. It returns nil only when the receipt's TreeSize equals Size
// and the root the receipt walked to equals RootHash; the root comparison runs
// in constant time. Callers must separately confirm that the receipt's key
// names this log: the Name of the key that verified the receipt equals Origin.
//
// A checkpoint for a larger tree does not cover the receipt even when the leaf
// is in that tree. Relating the two heads needs an RFC 6962 section 2.1.2
// consistency proof, which this package does not verify.
func (c *Checkpoint) Covers(r *VerifiedReceipt) error {
	if r.TreeSize != c.Size {
		return &CheckpointError{
			Type:    CheckpointErrSizeMismatch,
			Message: fmt.Sprintf("receipt tree size %d, checkpoint size %d", r.TreeSize, c.Size),
		}
	}
	if subtle.ConstantTimeCompare(r.RootHash[:], c.RootHash[:]) != 1 {
		return &CheckpointError{
			Type:    CheckpointErrRootMismatch,
			Message: "receipt root does not match the checkpoint root",
		}
	}
	return nil
}

// checkpointSignature is one parsed signature line: the signer name, the
// 4-byte key hash the signer advertises, and the signature bytes.
type checkpointSignature struct {
	name string
	kid  [4]byte
	sig  []byte
}

// VerifyCheckpoint parses a signed checkpoint note and verifies it against the
// trusted keys. The note has the shape golang.org/x/mod/sumdb/note produces:
//
//	<origin>\n
//	<decimal tree size>\n
//	<base64 root hash>\n
//	[extension lines]
//	\n
//	— <signer name> <base64(key hash || signature)>\n
//	[further signature lines]
//
// Each signature line names its key by the 4-byte key hash that /root-keys
// advertises. For every line whose key the lookup knows, the signature is
// checked as ASN.1 DER ECDSA over SHA-256 of the body, then as fixed-width
// r||s. The checkpoint is accepted once one line verifies and both its signer
// name and the note's origin equal that key's Name. Lines for unknown keys are
// skipped. A line under a known key that does not verify is tolerated only when
// its payload is a compact JWS envelope, which the log emits under the same key
// hash as its ECDSA signature; any other failing line under a known key rejects
// the note with SigErrSignatureInvalid.
//
// When no line verifies, the error is a *SignatureError: SigErrUnknownKeyID
// naming the first unknown key hash when the note carried one, with the
// lookup's error as Cause, so a caller can decide whether to refresh its keys
// and retry; SigErrSignatureInvalid otherwise. Structural problems are reported
// as *CheckpointError before any signature is examined.
//
// RootHash is the root the log signed for a tree of Size leaves. It is
// comparable with a receipt's VerifiedReceipt.RootHash only when Size equals
// the receipt's TreeSize and Origin equals the Name of the key that verified
// the receipt; Covers performs the size and root comparison. /checkpoint serves
// the latest tree head, so a receipt issued against an earlier tree needs an
// RFC 6962 section 2.1.2 consistency proof between the two heads, which this
// package does not verify.
func VerifyCheckpoint(note []byte, keys KeyLookup) (*Checkpoint, error) {
	if len(note) > MaxCheckpointNoteSize {
		return nil, &CheckpointError{
			Type:    CheckpointErrOversizedInput,
			Message: fmt.Sprintf("note is %d bytes, maximum is %d", len(note), MaxCheckpointNoteSize),
		}
	}
	if err := validateNoteText(note); err != nil {
		return nil, err
	}
	body, sigs, err := splitCheckpointNote(note)
	if err != nil {
		return nil, err
	}
	cp, err := parseCheckpointBody(body)
	if err != nil {
		return nil, err
	}

	var unknownKid *[4]byte
	var unknownErr, envelopeOnly error
	for _, s := range sigs {
		key, err := keys.Get(s.kid)
		if err != nil {
			if unknownKid == nil {
				kid := s.kid
				unknownKid, unknownErr = &kid, err
			}
			continue
		}
		if !verifyCheckpointSignature(key.Key, body, s.sig) {
			if !bytes.HasPrefix(s.sig, []byte(jwsHeaderMarker)) {
				return nil, &SignatureError{
					Type:    SigErrSignatureInvalid,
					Kid:     s.kid,
					Message: "checkpoint signature did not verify",
				}
			}
			envelopeOnly = firstError(envelopeOnly, &SignatureError{
				Type:    SigErrSignatureInvalid,
				Kid:     s.kid,
				Message: "only a JWS envelope under the trusted key; no ECDSA signature verified",
			})
			continue
		}
		if err := bindCheckpointSigner(cp.Origin, s.name, key); err != nil {
			return nil, err
		}
		cp.KeyID = key.Kid
		return cp, nil
	}

	if unknownKid != nil {
		return nil, &SignatureError{
			Type:    SigErrUnknownKeyID,
			Kid:     *unknownKid,
			Message: "no checkpoint signature under a trusted key",
			Cause:   unknownErr,
		}
	}
	return nil, envelopeOnly
}

// validateNoteText rejects a note that is not valid UTF-8 or that holds a
// control character other than newline, as golang.org/x/mod/sumdb/note does,
// so line splitting never sees a carriage return, NUL, or truncated rune.
func validateNoteText(note []byte) error {
	for i := 0; i < len(note); {
		r, size := utf8.DecodeRune(note[i:])
		if (r < ' ' && r != '\n') || (r == utf8.RuneError && size == 1) {
			return malformedf("byte %d is not printable UTF-8 text", i)
		}
		i += size
	}
	return nil
}

// splitCheckpointNote separates the signed body from the signature block and
// parses every signature line. The body keeps its trailing newline: those are
// exactly the bytes the signatures cover.
func splitCheckpointNote(note []byte) ([]byte, []checkpointSignature, error) {
	sep := bytes.Index(note, []byte(noteSeparator))
	if sep < 0 {
		return nil, nil, malformedf("missing blank line before the signature block")
	}
	body, block := note[:sep+1], string(note[sep+len(noteSeparator):])
	if block == "" || !strings.HasSuffix(block, "\n") {
		return nil, nil, malformedf("signature block must be one or more newline-terminated lines")
	}

	lines := strings.Split(strings.TrimSuffix(block, "\n"), "\n")
	sigs := make([]checkpointSignature, 0, len(lines))
	for i, line := range lines {
		sig, err := parseSignatureLine(i+1, line)
		if err != nil {
			return nil, nil, err
		}
		sigs = append(sigs, sig)
	}
	return body, sigs, nil
}

// parseSignatureLine parses "— <name> <base64(key hash || signature)>".
func parseSignatureLine(n int, line string) (checkpointSignature, error) {
	rest, ok := strings.CutPrefix(line, signaturePrefix)
	if !ok {
		return checkpointSignature{}, malformedf("signature line %d does not start with an em dash", n)
	}
	name, b64, ok := strings.Cut(rest, " ")
	if !ok || name == "" {
		return checkpointSignature{}, malformedf("signature line %d lacks a signer name", n)
	}
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return checkpointSignature{}, &CheckpointError{
			Type:    CheckpointErrMalformed,
			Message: fmt.Sprintf("signature line %d is not base64", n),
			Cause:   err,
		}
	}
	if len(blob) <= c2spKidLen {
		return checkpointSignature{}, malformedf("signature line %d is too short for a key hash and signature", n)
	}

	sig := checkpointSignature{name: name, sig: blob[c2spKidLen:]}
	copy(sig.kid[:], blob[:c2spKidLen])
	return sig, nil
}

// parseCheckpointBody reads the origin, tree size, and root hash from the
// signed body; extension lines beyond the third are ignored.
func parseCheckpointBody(body []byte) (*Checkpoint, error) {
	lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	if len(lines) < checkpointBodyLines {
		return nil, malformedf("body has %d lines, need at least %d", len(lines), checkpointBodyLines)
	}
	if lines[0] == "" {
		return nil, malformedf("origin line is empty")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return nil, &CheckpointError{
			Type:    CheckpointErrInvalidSize,
			Message: "tree size is not a decimal integer",
			Cause:   err,
		}
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, &CheckpointError{
			Type:    CheckpointErrInvalidRootHash,
			Message: "root hash is not base64",
			Cause:   err,
		}
	}
	if len(root) != hashLen {
		return nil, &CheckpointError{
			Type:    CheckpointErrInvalidRootHash,
			Message: fmt.Sprintf("root hash is %d bytes, want %d", len(root), hashLen),
		}
	}

	cp := &Checkpoint{Origin: lines[0], Size: size}
	copy(cp.RootHash[:], root)
	return cp, nil
}

// verifyCheckpointSignature checks an ECDSA signature over SHA-256(body), first
// as ASN.1 DER and then as the fixed-width r||s form of a P-256 signature. The
// r||s form is accepted only because early development builds of the log signed
// checkpoints that way; current logs emit DER.
func verifyCheckpointSignature(pub *ecdsa.PublicKey, body, sig []byte) bool {
	digest := sha256.Sum256(body)
	if ecdsa.VerifyASN1(pub, digest[:], sig) {
		return true
	}
	if len(sig) != p1363SignatureLen {
		return false
	}
	r := new(big.Int).SetBytes(sig[:hashLen])
	s := new(big.Int).SetBytes(sig[hashLen:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

// bindCheckpointSigner requires the key that verified the signature to be the
// one the note names, both on the signature line and as the origin. It runs
// after signature verification, as the receipt path does for the issuer claim.
func bindCheckpointSigner(origin, signer string, key *TrustedKey) error {
	if signer != key.Name {
		return &SignatureError{
			Type:    SigErrIssuerMismatch,
			Kid:     key.Kid,
			Message: fmt.Sprintf("signer %q does not match key name %q", signer, key.Name),
		}
	}
	if origin != key.Name {
		return &SignatureError{
			Type:    SigErrIssuerMismatch,
			Kid:     key.Kid,
			Message: fmt.Sprintf("origin %q does not match key name %q", origin, key.Name),
		}
	}
	return nil
}

// firstError keeps the first error seen, so the reported key hash is the
// first offending line's, as the unknown-key path reports.
func firstError(current, candidate error) error {
	if current != nil {
		return current
	}
	return candidate
}

func malformedf(format string, args ...any) *CheckpointError {
	return &CheckpointError{Type: CheckpointErrMalformed, Message: fmt.Sprintf(format, args...)}
}
