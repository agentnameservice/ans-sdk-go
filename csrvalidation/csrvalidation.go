// Package csrvalidation checks a PEM-encoded certificate signing request against
// the public-key and signature rules the ANS registry enforces at intake, so a
// CSR the registry would reject fails locally instead of after an authenticated
// round trip.
//
// The rule sets mirror the registry's CSR intake policy: the RSA key sizes,
// EC curves, and signature algorithms it accepts for each certificate type.
// When the registry's policy changes, change them together.
package csrvalidation

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const (
	rsa2048 = 2048
	rsa3072 = 3072
	rsa4096 = 4096

	// CurveP256 is the crypto/elliptic name of NIST P-256, the only EC curve
	// the registry issues identity certificates for.
	CurveP256 = "P-256"

	pemTypeCSR = "CERTIFICATE REQUEST"
)

var (
	// ErrInvalidCSR reports input that is not exactly one parseable PEM certificate request.
	ErrInvalidCSR = errors.New("csrvalidation: invalid CSR")
	// ErrSignature reports a CSR whose self-signature does not verify.
	ErrSignature = errors.New("csrvalidation: CSR self-signature does not verify")
	// ErrKeyAlgorithm reports a public key algorithm the rules do not accept.
	ErrKeyAlgorithm = errors.New("csrvalidation: public key algorithm not accepted")
	// ErrKeySize reports an RSA modulus size the rules do not accept.
	ErrKeySize = errors.New("csrvalidation: RSA key size not accepted")
	// ErrCurve reports an EC curve the rules do not accept.
	ErrCurve = errors.New("csrvalidation: EC curve not accepted")
	// ErrSignatureAlgorithm reports a CSR signature algorithm the rules do not accept.
	ErrSignatureAlgorithm = errors.New("csrvalidation: signature algorithm not accepted")
)

// Rules describes the public-key and signature constraints the registry applies
// to one CSR type at intake.
type Rules struct {
	// RSAKeySizes lists the accepted RSA modulus sizes in bits. An empty list rejects RSA keys.
	RSAKeySizes []int
	// ECCurves lists the accepted named curves by their crypto/elliptic name
	// ("P-256", "P-384", "P-521"). An empty list rejects EC keys.
	ECCurves []string
	// SignatureAlgorithms lists the accepted CSR signature algorithms.
	SignatureAlgorithms []x509.SignatureAlgorithm
}

// IdentityRules returns the intake rules for identity CSRs: RSA 2048, 3072, or
// 4096 bits, or EC P-256, signed with SHA-256, SHA-384, or SHA-512 over RSA or
// ECDSA. A registry deployment without EC support still rejects EC identity
// CSRs at submission.
func IdentityRules() Rules {
	return Rules{
		RSAKeySizes: []int{rsa2048, rsa3072, rsa4096},
		ECCurves:    []string{CurveP256},
		SignatureAlgorithms: []x509.SignatureAlgorithm{
			x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
			x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		},
	}
}

// ServerRules returns the intake rules for server CSRs: RSA 2048 or 4096 bits,
// signed with SHA-256 over RSA. The server-certificate PKI accepts RSA keys only.
func ServerRules() Rules {
	return Rules{
		RSAKeySizes:         []int{rsa2048, rsa4096},
		SignatureAlgorithms: []x509.SignatureAlgorithm{x509.SHA256WithRSA},
	}
}

// Validate parses csrPEM, which must hold exactly one PEM CERTIFICATE REQUEST
// block and nothing else, and applies Check. It returns the parsed request so
// callers can inspect the subject and SANs.
func Validate(csrPEM []byte, rules Rules) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != pemTypeCSR || !startsWithCSRBlock(csrPEM) || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: expected exactly one PEM %q block with nothing before or after it", ErrInvalidCSR, pemTypeCSR)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCSR, err)
	}
	if err := rules.Check(csr); err != nil {
		return nil, err
	}
	return csr, nil
}

func startsWithCSRBlock(csrPEM []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(csrPEM), []byte("-----BEGIN "+pemTypeCSR+"-----"))
}

// Check applies the rules to an already parsed request and verifies its
// self-signature.
func (r Rules) Check(csr *x509.CertificateRequest) error {
	if err := r.checkPublicKey(csr.PublicKey, csr.PublicKeyAlgorithm); err != nil {
		return err
	}
	if err := r.checkSignatureAlgorithm(csr.SignatureAlgorithm); err != nil {
		return err
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("%w: %w", ErrSignature, err)
	}
	return nil
}

// AllowsRSAKeySize reports whether an RSA key with the given modulus size is accepted.
func (r Rules) AllowsRSAKeySize(bits int) bool {
	return slices.Contains(r.RSAKeySizes, bits)
}

// AllowsCurve reports whether an EC key on the named curve is accepted.
func (r Rules) AllowsCurve(name string) bool {
	return slices.Contains(r.ECCurves, name)
}

// Describe returns the accepted keys in the registry's wording, for example
// "RSA 2048 or 3072 or 4096 bit keys or EC P-256 keys".
func (r Rules) Describe() string {
	var parts []string
	if len(r.RSAKeySizes) > 0 {
		parts = append(parts, "RSA "+joinInts(r.RSAKeySizes)+" bit keys")
	}
	if len(r.ECCurves) > 0 {
		parts = append(parts, "EC "+strings.Join(r.ECCurves, " or ")+" keys")
	}
	return strings.Join(parts, " or ")
}

func (r Rules) checkPublicKey(pub crypto.PublicKey, alg x509.PublicKeyAlgorithm) error {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if len(r.RSAKeySizes) == 0 {
			return r.keyTypeError("RSA")
		}
		bits := key.N.BitLen()
		if r.AllowsRSAKeySize(bits) {
			return nil
		}
		return fmt.Errorf("%w: RSA key size must be %s bits, but was %d bits", ErrKeySize, joinInts(r.RSAKeySizes), bits)
	case *ecdsa.PublicKey:
		if len(r.ECCurves) == 0 {
			return r.keyTypeError("EC")
		}
		curve := key.Curve.Params().Name
		if r.AllowsCurve(curve) {
			return nil
		}
		return fmt.Errorf("%w: EC key curve must be %s, but was '%s'", ErrCurve, strings.Join(r.ECCurves, " or "), curve)
	default:
		return r.keyTypeError(alg.String())
	}
}

// keyTypeError mirrors the registry's key-type rejection: the accepted
// algorithms, the offending one, and the PKI constraint behind the rule.
func (r Rules) keyTypeError(actual string) error {
	var types []string
	if len(r.RSAKeySizes) > 0 {
		types = append(types, "RSA")
	}
	if len(r.ECCurves) > 0 {
		types = append(types, "EC")
	}
	return fmt.Errorf("%w: CSR public key must use %s, but was '%s'. PKI only accepts %s",
		ErrKeyAlgorithm, strings.Join(types, " or "), actual, r.Describe())
}

func (r Rules) checkSignatureAlgorithm(alg x509.SignatureAlgorithm) error {
	if slices.Contains(r.SignatureAlgorithms, alg) {
		return nil
	}
	names := make([]string, 0, len(r.SignatureAlgorithms))
	for _, accepted := range r.SignatureAlgorithms {
		names = append(names, registrySignatureName(accepted))
	}
	return fmt.Errorf("%w: CSR signature algorithm must be %s, but was '%s'",
		ErrSignatureAlgorithm, strings.Join(names, " or "), registrySignatureName(alg))
}

// registrySignatureName renders a signature algorithm the way the registry
// reports it (Bouncy Castle's uppercase names such as SHA256WITHRSA and
// SHA256WITHECDSA), falling back to Go's name for anything else.
func registrySignatureName(alg x509.SignatureAlgorithm) string {
	name := alg.String()
	if hash, ok := strings.CutPrefix(name, "ECDSA-"); ok {
		return hash + "WITHECDSA"
	}
	if hash, ok := strings.CutSuffix(name, "-RSA"); ok {
		return hash + "WITHRSA"
	}
	return name
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, " or ")
}
