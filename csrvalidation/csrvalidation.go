// Package csrvalidation checks a PEM-encoded certificate signing request against
// the public-key and signature rules an ANS registry enforces at intake, so a
// CSR the registry would reject fails locally instead of after an authenticated
// round trip.
package csrvalidation

import (
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
	// ErrInvalidCSR reports input that is not a parseable PEM certificate request.
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

// Rules describes the public-key and signature constraints a registry applies
// to one CSR type at intake.
type Rules struct {
	// RSAKeySizes lists the accepted RSA modulus sizes in bits.
	RSAKeySizes []int
	// ECCurves lists the accepted named curves by their crypto/elliptic name
	// ("P-256", "P-384", "P-521"). An empty list rejects EC keys.
	ECCurves []string
	// SignatureAlgorithms lists the accepted CSR signature algorithms.
	SignatureAlgorithms []x509.SignatureAlgorithm
}

// IdentityRules returns the intake rules for identity CSRs: RSA 2048, 3072, or
// 4096 bits, or EC P-256, signed with SHA-256, SHA-384, or SHA-512 over RSA or
// ECDSA.
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
// signed with SHA-256 over RSA.
func ServerRules() Rules {
	return Rules{
		RSAKeySizes:         []int{rsa2048, rsa4096},
		SignatureAlgorithms: []x509.SignatureAlgorithm{x509.SHA256WithRSA},
	}
}

// Validate parses csrPEM, applies rules to its public key and signature
// algorithm, and verifies the self-signature. It returns the parsed request so
// callers can inspect the subject and SANs.
func Validate(csrPEM []byte, rules Rules) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != pemTypeCSR {
		return nil, fmt.Errorf("%w: expected a PEM %q block", ErrInvalidCSR, pemTypeCSR)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCSR, err)
	}
	if err := rules.checkPublicKey(csr.PublicKey); err != nil {
		return nil, err
	}
	if err := rules.checkSignatureAlgorithm(csr.SignatureAlgorithm); err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	return csr, nil
}

func (r Rules) checkPublicKey(pub crypto.PublicKey) error {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		bits := key.N.BitLen()
		if slices.Contains(r.RSAKeySizes, bits) {
			return nil
		}
		return fmt.Errorf("%w: RSA key size must be %s bits, but was %d bits", ErrKeySize, joinInts(r.RSAKeySizes), bits)
	case *ecdsa.PublicKey:
		if len(r.ECCurves) == 0 {
			return fmt.Errorf("%w: CSR public key must use RSA, but was EC", ErrKeyAlgorithm)
		}
		curve := key.Curve.Params().Name
		if slices.Contains(r.ECCurves, curve) {
			return nil
		}
		return fmt.Errorf("%w: EC key curve must be %s, but was %q", ErrCurve, strings.Join(r.ECCurves, " or "), curve)
	default:
		return fmt.Errorf("%w: CSR public key must use %s, but was %T", ErrKeyAlgorithm, r.acceptedKeyTypes(), pub)
	}
}

func (r Rules) checkSignatureAlgorithm(alg x509.SignatureAlgorithm) error {
	if slices.Contains(r.SignatureAlgorithms, alg) {
		return nil
	}
	names := make([]string, 0, len(r.SignatureAlgorithms))
	for _, accepted := range r.SignatureAlgorithms {
		names = append(names, accepted.String())
	}
	return fmt.Errorf("%w: CSR signature algorithm must be %s, but was %s", ErrSignatureAlgorithm, strings.Join(names, " or "), alg)
}

func (r Rules) acceptedKeyTypes() string {
	if len(r.ECCurves) == 0 {
		return "RSA"
	}
	return "RSA or EC"
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, " or ")
}
