// Package verify provides ANS trust verification functionality.
package verify

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/godaddy/ans-sdk-go/models"
)

// CertFingerprint represents a SHA-256 certificate fingerprint.
type CertFingerprint struct {
	bytes [32]byte
}

// CertFingerprintFromDER computes the fingerprint from DER-encoded certificate bytes.
func CertFingerprintFromDER(der []byte) CertFingerprint {
	return CertFingerprint{bytes: sha256.Sum256(der)}
}

// CertFingerprintFromBytes creates a fingerprint from raw bytes.
func CertFingerprintFromBytes(b [32]byte) CertFingerprint {
	return CertFingerprint{bytes: b}
}

// ParseCertFingerprint parses a fingerprint from "SHA256:<hex>" format.
func ParseCertFingerprint(s string) (CertFingerprint, error) {
	// Handle both "SHA256:" and "sha256:" prefixes
	var hexStr string
	switch {
	case strings.HasPrefix(s, "SHA256:"):
		hexStr = s[7:]
	case strings.HasPrefix(s, "sha256:"):
		hexStr = s[7:]
	default:
		return CertFingerprint{}, errors.New("invalid fingerprint format: must start with 'SHA256:' (e.g., SHA256:abc123...)")
	}

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return CertFingerprint{}, fmt.Errorf("invalid fingerprint hex: %w", err)
	}

	const sha256Len = 32
	if len(decoded) != sha256Len {
		return CertFingerprint{}, fmt.Errorf("invalid fingerprint length: expected 32 bytes, got %d", len(decoded))
	}

	var fp CertFingerprint
	copy(fp.bytes[:], decoded)
	return fp, nil
}

// String returns the fingerprint as "SHA256:<hex>".
func (f CertFingerprint) String() string {
	return "SHA256:" + hex.EncodeToString(f.bytes[:])
}

// Bytes returns the raw fingerprint bytes.
func (f CertFingerprint) Bytes() [32]byte {
	return f.bytes
}

// ToHex returns the hex string without prefix.
func (f CertFingerprint) ToHex() string {
	return hex.EncodeToString(f.bytes[:])
}

// Matches checks if this fingerprint matches a string representation.
func (f CertFingerprint) Matches(other string) bool {
	parsed, err := ParseCertFingerprint(other)
	if err != nil {
		return false
	}
	return f.bytes == parsed.bytes
}

// Equal returns true if the fingerprints are equal.
func (f CertFingerprint) Equal(other CertFingerprint) bool {
	return f.bytes == other.bytes
}

// IsZero returns true if the fingerprint has not been set.
func (f CertFingerprint) IsZero() bool {
	return f.bytes == [32]byte{}
}

// AnsName represents an ANS name URI (e.g., ans://v1.0.0.agent.example.com).
type AnsName struct {
	Version models.Version
	Host    string
	raw     string
}

// ParseAnsName parses an ANS name from a URI string.
// Format: ans://v<major>.<minor>.<patch>.<fqdn>
func ParseAnsName(uri string) (*AnsName, error) {
	const prefix = "ans://"

	if uri == "" {
		return nil, errors.New("empty ANS name")
	}

	if !strings.HasPrefix(uri, prefix) {
		return nil, fmt.Errorf("ANS name must start with '%s': %s", prefix, uri)
	}

	rest := uri[len(prefix):]

	// The format is: v<major>.<minor>.<patch>.<fqdn>
	if !strings.HasPrefix(rest, "v") {
		return nil, fmt.Errorf("ANS name version must start with 'v': %s", uri)
	}

	const minAnsNameParts = 4 // v<major>.<minor>.<patch>.<fqdn>
	parts := strings.SplitN(rest, ".", minAnsNameParts)
	if len(parts) < minAnsNameParts {
		return nil, fmt.Errorf("ANS name must have version and FQDN: %s", uri)
	}

	// Parse version from first 3 parts (including the 'v' prefix)
	versionStr := fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])
	version, err := models.ParseVersion(versionStr)
	if err != nil {
		return nil, fmt.Errorf("invalid version in ANS name: %w", err)
	}

	return &AnsName{
		Version: version,
		Host:    strings.ToLower(parts[3]),
		raw:     uri,
	}, nil
}

// String returns the raw ANS name URI.
func (a *AnsName) String() string {
	return a.raw
}

// CertIdentity holds the relevant identity information extracted from an X.509 certificate.
type CertIdentity struct {
	// CommonName from the certificate subject.
	CommonName *string
	// DNSSANs are the DNS Subject Alternative Names.
	DNSSANs []string
	// URISANs are the URI Subject Alternative Names.
	URISANs []string
	// Fingerprint is the certificate's SHA-256 fingerprint.
	Fingerprint CertFingerprint
}

// NewCertIdentity creates a new CertIdentity from components.
func NewCertIdentity(commonName *string, dnsSANs, uriSANs []string, fingerprint CertFingerprint) *CertIdentity {
	return &CertIdentity{
		CommonName:  commonName,
		DNSSANs:     dnsSANs,
		URISANs:     uriSANs,
		Fingerprint: fingerprint,
	}
}

// CertIdentityFromX509 extracts identity from an x509.Certificate.
func CertIdentityFromX509(cert *x509.Certificate) *CertIdentity {
	var cn *string
	if cert.Subject.CommonName != "" {
		cn = &cert.Subject.CommonName
	}

	// Extract URI SANs
	uriSANs := make([]string, 0, len(cert.URIs))
	for _, uri := range cert.URIs {
		uriSANs = append(uriSANs, uri.String())
	}

	fp := CertFingerprintFromDER(cert.Raw)

	return &CertIdentity{
		CommonName:  cn,
		DNSSANs:     cert.DNSNames,
		URISANs:     uriSANs,
		Fingerprint: fp,
	}
}

// CertIdentityFromDER parses a DER-encoded certificate and extracts identity.
func CertIdentityFromDER(der []byte) (*CertIdentity, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return CertIdentityFromX509(cert), nil
}

// CertIdentityFromFingerprintAndCN creates a CertIdentity with just fingerprint and CN.
func CertIdentityFromFingerprintAndCN(fingerprint CertFingerprint, cn string) *CertIdentity {
	return &CertIdentity{
		CommonName:  &cn,
		DNSSANs:     []string{cn},
		URISANs:     nil,
		Fingerprint: fingerprint,
	}
}

// FQDN returns the FQDN from the certificate.
// Prefers DNS SAN (more reliable) over CN.
func (c *CertIdentity) FQDN() *string {
	if len(c.DNSSANs) > 0 {
		return &c.DNSSANs[0]
	}
	return c.CommonName
}

// AnsName extracts the ANS name from URI SANs.
func (c *CertIdentity) AnsName() *AnsName {
	for _, uri := range c.URISANs {
		if strings.HasPrefix(uri, "ans://") {
			if ans, err := ParseAnsName(uri); err == nil {
				return ans
			}
		}
	}
	return nil
}

// Version extracts the version from ANS name in URI SAN.
func (c *CertIdentity) Version() *models.Version {
	ans := c.AnsName()
	if ans != nil {
		return &ans.Version
	}
	return nil
}
