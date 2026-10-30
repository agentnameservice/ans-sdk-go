package cmd

import (
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
)

func TestBuildGetIdentityCertsCmd(t *testing.T) {
	cmd := buildGetIdentityCertsCmd()

	if cmd == nil {
		t.Fatal("buildGetIdentityCertsCmd() returned nil")
	}

	if cmd.Use != "get-identity-certs <agentId>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "get-identity-certs <agentId>")
	}
}

func TestBuildGetServerCertsCmd(t *testing.T) {
	cmd := buildGetServerCertsCmd()

	if cmd == nil {
		t.Fatal("buildGetServerCertsCmd() returned nil")
	}

	if cmd.Use != "get-server-certs <agentId>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "get-server-certs <agentId>")
	}
}

func TestBuildSubmitIdentityCSRCmd(t *testing.T) {
	cmd := buildSubmitIdentityCSRCmd()

	if cmd == nil {
		t.Fatal("buildSubmitIdentityCSRCmd() returned nil")
	}

	if cmd.Use != "submit-identity-csr <agentId>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "submit-identity-csr <agentId>")
	}

	if cmd.Flags().Lookup("csr-file") == nil {
		t.Error("missing flag 'csr-file'")
	}
}

func TestBuildSubmitServerCSRCmd(t *testing.T) {
	cmd := buildSubmitServerCSRCmd()

	if cmd == nil {
		t.Fatal("buildSubmitServerCSRCmd() returned nil")
	}

	if cmd.Use != "submit-server-csr <agentId>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "submit-server-csr <agentId>")
	}

	if cmd.Flags().Lookup("csr-file") == nil {
		t.Error("missing flag 'csr-file'")
	}
}

func TestPrintCertificates(t *testing.T) {
	subject := "CN=test.example.com"
	issuer := "CN=ANS CA"
	serial := "ABC123"
	pubKeyAlgo := "RSA"
	sigAlgo := "SHA256-RSA"

	tests := []struct {
		name     string
		certType string
		certs    []models.CertificateResponse
	}{
		{
			name:     "no certificates",
			certType: "Identity",
			certs:    []models.CertificateResponse{},
		},
		{
			name:     "single certificate with all fields",
			certType: "Identity",
			certs: []models.CertificateResponse{
				{
					CsrID:                         "csr-123",
					CertificateSubject:            &subject,
					CertificateIssuer:             &issuer,
					CertificateSerialNumber:       &serial,
					CertificatePublicKeyAlgorithm: &pubKeyAlgo,
					CertificateSignatureAlgorithm: &sigAlgo,
					CertificateValidFrom:          time.Now(),
					CertificateValidTo:            time.Now().Add(365 * 24 * time.Hour),
				},
			},
		},
		{
			name:     "multiple certificates with minimal fields",
			certType: "Server",
			certs: []models.CertificateResponse{
				{CsrID: "csr-1"},
				{CsrID: "csr-2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			printCertificates(tt.certType, tt.certs)
		})
	}
}

func TestPrintCsrSubmissionResult(t *testing.T) {
	message := "CSR is being processed"

	tests := []struct {
		name    string
		csrType string
		result  *models.CsrSubmissionResponse
	}{
		{
			name:    "with message",
			csrType: "Identity",
			result: &models.CsrSubmissionResponse{
				CsrID:   "csr-123",
				Message: &message,
			},
		},
		{
			name:    "without message",
			csrType: "Server",
			result: &models.CsrSubmissionResponse{
				CsrID: "csr-456",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			printCsrSubmissionResult(tt.csrType, tt.result)
		})
	}
}
