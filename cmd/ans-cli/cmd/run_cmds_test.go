package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/spf13/viper"
)

// setupViperForTest sets viper values needed for config.Load() and registers cleanup.
// oauth-token is explicitly zeroed so a developer's exported ANS_OAUTH_TOKEN
// cannot leak into tests through viper's env binding.
func setupViperForTest(t *testing.T, serverURL string) {
	t.Helper()
	viper.Set("api-key", "testkey:testsecret")
	viper.Set("oauth-token", "")
	viper.Set("base-url", serverURL)
	viper.Set("verbose", false)
	viper.Set("json", false)
	t.Cleanup(func() {
		viper.Reset()
	})
}

func TestRunStatus_Success(t *testing.T) {
	agent := &models.AgentDetails{
		AgentID:          "agent-123",
		AgentDisplayName: "Test Agent",
		AgentHost:        "test.example.com",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agent)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	cmd := buildStatusCmd()
	cmd.SetArgs([]string{"agent-123"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runStatus() error = %v", err)
	}
}

func TestRunStatus_JSONMode(t *testing.T) {
	agent := &models.AgentDetails{
		AgentID: "agent-123",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agent)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	cmd := buildStatusCmd()
	cmd.SetArgs([]string{"agent-123"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runStatus() JSON mode error = %v", err)
	}
}

func TestRunStatus_NoAPIKey(t *testing.T) {
	viper.Set("api-key", "")
	viper.Set("oauth-token", "")
	viper.Set("base-url", "http://localhost")
	t.Cleanup(func() { viper.Reset() })

	cmd := buildStatusCmd()
	cmd.SetArgs([]string{"agent-123"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("runStatus() expected error for missing API key")
	}
}

func TestRunStatus_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	cmd := buildStatusCmd()
	cmd.SetArgs([]string{"agent-123"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("runStatus() expected error for server error")
	}
}

func TestRunSearchWithParams_Success(t *testing.T) {
	result := &models.AgentSearchResponse{
		TotalCount:    1,
		ReturnedCount: 1,
		Agents: []models.AgentSearchResult{
			{AgentDisplayName: "Test Agent", AgentHost: "test.example.com"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	err := runSearchWithParams(&searchParams{name: "test", limit: 20})
	if err != nil {
		t.Fatalf("runSearchWithParams() error = %v", err)
	}
}

func TestRunSearchWithParams_JSONMode(t *testing.T) {
	result := &models.AgentSearchResponse{
		Agents: []models.AgentSearchResult{
			{AgentDisplayName: "Test Agent"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	err := runSearchWithParams(&searchParams{name: "test", limit: 20})
	if err != nil {
		t.Fatalf("runSearchWithParams() JSON mode error = %v", err)
	}
}

func TestRunSearchWithParams_NoAPIKey(t *testing.T) {
	viper.Set("api-key", "")
	viper.Set("oauth-token", "")
	viper.Set("base-url", "http://localhost")
	t.Cleanup(func() { viper.Reset() })

	err := runSearchWithParams(&searchParams{name: "test", limit: 20})
	if err == nil {
		t.Fatal("runSearchWithParams() expected error for missing API key")
	}
}

func TestRunSearchWithParams_NoCriteria(t *testing.T) {
	setupViperForTest(t, "http://localhost")

	err := runSearchWithParams(&searchParams{limit: 20})
	if err == nil {
		t.Fatal("runSearchWithParams() expected error for no search criteria")
	}
}

func TestRunSearchWithParams_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	err := runSearchWithParams(&searchParams{name: "test", limit: 20})
	if err == nil {
		t.Fatal("runSearchWithParams() expected error for server error")
	}
}

// TestRunSearchWithParams_InvalidAPIKeyFormat exercises the createClient
// error branch: a non-empty API key that doesn't match the "key:secret" shape
// causes createClient to fail before any HTTP call.
func TestRunSearchWithParams_InvalidAPIKeyFormat(t *testing.T) {
	setupViperForTest(t, "http://localhost")
	viper.Set("api-key", "no-colon-here")

	err := runSearchWithParams(&searchParams{name: "test", limit: 20})
	if err == nil {
		t.Fatal("runSearchWithParams() expected error for malformed API key")
	}
}

// TestBuildSearchCmd_RunE invokes the cobra RunE closure so it's exercised by
// coverage. The inner call will return a "no criteria" error (no flags set),
// which is the easiest failure mode to reach without a live HTTP server.
func TestBuildSearchCmd_RunE(t *testing.T) {
	setupViperForTest(t, "http://localhost")

	cmd := buildSearchCmd()
	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("RunE() expected error when no criteria provided")
	}
}

func TestRunResolve_Success(t *testing.T) {
	result := &models.AgentCapabilityResponse{
		AnsName: "ans://v1.0.0.test.example.com",
		Links: []models.Link{
			{Rel: "self", Href: "/v1/agents/123"},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	err := runResolve("test.example.com", "*")
	if err != nil {
		t.Fatalf("runResolve() error = %v", err)
	}
}

func TestRunResolve_JSONMode(t *testing.T) {
	result := &models.AgentCapabilityResponse{
		AnsName: "ans://v1.0.0.test.example.com",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	err := runResolve("test.example.com", "*")
	if err != nil {
		t.Fatalf("runResolve() JSON mode error = %v", err)
	}
}

func TestRunResolve_NoAPIKey(t *testing.T) {
	viper.Set("api-key", "")
	viper.Set("oauth-token", "")
	viper.Set("base-url", "http://localhost")
	t.Cleanup(func() { viper.Reset() })

	err := runResolve("test.example.com", "*")
	if err == nil {
		t.Fatal("runResolve() expected error for missing API key")
	}
}

func TestRunResolve_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	err := runResolve("test.example.com", "*")
	if err == nil {
		t.Fatal("runResolve() expected error for server error")
	}
}

func TestRunRevoke_Success(t *testing.T) {
	result := &models.AgentRevocationResponse{
		AgentID:   "agent-123",
		AnsName:   "ans://v1.0.0.test.example.com",
		Status:    "REVOKED",
		Reason:    models.RevocationReasonKeyCompromise,
		RevokedAt: time.Now(),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	err := runRevoke("agent-123", "KEY_COMPROMISE", "test comment")
	if err != nil {
		t.Fatalf("runRevoke() error = %v", err)
	}
}

func TestRunRevoke_JSONMode(t *testing.T) {
	result := &models.AgentRevocationResponse{
		AgentID: "agent-123",
		Status:  "REVOKED",
		Reason:  models.RevocationReasonKeyCompromise,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	err := runRevoke("agent-123", "KEY_COMPROMISE", "")
	if err != nil {
		t.Fatalf("runRevoke() JSON mode error = %v", err)
	}
}

func TestRunRevoke_NoAPIKey(t *testing.T) {
	viper.Set("api-key", "")
	viper.Set("oauth-token", "")
	viper.Set("base-url", "http://localhost")
	t.Cleanup(func() { viper.Reset() })

	err := runRevoke("agent-123", "KEY_COMPROMISE", "")
	if err == nil {
		t.Fatal("runRevoke() expected error for missing API key")
	}
}

func TestRunRevoke_InvalidReason(t *testing.T) {
	setupViperForTest(t, "http://localhost")

	err := runRevoke("agent-123", "INVALID_REASON", "")
	if err == nil {
		t.Fatal("runRevoke() expected error for invalid reason")
	}
}

func TestRunRevoke_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	err := runRevoke("agent-123", "KEY_COMPROMISE", "")
	if err == nil {
		t.Fatal("runRevoke() expected error for server error")
	}
}

func TestRunCsrStatus_Success(t *testing.T) {
	result := &models.CsrStatusResponse{
		CsrID:  "csr-123",
		Type:   "IDENTITY",
		Status: "SIGNED",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	cmd := buildCsrStatusCmd()
	cmd.SetArgs([]string{"agent-123", "csr-123"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runCsrStatus() error = %v", err)
	}
}

func TestRunCsrStatus_JSONMode(t *testing.T) {
	result := &models.CsrStatusResponse{
		CsrID:  "csr-123",
		Type:   "IDENTITY",
		Status: "PENDING",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	cmd := buildCsrStatusCmd()
	cmd.SetArgs([]string{"agent-123", "csr-123"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runCsrStatus() JSON mode error = %v", err)
	}
}

func TestRunCsrStatus_NoAPIKey(t *testing.T) {
	viper.Set("api-key", "")
	viper.Set("oauth-token", "")
	viper.Set("base-url", "http://localhost")
	t.Cleanup(func() { viper.Reset() })

	cmd := buildCsrStatusCmd()
	cmd.SetArgs([]string{"agent-123", "csr-123"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("runCsrStatus() expected error for missing API key")
	}
}

func TestRunVerifyACME_Success(t *testing.T) {
	result := &models.AgentStatus{
		Status: "VERIFYING",
		Phase:  "ACME_VALIDATION",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	cmd := buildVerifyACMECmd()
	cmd.SetArgs([]string{"agent-123"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runVerifyACME() error = %v", err)
	}
}

func TestRunVerifyACME_JSONMode(t *testing.T) {
	result := &models.AgentStatus{
		Status: "VERIFYING",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	cmd := buildVerifyACMECmd()
	cmd.SetArgs([]string{"agent-123"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runVerifyACME() JSON mode error = %v", err)
	}
}

func TestRunVerifyACME_NoAPIKey(t *testing.T) {
	viper.Set("api-key", "")
	viper.Set("oauth-token", "")
	viper.Set("base-url", "http://localhost")
	t.Cleanup(func() { viper.Reset() })

	cmd := buildVerifyACMECmd()
	cmd.SetArgs([]string{"agent-123"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("runVerifyACME() expected error for missing API key")
	}
}

func TestRunVerifyDNS_Success(t *testing.T) {
	result := &models.AgentStatus{
		Status:         "ACTIVE",
		CompletedSteps: []string{"DNS_VERIFIED"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	cmd := buildVerifyDNSCmd()
	cmd.SetArgs([]string{"agent-123"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runVerifyDNS() error = %v", err)
	}
}

func TestRunVerifyDNS_JSONMode(t *testing.T) {
	result := &models.AgentStatus{
		Status: "ACTIVE",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	cmd := buildVerifyDNSCmd()
	cmd.SetArgs([]string{"agent-123"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runVerifyDNS() JSON mode error = %v", err)
	}
}

func TestRunVerifyDNS_NoAPIKey(t *testing.T) {
	viper.Set("api-key", "")
	viper.Set("oauth-token", "")
	viper.Set("base-url", "http://localhost")
	t.Cleanup(func() { viper.Reset() })

	cmd := buildVerifyDNSCmd()
	cmd.SetArgs([]string{"agent-123"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("runVerifyDNS() expected error for missing API key")
	}
}

func TestRunGetIdentityCerts_Success(t *testing.T) {
	subject := "CN=test.example.com"
	certs := []models.CertificateResponse{
		{
			CsrID:              "csr-123",
			CertificateSubject: &subject,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(certs)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	cmd := buildGetIdentityCertsCmd()
	cmd.SetArgs([]string{"agent-123"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runGetIdentityCerts() error = %v", err)
	}
}

func TestRunGetIdentityCerts_JSONMode(t *testing.T) {
	certs := []models.CertificateResponse{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(certs)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	cmd := buildGetIdentityCertsCmd()
	cmd.SetArgs([]string{"agent-123"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runGetIdentityCerts() JSON mode error = %v", err)
	}
}

func TestRunGetServerCerts_Success(t *testing.T) {
	certs := []models.CertificateResponse{
		{CsrID: "csr-456"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(certs)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	cmd := buildGetServerCertsCmd()
	cmd.SetArgs([]string{"agent-123"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runGetServerCerts() error = %v", err)
	}
}

func TestRunGetServerCerts_JSONMode(t *testing.T) {
	certs := []models.CertificateResponse{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(certs)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	cmd := buildGetServerCertsCmd()
	cmd.SetArgs([]string{"agent-123"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runGetServerCerts() JSON mode error = %v", err)
	}
}

func TestRunSubmitIdentityCSR_Success(t *testing.T) {
	result := &models.CsrSubmissionResponse{
		CsrID: "csr-new-123",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	// Create a temp CSR file
	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "identity.csr")
	os.WriteFile(csrFile, []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----\n"), 0600)

	err := runSubmitIdentityCSRWithParams("agent-123", csrFile)
	if err != nil {
		t.Fatalf("runSubmitIdentityCSRWithParams() error = %v", err)
	}
}

func TestRunSubmitIdentityCSR_JSONMode(t *testing.T) {
	result := &models.CsrSubmissionResponse{
		CsrID: "csr-new-123",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "identity.csr")
	os.WriteFile(csrFile, []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----\n"), 0600)

	err := runSubmitIdentityCSRWithParams("agent-123", csrFile)
	if err != nil {
		t.Fatalf("runSubmitIdentityCSRWithParams() JSON mode error = %v", err)
	}
}

func TestRunSubmitIdentityCSR_NoAPIKey(t *testing.T) {
	viper.Set("api-key", "")
	viper.Set("oauth-token", "")
	viper.Set("base-url", "http://localhost")
	t.Cleanup(func() { viper.Reset() })

	err := runSubmitIdentityCSRWithParams("agent-123", "/nonexistent/file.csr")
	if err == nil {
		t.Fatal("runSubmitIdentityCSRWithParams() expected error for missing API key")
	}
}

func TestRunSubmitIdentityCSR_BadFile(t *testing.T) {
	setupViperForTest(t, "http://localhost")

	err := runSubmitIdentityCSRWithParams("agent-123", "/nonexistent/file.csr")
	if err == nil {
		t.Fatal("runSubmitIdentityCSRWithParams() expected error for bad file")
	}
}

func TestRunSubmitServerCSR_Success(t *testing.T) {
	result := &models.CsrSubmissionResponse{
		CsrID: "csr-server-123",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "server.csr")
	os.WriteFile(csrFile, []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----\n"), 0600)

	err := runSubmitServerCSRWithParams("agent-123", csrFile)
	if err != nil {
		t.Fatalf("runSubmitServerCSRWithParams() error = %v", err)
	}
}

func TestRunSubmitServerCSR_JSONMode(t *testing.T) {
	result := &models.CsrSubmissionResponse{
		CsrID: "csr-server-123",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "server.csr")
	os.WriteFile(csrFile, []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----\n"), 0600)

	err := runSubmitServerCSRWithParams("agent-123", csrFile)
	if err != nil {
		t.Fatalf("runSubmitServerCSRWithParams() JSON mode error = %v", err)
	}
}

func TestRunSubmitServerCSR_BadFile(t *testing.T) {
	setupViperForTest(t, "http://localhost")

	err := runSubmitServerCSRWithParams("agent-123", "/nonexistent/file.csr")
	if err == nil {
		t.Fatal("runSubmitServerCSRWithParams() expected error for bad file")
	}
}

func TestRunEventsWithParams_Success(t *testing.T) {
	result := &models.EventPageResponse{
		Items: []models.EventItem{
			{
				LogID:     "log-1",
				EventType: "AGENT_REGISTERED",
				AgentHost: "test.example.com",
				Version:   "1.0.0",
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	err := runEventsWithParams(20, "", "", false, 5)
	if err != nil {
		t.Fatalf("runEventsWithParams() error = %v", err)
	}
}

func TestRunEventsWithParams_JSONMode(t *testing.T) {
	result := &models.EventPageResponse{
		Items: []models.EventItem{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	err := runEventsWithParams(20, "", "", false, 5)
	if err != nil {
		t.Fatalf("runEventsWithParams() JSON mode error = %v", err)
	}
}

func TestRunEventsWithParams_NoAPIKey(t *testing.T) {
	viper.Set("api-key", "")
	viper.Set("oauth-token", "")
	viper.Set("base-url", "http://localhost")
	t.Cleanup(func() { viper.Reset() })

	err := runEventsWithParams(20, "", "", false, 5)
	if err == nil {
		t.Fatal("runEventsWithParams() expected error for missing API key")
	}
}

func TestExecuteEvents_InvalidPollInterval(t *testing.T) {
	cfg := &eventsParams{
		follow:          true,
		pollIntervalSec: 0,
	}

	err := executeEvents(cfg)
	if err == nil {
		t.Fatal("executeEvents() expected error for invalid poll interval")
	}
}

func TestRunBadgeWithParams_Success(t *testing.T) {
	logEntry := &models.TransparencyLog{
		Status:  "ACTIVE",
		Payload: map[string]any{"logId": "test"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logEntry)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	err := runBadgeWithParams("agent-123", false, false, server.URL)
	if err != nil {
		t.Fatalf("runBadgeWithParams() error = %v", err)
	}
}

func TestRunBadgeWithParams_JSONMode(t *testing.T) {
	logEntry := &models.TransparencyLog{
		Status:  "ACTIVE",
		Payload: map[string]any{"logId": "test"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logEntry)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	err := runBadgeWithParams("agent-123", false, false, server.URL)
	if err != nil {
		t.Fatalf("runBadgeWithParams() JSON mode error = %v", err)
	}
}

func TestRunBadgeWithParams_WithAuditAndCheckpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/agents/agent-123" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(models.TransparencyLog{
				Status:  "ACTIVE",
				Payload: map[string]any{"logId": "test"},
			})
		case r.URL.Path == "/v1/agents/agent-123/audit":
			json.NewEncoder(w).Encode(models.TransparencyLogAudit{
				Records: []models.TransparencyLog{},
			})
		case r.URL.Path == "/v1/log/checkpoint":
			json.NewEncoder(w).Encode(models.CheckpointResponse{
				LogSize:  100,
				RootHash: "abc123",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	err := runBadgeWithParams("agent-123", true, true, server.URL)
	if err != nil {
		t.Fatalf("runBadgeWithParams() with audit+checkpoint error = %v", err)
	}
}

func TestRunBadgeWithParams_JSONWithAuditAndCheckpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/agents/agent-123" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(models.TransparencyLog{
				Status:  "ACTIVE",
				Payload: map[string]any{"logId": "test"},
			})
		case r.URL.Path == "/v1/agents/agent-123/audit":
			json.NewEncoder(w).Encode(models.TransparencyLogAudit{
				Records: []models.TransparencyLog{},
			})
		case r.URL.Path == "/v1/log/checkpoint":
			json.NewEncoder(w).Encode(models.CheckpointResponse{
				LogSize:  100,
				RootHash: "abc123",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	err := runBadgeWithParams("agent-123", true, true, server.URL)
	if err != nil {
		t.Fatalf("runBadgeWithParams() JSON with audit+checkpoint error = %v", err)
	}
}

func TestRunBadgeWithParams_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	err := runBadgeWithParams("agent-123", false, false, server.URL)
	if err == nil {
		t.Fatal("runBadgeWithParams() expected error for server error")
	}
}

func TestRunRegisterWithParams_NoAPIKey(t *testing.T) {
	viper.Set("api-key", "")
	viper.Set("oauth-token", "")
	viper.Set("base-url", "http://localhost")
	t.Cleanup(func() { viper.Reset() })

	err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
		"/nonexistent/id.csr", "", "", "https://example.com", "", "MCP", nil, nil, nil)
	if err == nil {
		t.Fatal("runRegisterWithParams() expected error for missing API key")
	}
}

func TestRunRegisterWithParams_BadIdentityCSR(t *testing.T) {
	setupViperForTest(t, "http://localhost")

	err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
		"/nonexistent/id.csr", "", "", "https://example.com", "", "MCP", nil, nil, nil)
	if err == nil {
		t.Fatal("runRegisterWithParams() expected error for bad identity CSR file")
	}
}

func TestRunRegisterWithParams_BadServerCSR(t *testing.T) {
	setupViperForTest(t, "http://localhost")

	tmpDir := t.TempDir()
	identityCSR := filepath.Join(tmpDir, "identity.csr")
	os.WriteFile(identityCSR, []byte("CSR"), 0600)

	err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
		identityCSR, "/nonexistent/server.csr", "", "https://example.com", "", "MCP", nil, nil, nil)
	if err == nil {
		t.Fatal("runRegisterWithParams() expected error for bad server CSR file")
	}
}

func TestRunRegisterWithParams_BadServerCert(t *testing.T) {
	setupViperForTest(t, "http://localhost")

	tmpDir := t.TempDir()
	identityCSR := filepath.Join(tmpDir, "identity.csr")
	os.WriteFile(identityCSR, []byte("CSR"), 0600)

	err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
		identityCSR, "", "/nonexistent/server.cert", "https://example.com", "", "MCP", nil, nil, nil)
	if err == nil {
		t.Fatal("runRegisterWithParams() expected error for bad server cert file")
	}
}

func TestRunRegisterWithParams_InvalidFunctions(t *testing.T) {
	setupViperForTest(t, "http://localhost")

	tmpDir := t.TempDir()
	identityCSR := filepath.Join(tmpDir, "identity.csr")
	os.WriteFile(identityCSR, []byte("CSR"), 0600)

	err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
		identityCSR, "", "", "https://example.com", "", "MCP", nil, []string{"invalid"}, nil)
	if err == nil {
		t.Fatal("runRegisterWithParams() expected error for invalid function flags")
	}
}

func TestRunRegisterWithParams_Success(t *testing.T) {
	result := &models.RegistrationPending{
		Status:  "PENDING",
		ANSName: "ans://v1.0.0.test.example.com",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	tmpDir := t.TempDir()
	identityCSR := filepath.Join(tmpDir, "identity.csr")
	os.WriteFile(identityCSR, []byte("CSR"), 0600)

	err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
		identityCSR, "", "", "https://example.com", "", "MCP", nil, nil, nil)
	if err != nil {
		t.Fatalf("runRegisterWithParams() error = %v", err)
	}
}

func TestRunRegisterWithParams_JSONMode(t *testing.T) {
	result := &models.RegistrationPending{
		Status:  "PENDING",
		ANSName: "ans://v1.0.0.test.example.com",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("json", true)

	tmpDir := t.TempDir()
	identityCSR := filepath.Join(tmpDir, "identity.csr")
	os.WriteFile(identityCSR, []byte("CSR"), 0600)

	err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
		identityCSR, "", "", "https://example.com", "", "MCP", nil, nil, nil)
	if err != nil {
		t.Fatalf("runRegisterWithParams() JSON mode error = %v", err)
	}
}

func TestRunRegisterWithParams_WithServerCSR(t *testing.T) {
	result := &models.RegistrationPending{
		Status:  "PENDING",
		ANSName: "ans://v1.0.0.test.example.com",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	tmpDir := t.TempDir()
	identityCSR := filepath.Join(tmpDir, "identity.csr")
	serverCSR := filepath.Join(tmpDir, "server.csr")
	os.WriteFile(identityCSR, []byte("ID-CSR"), 0600)
	os.WriteFile(serverCSR, []byte("SRV-CSR"), 0600)

	err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
		identityCSR, serverCSR, "", "https://example.com", "", "MCP", nil, nil, nil)
	if err != nil {
		t.Fatalf("runRegisterWithParams() with server CSR error = %v", err)
	}
}

func TestRunRegisterWithParams_WithServerCert(t *testing.T) {
	result := &models.RegistrationPending{
		Status:  "PENDING",
		ANSName: "ans://v1.0.0.test.example.com",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)

	tmpDir := t.TempDir()
	identityCSR := filepath.Join(tmpDir, "identity.csr")
	serverCert := filepath.Join(tmpDir, "server.cert")
	os.WriteFile(identityCSR, []byte("ID-CSR"), 0600)
	os.WriteFile(serverCert, []byte("CERT"), 0600)

	err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
		identityCSR, "", serverCert, "https://example.com", "", "MCP", nil, nil, nil)
	if err != nil {
		t.Fatalf("runRegisterWithParams() with server cert error = %v", err)
	}
}

func TestBuildRootCmd_HasSubcommands(t *testing.T) {
	cmd := buildRootCmd()
	if cmd == nil {
		t.Fatal("buildRootCmd() returned nil")
	}

	// Verify it has subcommands
	subCmds := cmd.Commands()
	if len(subCmds) == 0 {
		t.Error("buildRootCmd() has no subcommands")
	}

	// Verify key subcommands exist
	expectedCmds := []string{"badge", "register", "resolve", "search", "status", "events", "revoke"}
	for _, name := range expectedCmds {
		found := false
		for _, sub := range subCmds {
			if sub.Name() == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("buildRootCmd() missing subcommand %q", name)
		}
	}
}

// captureOutput redirects os.Stdout and os.Stderr while fn runs and returns
// what was written to each (stdout first), so tests can assert diagnostics
// land on stderr while stdout stays machine-parseable. The pipes are drained
// concurrently so fn can write more than the kernel pipe buffer without
// deadlocking.
func captureOutput(t *testing.T, fn func()) (string, string) {
	t.Helper()

	origStdout, origStderr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error: %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error: %v", err)
	}

	outCh := make(chan string, 1)
	errCh := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rOut)
		outCh <- buf.String()
	}()
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rErr)
		errCh <- buf.String()
	}()

	os.Stdout, os.Stderr = wOut, wErr //nolint:reassign // intentional stream capture; restored below
	defer func() {
		os.Stdout, os.Stderr = origStdout, origStderr //nolint:reassign // restores the original streams
	}()

	fn()

	_ = wOut.Close()
	_ = wErr.Close()
	return <-outCh, <-errCh
}

func TestRunStatus_OAuthToken(t *testing.T) {
	var mu sync.Mutex
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&models.AgentDetails{AgentID: "agent-123"})
	}))
	defer server.Close()

	viper.Set("api-key", "")
	viper.Set("oauth-token", "tok")
	viper.Set("base-url", server.URL)
	t.Cleanup(func() { viper.Reset() })

	cmd := buildStatusCmd()
	cmd.SetArgs([]string{"agent-123"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("runStatus() with OAuth token error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization header = %q, want %q", gotAuth, "Bearer tok")
	}
}

func TestRunStatus_OAuthPrecedence(t *testing.T) {
	var mu sync.Mutex
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&models.AgentDetails{AgentID: "agent-123"})
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("oauth-token", "secret-oauth-value")
	viper.Set("json", true)

	stdout, stderr := captureOutput(t, func() {
		cmd := buildStatusCmd()
		cmd.SetArgs([]string{"agent-123"})
		if err := cmd.Execute(); err != nil {
			t.Errorf("runStatus() with both credentials error = %v", err)
		}
	})

	mu.Lock()
	gotAuthCopy := gotAuth
	mu.Unlock()
	if gotAuthCopy != "Bearer secret-oauth-value" {
		t.Errorf("Authorization header = %q, want %q (OAuth must win over API key)", gotAuthCopy, "Bearer secret-oauth-value")
	}

	if !strings.Contains(stderr, "using the OAuth bearer token") {
		t.Errorf("stderr = %q, want the both-credentials notice", stderr)
	}
	if strings.Contains(stderr, "secret-oauth-value") {
		t.Errorf("stderr leaks the token value: %q", stderr)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(stdout), &parsed); err != nil {
		t.Errorf("stdout is not valid JSON with --json and the stderr notice active: %v\nstdout: %q", err, stdout)
	}
}

func TestRunStatus_OAuthExpired401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(&models.APIError{
			Status:  "error",
			Code:    "UNAUTHORIZED",
			Message: "token expired",
		})
	}))
	defer server.Close()

	viper.Set("api-key", "")
	viper.Set("oauth-token", "expired-tok")
	viper.Set("base-url", server.URL)
	t.Cleanup(func() { viper.Reset() })

	cmd := buildStatusCmd()
	cmd.SetArgs([]string{"agent-123"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("runStatus() expected error for expired token")
	}
	if !strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("error = %q, want it to surface the 401 as Unauthorized", err.Error())
	}
}

// TestRunRevoke_CredentialErrorBeforeArgValidation pins the error-precedence
// contract that keeps the credential check at each call site: with no
// credentials AND an invalid reason, the credential error must win.
func TestRunRevoke_CredentialErrorBeforeArgValidation(t *testing.T) {
	viper.Set("api-key", "")
	viper.Set("oauth-token", "")
	viper.Set("base-url", "http://localhost")
	t.Cleanup(func() { viper.Reset() })

	err := runRevoke("agent-123", "NOT_A_REASON", "")
	if err == nil {
		t.Fatal("runRevoke() expected error")
	}
	if !strings.Contains(err.Error(), "OAuth token or API key is required") {
		t.Errorf("error = %q, want the credentials error before reason validation", err.Error())
	}
}

func TestInitConfig_OAuthTokenEnv(t *testing.T) {
	viper.Reset()
	t.Setenv("ANS_OAUTH_TOKEN", "env-tok")
	t.Cleanup(func() { viper.Reset() })

	initConfig()

	if got := viper.GetString("oauth-token"); got != "env-tok" {
		t.Errorf("viper oauth-token = %q, want %q (ANS_OAUTH_TOKEN env binding)", got, "env-tok")
	}
}

// TestRunRegisterWithParams_InvalidDiscoveryProfile verifies the CLI
// wiring actually invokes the profile validation and surfaces the
// error: models.IsValidDiscoveryProfile is unit-tested in the models
// package, but this is the layer a user's typo actually hits.
func TestRunRegisterWithParams_InvalidDiscoveryProfile(t *testing.T) {
	setupViperForTest(t, "http://localhost")
	viper.Set("api-version", "v2")

	tmpDir := t.TempDir()
	identityCSR := filepath.Join(tmpDir, "identity.csr")
	os.WriteFile(identityCSR, []byte("CSR"), 0600)

	err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
		identityCSR, "", "", "https://example.com", "", "MCP", nil, nil, []string{"ANS_BOGUS"})
	if err == nil || !strings.Contains(err.Error(), "invalid discovery profile") {
		t.Fatalf("expected invalid-discovery-profile error, got %v", err)
	}
}

// TestRunRegisterWithParams_DiscoveryProfilesRequireV2 pins the lane
// guard: profiles on the default V1 lane would be silently ignored
// server-side, so the CLI must reject the combination up front.
func TestRunRegisterWithParams_DiscoveryProfilesRequireV2(t *testing.T) {
	setupViperForTest(t, "http://localhost") // api-version unset → flag default v1

	tmpDir := t.TempDir()
	identityCSR := filepath.Join(tmpDir, "identity.csr")
	os.WriteFile(identityCSR, []byte("CSR"), 0600)

	err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
		identityCSR, "", "", "https://example.com", "", "MCP", nil, nil, []string{"ANS_DNSAID"})
	if err == nil || !strings.Contains(err.Error(), "requires --api-version v2") {
		t.Fatalf("expected v2-lane guard error, got %v", err)
	}
}

// TestRunRegisterWithParams_DiscoveryProfilesV2Success drives the
// happy path end-to-end at the CLI layer: --api-version v2 routes the
// request to the V2 collection and the validated profiles reach the
// wire verbatim.
func TestRunRegisterWithParams_DiscoveryProfilesV2Success(t *testing.T) {
	result := &models.RegistrationPending{
		Status:  "PENDING",
		ANSName: "ans://v1.0.0.test.example.com",
	}

	var gotPath string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()

	setupViperForTest(t, server.URL)
	viper.Set("api-version", "v2")

	tmpDir := t.TempDir()
	identityCSR := filepath.Join(tmpDir, "identity.csr")
	os.WriteFile(identityCSR, []byte("CSR"), 0600)

	err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
		identityCSR, "", "", "https://example.com", "", "MCP", nil, nil, []string{"ans_dnsaid"})
	if err != nil {
		t.Fatalf("runRegisterWithParams() error = %v", err)
	}
	if gotPath != "/v2/ans/agents" {
		t.Errorf("path: got %q, want /v2/ans/agents", gotPath)
	}
	var body map[string]any
	if err := json.Unmarshal(gotBody, &body); err != nil {
		t.Fatalf("unmarshal request body: %v", err)
	}
	profiles, ok := body["discoveryProfiles"].([]any)
	if !ok || len(profiles) != 1 || profiles[0] != "ANS_DNSAID" {
		t.Errorf("discoveryProfiles: got %v, want [ANS_DNSAID] (input normalized to upper case)", body["discoveryProfiles"])
	}
}
