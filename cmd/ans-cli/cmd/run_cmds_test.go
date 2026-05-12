package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/godaddy/ans-sdk-go/models"
	"github.com/spf13/viper"
)

// setupViperForTest sets viper values needed for config.Load() and returns a cleanup function.
func setupViperForTest(t *testing.T, serverURL string) {
	t.Helper()
	viper.Set("api-key", "testkey:testsecret")
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
	viper.Set("base-url", "http://localhost")
	t.Cleanup(func() { viper.Reset() })

	err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
		"/nonexistent/id.csr", "", "", "https://example.com", "", "MCP", nil, nil)
	if err == nil {
		t.Fatal("runRegisterWithParams() expected error for missing API key")
	}
}

func TestRunRegisterWithParams_BadIdentityCSR(t *testing.T) {
	setupViperForTest(t, "http://localhost")

	err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
		"/nonexistent/id.csr", "", "", "https://example.com", "", "MCP", nil, nil)
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
		identityCSR, "/nonexistent/server.csr", "", "https://example.com", "", "MCP", nil, nil)
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
		identityCSR, "", "/nonexistent/server.cert", "https://example.com", "", "MCP", nil, nil)
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
		identityCSR, "", "", "https://example.com", "", "MCP", nil, []string{"invalid"})
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
		identityCSR, "", "", "https://example.com", "", "MCP", nil, nil)
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
		identityCSR, "", "", "https://example.com", "", "MCP", nil, nil)
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
		identityCSR, serverCSR, "", "https://example.com", "", "MCP", nil, nil)
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
		identityCSR, "", serverCert, "https://example.com", "", "MCP", nil, nil)
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
