package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godaddy/ans-sdk-go/cmd/ans-cli/internal/config"
	"github.com/godaddy/ans-sdk-go/models"
	"github.com/spf13/viper"
)

func TestBuildEventsCmd(t *testing.T) {
	tests := []struct {
		name      string
		checkUse  string
		flagNames []string
	}{
		{
			name:      "command properties and flags",
			checkUse:  "events",
			flagNames: []string{"limit", "provider-id", "last-log-id", "follow", "poll-interval"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := buildEventsCmd()
			if cmd == nil {
				t.Fatal("buildEventsCmd() returned nil")
			}
			if cmd.Use != tt.checkUse {
				t.Errorf("Use = %q, want %q", cmd.Use, tt.checkUse)
			}
			for _, flagName := range tt.flagNames {
				if cmd.Flags().Lookup(flagName) == nil {
					t.Errorf("missing flag %q", flagName)
				}
			}
		})
	}
}

func TestPrintEvents(t *testing.T) {
	agentName := "Test Agent"
	agentDesc := "A test agent"
	providerID := "provider-123"
	lastLogID := "log-456"
	expiresAt := time.Now().Add(24 * time.Hour)

	tests := []struct {
		name   string
		result *models.EventPageResponse
	}{
		{
			name: "no events",
			result: &models.EventPageResponse{
				Items: []models.EventItem{},
			},
		},
		{
			name: "with events and pagination",
			result: &models.EventPageResponse{
				Items: []models.EventItem{
					{
						LogID:            "log-1",
						EventType:        "AGENT_REGISTERED",
						CreatedAt:        time.Now(),
						ExpiresAt:        &expiresAt,
						AgentID:          "agent-1",
						AnsName:          "test.ans.godaddy",
						AgentHost:        "test.example.com",
						AgentDisplayName: &agentName,
						AgentDescription: &agentDesc,
						Version:          "1.0.0",
						ProviderID:       &providerID,
						Endpoints: []models.AgentEndpoint{
							{Protocol: "MCP"},
							{Protocol: "A2A"},
						},
					},
					{
						LogID:     "log-2",
						EventType: "AGENT_RENEWED",
						AgentID:   "agent-2",
						AnsName:   "other.ans.godaddy",
						AgentHost: "other.example.com",
						Version:   "2.0.0",
					},
				},
				LastLogID: &lastLogID,
			},
		},
		{
			name: "events without more results",
			result: &models.EventPageResponse{
				Items: []models.EventItem{
					{
						LogID:     "log-3",
						EventType: "AGENT_REVOKED",
						AgentID:   "agent-3",
						AnsName:   "revoked.ans.godaddy",
						AgentHost: "revoked.example.com",
						Version:   "1.0.0",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			printEvents(tt.result)
		})
	}
}

func TestPrintEventsStreaming(t *testing.T) {
	tests := []struct {
		name        string
		result      *models.EventPageResponse
		isFirstPoll bool
	}{
		{
			name: "first poll with no events",
			result: &models.EventPageResponse{
				Items: []models.EventItem{},
			},
			isFirstPoll: true,
		},
		{
			name: "subsequent poll with no events",
			result: &models.EventPageResponse{
				Items: []models.EventItem{},
			},
			isFirstPoll: false,
		},
		{
			name: "first poll with events",
			result: &models.EventPageResponse{
				Items: []models.EventItem{
					{
						EventType: "AGENT_REGISTERED",
						AgentHost: "test.example.com",
						Version:   "1.0.0",
						CreatedAt: time.Now(),
					},
					{
						EventType: "AGENT_RENEWED",
						AgentHost: "other.example.com",
						Version:   "v2.0.0",
					},
				},
			},
			isFirstPoll: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			printEventsStreaming(tt.result, tt.isFirstPoll)
		})
	}
}

func TestOutputEvents(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		follow      bool
		isFirstPoll bool
		result      *models.EventPageResponse
		wantErr     bool
	}{
		{
			name:        "non-JSON, non-follow mode",
			cfg:         &config.Config{JSON: false},
			follow:      false,
			isFirstPoll: true,
			result: &models.EventPageResponse{
				Items: []models.EventItem{},
			},
			wantErr: false,
		},
		{
			name:        "non-JSON, follow mode",
			cfg:         &config.Config{JSON: false},
			follow:      true,
			isFirstPoll: true,
			result: &models.EventPageResponse{
				Items: []models.EventItem{},
			},
			wantErr: false,
		},
		{
			name:        "JSON mode",
			cfg:         &config.Config{JSON: true},
			follow:      false,
			isFirstPoll: true,
			result: &models.EventPageResponse{
				Items: []models.EventItem{
					{
						LogID:     "log-1",
						EventType: "AGENT_REGISTERED",
						AgentHost: "test.example.com",
						Version:   "1.0.0",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := outputEvents(tt.result, tt.cfg, tt.follow, tt.isFirstPoll)
			if (err != nil) != tt.wantErr {
				t.Errorf("outputEvents() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunEventsWithParams(t *testing.T) {
	lastLogID := "log-cursor"

	tests := []struct {
		name         string
		handler      http.HandlerFunc
		setupViper   func(t *testing.T, serverURL string)
		limit        int
		providerID   string
		lastLogID    string
		follow       bool
		pollInterval int
		wantErr      bool
	}{
		{
			name: "with provider and cursor",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(models.EventPageResponse{
					Items: []models.EventItem{
						{
							LogID:     "log-1",
							EventType: "AGENT_REGISTERED",
							AgentHost: "test.example.com",
							Version:   "1.0.0",
						},
					},
					LastLogID: &lastLogID,
				})
			},
			limit:        20,
			providerID:   "provider-123",
			lastLogID:    "cursor-123",
			follow:       false,
			pollInterval: 1,
			wantErr:      false,
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			limit:        20,
			providerID:   "",
			lastLogID:    "",
			follow:       false,
			pollInterval: 5,
			wantErr:      true,
		},
		{
			name: "invalid API key format",
			setupViper: func(t *testing.T, _ string) {
				viper.Set("api-key", "invalid-no-colon")
				viper.Set("base-url", "http://localhost")
				t.Cleanup(func() { viper.Reset() })
			},
			limit:        20,
			providerID:   "",
			lastLogID:    "",
			follow:       false,
			pollInterval: 5,
			wantErr:      true,
		},
		{
			name: "follow mode",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(models.EventPageResponse{
					Items: []models.EventItem{
						{
							LogID:     "log-1",
							EventType: "AGENT_REGISTERED",
							AgentHost: "test.example.com",
							Version:   "1.0.0",
						},
					},
					LastLogID: &lastLogID,
				})
			},
			limit:        20,
			providerID:   "",
			lastLogID:    "",
			follow:       false,
			pollInterval: 1,
			wantErr:      false,
		},
		{
			name: "follow mode invalid poll interval",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(models.EventPageResponse{})
			},
			limit:        20,
			providerID:   "",
			lastLogID:    "",
			follow:       true,
			pollInterval: 0,
			wantErr:      true,
		},
		{
			name: "JSON output",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(models.EventPageResponse{
					Items:     []models.EventItem{},
					LastLogID: &lastLogID,
				})
			},
			setupViper: func(t *testing.T, serverURL string) {
				setupViperForTest(t, serverURL)
				viper.Set("json", true)
			},
			limit:        20,
			providerID:   "",
			lastLogID:    "",
			follow:       false,
			pollInterval: 5,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.handler != nil {
				server := httptest.NewServer(tt.handler)
				defer server.Close()

				if tt.setupViper != nil {
					tt.setupViper(t, server.URL)
				} else {
					setupViperForTest(t, server.URL)
				}
			} else if tt.setupViper != nil {
				tt.setupViper(t, "")
			}

			err := runEventsWithParams(tt.limit, tt.providerID, tt.lastLogID, tt.follow, tt.pollInterval)
			if (err != nil) != tt.wantErr {
				t.Errorf("runEventsWithParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunVerifyACME_ServerError(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "server returns 500",
			args:    []string{"agent-123"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()

			setupViperForTest(t, server.URL)

			cmd := buildVerifyACMECmd()
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("runVerifyACME() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunVerifyDNS_ServerError(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "server returns 500",
			args:    []string{"agent-123"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()

			setupViperForTest(t, server.URL)

			cmd := buildVerifyDNSCmd()
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("runVerifyDNS() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunGetIdentityCerts_ServerError(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "server returns 500",
			args:    []string{"agent-123"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()

			setupViperForTest(t, server.URL)

			cmd := buildGetIdentityCertsCmd()
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("runGetIdentityCerts() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunGetServerCerts_ServerError(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "server returns 500",
			args:    []string{"agent-123"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()

			setupViperForTest(t, server.URL)

			cmd := buildGetServerCertsCmd()
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("runGetServerCerts() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunCsrStatus_ServerError(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "server returns 500",
			args:    []string{"agent-123", "csr-123"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()

			setupViperForTest(t, server.URL)

			cmd := buildCsrStatusCmd()
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("runCsrStatus() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunSubmitIdentityCSR_ServerError(t *testing.T) {
	tests := []struct {
		name    string
		agentID string
		wantErr bool
	}{
		{
			name:    "server returns 500",
			agentID: "agent-123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()

			setupViperForTest(t, server.URL)

			tmpDir := t.TempDir()
			csrFile := filepath.Join(tmpDir, "identity.csr")
			os.WriteFile(csrFile, []byte("CSR-DATA"), 0600)

			err := runSubmitIdentityCSRWithParams(tt.agentID, csrFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("runSubmitIdentityCSRWithParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunSubmitServerCSR(t *testing.T) {
	tests := []struct {
		name       string
		setupViper func(t *testing.T, serverURL string)
		handler    http.HandlerFunc
		agentID    string
		wantErr    bool
	}{
		{
			name: "no API key",
			setupViper: func(t *testing.T, _ string) {
				viper.Set("api-key", "")
				viper.Set("base-url", "http://localhost")
				t.Cleanup(func() { viper.Reset() })
			},
			agentID: "agent-123",
			wantErr: true,
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			agentID: "agent-123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.handler != nil {
				server := httptest.NewServer(tt.handler)
				defer server.Close()

				if tt.setupViper != nil {
					tt.setupViper(t, server.URL)
				} else {
					setupViperForTest(t, server.URL)
				}
			} else if tt.setupViper != nil {
				tt.setupViper(t, "")
			}

			tmpDir := t.TempDir()
			csrFile := filepath.Join(tmpDir, "server.csr")
			os.WriteFile(csrFile, []byte("CSR-DATA"), 0600)

			err := runSubmitServerCSRWithParams(tt.agentID, csrFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("runSubmitServerCSRWithParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunRegisterWithParams(t *testing.T) {
	result := &models.RegistrationPending{
		Status:  "PENDING",
		ANSName: "ans://v1.0.0.test.example.com",
	}

	tests := []struct {
		name       string
		handler    http.HandlerFunc
		functions  []string
		transports []string
		wantErr    bool
	}{
		{
			name: "server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr: true,
		},
		{
			name: "with functions and transports",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(result)
			},
			functions:  []string{"fn-1:test-function:api,data"},
			transports: []string{"HTTPS", "SSE"},
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			setupViperForTest(t, server.URL)

			tmpDir := t.TempDir()
			identityCSR := filepath.Join(tmpDir, "identity.csr")
			os.WriteFile(identityCSR, []byte("CSR-DATA"), 0600)

			err := runRegisterWithParams("name", "host", "v1.0.0", "desc",
				identityCSR, "", "", "https://example.com", "", "MCP",
				tt.transports, tt.functions)
			if (err != nil) != tt.wantErr {
				t.Errorf("runRegisterWithParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunBadgeWithParams_JSONOutput(t *testing.T) {
	tests := []struct {
		name       string
		audit      bool
		checkpoint bool
	}{
		{
			name:       "JSON with audit and checkpoint success",
			audit:      true,
			checkpoint: true,
		},
		{
			name:       "JSON no extras",
			audit:      false,
			checkpoint: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == "/v1/agents/agent-123" && r.Method == http.MethodGet && r.URL.RawQuery == "":
					json.NewEncoder(w).Encode(models.TransparencyLog{
						Status:        "ACTIVE",
						SchemaVersion: "V1",
						Payload:       map[string]any{"logId": "test"},
					})
				case strings.Contains(r.URL.Path, "/audit"):
					json.NewEncoder(w).Encode(models.TransparencyLogAudit{Records: []models.TransparencyLog{}})
				case strings.Contains(r.URL.Path, "/checkpoint"):
					json.NewEncoder(w).Encode(models.CheckpointResponse{LogSize: 100})
				default:
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]any{})
				}
			}))
			defer server.Close()

			setupViperForTest(t, server.URL)
			viper.Set("json", true)

			err := runBadgeWithParams("agent-123", tt.audit, tt.checkpoint, server.URL)
			if err != nil {
				t.Errorf("runBadgeWithParams() error = %v", err)
			}
		})
	}
}

func TestRunBadgeWithParams_ServerErrors(t *testing.T) {
	tests := []struct {
		name       string
		audit      bool
		checkpoint bool
		wantErr    bool
	}{
		{
			name:       "audit server error",
			audit:      true,
			checkpoint: false,
			wantErr:    false,
		},
		{
			name:       "checkpoint server error",
			audit:      false,
			checkpoint: true,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/v1/agents/agent-123" && r.Method == http.MethodGet {
					json.NewEncoder(w).Encode(models.TransparencyLog{
						Status:  "ACTIVE",
						Payload: map[string]any{"logId": "test"},
					})
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			defer server.Close()

			setupViperForTest(t, server.URL)

			err := runBadgeWithParams("agent-123", tt.audit, tt.checkpoint, server.URL)
			if (err != nil) != tt.wantErr {
				t.Errorf("runBadgeWithParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
