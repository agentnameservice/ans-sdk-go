package ans

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/godaddy/ans-sdk-go/models"
)

func TestNewTransparencyClient(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{
			name:    "default config",
			opts:    nil,
			wantErr: false,
		},
		{
			name: "with base URL",
			opts: []Option{
				WithBaseURL("https://transparency.ans.godaddy.com"),
			},
			wantErr: false,
		},
		{
			name: "with verbose",
			opts: []Option{
				WithVerbose(true),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewTransparencyClient(tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTransparencyClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewTransparencyClient() returned nil client")
			}
		})
	}
}

func TestTransparencyClient_GetAgentTransparencyLog(t *testing.T) {
	leafIndex := int64(50)
	tests := []struct {
		name       string
		agentID    string
		statusCode int
		response   *models.TransparencyLog
		wantErr    bool
	}{
		{
			name:       "successful transparency log retrieval",
			agentID:    "test-agent-123",
			statusCode: http.StatusOK,
			response: &models.TransparencyLog{
				Status:        "ACTIVE",
				SchemaVersion: "V1",
				Payload: map[string]any{
					"ansId":    "test-agent-123",
					"ansName":  "ans://v1.0.0.agent-0.ai.domain.com",
					"raId":     "api.godaddy.com",
					"issuedAt": "2025-09-24T21:03:47.055000Z",
				},
				MerkleProof: &models.MerkleProof{
					TreeVersion: 1,
					TreeSize:    100,
					LeafIndex:   &leafIndex,
					LeafHash:    "abcd1234",
					RootHash:    "root5678",
				},
			},
			wantErr: false,
		},
		{
			name:       "not found",
			agentID:    "nonexistent-agent",
			statusCode: http.StatusNotFound,
			response:   nil,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request method
				if r.Method != http.MethodGet {
					t.Errorf("Expected GET request, got %s", r.Method)
				}

				// Verify request path
				expectedPath := "/v1/agents/" + tt.agentID
				if r.URL.Path != expectedPath {
					t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
				}

				// Write response
				w.WriteHeader(tt.statusCode)
				if tt.response != nil {
					json.NewEncoder(w).Encode(tt.response)
				} else {
					json.NewEncoder(w).Encode(&models.APIError{
						Status:  "error",
						Code:    "NOT_FOUND",
						Message: "Agent not found",
					})
				}
			}))
			defer server.Close()

			// Create client with test server URL
			client, err := NewTransparencyClient(
				WithBaseURL(server.URL),
			)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			// Execute test
			ctx := context.Background()
			result, err := client.GetAgentTransparencyLog(ctx, tt.agentID)

			// Verify error
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAgentTransparencyLog() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify result for successful case
			if !tt.wantErr {
				if result == nil {
					t.Error("GetAgentTransparencyLog() returned nil result")
					return
				}
				if result.Status != tt.response.Status {
					t.Errorf("Status = %v, want %v", result.Status, tt.response.Status)
				}
				if result.SchemaVersion != tt.response.SchemaVersion {
					t.Errorf("SchemaVersion = %v, want %v", result.SchemaVersion, tt.response.SchemaVersion)
				}
			}
		})
	}
}

func TestTransparencyClient_GetCheckpoint(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   *models.CheckpointResponse
		wantErr    bool
	}{
		{
			name:       "successful checkpoint retrieval",
			statusCode: http.StatusOK,
			response: &models.CheckpointResponse{
				LogSize:          1000,
				RootHash:         "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=",
				TreeHeight:       10,
				OriginName:       "ans-registry-log.example.com",
				CheckpointFormat: "c2sp-tlog/v1",
				Signatures: []models.CheckpointSignature{
					{
						SignerName:    "ans-registry-log.example.com",
						SignatureType: "C2SP",
						Algorithm:     "ES256",
						KeyHash:       "0x3de0ae58",
						RawSignature:  "Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=",
						Valid:         true,
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request method
				if r.Method != http.MethodGet {
					t.Errorf("Expected GET request, got %s", r.Method)
				}

				// Verify request path
				if r.URL.Path != "/v1/log/checkpoint" {
					t.Errorf("Expected path /v1/log/checkpoint, got %s", r.URL.Path)
				}

				// Write response
				w.WriteHeader(tt.statusCode)
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			// Create client with test server URL
			client, err := NewTransparencyClient(
				WithBaseURL(server.URL),
			)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			// Execute test
			ctx := context.Background()
			result, err := client.GetCheckpoint(ctx)

			// Verify error
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCheckpoint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify result for successful case
			if !tt.wantErr {
				if result == nil {
					t.Error("GetCheckpoint() returned nil result")
					return
				}
				if result.LogSize != tt.response.LogSize {
					t.Errorf("LogSize = %v, want %v", result.LogSize, tt.response.LogSize)
				}
				if result.RootHash != tt.response.RootHash {
					t.Errorf("RootHash = %v, want %v", result.RootHash, tt.response.RootHash)
				}
			}
		})
	}
}

func TestTransparencyClient_GetAgentTransparencyLogAudit(t *testing.T) {
	leafIndex := int64(50)
	tests := []struct {
		name       string
		agentID    string
		params     *models.AgentAuditParams
		statusCode int
		response   *models.TransparencyLogAudit
		wantErr    bool
	}{
		{
			name:       "successful audit retrieval",
			agentID:    "test-agent-123",
			params:     &models.AgentAuditParams{Limit: 10, Offset: 0},
			statusCode: http.StatusOK,
			response: &models.TransparencyLogAudit{
				Records: []models.TransparencyLog{
					{
						Status:        "ACTIVE",
						SchemaVersion: "V1",
						Payload: map[string]any{
							"eventType": "AGENT_REGISTERED",
							"ansId":     "test-agent-123",
						},
						MerkleProof: &models.MerkleProof{
							TreeVersion: 1,
							TreeSize:    100,
							LeafIndex:   &leafIndex,
						},
					},
					{
						Status:        "ACTIVE",
						SchemaVersion: "V1",
						Payload: map[string]any{
							"eventType": "AGENT_RENEWED",
							"ansId":     "test-agent-123",
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request path
				expectedPath := "/v1/agents/" + tt.agentID + "/audit"
				if !startsWith(r.URL.Path, expectedPath) {
					t.Errorf("Expected path to start with %s, got %s", expectedPath, r.URL.Path)
				}

				// Verify query parameters if provided
				if tt.params != nil {
					query := r.URL.Query()
					if tt.params.Limit > 0 {
						if query.Get("limit") != "10" {
							t.Errorf("Expected limit=10, got %s", query.Get("limit"))
						}
					}
				}

				// Write response
				w.WriteHeader(tt.statusCode)
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			// Create client
			client, err := NewTransparencyClient(
				WithBaseURL(server.URL),
			)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			// Execute test
			ctx := context.Background()
			result, err := client.GetAgentTransparencyLogAudit(ctx, tt.agentID, tt.params)

			// Verify error
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAgentTransparencyLogAudit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify result
			if !tt.wantErr {
				if result == nil {
					t.Error("GetAgentTransparencyLogAudit() returned nil result")
					return
				}
				if len(result.Records) != len(tt.response.Records) {
					t.Errorf("Records count = %v, want %v", len(result.Records), len(tt.response.Records))
				}
			}
		})
	}
}

func TestTransparencyClient_GetCheckpointHistory(t *testing.T) {
	since := time.Now().Add(-24 * time.Hour)
	tests := []struct {
		name       string
		params     *models.CheckpointHistoryParams
		statusCode int
		response   *models.CheckpointHistoryResponse
		wantErr    bool
	}{
		{
			name: "successful checkpoint history retrieval",
			params: &models.CheckpointHistoryParams{
				Limit:  10,
				Offset: 0,
				Since:  &since,
				Order:  "DESC",
			},
			statusCode: http.StatusOK,
			response: &models.CheckpointHistoryResponse{
				Checkpoints: []models.CheckpointResponse{
					{
						LogSize:    1000,
						RootHash:   "hash1",
						OriginName: "ans-registry-log.example.com",
					},
					{
						LogSize:    900,
						RootHash:   "hash2",
						OriginName: "ans-registry-log.example.com",
					},
				},
				Pagination: models.PaginationInfo{
					Total:      2,
					NextOffset: nil,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request path
				if r.URL.Path != "/v1/log/checkpoint/history" {
					t.Errorf("Expected path /v1/log/checkpoint/history, got %s", r.URL.Path)
				}

				// Verify query parameters
				query := r.URL.Query()
				if tt.params != nil {
					if tt.params.Limit > 0 && query.Get("limit") != "10" {
						t.Errorf("Expected limit=10, got %s", query.Get("limit"))
					}
					if tt.params.Order != "" && query.Get("order") != tt.params.Order {
						t.Errorf("Expected order=%s, got %s", tt.params.Order, query.Get("order"))
					}
				}

				// Write response
				w.WriteHeader(tt.statusCode)
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			// Create client
			client, err := NewTransparencyClient(
				WithBaseURL(server.URL),
			)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			// Execute test
			ctx := context.Background()
			result, err := client.GetCheckpointHistory(ctx, tt.params)

			// Verify error
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCheckpointHistory() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify result
			if !tt.wantErr {
				if result == nil {
					t.Error("GetCheckpointHistory() returned nil result")
					return
				}
				if len(result.Checkpoints) != len(tt.response.Checkpoints) {
					t.Errorf("Checkpoints count = %v, want %v", len(result.Checkpoints), len(tt.response.Checkpoints))
				}
			}
		})
	}
}

func TestTransparencyClient_GetLogSchema(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		statusCode int
		response   *models.JSONSchema
		wantErr    bool
	}{
		{
			name:       "successful schema retrieval V1",
			version:    "V1",
			statusCode: http.StatusOK,
			response: &models.JSONSchema{
				"type": "object",
				"properties": map[string]any{
					"ansId": map[string]any{
						"type":   "string",
						"format": "uuid",
					},
				},
			},
			wantErr: false,
		},
		{
			name:       "schema not found",
			version:    "V999",
			statusCode: http.StatusNotFound,
			response:   nil,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request path
				expectedPath := "/v1/log/schema/" + tt.version
				if r.URL.Path != expectedPath {
					t.Errorf("Expected path %s, got %s", expectedPath, r.URL.Path)
				}

				// Write response
				w.WriteHeader(tt.statusCode)
				if tt.response != nil {
					json.NewEncoder(w).Encode(tt.response)
				} else {
					json.NewEncoder(w).Encode(&models.APIError{
						Status:  "error",
						Code:    "NOT_FOUND",
						Message: "Schema version not found",
					})
				}
			}))
			defer server.Close()

			// Create client
			client, err := NewTransparencyClient(
				WithBaseURL(server.URL),
			)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			// Execute test
			ctx := context.Background()
			result, err := client.GetLogSchema(ctx, tt.version)

			// Verify error
			if (err != nil) != tt.wantErr {
				t.Errorf("GetLogSchema() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Verify result
			if !tt.wantErr {
				if result == nil {
					t.Error("GetLogSchema() returned nil result")
					return
				}
			}
		})
	}
}

func TestTransparencyClient_parsePayloadBySchema(t *testing.T) {
	client := &TransparencyClient{config: defaultConfig()}

	tests := []struct {
		name          string
		payload       map[string]any
		schemaVersion string
		wantNil       bool
		wantType      string
	}{
		{
			name: "V1 payload",
			payload: map[string]any{
				"logId": "test-log",
				"producer": map[string]any{
					"event": map[string]any{
						"ansId":     "test-id",
						"eventType": "AGENT_REGISTERED",
					},
				},
			},
			schemaVersion: "V1",
			wantType:      "*models.TransparencyLogV1",
		},
		{
			name: "V0 payload",
			payload: map[string]any{
				"logId": "test-log",
				"producer": map[string]any{
					"event": map[string]any{
						"agentFqdn": "example.com",
						"agentId":   "test-id",
					},
				},
			},
			schemaVersion: "V0",
			wantType:      "*models.TransparencyLogV0",
		},
		{
			name: "empty schema defaults to V0",
			payload: map[string]any{
				"logId": "test-log",
			},
			schemaVersion: "",
			wantType:      "*models.TransparencyLogV0",
		},
		{
			name: "V2 payload",
			payload: map[string]any{
				"logId": "test-log",
				"producer": map[string]any{
					"event": map[string]any{
						"ansId":     "test-id",
						"eventType": "AGENT_REGISTERED",
						"attestations": map[string]any{
							"serverCerts": []any{
								map[string]any{"fingerprint": "fp-a", "type": "X509-DV-SERVER"},
							},
							"dnsRecordsProvisioned": []any{
								map[string]any{"name": "_ans.x", "data": "d", "type": "TXT"},
							},
						},
					},
				},
			},
			schemaVersion: "V2",
			wantType:      "*models.TransparencyLogV2",
		},
		{
			name: "unknown schema falls back to V0",
			payload: map[string]any{
				"logId": "test-log",
			},
			schemaVersion: "V99",
			wantType:      "*models.TransparencyLogV0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.parsePayloadBySchema(tt.payload, tt.schemaVersion)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parsePayloadBySchema() = %v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Fatal("parsePayloadBySchema() returned nil")
			}
			if got := fmt.Sprintf("%T", result); got != tt.wantType {
				t.Errorf("parsePayloadBySchema() type = %s, want %s", got, tt.wantType)
			}
		})
	}
}

func TestTransparencyClient_doRequestWithSchemaVersion_SchemaFromHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Schema-Version", "V1")
		w.Header().Set("Content-Type", "application/json")
		response := models.TransparencyLog{
			Status: "ACTIVE",
			Payload: map[string]any{
				"logId": "test-log",
				"producer": map[string]any{
					"event": map[string]any{
						"ansId":     "test-id",
						"eventType": "AGENT_REGISTERED",
					},
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, _ := NewTransparencyClient(WithBaseURL(server.URL))
	result, err := client.GetAgentTransparencyLog(context.Background(), "test-agent")
	if err != nil {
		t.Fatalf("GetAgentTransparencyLog() error = %v", err)
	}
	if result.SchemaVersion != "V1" {
		t.Errorf("SchemaVersion = %q, want V1", result.SchemaVersion)
	}
}

func TestTransparencyClient_doRequestWithSchemaVersion_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	client, _ := NewTransparencyClient(WithBaseURL(server.URL))
	_, err := client.GetAgentTransparencyLog(context.Background(), "test-agent")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	// Verify ResponseError is extractable with non-JSON body
	var respErr *models.ResponseError
	if !errors.As(err, &respErr) {
		t.Fatal("expected error to be *models.ResponseError")
	}
	if respErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want %d", respErr.StatusCode, http.StatusInternalServerError)
	}
	if respErr.Message != "internal server error" {
		t.Errorf("Message = %q, want %q", respErr.Message, "internal server error")
	}
}

func TestTransparencyClient_doRequestWithSchemaVersion_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()

	client, _ := NewTransparencyClient(WithBaseURL(server.URL))
	_, err := client.GetAgentTransparencyLog(context.Background(), "test-agent")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestTransparencyClient_GetAgentTransparencyLogAudit_NilParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.TransparencyLogAudit{
			Records: []models.TransparencyLog{},
		})
	}))
	defer server.Close()

	client, _ := NewTransparencyClient(WithBaseURL(server.URL))
	result, err := client.GetAgentTransparencyLogAudit(context.Background(), "test-agent", nil)
	if err != nil {
		t.Fatalf("GetAgentTransparencyLogAudit() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetAgentTransparencyLogAudit() returned nil")
	}
}

func TestTransparencyClient_GetAgentTransparencyLogAudit_WithPayloadParsing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		audit := models.TransparencyLogAudit{
			Records: []models.TransparencyLog{
				{
					SchemaVersion: "V1",
					Payload: map[string]any{
						"logId": "test-log-1",
					},
				},
				{
					// No schema version - should default to V0
					Payload: map[string]any{
						"logId": "test-log-2",
					},
				},
			},
		}
		json.NewEncoder(w).Encode(audit)
	}))
	defer server.Close()

	client, _ := NewTransparencyClient(WithBaseURL(server.URL))
	result, err := client.GetAgentTransparencyLogAudit(context.Background(), "test-agent",
		&models.AgentAuditParams{Limit: 10})
	if err != nil {
		t.Fatalf("GetAgentTransparencyLogAudit() error = %v", err)
	}
	if len(result.Records) != 2 {
		t.Errorf("Records count = %d, want 2", len(result.Records))
	}
}

func TestTransparencyClient_GetCheckpointHistory_NilParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.CheckpointHistoryResponse{
			Checkpoints: []models.CheckpointResponse{},
		})
	}))
	defer server.Close()

	client, _ := NewTransparencyClient(WithBaseURL(server.URL))
	result, err := client.GetCheckpointHistory(context.Background(), nil)
	if err != nil {
		t.Fatalf("GetCheckpointHistory() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetCheckpointHistory() returned nil")
	}
}

func TestAppendAuditParams_WithSince(t *testing.T) {
	params := &models.AgentAuditParams{
		Limit:  10,
		Offset: 5,
	}
	got := appendAuditParams("/test", params)
	if got != "/test?limit=10&offset=5" {
		t.Errorf("appendAuditParams() = %q, want %q", got, "/test?limit=10&offset=5")
	}
}

func TestAppendCheckpointHistoryParams_WithSince(t *testing.T) {
	params := &models.CheckpointHistoryParams{
		Limit:    5,
		FromSize: 100,
		ToSize:   200,
	}
	got := appendCheckpointHistoryParams("/test", params)
	if got != "/test?fromSize=100&limit=5&toSize=200" {
		t.Errorf("appendCheckpointHistoryParams() = %q, want %q", got, "/test?fromSize=100&limit=5&toSize=200")
	}
}

func TestTransparencyClient_doRequestWithSchemaVersion_JSONErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.APIError{
			Status:  "error",
			Code:    "INVALID_AGENT_ID",
			Message: "invalid agent ID",
		})
	}))
	defer server.Close()

	client, _ := NewTransparencyClient(WithBaseURL(server.URL))
	_, err := client.GetAgentTransparencyLog(context.Background(), "bad-id")
	if err == nil {
		t.Fatal("expected error for 400 response")
	}

	// Verify ResponseError is extractable with JSON error body
	var respErr *models.ResponseError
	if !errors.As(err, &respErr) {
		t.Fatal("expected error to be *models.ResponseError")
	}
	if respErr.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want %d", respErr.StatusCode, http.StatusBadRequest)
	}
	if respErr.Code != "INVALID_AGENT_ID" {
		t.Errorf("Code = %q, want %q", respErr.Code, "INVALID_AGENT_ID")
	}
	if respErr.Message != "invalid agent ID" {
		t.Errorf("Message = %q, want %q", respErr.Message, "invalid agent ID")
	}
}

func TestTransparencyClient_doRequestWithSchemaVersion_SchemaVersionInBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Schema version in the response body, not the header
		response := models.TransparencyLog{
			Status:        "ACTIVE",
			SchemaVersion: "V0",
			Payload: map[string]any{
				"logId": "test-log",
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, _ := NewTransparencyClient(WithBaseURL(server.URL))
	result, err := client.GetAgentTransparencyLog(context.Background(), "test-agent")
	if err != nil {
		t.Fatalf("GetAgentTransparencyLog() error = %v", err)
	}
	if result.SchemaVersion != "V0" {
		t.Errorf("SchemaVersion = %q, want V0", result.SchemaVersion)
	}
	if result.ParsedPayload == nil {
		t.Error("ParsedPayload should not be nil when payload exists")
	}
}

func TestTransparencyClient_GetLogSchema_V0(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.JSONSchema{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type":    "object",
		})
	}))
	defer server.Close()

	client, _ := NewTransparencyClient(WithBaseURL(server.URL))
	result, err := client.GetLogSchema(context.Background(), "V0")
	if err != nil {
		t.Fatalf("GetLogSchema() error = %v", err)
	}
	if (*result)["type"] != "object" {
		t.Errorf("type = %v, want object", (*result)["type"])
	}
}

func TestTransparencyClient_GetCheckpointHistory_WithParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify query params are passed
		if r.URL.Query().Get("limit") != "5" {
			t.Errorf("expected limit=5, got %s", r.URL.Query().Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.CheckpointHistoryResponse{
			Checkpoints: []models.CheckpointResponse{},
		})
	}))
	defer server.Close()

	client, _ := NewTransparencyClient(WithBaseURL(server.URL))
	result, err := client.GetCheckpointHistory(context.Background(), &models.CheckpointHistoryParams{Limit: 5})
	if err != nil {
		t.Fatalf("GetCheckpointHistory() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetCheckpointHistory() returned nil")
	}
}

func TestTransparencyClient_GetAgentTransparencyLogAudit_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, _ := NewTransparencyClient(WithBaseURL(server.URL))
	_, err := client.GetAgentTransparencyLogAudit(context.Background(), "test-agent", nil)
	if err == nil {
		t.Fatal("expected error for server error")
	}
}

func TestTransparencyClient_GetCheckpointHistory_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, _ := NewTransparencyClient(WithBaseURL(server.URL))
	_, err := client.GetCheckpointHistory(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for server error")
	}
}

func TestTransparencyClient_GetLogSchema_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, _ := NewTransparencyClient(WithBaseURL(server.URL))
	_, err := client.GetLogSchema(context.Background(), "V99")
	if err == nil {
		t.Fatal("expected error for not found")
	}
}

func TestTransparencyClient_SchemaVersionHandling(t *testing.T) {
	tests := []struct {
		name            string
		responseBody    any
		schemaHeader    string
		expectedVersion string
		validatePayload func(*testing.T, *models.TransparencyLog)
	}{
		{
			name: "V1 schema with header",
			responseBody: map[string]any{
				"status": "ACTIVE",
				"payload": map[string]any{
					"logId": "01936db8-b65e-7e2f-b5e4-d0b5c1234567",
					"producer": map[string]any{
						"event": map[string]any{
							"ansId":     "6bf2b7a9-1383-4e33-a945-845f34af7526",
							"ansName":   "ans://v1.0.0.agent-0.ai.domain.com",
							"eventType": "AGENT_REGISTERED",
							"agent": map[string]any{
								"host":    "agent-0.ai.domain.com",
								"version": "v1.0.0",
							},
							"attestations": map[string]any{
								"domainValidation": "ACME-DNS-01",
								"identityCert": map[string]any{
									"fingerprint": "SHA256:abcdef",
									"type":        "X509-OV-CLIENT",
								},
							},
							"issuedAt":  "2025-01-15T10:00:00Z",
							"raId":      "api.godaddy.com",
							"timestamp": "2025-01-15T10:00:00Z",
						},
						"keyId":     "test-key",
						"signature": "test-signature",
					},
				},
			},
			schemaHeader:    "V1",
			expectedVersion: "V1",
			validatePayload: func(t *testing.T, log *models.TransparencyLog) {
				if !log.IsV1() {
					t.Error("Expected V1 schema detection")
				}
				v1 := log.GetV1Payload()
				if v1 == nil {
					t.Fatal("Expected V1 payload to be parsed")
				}
				if v1.Producer.Event.ANSID != "6bf2b7a9-1383-4e33-a945-845f34af7526" {
					t.Errorf("Expected ANSID to be parsed correctly")
				}
				if v1.Producer.Event.EventType != models.EventTypeV1AgentRegistered {
					t.Errorf("Expected EventType to be AGENT_REGISTERED")
				}
			},
		},
		{
			name: "V0 schema with header",
			responseBody: map[string]any{
				"status": "ACTIVE",
				"payload": map[string]any{
					"logId": "01936db8-b65e-7e2f-b5e4-d0b5c1234568",
					"producer": map[string]any{
						"event": map[string]any{
							"agentFqdn": "agent-0.capability.provider.domain.com",
							"agentId":   "6bf2b7a9-1383-4e33-a945-845f34af7527",
							"ansName":   "mcp://agent-0.capability.provider.v1.0.0.domain.com",
							"eventType": "AGENT_ACTIVE",
							"protocol":  "mcp",
							"raBadge": map[string]any{
								"attestations": map[string]any{
									"domainValidation": "acme-dns-01",
								},
								"badgeUrlStatus": "verified_link",
								"issuedAt":       "2025-01-15T10:00:00Z",
								"raId":           "api.godaddy.com",
							},
							"timestamp": "2025-01-15T10:00:00Z",
						},
						"keyId":     "test-key",
						"signature": "test-signature",
					},
				},
			},
			schemaHeader:    "V0",
			expectedVersion: "V0",
			validatePayload: func(t *testing.T, log *models.TransparencyLog) {
				if !log.IsV0() {
					t.Error("Expected V0 schema detection")
				}
				v0 := log.GetV0Payload()
				if v0 == nil {
					t.Fatal("Expected V0 payload to be parsed")
				}
				if v0.Producer.Event.AgentID != "6bf2b7a9-1383-4e33-a945-845f34af7527" {
					t.Errorf("Expected AgentID to be parsed correctly")
				}
				if v0.Producer.Event.EventType != models.EventTypeV0AgentActive {
					t.Errorf("Expected EventType to be AGENT_ACTIVE")
				}
			},
		},
		{
			name: "V0 schema without header (default)",
			responseBody: map[string]any{
				"status": "ACTIVE",
				"payload": map[string]any{
					"logId": "01936db8-b65e-7e2f-b5e4-d0b5c1234569",
					"producer": map[string]any{
						"event": map[string]any{
							"agentFqdn": "agent.example.com",
							"agentId":   "test-agent-id",
							"ansName":   "mcp://agent.example.com",
							"eventType": "agent_active",
							"protocol":  "mcp",
							"raBadge": map[string]any{
								"attestations":   map[string]any{},
								"badgeUrlStatus": "pending_verification",
								"issuedAt":       "2025-01-15T10:00:00Z",
								"raId":           "ra.example.com",
							},
							"timestamp": "2025-01-15T10:00:00Z",
						},
						"keyId":     "test-key",
						"signature": "test-signature",
					},
				},
			},
			schemaHeader:    "", // No header, should default to V0
			expectedVersion: "",
			validatePayload: func(t *testing.T, log *models.TransparencyLog) {
				if !log.IsV0() {
					t.Error("Expected V0 schema detection for missing version")
				}
				v0 := log.GetV0Payload()
				if v0 == nil {
					t.Fatal("Expected V0 payload to be parsed for missing version")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.schemaHeader != "" {
					w.Header().Set("X-Schema-Version", tt.schemaHeader)
				}
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(tt.responseBody)
			}))
			defer server.Close()

			client, err := NewTransparencyClient(
				WithBaseURL(server.URL),
			)
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}

			ctx := context.Background()
			result, err := client.GetAgentTransparencyLog(ctx, "test-agent-id")
			if err != nil {
				t.Fatalf("GetAgentTransparencyLog() unexpected error: %v", err)
			}

			if result.SchemaVersion != tt.expectedVersion {
				t.Errorf("SchemaVersion = %v, want %v", result.SchemaVersion, tt.expectedVersion)
			}

			if tt.validatePayload != nil {
				tt.validatePayload(t, result)
			}
		})
	}
}

func TestTransparencyClient_AuditWithSchemas(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := models.TransparencyLogAudit{
			Records: []models.TransparencyLog{
				{
					Status:        "ACTIVE",
					SchemaVersion: "V1",
					Payload: map[string]any{
						"logId": "log-v1",
						"producer": map[string]any{
							"event": map[string]any{
								"ansId":     "ans-id-v1",
								"ansName":   "ans://v1.0.0.test",
								"eventType": "AGENT_REGISTERED",
								"agent": map[string]any{
									"host":    "test.com",
									"version": "v1.0.0",
								},
								"attestations": map[string]any{},
								"issuedAt":     time.Now().Format(time.RFC3339),
								"raId":         "ra.test",
								"timestamp":    time.Now().Format(time.RFC3339),
							},
							"keyId":     "key1",
							"signature": "sig1",
						},
					},
				},
				{
					Status:        "ACTIVE",
					SchemaVersion: "V2",
					Payload: map[string]any{
						"logId": "log-v2",
						"producer": map[string]any{
							"event": map[string]any{
								"ansId":     "ans-id-v2",
								"ansName":   "ans://v1.0.0.test",
								"eventType": "AGENT_REGISTERED",
								"agent": map[string]any{
									"host":    "test.com",
									"version": "v1.0.0",
								},
								"attestations": map[string]any{
									"serverCerts": []any{
										map[string]any{"fingerprint": "v2-srv-fp", "type": "X509-DV-SERVER"},
									},
									"identityCerts": []any{
										map[string]any{"fingerprint": "v2-id-fp", "type": "X509-OV-CLIENT"},
									},
									"dnsRecordsProvisioned": []any{
										map[string]any{"name": "_ans.test.com", "data": "txt-data", "type": "TXT"},
									},
								},
								"issuedAt":  time.Now().Format(time.RFC3339),
								"raId":      "ra.test",
								"timestamp": time.Now().Format(time.RFC3339),
							},
							"keyId":     "key-v2",
							"signature": "sig-v2",
						},
					},
				},
				{
					Status:        "ACTIVE",
					SchemaVersion: "V0",
					Payload: map[string]any{
						"logId": "log-v0",
						"producer": map[string]any{
							"event": map[string]any{
								"agentFqdn": "agent.test.com",
								"agentId":   "agent-id-v0",
								"ansName":   "mcp://test",
								"eventType": "AGENT_ACTIVE",
								"protocol":  "mcp",
								"raBadge": map[string]any{
									"attestations":   map[string]any{},
									"badgeUrlStatus": "verified_link",
									"issuedAt":       time.Now().Format(time.RFC3339),
									"raId":           "ra.test",
								},
								"timestamp": time.Now().Format(time.RFC3339),
							},
							"keyId":     "key2",
							"signature": "sig2",
						},
					},
				},
			},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewTransparencyClient(
		WithBaseURL(server.URL),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	params := &models.AgentAuditParams{Limit: 10}
	result, err := client.GetAgentTransparencyLogAudit(ctx, "test-agent", params)
	if err != nil {
		t.Fatalf("GetAgentTransparencyLogAudit() error: %v", err)
	}

	if len(result.Records) != 3 {
		t.Fatalf("Expected 3 records, got %d", len(result.Records))
	}

	if !result.Records[0].IsV1() {
		t.Error("Expected first record to be V1")
	}
	if v1 := result.Records[0].GetV1Payload(); v1 == nil {
		t.Error("Expected V1 payload to be parsed")
	}

	if !result.Records[1].IsV2() {
		t.Error("Expected second record to be V2")
	}
	v2 := result.Records[1].GetV2Payload()
	if v2 == nil {
		t.Fatal("Expected V2 payload to be parsed")
	}
	if got := v2.Producer.Event.Attestations.ServerCerts; len(got) != 1 || got[0].Fingerprint != "v2-srv-fp" {
		t.Errorf("V2 ServerCerts mismatch: %+v", got)
	}
	if got := v2.Producer.Event.Attestations.DNSRecordsProvisioned; len(got) != 1 || got[0].Name != "_ans.test.com" {
		t.Errorf("V2 DNSRecordsProvisioned mismatch: %+v", got)
	}

	if !result.Records[2].IsV0() {
		t.Error("Expected third record to be V0")
	}
	if v0 := result.Records[2].GetV0Payload(); v0 == nil {
		t.Error("Expected V0 payload to be parsed")
	}
}

func TestTransparencyClient_ParameterValidation(t *testing.T) {
	client, err := NewTransparencyClient(WithBaseURL("http://localhost"))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "GetAgentTransparencyLog empty agentID",
			call: func() error { _, err := client.GetAgentTransparencyLog(ctx, ""); return err },
		},
		{
			name: "GetAgentTransparencyLogAudit empty agentID",
			call: func() error { _, err := client.GetAgentTransparencyLogAudit(ctx, "", nil); return err },
		},
		{
			name: "GetLogSchema empty version",
			call: func() error { _, err := client.GetLogSchema(ctx, ""); return err },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !errors.Is(err, models.ErrBadRequest) {
				t.Errorf("expected ErrBadRequest, got %v", err)
			}
		})
	}
}

// Helper function for string prefix matching
func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestDoRequestWithSchemaVersion_ErrorPaths(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr string
	}{
		{
			name: "invalid JSON response",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("not-json"))
			},
			wantErr: "failed to parse response",
		},
		{
			name: "schema version from header when missing in body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Schema-Version", "V1")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]any{
					"status": "ACTIVE",
					"payload": map[string]any{
						"ansId":   "agent-1",
						"ansName": "ans://v1.0.0.host.com",
					},
				})
			},
		},
		{
			name: "response with empty payload",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]any{
					"status":        "ACTIVE",
					"schemaVersion": "V1",
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client, err := NewTransparencyClient(WithBaseURL(server.URL))
			if err != nil {
				t.Fatalf("NewTransparencyClient() error = %v", err)
			}

			ctx := context.Background()
			result, err := client.GetAgentTransparencyLog(ctx, "test-agent")
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if result == nil {
					t.Fatal("result is nil")
				}
			}
		})
	}
}

func TestDoRequestWithSchemaVersion_HTTPClientFailure(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "connection refused"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use a server that's been shut down to simulate connection failure
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			serverURL := server.URL
			server.Close() // Close immediately so connections fail

			client, err := NewTransparencyClient(WithBaseURL(serverURL))
			if err != nil {
				t.Fatalf("NewTransparencyClient() error = %v", err)
			}

			ctx := context.Background()
			_, err = client.GetAgentTransparencyLog(ctx, "test-agent")
			if err == nil {
				t.Fatal("expected error for connection failure")
			}
		})
	}
}
