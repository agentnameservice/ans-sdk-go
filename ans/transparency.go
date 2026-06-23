package ans

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/agentnameservice/ans-sdk-go/internal/httputility"
	"github.com/agentnameservice/ans-sdk-go/models"
)

// TransparencyClient represents an ANS Transparency Log API client
type TransparencyClient struct {
	config *clientConfig
}

// NewTransparencyClient creates a new Transparency Log API client with functional options
func NewTransparencyClient(opts ...Option) (*TransparencyClient, error) {
	cfg := defaultConfig()
	// Override default base URL for transparency log
	cfg.baseURL = "https://transparency.ans.godaddy.com"

	// Apply options (which may override the default)
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	return &TransparencyClient{
		config: cfg,
	}, nil
}

// doGet performs an HTTP GET request without authentication
func (c *TransparencyClient) doGet(ctx context.Context, path string, result any) error {
	httpCfg := &httputility.ClientConfig{
		BaseURL:    c.config.baseURL,
		HTTPClient: c.config.httpClient,
		AuthHeader: "", // Transparency log is public, no auth needed
	}
	return httputility.DoRequest(ctx, httpCfg, http.MethodGet, path, nil, result)
}

// GetAgentTransparencyLog retrieves the current Agent Transparency Log entry for an agent
func (c *TransparencyClient) GetAgentTransparencyLog(ctx context.Context, agentID string) (*models.TransparencyLog, error) {
	if err := validateRequired("agentID", agentID); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/v1/agents/%s", url.PathEscape(agentID))

	// Make request with custom handling for schema version header
	result, err := c.doRequestWithSchemaVersion(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// doRequestWithSchemaVersion performs an HTTP request and captures the schema version header
func (c *TransparencyClient) doRequestWithSchemaVersion(ctx context.Context, method, path string, body any) (*models.TransparencyLog, error) {
	// Prepare request body if needed
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	// Create request
	reqURL := c.config.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if c.config.authHeader != "" {
		req.Header.Set("Authorization", c.config.authHeader)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := c.config.httpClient.Do(req) //nolint:gosec // G704 - BaseURL from SDK config, paths use url.PathEscape
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body (limit to 10MB to prevent memory exhaustion)
	const maxResponseBodyBytes = 10 << 20
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for errors
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, httputility.HandleErrorResponse(resp.StatusCode, respBody)
	}

	// Parse base response
	var result models.TransparencyLog
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Get schema version from header if not in response body
	if result.SchemaVersion == "" {
		if schemaVersion := resp.Header.Get("X-Schema-Version"); schemaVersion != "" {
			result.SchemaVersion = schemaVersion
		}
	}

	// Parse payload based on schema version
	if result.Payload != nil {
		result.ParsedPayload = c.parsePayloadBySchema(result.Payload, result.SchemaVersion)
	}

	return &result, nil
}

// parsePayloadBySchema parses the payload into the appropriate schema version structure
func (c *TransparencyClient) parsePayloadBySchema(payload map[string]any, schemaVersion string) any {
	// Convert payload back to JSON for parsing
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		// If we can't marshal, return nil
		return nil
	}

	switch schemaVersion {
	case "V1":
		var v1 models.TransparencyLogV1
		if err := json.Unmarshal(payloadJSON, &v1); err == nil {
			return &v1
		}
	case "V0", "":
		// V0 is the default for missing schema version
		var v0 models.TransparencyLogV0
		if err := json.Unmarshal(payloadJSON, &v0); err == nil {
			return &v0
		}
	default:
		// Try V0 as fallback
		var v0 models.TransparencyLogV0
		if err := json.Unmarshal(payloadJSON, &v0); err == nil {
			return &v0
		}
	}

	// If parsing failed, return nil
	return nil
}

// GetAgentTransparencyLogAudit retrieves a paginated list of agent Transparency Log records
func (c *TransparencyClient) GetAgentTransparencyLogAudit(ctx context.Context, agentID string, params *models.AgentAuditParams) (*models.TransparencyLogAudit, error) {
	if err := validateRequired("agentID", agentID); err != nil {
		return nil, err
	}
	var result models.TransparencyLogAudit
	path := fmt.Sprintf("/v1/agents/%s/audit", url.PathEscape(agentID))

	// Build query parameters
	if params != nil {
		path = appendAuditParams(path, params)
	}

	err := c.doGet(ctx, path, &result)
	if err != nil {
		return nil, err
	}

	// Parse payloads for each record based on schema version
	for i := range result.Records {
		record := &result.Records[i]
		if record.Payload != nil {
			// Use schema version from individual record or fall back to V0
			schemaVersion := record.SchemaVersion
			if schemaVersion == "" {
				schemaVersion = "V0" // Default to V0 for backward compatibility
			}
			record.ParsedPayload = c.parsePayloadBySchema(record.Payload, schemaVersion)
		}
	}

	return &result, nil
}

// GetCheckpoint retrieves the current checkpoint for the transparency log
func (c *TransparencyClient) GetCheckpoint(ctx context.Context) (*models.CheckpointResponse, error) {
	var result models.CheckpointResponse
	err := c.doGet(ctx, "/v1/log/checkpoint", &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetCheckpointHistory retrieves a paginated list of checkpoints with optional filtering
func (c *TransparencyClient) GetCheckpointHistory(ctx context.Context, params *models.CheckpointHistoryParams) (*models.CheckpointHistoryResponse, error) {
	var result models.CheckpointHistoryResponse
	path := "/v1/log/checkpoint/history"

	// Build query parameters
	if params != nil {
		path = appendCheckpointHistoryParams(path, params)
	}

	err := c.doGet(ctx, path, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// GetLogSchema retrieves the JSON schema for a specific Transparency Log event schema version
func (c *TransparencyClient) GetLogSchema(ctx context.Context, version string) (*models.JSONSchema, error) {
	if err := validateRequired("version", version); err != nil {
		return nil, err
	}
	var result models.JSONSchema
	path := fmt.Sprintf("/v1/log/schema/%s", url.PathEscape(version))
	err := c.doGet(ctx, path, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// appendAuditParams appends audit query parameters to the path
func appendAuditParams(path string, params *models.AgentAuditParams) string {
	values := url.Values{}
	if params.Offset > 0 {
		values.Set("offset", strconv.Itoa(params.Offset))
	}
	if params.Limit > 0 {
		values.Set("limit", strconv.Itoa(params.Limit))
	}
	if len(values) > 0 {
		return path + "?" + values.Encode()
	}
	return path
}

// appendCheckpointHistoryParams appends checkpoint history query parameters to the path
func appendCheckpointHistoryParams(path string, params *models.CheckpointHistoryParams) string {
	values := url.Values{}
	if params.Limit > 0 {
		values.Set("limit", strconv.Itoa(params.Limit))
	}
	if params.Offset > 0 {
		values.Set("offset", strconv.Itoa(params.Offset))
	}
	if params.FromSize > 0 {
		values.Set("fromSize", strconv.FormatUint(params.FromSize, 10))
	}
	if params.ToSize > 0 {
		values.Set("toSize", strconv.FormatUint(params.ToSize, 10))
	}
	if params.Since != nil {
		values.Set("since", params.Since.Format(time.RFC3339))
	}
	if params.Order != "" {
		values.Set("order", params.Order)
	}
	if len(values) > 0 {
		return path + "?" + values.Encode()
	}
	return path
}
