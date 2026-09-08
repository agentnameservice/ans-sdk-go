package a2a_test

import (
	"encoding/json"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/ans/a2a"
)

// TestBuildRequest_Text verifies that a text message produces a well-formed
// JSON-RPC 2.0 envelope with the correct method, a non-empty id, and a single
// text Part with ROLE_USER role.
func TestBuildRequest_Text(t *testing.T) {
	req := a2a.BuildRequest("msg-1", "hello world")

	if req.JSONRPC != "2.0" {
		t.Errorf("JSONRPC = %q, want %q", req.JSONRPC, "2.0")
	}
	if req.Method != "SendMessage" {
		t.Errorf("Method = %q, want %q", req.Method, "SendMessage")
	}
	if req.ID == "" {
		t.Error("ID must not be empty")
	}

	msg := req.Params.Message
	if msg.MessageID != "msg-1" {
		t.Errorf("Message.messageId = %q, want %q", msg.MessageID, "msg-1")
	}
	if msg.Role != "ROLE_USER" {
		t.Errorf("Message.role = %q, want %q", msg.Role, "ROLE_USER")
	}
	if len(msg.Parts) != 1 {
		t.Fatalf("len(Parts) = %d, want 1", len(msg.Parts))
	}
	if msg.Parts[0].Text != "hello world" {
		t.Errorf("Parts[0].text = %q, want %q", msg.Parts[0].Text, "hello world")
	}
}

// TestBuildRequestWithParts verifies that a multi-part message builds the
// correct envelope, preserving part order and text values.
func TestBuildRequestWithParts(t *testing.T) {
	parts := []a2a.Part{
		{Text: "part one"},
		{Text: "part two"},
	}
	req := a2a.BuildRequestWithParts("msg-2", parts)

	if len(req.Params.Message.Parts) != 2 {
		t.Fatalf("len(Parts) = %d, want 2", len(req.Params.Message.Parts))
	}
	if req.Params.Message.Parts[0].Text != "part one" {
		t.Errorf("Parts[0].text = %q, want %q", req.Params.Message.Parts[0].Text, "part one")
	}
	if req.Params.Message.Parts[1].Text != "part two" {
		t.Errorf("Parts[1].text = %q, want %q", req.Params.Message.Parts[1].Text, "part two")
	}
}

// TestBuildRequest_EnvelopeRoundTrip marshals a request to JSON and back,
// confirming camelCase field names on the wire.
func TestBuildRequest_EnvelopeRoundTrip(t *testing.T) {
	req := a2a.BuildRequest("msg-3", "round trip")

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Verify camelCase on the wire.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal raw: %v", err)
	}
	for _, key := range []string{"jsonrpc", "method", "id", "params"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("envelope missing key %q in marshalled output", key)
		}
	}

	// Round-trip: decode params.message.messageId.
	var envelope struct {
		Params struct {
			Message struct {
				MessageID string `json:"messageId"`
			} `json:"message"`
		} `json:"params"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("Unmarshal envelope: %v", err)
	}
	if envelope.Params.Message.MessageID != "msg-3" {
		t.Errorf("decoded messageId = %q, want %q", envelope.Params.Message.MessageID, "msg-3")
	}
}

// TestParseResponse_SuccessTask verifies that a JSON-RPC success envelope
// whose result is a Task round-trips into a TaskResult with the correct
// state and a text convenience method.
func TestParseResponse_SuccessTask(t *testing.T) {
	const rawResp = `{
		"jsonrpc": "2.0",
		"id": "req-1",
		"result": {
			"id": "task-abc",
			"contextId": "ctx-xyz",
			"status": {
				"state": "TASK_STATE_COMPLETED"
			},
			"artifacts": [
				{
					"artifactId": "art-1",
					"parts": [
						{"text": "agent response text"}
					]
				}
			]
		}
	}`

	result, err := a2a.ParseResponse([]byte(rawResp))
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if result.Task == nil {
		t.Fatal("expected Task, got nil")
	}
	if result.Task.ID != "task-abc" {
		t.Errorf("Task.id = %q, want %q", result.Task.ID, "task-abc")
	}
	if result.Task.Status.State != "TASK_STATE_COMPLETED" {
		t.Errorf("Task.status.state = %q, want %q", result.Task.Status.State, "TASK_STATE_COMPLETED")
	}

	got := result.Task.Text()
	const want = "agent response text"
	if got != want {
		t.Errorf("Task.Text() = %q, want %q", got, want)
	}
}

// TestParseResponse_SuccessMessage verifies that a result that is a Message
// (not a Task) is parsed correctly.
func TestParseResponse_SuccessMessage(t *testing.T) {
	const rawResp = `{
		"jsonrpc": "2.0",
		"id": "req-2",
		"result": {
			"messageId": "msg-99",
			"role": "ROLE_AGENT",
			"parts": [{"text": "direct reply"}]
		}
	}`

	result, err := a2a.ParseResponse([]byte(rawResp))
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if result.Message == nil {
		t.Fatal("expected Message result, got nil")
	}
	if result.Message.MessageID != "msg-99" {
		t.Errorf("Message.messageId = %q, want %q", result.Message.MessageID, "msg-99")
	}
	if result.Message.Role != "ROLE_AGENT" {
		t.Errorf("Message.role = %q, want %q", result.Message.Role, "ROLE_AGENT")
	}
	if len(result.Message.Parts) != 1 || result.Message.Parts[0].Text != "direct reply" {
		t.Errorf("Message.parts unexpected: %+v", result.Message.Parts)
	}
}

// TestParseResponse_JSONRPCError verifies that a JSON-RPC error envelope is
// returned as an *a2a.RPCError with the correct code and message.
func TestParseResponse_JSONRPCError(t *testing.T) {
	const rawResp = `{
		"jsonrpc": "2.0",
		"id": "req-3",
		"error": {
			"code": -32001,
			"message": "Task not found"
		}
	}`

	_, err := a2a.ParseResponse([]byte(rawResp))
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var rpcErr *a2a.RPCError
	if !isRPCError(err, &rpcErr) {
		t.Fatalf("expected *a2a.RPCError, got %T: %v", err, err)
	}
	if rpcErr.Code != -32001 {
		t.Errorf("Code = %d, want -32001", rpcErr.Code)
	}
	if rpcErr.Message != "Task not found" {
		t.Errorf("Message = %q, want %q", rpcErr.Message, "Task not found")
	}
}

// TestParseResponse_MalformedJSON verifies that malformed JSON returns an error.
func TestParseResponse_MalformedJSON(t *testing.T) {
	_, err := a2a.ParseResponse([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

// TestParseResponse_Task_NoArtifacts verifies that Text() returns empty string
// when a task has no artifacts.
func TestParseResponse_Task_NoArtifacts(t *testing.T) {
	const rawResp = `{
		"jsonrpc": "2.0",
		"id": "req-4",
		"result": {
			"id": "task-empty",
			"status": {"state": "TASK_STATE_WORKING"}
		}
	}`

	result, err := a2a.ParseResponse([]byte(rawResp))
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if result.Task == nil {
		t.Fatal("expected Task, got nil")
	}
	if result.Task.Text() != "" {
		t.Errorf("Text() = %q, want empty for task with no artifacts", result.Task.Text())
	}
}

// isRPCError is a helper that avoids importing errors in the test file.
func isRPCError(err error, target **a2a.RPCError) bool {
	if rpcErr, ok := err.(*a2a.RPCError); ok { //nolint:errorlint // table test, shallow type assertion is correct here
		*target = rpcErr
		return true
	}
	return false
}
