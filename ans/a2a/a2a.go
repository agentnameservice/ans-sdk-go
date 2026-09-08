// Package a2a provides A2A protocol primitives for building and parsing
// JSON-RPC 2.0 message/send requests and task results.
//
// The A2A specification uses ProtoJSON serialization conventions:
// camelCase field names and SCREAMING_SNAKE_CASE enum values.
// JSON-RPC method names follow the A2A method mapping table (§5.3):
// "SendMessage" for the send-message operation.
//
// This package handles only the A2A framing layer. Authentication,
// TLS, and badge verification are handled by [ans.AgentClient], which
// provides the underlying transport.
package a2a

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
)

// Part is a single content unit within a Message or Artifact.
// All fields are optional except that at least one content field (Text, URL,
// Filename) should be non-empty for the part to be meaningful.
// JSON field names follow ProtoJSON camelCase conventions (§5.5 of the A2A spec).
type Part struct {
	// Text is the string content of a text part.
	Text string `json:"text,omitempty"`
	// URL is a URL pointing to file content.
	URL string `json:"url,omitempty"`
	// Filename is an optional filename hint (e.g. "document.pdf").
	Filename string `json:"filename,omitempty"`
	// MediaType is the MIME type of the part content (e.g. "text/plain").
	MediaType string `json:"mediaType,omitempty"`
}

// Message is one unit of communication from client to agent, or agent to
// client, as defined in §4.1.4 of the A2A specification.
// JSON field names follow ProtoJSON camelCase conventions.
type Message struct {
	// MessageID is the unique identifier for this message, created by the sender.
	MessageID string `json:"messageId"`
	// ContextID optionally associates the message with a conversation context.
	ContextID string `json:"contextId,omitempty"`
	// TaskID optionally associates the message with an existing task.
	TaskID string `json:"taskId,omitempty"`
	// Role identifies the sender: "ROLE_USER" for client messages.
	Role string `json:"role"`
	// Parts holds the message content.
	Parts []Part `json:"parts"`
}

// SendMessageParams is the params object of a JSON-RPC message/send request.
// Only the required Message field is included; optional configuration and
// metadata are omitted for the minimal helper surface.
type SendMessageParams struct {
	// Message is the message to send to the agent.
	Message Message `json:"message"`
}

// Request is a JSON-RPC 2.0 request envelope for the A2A SendMessage method.
// Serialize this struct to JSON to obtain the wire payload.
type Request struct {
	// JSONRPC is always "2.0".
	JSONRPC string `json:"jsonrpc"`
	// Method is the JSON-RPC method name. For send-message it is "SendMessage".
	Method string `json:"method"`
	// Params holds the SendMessageParams.
	Params SendMessageParams `json:"params"`
	// ID is a unique request identifier (string form).
	ID string `json:"id"`
}

// TaskStatus holds the state of a task at a point in time.
type TaskStatus struct {
	// State is the lifecycle state, e.g. "TASK_STATE_COMPLETED" (SCREAMING_SNAKE_CASE).
	State string `json:"state"`
}

// Artifact is an output produced by an agent during a task.
type Artifact struct {
	// ArtifactID is the unique identifier for this artifact within the task.
	ArtifactID string `json:"artifactId"`
	// Name is an optional human-readable name.
	Name string `json:"name,omitempty"`
	// Description is an optional human-readable description.
	Description string `json:"description,omitempty"`
	// Parts holds the artifact content.
	Parts []Part `json:"parts"`
}

// Task is the core unit of action in the A2A protocol (§4.1.1).
// It carries a current status and any output artifacts.
type Task struct {
	// ID is the server-generated unique identifier for the task.
	ID string `json:"id"`
	// ContextID optionally links the task to a conversation context.
	ContextID string `json:"contextId,omitempty"`
	// Status is the current lifecycle status of the task.
	Status TaskStatus `json:"status"`
	// Artifacts holds any output artifacts produced by the task.
	Artifacts []Artifact `json:"artifacts,omitempty"`
	// History holds the interaction history for multi-turn tasks.
	History []Message `json:"history,omitempty"`
}

// Text returns a convenience concatenation of the text content from all Parts
// of the first Artifact in the task. Returns an empty string if the task has
// no artifacts or no text Parts.
func (t *Task) Text() string {
	if len(t.Artifacts) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, p := range t.Artifacts[0].Parts {
		sb.WriteString(p.Text)
	}
	return sb.String()
}

// TaskResult is returned by ParseResponse and carries either a Task or a
// Message result. Exactly one field is non-nil for a successful response.
type TaskResult struct {
	// Task is set when the agent returned a Task result.
	Task *Task
	// Message is set when the agent returned a direct Message result (simple interactions).
	Message *Message
}

// RPCError represents a JSON-RPC 2.0 error object returned by the remote agent.
// It implements the error interface.
type RPCError struct {
	// Code is the JSON-RPC error code. A2A-specific codes start at -32001.
	Code int `json:"code"`
	// Message is a short description of the error.
	Message string `json:"message"`
	// Data holds optional structured error detail.
	Data json.RawMessage `json:"data,omitempty"`
}

// Error implements the error interface.
func (e *RPCError) Error() string {
	return fmt.Sprintf("A2A JSON-RPC error %d: %s", e.Code, e.Message)
}

// BuildRequest constructs a JSON-RPC 2.0 SendMessage envelope for a plain
// text message. messageID should be a caller-supplied unique identifier for
// the message (e.g. a UUID); text is the message content.
//
// The request ID is generated from a random number. Callers needing a
// deterministic ID should use [BuildRequestWithParts] and set the ID field
// directly after construction.
func BuildRequest(messageID, text string) Request {
	return BuildRequestWithParts(messageID, []Part{{Text: text}})
}

// BuildRequestWithParts constructs a JSON-RPC 2.0 SendMessage envelope for a
// message composed of the provided Parts. messageID should be a caller-supplied
// unique identifier for the message.
func BuildRequestWithParts(messageID string, parts []Part) Request {
	return Request{
		JSONRPC: "2.0",
		Method:  "SendMessage",
		ID:      strconv.FormatUint(rand.Uint64(), 10), //nolint:gosec // request ID, not a secret
		Params: SendMessageParams{
			Message: Message{
				MessageID: messageID,
				Role:      "ROLE_USER",
				Parts:     parts,
			},
		},
	}
}

// rpcResponse is the wire shape of a JSON-RPC 2.0 response envelope.
// result is held as raw JSON so we can distinguish Task from Message after
// the top-level unmarshal.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *RPCError       `json:"error"`
}

// ParseResponse parses a JSON-RPC 2.0 response envelope from the agent.
// On a JSON-RPC error response it returns nil and a *RPCError. On success
// it decodes result as a Task (when the response contains an "id" field, which
// Tasks always have) or a Message (when it contains "messageId").
func ParseResponse(data []byte) (*TaskResult, error) {
	var envelope rpcResponse
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("a2a: decode response envelope: %w", err)
	}

	if envelope.Error != nil {
		return nil, envelope.Error
	}

	if envelope.Result == nil {
		return nil, errors.New("a2a: response contains neither result nor error")
	}

	// Probe for a Task vs. a Message: Tasks always have an "id" field;
	// Messages always have a "messageId" field. Check by partial unmarshal.
	var probe struct {
		ID        *json.RawMessage `json:"id"`
		MessageID *json.RawMessage `json:"messageId"`
	}
	if err := json.Unmarshal(envelope.Result, &probe); err != nil {
		return nil, fmt.Errorf("a2a: probe result type: %w", err)
	}

	if probe.MessageID != nil {
		var msg Message
		if err := json.Unmarshal(envelope.Result, &msg); err != nil {
			return nil, fmt.Errorf("a2a: decode Message result: %w", err)
		}
		return &TaskResult{Message: &msg}, nil
	}

	var task Task
	if err := json.Unmarshal(envelope.Result, &task); err != nil {
		return nil, fmt.Errorf("a2a: decode Task result: %w", err)
	}
	return &TaskResult{Task: &task}, nil
}
