# ANS Registry Go SDK

A comprehensive Go SDK for interacting with the Agent Name Service (ANS) Registry Authority and Transparency Log.


## API Specification Reference

The ANS Registry SDK is based off of the REST API. The spec is documented using the OpenAPI (Swagger) specification:
- [View OpenAPI Spec - Human Readable](https://developer.godaddy.com/doc/endpoint/ans)
- [OpenAPI Spec - AI/Machine Readable](https://developer.godaddy.com/swagger/swagger_ans.json)

## CLI Tool

A full-featured CLI for interacting with ANS is included in this repository. See [cmd/ans-cli](cmd/ans-cli) for installation and usage instructions.

## Installation

```bash
go get github.com/godaddy/ans-sdk-go
```

## Quick Start

### Registry Authority Client

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/godaddy/ans-sdk-go/ans"
    "github.com/godaddy/ans-sdk-go/models"
)

func main() {
    // Create a new Registry Authority client
    client, err := ans.NewClient(
        ans.WithBaseURL("https://api.godaddy.com"),
        ans.WithAPIKey("your-api-key", "your-api-secret"),
        ans.WithVerbose(true),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Register a new agent
    req := &models.AgentRegistrationRequest{
        AgentDisplayName: "My AI Agent",
        AgentHost:        "my-agent.example.com",
        AgentDescription: "An example AI agent",
        Version:          "1.0.0",
        IdentityCSRPEM:   string(identityCSR),
        Endpoints: []models.AgentEndpoint{
            {
                AgentURL:   "https://my-agent.example.com/mcp",
                Protocol:   "MCP",
                Transports: []string{"STREAMABLE-HTTP"},
                Functions: []models.AgentFunction{
                    {
                        ID:   "search",
                        Name: "Web Search",
                        Tags: []string{"search", "web", "retrieval"},
                    },
                    {
                        ID:   "summarize",
                        Name: "Text Summarizer",
                        Tags: []string{"nlp", "summarization", "text"},
                    },
                    {
                        ID:   "translate",
                        Name: "Language Translator",
                        Tags: []string{"nlp", "translation", "i18n"},
                    },
                },
            },
        },
    }

    ctx := context.Background()
    result, err := client.RegisterAgent(ctx, req)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Agent registered: %s (ID: %s)\n", result.ANSName, result.AgentID)
}
```

### Transparency Log Client

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/godaddy/ans-sdk-go/ans"
)

func main() {
    // Create a new Transparency Log client
    tlClient, err := ans.NewTransparencyClient(
        ans.WithBaseURL("https://transparency.ans.godaddy.com"),
        ans.WithVerbose(true),
    )
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Get transparency log entry
    logEntry, err := tlClient.GetAgentTransparencyLog(ctx, "agent-uuid-here")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %s\n", logEntry.Status)
    if logEntry.MerkleProof != nil {
        fmt.Printf("Tree Size: %d\n", logEntry.MerkleProof.TreeSize)
    }
}
```

## Features

### ✅ Implemented

#### Registry Authority Client (`ans.Client`)
- ✅ Agent Registration
- ✅ Agent Details Retrieval
- ✅ Agent Search
- ✅ Agent Resolution (by host + version pattern)
- ✅ Agent Revocation
- ✅ Certificate Management
  - ✅ Identity Certificate Retrieval
  - ✅ Server Certificate Retrieval
  - ✅ CSR Submission (Identity & Server)
  - ✅ CSR Status Checking
- ✅ ACME Challenge Verification
- ✅ DNS Record Verification
- ✅ Event Stream (Pagination + Follow mode)

#### Transparency Log Client (`ans.TransparencyClient`)
- ✅ Agent Transparency Log Retrieval
- ✅ Audit Trail Queries (Paginated)
- ✅ Log Checkpoint Retrieval
- ✅ Checkpoint History (Paginated)
- ✅ Log Schema Retrieval

#### Agent-to-Agent Client (`ans.AgentClient`)
- ✅ Badge-verified HTTP client
- ✅ GET/POST/PUT/DELETE with automatic verification
- ✅ JSON request/response helpers
- ✅ Configurable failure policies (fail-open/fail-closed)

#### Key Generation (`keygen` package)
- ✅ RSA key pair generation (2048+ bits)
- ✅ EC key pair generation (P-256, P-384, P-521)
- ✅ PEM encoding/decoding with optional encryption
- ✅ File I/O utilities

### Authentication Methods
- ✅ JWT Bearer Token
- ✅ API Key (Public gateway endpoints)
- ✅ Custom HTTP Client support

## Configuration

### Functional Options Pattern

The SDK uses the functional options pattern for flexible client configuration:

```go
client, err := ans.NewClient(
    ans.WithBaseURL("https://api.godaddy.com"),
    ans.WithJWT("your-jwt-token"),
    ans.WithTimeout(120 * time.Second),
    ans.WithVerbose(true),
    ans.WithHTTPClient(customHTTPClient),
)
```

### Available Options

| Option | Description | Example |
|--------|-------------|---------|
| `WithBaseURL(url string)` | Set the API base URL | `ans.WithBaseURL("https://api.godaddy.com")` |
| `WithJWT(token string)` | Set JWT authentication | `ans.WithJWT("eyJhbGciOi...")` |
| `WithAPIKey(key, secret string)` | Set API key authentication (public gateway) | `ans.WithAPIKey("key", "secret")` |
| `WithTimeout(duration time.Duration)` | Set HTTP client timeout | `ans.WithTimeout(60 * time.Second)` |
| `WithVerbose(verbose bool)` | Enable verbose logging | `ans.WithVerbose(true)` |
| `WithHTTPClient(client *http.Client)` | Use custom HTTP client | `ans.WithHTTPClient(myClient)` |

### Environment URLs

| Environment | Registry Authority | Transparency Log |
|-------------|-------------------|------------------|
| **Production** | `https://api.godaddy.com` | `https://transparency.ans.godaddy.com` |
| **OTE** | `https://api.ote-godaddy.com` | `https://transparency.ans.ote-godaddy.com` |

## API Reference

### Registry Authority Client Methods

All methods accept `context.Context` as the first parameter for cancellation and timeouts.

#### Agent Registration

```go
RegisterAgent(ctx context.Context, req *models.AgentRegistrationRequest) (*models.RegistrationPending, error)
```
Registers a new agent with the ANS Registry. Returns pending registration with challenges.

#### Agent Management

```go
GetAgentDetails(ctx context.Context, agentID string) (*models.AgentDetails, error)
```
Retrieves detailed information about a specific agent.

```go
SearchAgents(ctx context.Context, name, host, version string, limit, offset int) (*models.AgentSearchResponse, error)
```
Searches for agents using flexible criteria with pagination support.

#### Agent Resolution

```go
ResolveAgent(ctx context.Context, host, version string) (*models.AgentCapabilityResponse, error)
```
Resolves an agent by host and version pattern. Supports semver patterns: `*`, `^1.0.0`, `~1.2.3`.

#### Agent Revocation

```go
RevokeAgent(ctx context.Context, agentID string, reason models.RevocationReason, comments string) (*models.AgentRevocationResponse, error)
```
Revokes an agent registration with a specified reason.

#### Verification

```go
VerifyACME(ctx context.Context, agentID string) (*models.AgentStatus, error)
```
Triggers ACME challenge validation for an agent.

```go
VerifyDNS(ctx context.Context, agentID string) (*models.AgentStatus, error)
```
Verifies DNS records are configured correctly for an agent.

```go
GetChallengeDetails(ctx context.Context, agentID string) (*models.ChallengeDetails, error)
```
Retrieves ACME challenge details for an agent.

#### Certificate Management

```go
GetIdentityCertificates(ctx context.Context, agentID string) ([]models.CertificateResponse, error)
```
Retrieves all identity certificates for an agent.

```go
GetServerCertificates(ctx context.Context, agentID string) ([]models.CertificateResponse, error)
```
Retrieves all server certificates for an agent.

```go
SubmitIdentityCSR(ctx context.Context, agentID, csrPEM string) (*models.CsrSubmissionResponse, error)
```
Submits an identity certificate signing request.

```go
SubmitServerCSR(ctx context.Context, agentID, csrPEM string) (*models.CsrSubmissionResponse, error)
```
Submits a server certificate signing request.

```go
GetCSRStatus(ctx context.Context, agentID, csrID string) (*models.CsrStatusResponse, error)
```
Checks the status of a submitted CSR.

#### Events

```go
GetAgentEvents(ctx context.Context, limit int, providerID, lastLogID string) (*models.EventPageResponse, error)
```
Retrieves paginated agent events for monitoring and synchronization.

### Transparency Log Client Methods

#### Agent Transparency Log

```go
GetAgentTransparencyLog(ctx context.Context, agentID string) (*models.TransparencyLog, error)
```
Retrieves the current transparency log entry for an agent, including Merkle proof, payload, and status.

#### Audit Trail

```go
GetAgentTransparencyLogAudit(ctx context.Context, agentID string, params *models.AgentAuditParams) (*models.TransparencyLogAudit, error)
```
Retrieves a paginated list of transparency log records for an agent.

#### Log State

```go
GetCheckpoint(ctx context.Context) (*models.CheckpointResponse, error)
```
Retrieves the current checkpoint (state) of the Transparency Log.

```go
GetCheckpointHistory(ctx context.Context, params *models.CheckpointHistoryParams) (*models.CheckpointHistoryResponse, error)
```
Retrieves a paginated list of historical checkpoints with optional filtering.

#### Log Schema

```go
GetLogSchema(ctx context.Context, version string) (*models.JSONSchema, error)
```
Retrieves the JSON schema for a specific Transparency Log event schema version.

### Agent-to-Agent Client

The SDK provides a verified HTTP client for secure agent-to-agent communication:

```go
import (
    "context"
    "time"

    "github.com/godaddy/ans-sdk-go/ans"
)

// Create agent client with badge verification
agentClient := ans.NewAgentClient(
    ans.WithAgentClientTimeout(30 * time.Second),
    ans.WithAgentClientVerifyServer(true),
)

// Make verified requests
resp, err := agentClient.Get(ctx, "https://other-agent.example.com/api/data")
if err != nil {
    log.Fatal(err)
}
defer resp.Body.Close()

// JSON helpers
var result MyResponse
resp, err = agentClient.GetJSON(ctx, "https://other-agent.example.com/api/data", &result)
```

#### Agent Client Options

| Option | Description |
|--------|-------------|
| `WithAgentClientTimeout(d time.Duration)` | Set HTTP client timeout (default: 30s) |
| `WithAgentClientVerifyServer(bool)` | Enable/disable server certificate verification |
| `WithAgentClientFailurePolicy(policy)` | Set failure policy (`verify.FailClosed`, `verify.FailOpenWithCache`, or `verify.FailOpen`) |
| `WithAgentClientTLS(*tls.Config)` | Use custom TLS configuration |
| `WithAgentClientVerifierOptions(opts...)` | Pass custom `verify.Option` values (e.g., `verify.WithCacheConfig(...)`) |

> **Note:** When using `verify.FailOpenWithCache`, you must also provide a cache via `verify.WithCacheConfig(...)` in the verifier options. Without a cache, `FailOpenWithCache` behaves like `FailClosed`.

### Key Generation

The `keygen` package provides utilities for key generation:

```go
import "github.com/godaddy/ans-sdk-go/keygen"

// Generate RSA key pair
keyPair, err := keygen.GenerateRSAKeyPairWithPEM(2048, nil)
if err != nil {
    log.Fatal(err)
}

// Generate EC key pair (P-256)
ecKeyPair, err := keygen.GenerateECKeyPairWithPEM(keygen.CurveP256(), nil)
if err != nil {
    log.Fatal(err)
}

// Save to files
err = keyPair.WriteKeyPairToFiles("private.key", "public.pem")
```

## Error Handling

API errors are returned as `*models.ResponseError`, which provides the HTTP status code, API error code, message, and optional details:

```go
import (
    "errors"
    "net/http"
    "github.com/godaddy/ans-sdk-go/models"
)

result, err := client.GetAgentDetails(ctx, agentID)
if err != nil {
    var respErr *models.ResponseError
    if errors.As(err, &respErr) {
        switch respErr.StatusCode {
        case http.StatusNotFound:
            fmt.Println("Agent not found")
        case http.StatusUnauthorized:
            fmt.Println("Authentication failed")
        case http.StatusBadRequest:
            fmt.Printf("Invalid request: %s\n", respErr.Code)
        default:
            fmt.Printf("API error %d: %s\n", respErr.StatusCode, respErr.Message)
        }
    } else {
        fmt.Printf("Error: %v\n", err)
    }
}

## CLI Tool

The SDK includes a comprehensive CLI tool for interacting with ANS:

### Installation

```bash
cd cmd/ans-cli
go build -o ans-cli
./ans-cli --help
```

### Usage Examples

```bash
# Set authentication
export ANS_API_KEY="your-jwt-token"
export ANS_BASE_URL="https://api.godaddy.com"

# Register a new agent
ans-cli register \
  --name "My Agent" \
  --host "my-agent.example.com" \
  --version "1.0.0" \
  --identity-csr ./identity.csr \
  --endpoint-url "https://my-agent.example.com/api" \
  --metadata-url "https://my-agent.example.com/.well-known/agent-card.json"

# Search for agents
ans-cli search --name "My Agent"

# Resolve an agent by host
ans-cli resolve my-agent.example.com --version "^1.0.0"

# Get agent status
ans-cli status <agent-id>

# Verify ACME challenges
ans-cli verify-acme <agent-id>

# Revoke an agent
ans-cli revoke <agent-id> --reason SUPERSEDED --comments "Replaced by v2.0.0"

# Get transparency log badge
ans-cli badge <agentId> --audit

# Follow events in real-time
ans-cli events --follow
```

## Package Structure

```
ans-sdk-go/
├── go.mod                     # Module definition
├── README.md                  # This file
├── ans/                       # Main SDK package
│   ├── client.go             # Registry Authority client
│   ├── agent_client.go       # Agent-to-agent HTTP client
│   ├── transparency.go       # Transparency Log client
│   └── options.go            # Functional options
├── keygen/                    # Key generation utilities
│   └── keygen.go             # RSA/EC key generation
├── models/                    # Data models (importable)
│   ├── agent.go              # Agent-related models
│   ├── certificate.go        # Certificate models
│   ├── event.go              # Event models
│   ├── resolution.go         # Agent resolution models
│   ├── revocation.go         # Agent revocation models
│   ├── transparency.go       # Transparency Log models
│   └── error.go              # Error types & sentinel errors
├── verify/                    # Certificate verification
│   └── ...                   # Verification utilities
├── examples/                  # Usage examples
│   └── byoc/                 # BYOC registration example
└── cmd/
    └── ans-cli/              # CLI application
        ├── main.go
        ├── cmd/              # CLI commands
        └── internal/         # CLI-specific code
```

## Testing

Run tests with:
```bash
go test ./...
```

Run tests with coverage:
```bash
go test -cover -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

Run linting:
```bash
golangci-lint run ./...
```

## Best Practices

### Context Usage

Always pass `context.Context` to client methods for proper cancellation and timeout handling:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

result, err := client.RegisterAgent(ctx, req)
```

### Error Handling

Use `errors.As` to extract structured error details from API responses:

```go
agent, err := client.GetAgentDetails(ctx, agentID)
var respErr *models.ResponseError
if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
    return nil, fmt.Errorf("agent %s does not exist", agentID)
}
```

### URL Encoding

The SDK automatically handles URL encoding for query parameters and path segments. Don't encode values manually:

```go
// ✅ Correct - SDK handles encoding
client.SearchAgents(ctx, "Name with spaces", "host.com", "1.0.0", 20, 0)

// ❌ Wrong - don't pre-encode
client.SearchAgents(ctx, url.QueryEscape("Name with spaces"), ...)
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on
how to get involved, including commit message conventions, code review process, and more.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
