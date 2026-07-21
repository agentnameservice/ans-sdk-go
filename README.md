# ANS CLI and Go SDK

A command-line tool and Go SDK for the Agent Name Service (ANS) Registry Authority and Transparency Log.

- **`ans-cli`** ([cmd/ans-cli](cmd/ans-cli)) — the fastest way to register, verify, and manage agents from a terminal. Most users start here.
- **Go SDK** (`github.com/agentnameservice/ans-sdk-go/ans`) — the library the CLI is built on. Embed it in Go services that need to register agents programmatically, verify agent badges, or query the Transparency Log.

## API Specification Reference

Both the CLI and the SDK target the published REST API:
- [View OpenAPI Spec — Human Readable](https://developer.godaddy.com/doc/endpoint/ans)
- [OpenAPI Spec — AI/Machine Readable](https://developer.godaddy.com/swagger/swagger_ans.json)

## CLI Quickstart

### Install

Top two options shown; see [cmd/ans-cli/README.md#installation](cmd/ans-cli/README.md#installation) for all five (release archive, `go install`, build from source).

```bash
# macOS / Linux
brew install agentnameservice/ans/ans-cli
```

```powershell
# Windows (PowerShell)
scoop bucket add ans https://github.com/agentnameservice/scoop-ans
scoop install ans/ans-cli
```

### Authenticate

```bash
export ANS_API_KEY="your-api-key"
export ANS_BASE_URL="https://api.ote-godaddy.com"   # OTE — use https://api.godaddy.com for production
```

Or authenticate with an OAuth 2.0 access token instead of an API key:

```bash
export ANS_OAUTH_TOKEN="your-oauth-token"
```

The API key remains the default path; when both are set, the OAuth token takes precedence.

### Register an agent (end-to-end)

```bash
# 1. Generate identity + server CSRs
ans-cli generate-csr \
  --host myagent.example.com \
  --org "Example Corp" \
  --version 1.0.0 \
  --out-dir ./certs

# 2. Register the agent — declare endpoint, transports, and functions with tags
ans-cli register \
  --name "My Agent" \
  --host myagent.example.com \
  --version 1.0.0 \
  --description "An AI agent that analyzes sentiment" \
  --identity-csr ./certs/identity.csr \
  --server-csr ./certs/server.csr \
  --endpoint-url https://myagent.example.com/mcp \
  --metadata-url https://myagent.example.com/.well-known/agent-card.json \
  --endpoint-protocol MCP \
  --endpoint-transports STREAMABLE-HTTP \
  --function "analyze-sentiment:Sentiment Analysis:nlp,ml" \
  --function "extract-entities:Entity Extraction:nlp,ner"

# Note the agentId from the response.

# 3. Place the DNS TXT record shown in the registration response.

# 4. Trigger ACME validation
ans-cli verify-acme <agentId>

# 5. Poll until certificates are ready
ans-cli status <agentId>

# 6. Retrieve your certificates
ans-cli get-identity-certs <agentId>
ans-cli get-server-certs <agentId>
```

### Other common commands

```bash
ans-cli search --name "My Agent"
ans-cli resolve myagent.example.com --version "^1.0.0"
ans-cli badge <agentId> --audit
ans-cli events --follow
ans-cli revoke <agentId> --reason SUPERSEDED --comments "Replaced by v2.0.0"
```

For full per-command flag references and additional workflows, see [cmd/ans-cli/README.md](cmd/ans-cli/README.md). For release-engineering / publishing the CLI, see [RELEASE.md](RELEASE.md).

## SDK Installation

```bash
go get github.com/agentnameservice/ans-sdk-go
```

## SDK Quick Start

### Registry Authority Client

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/agentnameservice/ans-sdk-go/ans"
    "github.com/agentnameservice/ans-sdk-go/models"
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
                AgentURL:    "https://my-agent.example.com/mcp",
                MetaDataURL: "https://my-agent.example.com/.well-known/agent-card.json",
                Protocol:    "MCP",
                Transports:  []string{"STREAMABLE-HTTP"},
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

    "github.com/agentnameservice/ans-sdk-go/ans"
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
- ✅ OAuth 2.0 Bearer Token (static via `WithBearerToken`, refreshable via `WithTokenSource`)
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
| `WithBearerToken(token string)` | Set a static OAuth 2.0 bearer token | `ans.WithBearerToken("your-oauth-token")` |
| `WithTokenSource(ts ans.TokenSource)` | Set a refreshable OAuth 2.0 token source | `ans.WithTokenSource(mySource)` |
| `WithTimeout(duration time.Duration)` | Set HTTP client timeout | `ans.WithTimeout(60 * time.Second)` |
| `WithVerbose(verbose bool)` | Enable verbose logging | `ans.WithVerbose(true)` |
| `WithHTTPClient(client *http.Client)` | Use custom HTTP client | `ans.WithHTTPClient(myClient)` |
| `WithAPIVersion(v ans.APIVersion)` | Select the RA API lane for agent lifecycle routes (`ans.APIVersionV1` default, `ans.APIVersionV2`) | `ans.WithAPIVersion(ans.APIVersionV2)` |

Auth options are last-wins: applying any of `WithJWT`, `WithAPIKey`, `WithBearerToken`, or `WithTokenSource` replaces the previously configured credential.

### API Versions and Discovery Profiles

`WithAPIVersion(ans.APIVersionV2)` routes the agent-lifecycle and certificate methods through the RA's V2 lane (`/v2/ans/agents/...`). The request/response shapes are identical to V1; the lane matters because **DNS discovery profiles** are a V2 feature: on V2 the `AgentRegistrationRequest.DiscoveryProfiles` field selects which DNS record families the RA asks the operator to publish (`models.DiscoveryProfileANSDNSAID` — RFC 9460 SVCB records, the server default — and/or `models.DiscoveryProfileANSTXT`, the legacy `_ans` TXT shape). The V1 lane ignores the field and always emits the ANS_TXT family. The equivalent CLI switches are `--api-version v2` (also `ANS_API_VERSION`) and `register --discovery-profiles ANS_DNSAID,ANS_TXT`.

### OAuth 2.0 Bearer Tokens

For a static access token, use `WithBearerToken` — every request sends `Authorization: Bearer <token>`:

```go
client, err := ans.NewClient(
    ans.WithBaseURL("https://api.godaddy.com"),
    ans.WithBearerToken(os.Getenv("ANS_OAUTH_TOKEN")),
)
```

For tokens that need refreshing, implement the SDK's small `TokenSource` interface. `Token` is called for each outgoing request, so implementations should cache and refresh proactively, must be safe for concurrent use, and must honor `ctx` cancellation — the client's `WithTimeout` does **not** bound the token fetch:

```go
type TokenSource interface {
    Token(ctx context.Context) (string, error)
}
```

The SDK deliberately has no `golang.org/x/oauth2` dependency. If you already use that package, a four-line adapter bridges it — and because `oauth2.Config`/`clientcredentials.Config` token sources wrap `ReuseTokenSource`, the adapter below caches automatically instead of hitting your identity provider on every call (avoid writing a source that fetches per request):

```go
type oauth2Adapter struct{ src oauth2.TokenSource }

func (a oauth2Adapter) Token(_ context.Context) (string, error) {
    t, err := a.src.Token()
    if err != nil {
        return "", err // never embed credentials or raw token-endpoint responses in errors
    }
    return t.AccessToken, nil
}

// x/oauth2 sources capture their context at construction and cannot honor the
// per-request ctx, so bound the token fetch here — otherwise a hung identity
// provider stalls every SDK call indefinitely.
srcCtx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Timeout: 10 * time.Second})
src := clientCredentialsConfig.TokenSource(srcCtx) // caching, auto-refreshing
client, err := ans.NewClient(ans.WithTokenSource(oauth2Adapter{src: src}))
```

Notes:

- Only use bearer tokens over `https` base URLs — RFC 6750 requires TLS, and a token sent over plain HTTP is trivially stolen and replayable.
- The SDK does not retry or refresh on `401`; sources should refresh ahead of expiry. A token revoked before expiry fails with `401` until the source refreshes.
- Failure signatures: an error from the token source is returned with the `failed to obtain bearer token` prefix; a source that returns an empty or malformed token fails with `models.ErrBadRequest`. In both cases no HTTP call is made. A server rejection is a `*models.ResponseError` with `StatusCode: 401`.
- `TransparencyClient` public endpoints (checkpoint, audit, schema) never send credentials; only `GetAgentTransparencyLog` authenticates when a credential is configured.

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
SearchAgents(ctx context.Context, opts ...ans.SearchOption) (*models.AgentSearchResponse, error)
```
Searches for agents using flexible criteria with pagination support. Filter
values are provided via functional options:

- `ans.WithSearchName(name)` — agent display name (partial match)
- `ans.WithSearchHost(host)` — agent host domain (partial match)
- `ans.WithSearchVersion(version)` — agent version (flexible match)
- `ans.WithSearchProtocol(models.AgentProtocolMCP)` — endpoint protocol
- `ans.WithSearchStatus(models.AgentStatusPendingDNS, ...)` — lifecycle status (multi-valued). Defaults to `ACTIVE` server-side when unset; pass `AgentStatusPendingDNS` to find registrations still completing DNS validation, or `AgentStatusAll` to include every state.
- `ans.WithSearchLimit(n)` / `ans.WithSearchOffset(n)` — pagination

Example — list every pending registration:

```go
result, err := client.SearchAgents(ctx,
    ans.WithSearchStatus(models.AgentStatusPendingDNS),
)
```

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

    "github.com/agentnameservice/ans-sdk-go/ans"
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
import "github.com/agentnameservice/ans-sdk-go/keygen"

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
    "github.com/agentnameservice/ans-sdk-go/models"
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
client.SearchAgents(ctx,
    ans.WithSearchName("Name with spaces"),
    ans.WithSearchHost("host.com"),
    ans.WithSearchVersion("1.0.0"),
    ans.WithSearchLimit(20),
)

// ❌ Wrong - don't pre-encode
client.SearchAgents(ctx, ans.WithSearchName(url.QueryEscape("Name with spaces")))
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on
how to get involved, including commit message conventions, code review process, and more.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
