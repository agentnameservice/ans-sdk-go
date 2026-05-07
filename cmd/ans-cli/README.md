# ANS CLI - Agent Name Service Command Line Tool

A command-line tool for interacting with the Agent Name Service (ANS). Use this tool to register agents, verify domain ownership, and search for registered agents.

## Installation

Five install options, in recommended order:

### Install with Homebrew (macOS / Linux)

```bash
brew install godaddy/ans/ans-cli
```

This auto-taps <https://github.com/godaddy/homebrew-ans> the first time you reference it. To upgrade later: `brew upgrade ans-cli`.

### Install with Scoop (Windows)

```powershell
scoop bucket add ans https://github.com/godaddy/scoop-ans
scoop install ans/ans-cli
```

To upgrade later: `scoop update ans-cli`.

### Download a release binary

Prebuilt binaries for linux, macOS, and Windows are published with each release.

- Browse releases: <https://github.com/godaddy/ans-sdk-go/releases/latest>
- Archive name pattern: `ans-cli_<version>_<os>_<arch>.tar.gz` (linux/darwin) or `ans-cli_<version>_windows_amd64.zip`
- Supported targets: `linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64`, `windows_amd64`
- Note: `windows_arm64` is **not** published — Windows ARM users should use `go install` or build from source.

#### macOS / Linux one-liner

```bash
VERSION=0.1.10
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -L "https://github.com/godaddy/ans-sdk-go/releases/download/v${VERSION}/ans-cli_${VERSION}_${OS}_${ARCH}.tar.gz" \
  | tar -xz ans-cli
sudo mv ans-cli /usr/local/bin/
ans-cli --version
```

#### Windows (amd64)

Most Windows users will prefer the Scoop install above. If you want the raw archive:

1. Download `ans-cli_<version>_windows_amd64.zip` from the [latest release](https://github.com/godaddy/ans-sdk-go/releases/latest).
2. Extract `ans-cli.exe` to a directory on your `%PATH%` (e.g., `C:\Tools\ans-cli\`).
3. Verify: `ans-cli.exe --version`

#### Verify the download against `checksums.txt`

Each release ships a `checksums.txt` of SHA-256 hashes. Download it alongside the archive, then:

- macOS: `shasum -a 256 -c checksums.txt --ignore-missing`
- Linux: `sha256sum -c checksums.txt --ignore-missing`
- Windows (PowerShell): `Get-FileHash -Algorithm SHA256 ans-cli_<version>_windows_amd64.zip` and compare the hash against the corresponding line in `checksums.txt`.

### Install with `go install`

If you have Go 1.25 or newer:

```bash
# Track the latest tag
go install github.com/godaddy/ans-sdk-go/cmd/ans-cli@latest

# Or pin to a specific release (recommended for reproducible installs)
go install github.com/godaddy/ans-sdk-go/cmd/ans-cli@v0.1.10
```

The binary lands in `$(go env GOBIN)`, falling back to `$(go env GOPATH)/bin`. Make sure that directory is on your `PATH`.

> **Heads up:** `go install` does not embed the version metadata that GoReleaser injects, so `ans-cli --version` will report the in-source defaults (`version: dev`, `commit: none`, `date: unknown`). Download a release archive if you need accurate build provenance.

### Build from source

For contributors and local testing:

```bash
cd cmd/ans-cli
go build -o ans-cli .
./ans-cli --version
```

The binary is written to the current directory.

## Configuration

The CLI can be configured using environment variables or command-line flags:

| Environment Variable | Flag | Description | Default |
|---------------------|------|-------------|---------|
| `ANS_API_KEY` | `--api-key` | API key for authentication | (required) |
| `ANS_BASE_URL` | `--base-url` | API base URL | `https://api.ote-godaddy.com` |
| N/A | `--verbose` / `-v` | Enable verbose output | `false` |
| N/A | `--json` / `-j` | Output in JSON format | `false` |

## Commands

### generate-csr

Generate RSA key pairs and Certificate Signing Requests (CSRs) for both identity and server certificates.

```bash
ans-cli generate-csr \
  --host myagent.example.com \
  --org "Example Corp" \
  --version 1.0.0 \
  --country US \
  --out-dir ./certs
```

**Flags:**
- `--host` (required): Agent host domain
- `--org` (required): Organization name
- `--version` (required): Agent version for ANS URI (e.g., 1.0.0)
- `--country`: Country code (default: US)
- `--out-dir`: Output directory (default: current directory)
- `--key-size`: RSA key size in bits (default: 2048)

**Output:**
- `identity.key` - Private key for identity certificate
- `identity.csr` - CSR for identity certificate
- `server.key` - Private key for server certificate
- `server.csr` - CSR for server certificate

### register

Register a new agent with the Agent Name Service.

```bash
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
  --function "analyze-sentiment:Sentiment Analysis:nlp,ml"
```

**Flags:**
- `--name` (required): Agent display name
- `--host` (required): Agent host domain
- `--version` (required): Agent version (semver format)
- `--identity-csr` (required): Path to identity CSR PEM file
- `--endpoint-url` (required): Agent endpoint URL
- `--description`: Agent description
- `--server-csr`: Path to server CSR PEM file
- `--server-cert`: Path to server certificate PEM file (BYOC)
- `--metadata-url`: Agent metadata URL (e.g., `/.well-known/agent-card.json`)
- `--endpoint-protocol`: Protocol (MCP, A2A, HTTP-API) (default: MCP)
- `--endpoint-transports`: Comma-separated list of transports (default: STREAMABLE-HTTP)
- `--function`: Agent function in format `id:name` or `id:name:tag1,tag2` (repeatable)

**Function Flag Format:**

The `--function` flag can be specified multiple times to declare the capabilities/operations your agent provides. Each function must include an ID and name, with optional tags for categorization:

```bash
# Basic format: id:name
--function "analyze-sentiment:Sentiment Analysis"

# With tags: id:name:tag1,tag2,tag3
--function "analyze-text:Text Analysis:nlp,ml,analytics"
```

**Function Constraints:**
- Function ID: Max 64 characters, must be unique
- Function Name: Max 64 characters
- Tags: Max 5 tags per function, max 20 characters per tag

**Example with functions:**
```bash
ans-cli register \
  --name "NLP Agent" \
  --host myagent.example.com \
  --version 1.0.0 \
  --identity-csr ./certs/identity.csr \
  --server-csr ./certs/server.csr \
  --endpoint-url https://myagent.example.com/api \
  --function "analyze-sentiment:Sentiment Analysis:nlp,ml" \
  --function "extract-entities:Entity Extraction:nlp,ner" \
  --function "summarize:Text Summarization:nlp"
```

### status

Get detailed status and information about a registered agent.

```bash
ans-cli status <agentId>
```

### verify-acme

Trigger ACME domain validation. Call this after placing the ACME challenge token.

```bash
ans-cli verify-acme <agentId>
```

### verify-dns

Verify that all required DNS records have been configured correctly.

```bash
ans-cli verify-dns <agentId>
```

### search

Search for registered agents using flexible criteria.

```bash
# Search by name
ans-cli search --name "Sentiment Analyzer"

# Search by host
ans-cli search --host myagent.example.com

# Search with pagination
ans-cli search --name "Analyzer" --limit 10 --offset 0
```

**Flags:**
- `--name`: Agent display name (partial matching)
- `--host`: Agent host domain (partial matching)
- `--version`: Agent version (flexible matching)
- `--limit`: Maximum number of results (default: 20, max: 100)
- `--offset`: Number of results to skip

### resolve

Resolve an agent by host and version pattern.

```bash
# Resolve any version
ans-cli resolve myagent.example.com

# Resolve specific version pattern
ans-cli resolve myagent.example.com --version "^1.0.0"

# Resolve exact version
ans-cli resolve myagent.example.com --version "2.1.0"
```

**Flags:**
- `--version` / `-V`: Version pattern to match (default: "*" for any)

**Version Patterns:**
- `*` - Match any version
- `1.0.0` - Exact version match
- `^1.0.0` - Compatible with 1.x.x (major fixed)
- `~1.2.3` - Compatible with 1.2.x (minor fixed)

### revoke

Revoke an agent registration.

```bash
# Revoke due to key compromise
ans-cli revoke <agentId> --reason KEY_COMPROMISE

# Revoke with comments
ans-cli revoke <agentId> --reason SUPERSEDED --comments "Replaced by v2.0.0"
```

**Flags:**
- `--reason` (required): Revocation reason
- `--comments`: Additional context for the revocation

**Valid Revocation Reasons:**
- `KEY_COMPROMISE` - Private key was compromised
- `CA_COMPROMISE` - Certificate authority was compromised
- `AFFILIATION_CHANGED` - Agent ownership/affiliation changed
- `SUPERSEDED` - Replaced by a newer agent version
- `CESSATION_OF_OPERATION` - Agent is no longer operational
- `CERTIFICATE_HOLD` - Temporarily suspended
- `PRIVILEGE_WITHDRAWN` - Authorization was revoked
- `AA_COMPROMISE` - Attribute authority was compromised
- `EXPIRED_CERT` - Certificate or credential has expired
- `REMOVE_FROM_CRL` - Remove a previously revoked certificate from the revocation list
- `UNSPECIFIED` - Revoked for an unspecified reason

### events

Retrieve paginated ANS events for monitoring and auditing.

```bash
# Get recent events
ans-cli events

# Get events with pagination
ans-cli events --limit 50 --last-log-id <cursor>

# Filter by provider
ans-cli events --provider-id <provider-id>
```

**Flags:**
- `--limit`: Maximum number of events (default: 20, max: 200)
- `--provider-id`: Filter events by provider ID
- `--last-log-id`: Cursor for pagination (use lastLogId from previous response)
- `--follow` / `-f`: Continuously poll for new events (Ctrl+C to stop)
- `--poll-interval`: Seconds between polls in follow mode (default: 5)

**Follow Mode Examples:**
```bash
# Continuously poll for new events
ans-cli events --follow

# Follow with custom poll interval (10 seconds)
ans-cli events --follow --poll-interval 10
```

### csr-status

Check the processing status of a Certificate Signing Request.

```bash
ans-cli csr-status <agentId> <csrId>
```

### submit-identity-csr

Submit a new identity CSR for certificate renewal or updates.

```bash
ans-cli submit-identity-csr <agentId> --csr-file ./new-identity.csr
```

**Flags:**
- `--csr-file` (required): Path to CSR PEM file

### submit-server-csr

Submit a new server CSR for certificate renewal or updates.

```bash
ans-cli submit-server-csr <agentId> --csr-file ./new-server.csr
```

**Flags:**
- `--csr-file` (required): Path to CSR PEM file

### get-identity-certs

List all identity certificates associated with an agent.

```bash
ans-cli get-identity-certs <agentId>
```

### get-server-certs

List all server certificates associated with an agent.

```bash
ans-cli get-server-certs <agentId>
```

### badge

Retrieve the transparency log entry for an agent.

```bash
# Get transparency log entry
ans-cli badge <agentId>

# Include audit trail
ans-cli badge <agentId> --audit

# Include log checkpoint
ans-cli badge <agentId> --checkpoint

# Get everything
ans-cli badge <agentId> --audit --checkpoint
```

**Flags:**
- `--audit`: Also retrieve audit trail
- `--checkpoint`: Also retrieve log checkpoint
- `--transparency-url`: Transparency log base URL (env: ANS_TRANSPARENCY_URL)

## Complete Registration Workflow

Here's a complete example of registering a new agent:

```bash
# 1. Generate CSRs
ans-cli generate-csr \
  --host myagent.example.com \
  --org "Example Corp" \
  --version 1.0.0 \
  --country US \
  --out-dir ./certs

# 2. Register the agent
ans-cli register \
  --name "My Agent" \
  --host myagent.example.com \
  --version 1.0.0 \
  --description "An AI agent" \
  --identity-csr ./certs/identity.csr \
  --server-csr ./certs/server.csr \
  --endpoint-url https://myagent.example.com/mcp \
  --metadata-url https://myagent.example.com/.well-known/agent-card.json \
  --function "analyze:Analyze Data:analytics,ml" \
  --function "predict:Make Predictions:ml,forecasting"

# Note the agentId from the response

# 3. Configure DNS TXT record with the challenge token
# (Follow instructions from the registration response)

# 4. Trigger ACME validation
ans-cli verify-acme <agentId>

# 5. Wait for certificates to be issued
ans-cli status <agentId>
# Repeat until status shows certificates are ready

# 6. Retrieve your certificates
ans-cli get-identity-certs <agentId>
ans-cli get-server-certs <agentId>
```

## JSON Output

All commands support JSON output for scripting and automation:

```bash
ans-cli status <agentId> --json
```

## Verbose Mode

Enable verbose output to see HTTP requests and responses:

```bash
ans-cli register --verbose ...
```

## Examples

### Search for agents by name
```bash
export ANS_API_KEY="your-api-key"
ans-cli search --name "Analyzer"
```

### Get agent status in JSON format
```bash
ans-cli status 550e8400-e29b-41d4-a716-446655440000 --json
```

### Register with environment variables
```bash
export ANS_API_KEY="your-api-key"
export ANS_BASE_URL="https://api.ote-godaddy.com"

ans-cli register \
  --name "My Agent" \
  --host myagent.example.com \
  --version 1.0.0 \
  --identity-csr ./certs/identity.csr \
  --server-csr ./certs/server.csr \
  --endpoint-url https://myagent.example.com/mcp
```

### Register with metadata URL
```bash
ans-cli register \
  --name "My Agent" \
  --host myagent.example.com \
  --version 1.0.0 \
  --identity-csr ./certs/identity.csr \
  --server-csr ./certs/server.csr \
  --endpoint-url https://myagent.example.com/mcp \
  --metadata-url https://myagent.example.com/.well-known/agent-card.json \
  --function "analyze:Analyze Data:analytics"
```

## Development

### Build
```bash
go build ./...
```

### Run tests
```bash
go test ./...
```

### Lint
```bash
golangci-lint run
```

## License

Copyright © GoDaddy
