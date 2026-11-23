<h1><img src="docs/logo.svg" alt="MCPGuard Logo" width="32" align="center" /> &nbsp;MCPGuard</h1>

**MCP (Model Context Protocol) & AI Tool-Use Security Auditor, Runtime JSON-RPC Firewall, and OWASP Compliance Platform**

![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![Wails](https://img.shields.io/badge/Wails-v2-DF0000?logo=go&logoColor=white)
![React](https://img.shields.io/badge/React-19%20%2B%20TypeScript-61DAFB?logo=react&logoColor=black)
![SQLite](https://img.shields.io/badge/SQLite-Pure%20Go-003B57?logo=sqlite&logoColor=white)
![AppSec](https://img.shields.io/badge/Focus-AI%20%26%20MCP%20Security-10B981)

**MCPGuard** is a cross-platform desktop application built with **Go** and **Wails** that audits, monitors, and enforces runtime security policies over **Model Context Protocol (MCP)** servers connected to AI coding agents and assistants (Claude Desktop, Cursor, Windsurf, VS Code, Cline, Roo Code, Claude Code, Zed, and Antigravity).

---

## Why MCPGuard?

Modern AI agents use MCP to read local files, execute shell commands, query databases, and send external requests. Traditional antivirus and network firewalls do not inspect **JSON-RPC 2.0 tool schemas or AI tool-use payloads**, leaving workstations exposed to emerging LLM/MCP threat classes:

- **Tool Poisoning & ASCII Smuggling**: Hidden `<IMPORTANT>` / `<SYSTEM>` directives or invisible Unicode characters embedded inside MCP tool descriptions that trick models into exfiltrating `~/.ssh/id_rsa`, `~/.aws/credentials`, or `.env`.
- **Rug Pull Attacks (Schema Drift)**: Legitimate MCP servers silently mutating their tool descriptions or adding covert tools *after* user approval.
- **Cross-Server Tool Shadowing**: Malicious servers registering colliding tool names or attempting to hijack invocations belonging to trusted servers.
- **Excessive Agency & Indirect Prompt Injection**: AI agents executing destructive shell commands or following injected instructions embedded inside untrusted tool outputs (emails, docs, webhooks).

**MCPGuard** addresses these risks across both **static posture auditing** and **real-time runtime enforcement**.

---

## Screenshots

| Security Posture Overview | Rug Pull Detection (SHA-256 Schema Drift) |
|---|---|
| ![Security Posture Overview](docs/screenshot-overview.png) | ![Rug Pull SHA-256 Diff](docs/screenshot-rugpull.png) |
| *Real-time posture score, severity distribution, server risk breakdown, and tool-poisoning findings.* | *Side-by-side SHA-256 drift diff catching mutated descriptions and covertly added tools.* |

| Runtime Firewall & HITL Approval Modal | OWASP LLM/MCP Compliance & Enterprise Reports |
|---|---|
| ![HITL Approval Modal](docs/screenshot-firewall-hitl.png) | ![OWASP Compliance & Reports](docs/screenshot-compliance.png) |
| *Real-time Human-in-the-Loop approval gate intercepting high-risk shell tool calls before execution.* | *OWASP LLM/MCP Matrix, 9-case Firewall Policy Coverage self-audit, and HTML/SARIF/Markdown exporters.* |

---

## System Architecture

```text
                       ┌─────────────────────────────────────────────┐
                       │    AI Clients (Claude / Cursor / VS Code)   │
                       └──────────┬───────────────────────┬──────────┘
                   stdio JSON-RPC │                       │ HTTP / SSE JSON-RPC
                                  ▼                       ▼
                    ┌──────────────────────────┐   ┌─────────────────────────────┐
                    │  mcpguard-proxy (Go CLI) │   │  HTTP/SSE Reverse Proxy     │
                    │  • Offline fail-closed   │   │  127.0.0.1:43772/mcp/<slug> │
                    │  • Zero-trust wrapper    │   └──────────────┬──────────────┘
                    └─────────────┬────────────┘                  │
                                  │ Loopback IPC (Bearer Auth)    │
                                  ▼                               ▼
                 ┌─────────────────────────────────────────────────────────────┐
                 │           MCPGuard Desktop App (Go + Wails v2)              │
                 │  ┌───────────────────┐  ┌────────────────────────────────┐  │
                 │  │ Static & Drift    │  │ Runtime Firewall Control Plane │  │
                 │  │ • Auto-Discovery  │  │ • YAML Policy Engine (RE2)     │  │
                 │  │ • Read-Only RPC   │  │ • HITL Approval Modal Gate     │  │
                 │  │ • Poisoning/UTF-8 │  │ • DLP Secret Redactor          │  │
                 │  │ • SHA-256 Drift   │  │ • Indirect Injection Guard     │  │
                 │  └─────────┬─────────┘  └───────────────┬────────────────┘  │
                 │            └──────────────┬─────────────┘                   │
                 │                           ▼                                 │
                 │   SQLite Store (Baselines, Policies, Traffic, Audit Logs)   │
                 │   Compliance Engine (OWASP Matrix) + SARIF/HTML/MD Exports  │
                 └───────────────────────────┬─────────────────────────────────┘
                                             ▼
                           [ Target Local & Remote MCP Servers ]
```

---

## Key Features

### 1. Static MCP Discovery, Poisoning & Rug-Pull Auditing
- **Multi-Client Config Auto-Discovery**: Automatically scans Claude Desktop, Cursor, Windsurf, VS Code, Cline, Roo Code, Claude Code, Antigravity, Zed, and user-added custom JSON/JSONC files.
- **Safe Read-Only Live MCP Inspection**: Performs read-only JSON-RPC 2.0 handshakes (`initialize` → `tools/list`, `resources/list`, `prompts/list`) over `stdio` and `HTTP/SSE` without ever invoking `tools/call`.
- **Tool Poisoning & Unicode Smuggling Detection**: Flags covert XML/HTML directive tags, stealth override phrases, sensitive credential file references, invisible Unicode characters (`\u200B`, BiDi overrides, Tag Block `U+E0000..U+E007F`), and suspicious Base64 blobs.
- **SHA-256 Baseline & Rug Pull Drift Detection**: Pins canonical SHA-256 tool fingerprints in SQLite and highlights `MODIFIED`, `ADDED`, or `REMOVED` tools with side-by-side description diffs.
- **Cross-Server Tool Shadowing & Supply-Chain Hygiene**: Detects colliding tool names, hardcoded API keys/tokens (automatically masked in UI), unpinned `npx`/`uvx`/Docker `:latest` runners, shell wrappers, and cleartext remote HTTP servers.

### 2. Runtime MCP Firewall, Policy Engine & HITL Gate
- **Standalone Stdio Proxy (`mcpguard-proxy`)**: Wraps local `stdio` MCP servers (`mcpguard-proxy --server <name> -- <cmd> [args...]`) with automatic offline fail-closed fallback if the desktop UI is closed.
- **1-Click Config Patcher**: Automatically backs up (`*.mcpguard.bak`) and wraps/unwraps local `stdio` server entries from the desktop UI.
- **Hot-Reload YAML Policy Engine**: First-match-wins ordered rules (`ALLOW`, `DENY`, `ASK`) with server/tool glob patterns and Go RE2 argument regexes.
- **Human-in-the-Loop (HITL) Desktop Modal**: Intercepts high-risk `tools/call` requests (shell execution, file deletion, outbound emails/webhooks) and prompts the user in real time to **Approve Once**, **Approve for Session**, or **Deny** (fail-closed on timeout).
- **DLP Secret Redaction & Indirect Prompt Injection Guard**: Automatically masks leaked API keys/tokens (OpenAI, Anthropic, GitHub, AWS, Slack, Google, JWT, PEM) and blocks indirect prompt injection payloads in tool responses.

### 3. HTTP/SSE Reverse Proxy, Compliance & Enterprise Reporting
- **HTTP / Streamable-HTTP / SSE Reverse Proxy**: Exposes local loopback routes (`http://127.0.0.1:43772/mcp/<slug>`) so remote MCP servers receive the exact same Policy, HITL, DLP, and Injection protections—complete with a 1-click **Loopback Self-Test**.
- **JSON Schema Hardening Auditor**: Statically checks tool `inputSchema` definitions for missing `pattern`/`enum`/`maxLength` bounds and permissive `additionalProperties`.
- **Firewall Policy Coverage Benchmark**: Self-audits your active YAML policy against 9 defensive test cases (`BM-01`–`BM-09`) to score policy coverage (`0–100%`).
- **OWASP LLM Top 10 & MCP Compliance Matrix**: Maps findings and safeguards to OWASP controls with an overall grade (`A`–`F`).
- **Enterprise Report Exporters**:
  - **Executive HTML Report** (self-contained, `@media print` PDF-ready)
  - **SARIF 2.1.0** (GitHub Code Scanning & CI/CD compatible)
  - **Markdown Summary** & **Structured JSON**

### 4. Built-In Demo Security Lab & Live Test Bench
Evaluate every detection and enforcement engine immediately—even without installing vulnerable local MCP servers:
- **Demo Security Lab**: Loads 4 realistic simulated MCP servers (Poisoned + Unicode smuggling, Rug Pull Simulator, Hardcoded Secrets + Shadowing, and Clean Hardened server) plus a 1-click **Simulate Rug Pull** trigger.
- **Interactive Firewall Test Bench**: Fires real test events through the live Control Plane to demonstrate Policy `DENY`, the real-time **HITL Approval Modal**, **DLP Secret Redaction**, and **Indirect Prompt Injection Blocking**.

---

## Detection Rule Catalog

| Rule ID | Category | Severity | OWASP / MCP Mapping | Description |
|---|---|---|---|---|
| `MCP-POI-001` | Tool Poisoning | CRITICAL | LLM01 / MCP01 | Hidden XML/HTML directive tags (`<IMPORTANT>`, `<SYSTEM>`) |
| `MCP-POI-002` | Tool Poisoning | CRITICAL | LLM01 / MCP01 | Stealth override directives (`do not tell the user`, `ignore previous`) |
| `MCP-POI-003` | Tool Poisoning | CRITICAL | LLM02 / MCP01 | Sensitive local file references (`~/.ssh`, `.aws`, `.env`, AI configs) |
| `MCP-POI-004` | Tool Poisoning | CRITICAL | LLM01 / MCP01 | Invisible Unicode / ASCII smuggling (`\u200B`, BiDi, Tag Block) |
| `MCP-POI-005` | Tool Poisoning | HIGH | LLM01 / MCP01 | Embedded shell/exfiltration directives (`curl`, `wget`, side-channel) |
| `MCP-POI-006` | Tool Poisoning | MEDIUM | MCP01 | Long obfuscated Base64 payload in tool metadata |
| `MCP-DRF-001` | Rug Pull / Drift | CRITICAL | MCP02 | Approved tool description or input schema mutated (SHA-256 mismatch) |
| `MCP-DRF-002` | Rug Pull / Drift | HIGH | MCP02 | Unapproved new tool silently added to a baselined server |
| `MCP-SHD-001` | Tool Shadowing | HIGH | MCP03 | Cross-server duplicate tool name collision |
| `MCP-SHD-002` | Tool Shadowing | CRITICAL | MCP03 | Cross-tool hijacking / redirection directive in description |
| `MCP-SEC-001` | Secrets Exposure | HIGH | LLM02 | Hardcoded API key, PAT, AWS key, JWT, or PEM private key in config |
| `MCP-SUP-001` | Supply Chain | MEDIUM | LLM03 | Unpinned `npx`, `uvx`, or Docker `:latest` MCP runner |
| `MCP-SUP-002` | Supply Chain | HIGH | LLM03 | Shell interpreter wrapper (`bash -c`, `cmd /c`) used as MCP entrypoint |
| `MCP-NET-001` | Transport Security | HIGH | MCP04 | Unencrypted `http://` transport for non-localhost remote MCP server |
| `MCP-CAP-001` | Excessive Agency | HIGH | LLM06 | Arbitrary command / shell execution capability |
| `MCP-VAL-001` | Schema Hardening | HIGH | LLM06 | Sensitive string parameter (`path`, `cmd`, `url`) lacks `pattern`/`enum` |
| `MCP-VAL-002` | Schema Hardening | LOW | LLM06 | Permissive `additionalProperties` enabling parameter smuggling |

---

## Sample Runtime Firewall Policy (YAML)

```yaml
version: "1.0"
defaultAction: ALLOW
dlpRedactSecrets: true
blockIndirectInjection: true
approvalTimeoutSec: 60

rules:
  - id: POL-001
    name: Block Sensitive Credential Paths
    enabled: true
    action: DENY
    severity: CRITICAL
    serverPattern: "*"
    toolPattern: "*"
    argRegex: '(?i)(~\/\.ssh|id_rsa|\.aws[\/\\]credentials|\/etc\/passwd|\.env\b)'
    reason: "Blocked attempt to access sensitive local credentials."

  - id: POL-003
    name: Require HITL Approval for Command / Shell Execution
    enabled: true
    action: ASK
    severity: HIGH
    serverPattern: "*"
    toolPattern: "*exec*,*shell*,*command*,*bash*,*terminal*"
    reason: "Shell execution requires explicit Human-in-the-Loop approval."
```

---

## Getting Started

### Prerequisites
- **Go 1.25+** (pure-Go SQLite via `modernc.org/sqlite` — no CGO required)
- **Node.js 18+** & **npm**
- **Wails CLI v2** (`go install github.com/wailsapp/wails/v2/cmd/wails@latest`)

### Run Unit Tests (9 Packages)
```bash
go test -v ./...
```

### Build Production Binaries
Build `mcpguard-proxy` alongside the main Wails desktop binary so 1-click **Protect via Proxy** detects it automatically:

```bash
# 1. Build standalone stdio firewall proxy CLI
go build -o build/bin/mcpguard-proxy.exe ./cmd/mcpguard-proxy   # Windows
# go build -o build/bin/mcpguard-proxy ./cmd/mcpguard-proxy     # macOS / Linux

# 2. Build Wails desktop application
wails build
```

### Run in Development Mode (Hot Reload)
```bash
wails dev
```

---

## Project Structure

```text
mcpguard/
├── main.go                     # Wails v2 desktop window entrypoint
├── app.go                      # Wails Go bindings & scan/firewall orchestrator
├── docs/
│   ├── logo.svg                # Compact vector logo for README
│   ├── screenshot-overview.png
│   ├── screenshot-rugpull.png
│   ├── screenshot-firewall-hitl.png
│   └── screenshot-compliance.png
├── cmd/
│   └── mcpguard-proxy/         # Standalone stdio JSON-RPC firewall proxy CLI
├── internal/
│   ├── model/                  # Shared domain models & audit result structs
│   ├── discovery/              # Multi-client MCP config discovery & secret masking
│   ├── mcpclient/              # Read-only JSON-RPC 2.0 inspector (stdio & HTTP/SSE)
│   ├── analyzer/               # Tool poisoning, drift, shadowing & supply-chain engine
│   ├── policy/                 # YAML policy engine, DLP redactor & injection guard
│   ├── firewall/               # Loopback IPC control plane & HITL approval broker
│   ├── httpproxy/              # HTTP / Streamable-HTTP / SSE reverse proxy firewall
│   ├── configpatch/            # 1-click stdio config wrapper/unwrapper with backup
│   ├── compliance/             # Schema hardening, policy benchmark & OWASP matrix
│   ├── reporter/               # SARIF 2.1.0, Executive HTML/PDF & Markdown exporters
│   ├── storage/                # Pure-Go SQLite persistence layer
│   └── demolab/                # Built-in vulnerable demo security lab
└── frontend/                   # React + TypeScript + Vite desktop UI
    └── src/
        ├── App.tsx             # Main desktop workspace & navigation
        ├── api.ts              # Typed Wails Go bridge & real-time event bindings
        └── components/         # FirewallView, HttpProxyView, PolicyView, ComplianceView, ApprovalModal
```

---

## Security & Design Principles
- **Strict Read-Only Static Inspection**: MCPGuard's live inspector only calls `initialize`, `tools/list`, `resources/list`, and `prompts/list`—never `tools/call`.
- **Fail-Closed Runtime Enforcement**: Timed-out HITL approvals and unreachable control-plane fallbacks default to `DENY` for gated tools.
- **Loopback-Only Authenticated IPC**: Local IPC binds strictly to `127.0.0.1` with a per-installation Bearer token stored with `0600` permissions.
- **Secret Hygiene**: Raw environment credentials discovered in MCP configs are never serialized to the frontend WebView—only masked previews are exposed.
