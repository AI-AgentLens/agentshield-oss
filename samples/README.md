# AgentShield MCP Samples

Two runnable demos showing AgentShield intercepting MCP tool calls in action.

---

## What is MCP and why does it matter?

Model Context Protocol (MCP) lets AI agents (Claude, Cursor, Windsurf, etc.) call
external tools — read files, run code, transfer tokens, query databases. Every one
of those tool calls is a potential attack surface: a compromised or misconfigured
MCP server can instruct an agent to exfiltrate credentials, write backdoors, or
drain a crypto wallet.

AgentShield sits between the AI agent and the MCP server, evaluating every tool call
before it reaches the server. Dangerous calls are blocked; suspicious ones are
audited; benign calls pass through transparently.

---

## The two samples

### `mcp-demo/` — Library integration test

**What it does**

Calls the AgentShield Go library directly in-process. No binary is involved.
Runs 15 curated attack scenarios through the proxy and prints a decision table.

**How it works**

```
demo-client (Go process)
    ├── mcp.NewProxy(...)       ← AgentShield library, called in-process
    └── demo-server subprocess  ← real MCP server receiving forwarded calls
```

**When to use it**

- Verifying that the policy engine and all interception layers work correctly
- CI regression testing
- Library integration (embedding AgentShield directly into a Go application)

**Who it is for**

Engineering teams evaluating the Go library API or building AgentShield into
their own Go services.

**Run it**

```bash
go run ./samples/mcp-demo/
```

---

### `cli-demo/` — End-to-end CLI deployment demo ✅ recommended for customer demos

**What it does**

Launches the `agentshield` binary as a stdio proxy — the exact same topology used
in production when installed into Cursor or Claude Desktop. Runs 7 attack scenarios
(one per interception layer) and prints live decisions.

**How it works**

```
demo-client (this program)
    │  stdin/stdout JSON-RPC
    ▼
agentshield mcp-proxy --mcp-policy demo.yaml -- demo-server   ← real binary
    │  stdin/stdout JSON-RPC
    ▼
demo-server (same server as mcp-demo)
```

This is identical to what happens after `agentshield setup mcp` rewrites an IDE
config:

```json
"command": "agentshield",
"args":    ["mcp-proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem"]
```

**When to use it**

- Customer demos: shows the real binary intercepting real JSON-RPC traffic
- Smoke-testing a freshly built binary before shipping
- Explaining the deployment model to a prospect

**Who it is for**

Sales engineers, prospects, and anyone who wants to see AgentShield working as a
deployed product rather than a library.

**Run it**

```bash
go run ./samples/cli-demo/
```

---

## What each interception layer catches

| # | Scenario | Layer | Expected |
|---|----------|-------|----------|
| 1 | `execute_command` (shell execution tool) | Blocked-tool list | 🔴 BLOCK |
| 2 | `write_file → /etc/passwd` | Policy rule (path match) | 🔴 BLOCK |
| 3 | `store_data` containing an SSH private key | Content scan | 🔴 BLOCK |
| 4 | `send_tokens` — 52,000,000 SOL transfer | Value limit guard | 🔴 BLOCK |
| 5 | `tools/list` with a poisoned tool description | Description scan | 🫥 HIDDEN |
| 6 | `resources/read file://~/.ssh/id_rsa` | Resource rule | 🔴 BLOCK |
| 7 | `get_weather` (benign call) | — | 🟡 AUDIT |

All decisions (including AUDIT) are written to `~/.agentshield/audit.jsonl`.

---

## Side-by-side comparison

| | `mcp-demo` | `cli-demo` |
|---|---|---|
| AgentShield binary invoked? | No — library in-process | **Yes** |
| Production topology? | No | **Yes** |
| Best for | Regression / library testing | Customer demos |
| Scenarios | 15 (comprehensive) | 7 (one per layer) |
| Audit log written? | Yes | Yes |
| Shows live proxy output? | No | **Yes** (stderr) |
