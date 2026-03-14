# AgentShield

**Local-first runtime security gateway for LLM coding agents.**

AI coding agents (Windsurf, Cursor, Claude Code, OpenClaw, etc.) execute shell commands with the developer's full permissions — access to `~/.ssh`, `~/.aws`, environment variables, and the entire filesystem. There is no enforcement layer between the LLM's decision and the operating system.

AgentShield is a deterministic policy gate that sits between the agent and the OS. Every shell command is evaluated through a 6-layer analyzer pipeline *before* execution. Dangerous commands are blocked. Safe commands pass through. Everything is logged.

AgentShield also mediates **MCP (Model Context Protocol) tool calls** — intercepting agent-to-server communication and blocking dangerous tool invocations before they reach the server.

This project is one attempt at the "complete mediation" pattern [recommended by OWASP](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) for mitigating Excessive Agency (LLM06) in LLM applications.

> **📝 Blog post:** [AI Agents Have Root Access to Your Machine — And Nobody's Watching](https://medium.com/@gzxuexi/ai-agents-have-root-access-to-your-machine-and-nobodys-watching-9965606176a4) — background research, real-world incidents, and OWASP alignment.
>
> **📝 Blog post:** [From rm -rf to $250K — Why Every AI Agent Needs a Policy Gate](https://medium.com/@gzxuexi/from-rm-rf-to-250k-why-every-ai-agent-needs-a-policy-gate-550c62459011) — the Lobstar Wilde incident: an AI agent sent 52,000,000 SOL instead of 4 because there was no numeric bound on the `amount` argument. AgentShield's value limits feature prevents this class of uncontrolled resource commitment.

## Install

```bash
brew tap security-researcher-ca/tap
brew install agentshield
```

<details><summary>Other install methods</summary>

```bash
# Build from source
make build && sudo make install

# Curl installer
curl -sSL https://raw.githubusercontent.com/security-researcher-ca/AI_Agent_Shield/main/scripts/install.sh | bash
```
</details>

## Quick Start

```bash
# Set up IDE hooks (one command per IDE)
agentshield setup claude-code  # Claude Code (PreToolUse hook — native)
agentshield setup windsurf     # Windsurf (Cascade Hooks)
agentshield setup cursor       # Cursor (Cursor Hooks)
agentshield setup openclaw     # OpenClaw (Agent Bootstrap Hook)

# Set up MCP proxy (wraps all detected MCP servers)
agentshield setup mcp

# Or view all options
agentshield setup
```

That's it — shell commands and MCP tool calls are both intercepted and evaluated automatically.

## How It Works

Every command passes through a **6-layer analyzer pipeline** before execution:

```
Agent: "cat ~/.ssh/id_rsa"
  → Unicode check → Normalize → Regex → Structural → Semantic
  → Dataflow → Stateful → Guardian → Policy Engine
  → Decision: BLOCK (protected path: ~/.ssh/**)
  → cat NEVER executes
```

| Decision | Behavior |
|----------|----------|
| **ALLOW** | Execute normally, log |
| **AUDIT** | Execute, flag for review |
| **BLOCK** | Reject — command never runs |

## Demo

```bash
$ agentshield run -- rm -rf /
🛑 BLOCKED by AgentShield — Destructive remove at filesystem root

$ agentshield run -- cat ~/.ssh/id_rsa
🛑 BLOCKED by AgentShield — Access to protected path: ~/.ssh/**

$ agentshield run -- ls -la
total 48
drwxr-xr-x  12 user  staff  384 ...    # executes normally
```

## IDE Integration

| IDE / Agent | Hook System | Setup | How it blocks |
|-------------|-------------|-------|---------------|
| **Claude Code** | PreToolUse hook (native) | `agentshield setup claude-code` | Exit code 2 |
| **Windsurf** | Cascade Hooks (`pre_run_command`) | `agentshield setup windsurf` | Exit code 2 |
| **Cursor** | Cursor Hooks (`beforeShellExecution`) | `agentshield setup cursor` | JSON `permission: deny` |
| **OpenClaw** | Agent Bootstrap Hook (`agent:bootstrap`) | `agentshield setup openclaw` | Exit code 1 via `agentshield run` |
| **LangChain / Custom** | CLI wrapping | `agentshield run -- <cmd>` | Exit code 1 |

<details><summary>Disable / Re-enable</summary>

```bash
# Remove hooks (permanent until re-enabled):
agentshield setup claude-code --disable
agentshield setup windsurf    --disable
agentshield setup cursor      --disable
agentshield setup openclaw    --disable

# Re-enable:
agentshield setup claude-code
agentshield setup windsurf
agentshield setup cursor
agentshield setup openclaw

# Quick session bypass (without removing hooks):
export AGENTSHIELD_BYPASS=1    # disable
unset AGENTSHIELD_BYPASS       # re-enable

# Note: in managed mode, --disable and AGENTSHIELD_BYPASS are both blocked.
# See "Enterprise Tamper Protection" below.
```
</details>

## Configuration

AgentShield uses `~/.agentshield/` for runtime data:

```
~/.agentshield/
├── audit.jsonl        # Audit log — auto-rotates at 10 MB (keeps 1 backup: audit.jsonl.1)
├── policy.yaml        # Custom policy (optional — built-in defaults apply without it)
├── mcp-policy.yaml    # MCP proxy policy (auto-created by setup mcp)
├── managed.json       # Enterprise managed mode config (optional — see Tamper Protection)
└── packs/             # Policy packs (installed via `agentshield setup --install`)
    ├── terminal-safety.yaml
    ├── secrets-pii.yaml
    ├── network-egress.yaml
    └── supply-chain.yaml
```

Built-in defaults protect `~/.ssh`, `~/.aws`, `~/.gnupg`, block `rm -rf /`, and audit package installs — no config file needed.

To **override defaults** or add custom rules, create `~/.agentshield/policy.yaml`:

```yaml
version: "0.1"
defaults:
  decision: "AUDIT"
  protected_paths:
    - "~/.ssh/**"
    - "~/.aws/**"
    - "~/my-company-secrets/**"    # add your own

rules:
  - id: block-production-db
    match:
      command_regex: "psql.*prod"
    decision: "BLOCK"
    reason: "Direct production database access is not allowed."
```

See the **[Policy Authoring Guide](docs/policy-guide.md)** for full rule syntax, analyzer layers, and examples.

## Security Highlights

- **6-layer analysis** — Regex, Structural (AST), Semantic, Dataflow, Stateful, Guardian
- **MCP tool call mediation** — intercepts `tools/call` and `resources/read` requests via both **stdio** and **Streamable HTTP** transports, blocks dangerous tool invocations and sensitive resource access ([details](docs/mcp-mediation.md#streamable-http-transport))
- **Tool description poisoning detection** — scans `tools/list` responses for hidden instructions, credential harvesting, exfiltration, and cross-tool shadowing ([details](docs/mcp-mediation.md#tool-description-poisoning-detection))
- **Argument content scanning** — detects SSH keys, AWS credentials, API tokens, .env contents, and large base64 blobs in MCP tool call arguments ([details](docs/mcp-mediation.md#argument-content-scanning))
- **Config file write protection** — blocks writes to IDE hooks, MCP configs, shell dotfiles, package manager configs, and AgentShield’s own policy files ([details](docs/mcp-mediation.md#config-file-write-protection))
- **Value limits on tool call arguments** — enforces numeric thresholds (max/min) on MCP tool call arguments to prevent uncontrolled resource commitment — e.g., [the Lobstar Wilde incident](https://medium.com/@gzxuexi/from-rm-rf-to-250k-why-every-ai-agent-needs-a-policy-gate-550c62459011) where an AI agent sent 52,000,000 SOL instead of 4, causing ~$250K in losses. AgentShield would have blocked this. ([details](docs/mcp-mediation.md#value-limits))
- **100% precision / 100% recall** across 123 shell threat test cases ([details](docs/accuracy.md))
- **24/24 MCP red-team cases** pass (blocked tools, credential access, system writes, evasion)
- **Protected paths** — `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`
- **Prompt injection detection** — instruction overrides, obfuscation, base64 payloads
- **Unicode smuggling detection** — homoglyphs, zero-width chars, bidi overrides
- **Automatic secret redaction** in audit logs
- **MCP policy packs** — 3 built-in packs (Safety, Secrets, Financial) installed by `agentshield setup mcp`, composable with custom packs ([details](docs/policy-guide.md#mcp-packs))
- **Fail-safe defaults** — unknown commands → AUDIT, not ALLOW
- **Enterprise tamper protection** — managed mode with self-protection rules, bypass immunity, fail-closed, hash-chained audit logs, remote log forwarding, and background watchdog ([details](#enterprise-tamper-protection))

## Enterprise Tamper Protection

For organizations that need to ensure AgentShield **cannot be turned off** by an AI agent, AgentShield supports a managed mode that closes the bypass vectors listed in [Known Limitations](#known-limitations).

### Enable Managed Mode

Create `~/.agentshield/managed.json`:

```json
{
  "managed": true,
  "organization_id": "acme-corp",
  "fail_closed": true,
  "remote_logging": {
    "webhook": {
      "url": "https://siem.example.com/ingest",
      "auth_header": "Bearer <token>"
    }
  },
  "watchdog": {
    "interval_seconds": 30,
    "alert_webhook": "https://alerts.example.com/tamper"
  }
}
```

### What Managed Mode Does

| Protection | Detail |
|-----------|--------|
| **Bypass immunity** | `AGENTSHIELD_BYPASS=1` is ignored — evaluation always runs |
| **Setup disable guard** | `agentshield setup <ide> --disable` is refused |
| **Self-protection rules** | Commands that delete config, overwrite the binary, remove hook files, or set bypass env vars are blocked (6 hardcoded regex rules) |
| **Fail-closed mode** | When `fail_closed: true`, policy errors block instead of allowing through |
| **CLI flag lockdown** | `--policy` and `--log` flag overrides are ignored — always uses default paths |
| **Hash-chained audit log** | SHA-256 chain on audit entries — tampering is detectable via `agentshield scan` |
| **Remote log forwarding** | Forward audit events to syslog (RFC 5424) and/or HTTP webhook |
| **Watchdog** | `agentshield watchdog` polls hook files, policy, managed.json, and env vars — alerts on tamper |

### Verify

```bash
agentshield scan   # shows Tamper Protection section in managed mode
```

```
─── Tamper Protection ─────────────────────────────────
  ✅ Managed mode:          active (org: acme-corp, fail_closed: on)
  ✅ AGENTSHIELD_BYPASS:    not set
  ✅ Policy file:           present and valid
  ✅ Self-protection rules: 6 rules active
  ✅ Hook integrity:        verified
  ✅ Audit chain:           verified (247 entries, no gaps)
```

## Known Limitations

AgentShield is a **user-space command wrapper**, not a kernel-level enforcement mechanism. Be aware of these boundaries:

| Limitation | Detail | Mitigation |
|-----------|--------|------------|
| **Agent can disable hooks** | An agent with shell access could run `agentshield setup --disable` or `export AGENTSHIELD_BYPASS=1`. | **Managed mode** blocks both vectors. |
| **Agent can tamper with audit logs** | `~/.agentshield/audit.jsonl` is a local file. An agent could delete or truncate it. | **Hash-chained logs** + **remote forwarding** detect and survive tampering. |
| **Agent can modify policy files** | Policy packs in `~/.agentshield/packs/` are user-writable YAML. | **Self-protection rules** block writes to policy files; managed mode ignores `--policy` overrides. |
| **Only intercepts routed commands** | Commands not routed through `agentshield run --` are not intercepted. If an agent bypasses the wrapper (e.g., direct syscall, spawning a child process outside the hook), AgentShield won't see it. | OS-level controls (macOS TCC, SELinux). |
| **Not a network firewall** | AgentShield analyzes command strings. It does not inspect network packets or block outbound connections at the OS level. | Combine with network firewalls. |
| **Not an LLM guardrail** | AgentShield does not filter prompts sent to models or inspect model outputs. It operates at the shell command and MCP tool call layers. | — |

These limitations are inherent to the user-space wrapper approach. Enterprise managed mode mitigates the first three. Remaining gaps require OS-level controls (e.g., macOS TCC, SELinux, network firewalls).

## Roadmap

AgentShield currently mediates **shell commands**. The threat surface for AI agents is broader. Planned and exploratory directions:

- **~~MCP communication mediation~~** ✅ — Intercept and evaluate [Model Context Protocol](https://modelcontextprotocol.io/) tool calls between agents and MCP servers via `agentshield mcp-proxy`. See [MCP Mediation docs](docs/mcp-mediation.md).
- **~~Remote audit log forwarding~~** ✅ — Forward audit events to syslog (RFC 5424) and HTTP webhooks. See [Enterprise Tamper Protection](#enterprise-tamper-protection).
- **~~Enterprise tamper protection~~** ✅ — Managed mode, self-protection rules, bypass immunity, fail-closed, hash-chained audit logs, watchdog. See [Enterprise Tamper Protection](#enterprise-tamper-protection).
- **File-write policy** — Evaluate file creation and modification operations (not just shell commands), especially writes to sensitive config files (`.cursor/mcp.json`, `.vscode/tasks.json`, crontabs).
- **OS-level enforcement** — Explore eBPF-based or sandbox-based approaches for commands that bypass the wrapper.
- **Policy-as-code CI integration** — Validate policy packs in CI pipelines, share them across teams via git.
- **Agent identity tagging** — Distinguish which agent (Windsurf, Cursor, OpenClaw) initiated a command for per-agent policy and audit.

Contributions and ideas are welcome — [open an issue](https://github.com/security-researcher-ca/AI_Agent_Shield/issues) or submit a PR.

## Integrate Any Agent

AgentShield works with any AI coding agent — not just the ones listed above. If you’re using a new IDE or building your own agent, the integration pattern is simple:

- **Shell commands:** route through `agentshield run -- <cmd>`
- **MCP servers:** wrap with `agentshield mcp-proxy` (stdio) or `agentshield mcp-http-proxy` (HTTP)

We provide a structured **[Agent Integration Guide](docs/agent-integration.md)** designed for both humans and code agents to follow. If your coding agent can read files and run shell commands, it can self-integrate with AgentShield by following the guide.

```bash
# Universal: any agent can verify integration with these two commands
agentshield run -- echo "test"      # should pass (ALLOW/AUDIT)
agentshield run -- rm -rf /          # should BLOCK
```

## Documentation

- [Policy Authoring Guide](docs/policy-guide.md) — Rule syntax, analyzer layers, custom packs, recipes
- [Architecture & Pipeline Details](docs/architecture.md)
- [MCP Mediation](docs/mcp-mediation.md) — MCP proxy, policy format, IDE setup
- [Agent Integration Guide](docs/agent-integration.md) — Structured spec for integrating AgentShield into any agent environment
- [Accuracy Baseline & Red-Team Results](docs/accuracy.md)
- [OWASP LLM Top 10 Compliance Mapping](compliance/indexes/owasp-llm-2025.md)

## Development

```bash
make build    # Build binary
make test     # Run tests
make lint     # Run linter
```

## License

Apache 2.0
