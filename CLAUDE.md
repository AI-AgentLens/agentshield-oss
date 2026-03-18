# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
make build        # Build binary to ./build/agentshield
make test         # Run all tests (go test -v ./...)
make lint         # Run golangci-lint
make lint-fix     # Run linter with auto-fix
make check        # Full pre-commit check: lint-fix + test + build
make run ARGS="run -- echo hi"  # Build and run with arguments
make install      # Install to /usr/local/bin

# Run a single package's tests
go test -v ./internal/analyzer/...

# Run a specific test
go test -v -run TestAccuracy ./internal/analyzer/

# Regenerate failing tests report
go test -v -run TestGenerateFailingTestsReport ./internal/analyzer/
```

Go 1.23+ is required. Dependencies: `github.com/spf13/cobra` (CLI), `gopkg.in/yaml.v3` (config), `mvdan.cc/sh/v3` (shell AST parsing).

## Code Style

See global rules in `~/.claude/CLAUDE.md` for the Fowler philosophy and Go standards. Project-specific additions:

- **Test before fix**: When closing a false negative, add the failing test case first, then write the fix
- **Known gaps**: Mark test cases with `KnownGap: true` — never leave unexplained failures
- **Confidence scores**: Always set on `Finding`; default to 0.85 if uncertain
- **Fail safe**: Policy evaluation must never panic — return the default decision (AUDIT) on any error
- **Accuracy test caveat**: The accuracy test runner passes `nil` for paths (`engine.Evaluate(tc.Command, nil)`), so `protected_paths` checks are not exercised by tests — use structural/regex rules to cover those cases in tests

## Architecture Overview

AgentShield is a **local-first runtime security gateway** that sits between AI agents (Cursor, Windsurf, Claude Code, etc.) and the OS, evaluating every shell command through a 6-layer analyzer pipeline before execution. It also mediates MCP (Model Context Protocol) tool calls.

### 6-Layer Analyzer Pipeline

Defined in `internal/policy/pipeline.go` and `internal/analyzer/`. The pipeline runs in order:

```
regex → structural → semantic → dataflow → stateful → guardian
  ↓         ↓           ↓          ↓          ↓          ↓
           Combiner (most_restrictive_wins) → Policy Engine
```

1. **Regex** (`internal/analyzer/regex.go`) — Pattern matching (prefix, exact, regex). Catches obvious threats like `rm -rf /`, `curl | bash`.
2. **Structural** (`internal/analyzer/structural.go`) — Shell AST parsing via `mvdan.cc/sh`. Normalizes flags (catches `--recursive` as `-r`), detects pipes, handles sudo wrapping. Produces `ParsedCommand` in `AnalysisContext`.
3. **Semantic** (`internal/analyzer/semantic.go`) — Intent classification (file-delete, network-exfil, code-execute, etc.). Catches alternative destructive tools (`shred`, `wipefs`, `find -delete`). Produces `CommandIntent` slice.
4. **Dataflow** (`internal/analyzer/dataflow.go`) — Source→sink taint tracking through pipes/redirects. Catches exfiltration chains (`cat ~/.ssh/id_rsa | base64 | curl`).
5. **Stateful** (`internal/analyzer/stateful.go`) — Multi-step attack chain detection within compound commands connected by `&&`, `||`, `;`, `|`.
6. **Guardian** (`internal/guardian/`) — Heuristic-based detection: prompt injection, inline secrets, obfuscation, bulk exfiltration.

The `AnalysisContext` (`internal/analyzer/types.go`) carries enrichments through all layers — each analyzer reads from and writes to it. The Combiner uses `most_restrictive_wins`: `BLOCK > AUDIT > ALLOW`.

### Policy Engine

`internal/policy/engine.go` evaluates commands against policy rules. `BuildAnalyzerPipeline` in `pipeline.go` routes each YAML rule to the correct analyzer based on its `match` type. The policy engine falls back to regex-only if the pipeline is disabled. Default decision is `AUDIT`.

**Policy YAML schema** (`internal/policy/types.go`):
```yaml
version: "0.1"
defaults:
  decision: "AUDIT"
  protected_paths: ["~/.ssh/**", "~/.aws/**", "~/.gnupg/**", "~/.kube/**"]

rules:
  - id: "rule-id"
    taxonomy: "kingdom/subcategory/specific"
    match:
      command_regex: "..."           # → RegexAnalyzer
      structural:                    # → StructuralAnalyzer (AST-based)
        executable: ["rm", "unlink"]
        flags_all: ["r", "f"]
        args_any: ["/"]
      dataflow:                      # → DataflowAnalyzer
        source: {type: "credential"}
        sink: {type: "network"}
      semantic:                      # → SemanticAnalyzer
        intent_any: ["file-delete"]
        risk_min: "high"
      stateful:                      # → StatefulAnalyzer
        chain:
          - executable_any: ["curl", "wget"]
            operator: "&&"
          - executable_any: ["bash", "sh"]
    decision: "BLOCK"
    reason: "Human-readable explanation"
    confidence: 0.95
```

### MCP Mediation

`internal/mcp/` intercepts Model Context Protocol JSON-RPC calls (both stdio proxy in `proxy.go` and HTTP Streamable proxy in `http_proxy.go`). Key components:
- `handler.go` — Core JSON-RPC dispatch
- `description_scanner.go` — Detects tool description poisoning (hidden instructions, credential harvesting prompts)
- `content_scanner.go` — Scans tool call arguments for SSH keys, AWS credentials, base64 blobs
- `config_guard.go` — Guards config file writes from MCP tools
- `policy.go` — MCP-specific policy evaluation

### Test Infrastructure

Test cases live in `internal/analyzer/testdata/` organized by threat kingdom (credential_exposure, data_exfiltration, destructive_ops, persistence_evasion, privilege_escalation, reconnaissance, supply_chain, unauthorized_execution). `all_cases.go` aggregates them. Each case has an ID, command, expected decision, taxonomy ref, and optional `KnownGap` flag.

**Current status**: 1166 test cases, 99.7% recall, 2 known false negatives tracked in `FAILING_TESTS.md`. Known gaps:
- `while true; do bash & done` fork bomb (while-loop structural detection — requires AST loop analysis)

When adding new test cases, mark known gaps with the `KnownGap` field rather than leaving them as unexplained failures. Run `TestGenerateFailingTestsReport` to regenerate `FAILING_TESTS.md`.

### Rule Test Coverage Requirement

Every policy pack rule (in `packs/` and `packs/mcp/`) MUST have at least one:
- **True Positive (TP)** — malicious/risky command that the rule correctly flags (`BLOCK` or `AUDIT`). Use ID format `TP-<RULE-ID>-NNN`.
- **True Negative (TN)** — benign command that the rule correctly allows (`ALLOW`). Use ID format `TN-<RULE-ID>-NNN`.

Add test cases to the appropriate kingdom file under `internal/analyzer/testdata/`:

| Kingdom | File |
|---------|------|
| Destructive operations | `destructive_ops.go` |
| Credential exposure | `credential_exposure.go` |
| Data exfiltration | `data_exfiltration.go` |
| Persistence & evasion | `persistence_evasion.go` |
| Privilege escalation | `privilege_escalation.go` |
| Reconnaissance | `reconnaissance.go` |
| Supply chain | `supply_chain.go` |
| Unauthorized execution | `unauthorized_execution.go` |

Example:
```go
{
    ID:               "TP-TS-BLOCK-SHUTDOWN-001",
    Command:          "sudo shutdown -h now",
    ExpectedDecision: "BLOCK",
    TaxonomyRef:      "destructive-ops/system-management/system-shutdown",
    Analyzer:         "regex",
    Description:      "shutdown command — must be blocked",
    Tags:             []string{"tp", "destructive"},
},
{
    ID:               "TN-TS-BLOCK-SHUTDOWN-001",
    Command:          "systemctl status nginx",
    ExpectedDecision: "ALLOW",
    TaxonomyRef:      "destructive-ops/system-management/system-shutdown",
    Analyzer:         "regex",
    Description:      "read-only systemctl status — must be allowed",
    Tags:             []string{"tn", "safe"},
},
```

Run: `go test -v -run TestAccuracy ./internal/analyzer/`

### Enterprise Tamper Protection (`internal/enterprise/`)

Managed mode ensures AgentShield cannot be turned off by an AI agent. All enterprise logic lives in `internal/enterprise/` — core code has minimal coupling.

**Architecture: Middleware Chain**

`evaluateCommand()` in `hook.go` runs an `EvalMiddleware` chain before core policy evaluation. In non-managed mode the chain is empty (zero overhead). In managed mode (`~/.agentshield/managed.json` with `"managed": true`), the chain includes:

1. **BypassGuard** (pre-eval) — Ignores `AGENTSHIELD_BYPASS=1` env var
2. **SelfProtect** (pre-eval) — Blocks commands targeting AgentShield itself (6 hardcoded regex rules)

The chain uses a simple `func(ctx *EvalContext, next func())` pattern. To add new middleware:

```go
// In internal/enterprise/your_feature.go
func YourMiddleware(cfg *ManagedConfig) EvalMiddleware {
    return func(ctx *EvalContext, next func()) {
        // pre-eval logic
        next()
        // post-eval logic
    }
}

// Then add to buildMiddlewareChain() in hook.go:
chain = append(chain, enterprise.YourMiddleware(managedCfg))
```

**Key types:**
- `EvalContext` (`managed.go`) — Carries Command, Cwd, Source, Result, Blocked, BlockMsg, AuditEvent through the chain
- `EvalMiddleware` (`managed.go`) — `func(ctx *EvalContext, next func())`
- `ManagedConfig` (`types.go`) — Loaded from `~/.agentshield/managed.json`

**Enterprise files:**

| File | Purpose |
|------|---------|
| `types.go` | ManagedConfig, RemoteLog, WatchdogConf structs |
| `managed.go` | EvalContext, EvalMiddleware, RunChain, BypassGuard, SelfProtect |
| `failclosed.go` | FailClosed post-eval middleware |
| `remote_log.go` | Webhook forwarding (async, fire-and-forget with retry) |
| `watchdog.go` | Background watchdog service |
| `setup_guard.go` | CheckDisableAllowed + LoadManagedConfig/LoadManagedConfigFrom |

**Self-protection rules** (hardcoded in `managed.go`):

| ID | Blocks |
|----|--------|
| `sp-block-bypass-env` | `export AGENTSHIELD_BYPASS=1` |
| `sp-block-setup-disable` | `agentshield setup ... --disable` |
| `sp-block-delete-config` | `rm ... ~/.agentshield` |
| `sp-block-delete-hooks` | `rm ...settings.json` / `hooks.json` for any IDE |
| `sp-block-policy-write` | `echo > ~/.agentshield/policy.yaml` |
| `sp-block-binary-replace` | `cp /tmp/x .../agentshield` |

**Setup disable guard:** Each IDE's setup function calls `enterprise.CheckDisableAllowed()` before running its disable handler. In managed mode, this returns an error.

**Config loading:** `config.Load()` reads `managed.json` from `~/.agentshield/`. When managed, `--policy` and `--log` CLI flag overrides are ignored (always uses default paths).

### Logger Package (`internal/logger/`)

The logger package uses an interface pattern for pluggable backends:

| File | Purpose |
|------|---------|
| `logger.go` | `Logger` interface, `AuditLogger` (file backend), `AuditEvent` struct |
| `multi.go` | `MultiLogger` — fans out `Log()` to multiple backends |
| `syslog.go` | `SyslogLogger` — RFC 5424 syslog backend |
| `webhook.go` | `WebhookLogger` — HTTP POST backend (async with retry) |
| `integrity.go` | `ChainedEvent`, `ComputeEntryHash`, `ComputeChainedHash`, `VerifyChain` |

To add a new logger backend, implement `Logger` (Log + Close) and add it to `MultiLogger`.

### CLI Commands

Implemented in `internal/cli/` using Cobra. Key subcommands:
- `run` — Execute a command through the analyzer pipeline
- `setup` — Configure IDE hooks (Windsurf, Cursor, Claude Code, Gemini CLI, Codex)
- `setup-mcp` — Configure MCP proxy
- `mcp-proxy` — stdio MCP proxy mode
- `mcp-http-proxy` — HTTP Streamable MCP proxy mode
- `scan` — Self-test diagnostic (includes Tamper Protection section in managed mode)
- `pack` — Manage policy packs
- `log` — View audit logs
- `watchdog` — Background tamper detection (enterprise, requires managed mode)

### Policy Packs

`packs/` contains built-in YAML policy packs (terminal-safety, secrets-pii, network-egress, supply-chain). `internal/policy/pack.go` handles loading. Custom user config lives at `~/.agentshield/`.

### Taxonomy

`taxonomy/` contains 135 YAML entries organized by 8 kingdoms, each mapping to OWASP LLM Top 10 2025. `internal/taxonomy/` handles loading and compliance index generation.

## Automated Rule Generation

Rule requests can be submitted as GitHub issues using the "Rule Request" template. Labels track progress: `rule-request` → `in-progress` → `pr-ready` (or `needs-manual` on failure).

- **Manual**: `/project:new-rule <issue-url>` in Claude Code
- **Automated**: Desktop scheduled task runs hourly, processes new `rule-request` issues

See `.claude/commands/new-rule.md` for the full generation prompt.
