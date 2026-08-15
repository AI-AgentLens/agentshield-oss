# shield-server — agentless evaluation (experimental)

`shield-server` exposes the AgentShield analyzer pipeline over HTTP so that
hosts **without an installed binary** can have their agents' actions
evaluated: the endpoint runs as a customer-VPC appliance (or hosted service),
and thin clients — a curl-based IDE hook, a CI wrapper, an LLM-gateway policy
callout — POST each shell command or MCP tool call and receive the same
verdict a local install would produce.

Status: **Phase 0 walking skeleton** (issue #3315). Optional artifact — it is
not built by `make build`, not installed by `agentshield setup`, and not part
of releases. Later phases are trigger-gated on real customer pull; see the
issue for the phase plan and the decoupling contract.

Like every AgentShield surface, this server **evaluates and never executes**.

## Build & run

```bash
make build-server                 # → ./build/shield-server
./build/shield-server             # listens on 127.0.0.1:8383, no auth (loopback only)

# Non-loopback requires a bearer token — the server refuses to start otherwise:
AGENTSHIELD_SERVER_TOKEN=$(openssl rand -hex 32) ./build/shield-server --addr 0.0.0.0:8383
```

Flags: `--addr`, `--policy` (shell policy override; skips disk packs, same
semantics as `agentshield check --policy`, #3030), `--mcp-policy`, `--log`,
`--mode enforce|audit-only`, `--token`, `--version`.

Policy resolution matches a local install: embedded community packs always
apply; `~/.agentshield/packs` and `~/.agentshield/mcp-packs` (premium / custom)
layer on top. TLS is out of scope — run a reverse proxy in front.

## API

### `POST /v1/evaluate`

Exactly one of `command` (shell surface) or `tool_name` (MCP surface) per
request. The schema is versioned and changes are additive-only — this is the
contract every thin client builds against.

```json
{
  "command": "ls -la",            // shell path (mutually exclusive with tool_name)
  "cwd": "/repo",
  "tool_name": "read_file",       // MCP path
  "arguments": {"path": "/workspace/project/README.md"},
  "session_id": "s-123",          // identity plane — carried from day one
  "agent_id": "claude-code",
  "principal": "dev@example.com",
  "source": "ci"
}
```

Response:

```json
{
  "decision": "ALLOW | AUDIT | BLOCK | REQUIRE_APPROVAL",
  "rules": ["rule-id"],
  "reasons": ["…"],
  "taxonomy": ["kingdom/subcategory/specific"],
  "original_decision": "BLOCK",   // present only on audit-only downgrade
  "remediation": "…",
  "mode": "enforce",
  "degraded": false,              // true when any pack failed to load
  "session_id": "s-123"
}
```

`taxonomy` is the first hop of the fusion chain (decision → taxonomy node →
compliance control → attestation receipt); the test suite asserts a BLOCK
carries refs. Evaluations are appended to the audit log (hash-chained
`audit.jsonl`) with `session_id` / `principal` / `source` attribution.

Per-`session_id` MCP call history feeds sequence rules server-side — one
tracker per session, unlike the in-process HTTP proxy's shared history.
Shell `stateful.chain` rules need no cross-call state (they match within one
compound command), so shell evaluation is fully stateless.

### `GET /healthz`

Unauthenticated. Reports `status`, `version`, `mode`, `degraded`, and any
failed pack paths — a degraded ruleset is visible, never silent.

## Hooking up Claude Code / Codex CLI — no binary on the host

`clients/agentshield-remote-hook.py` is the thin client (Python stdlib only).
It speaks the same PreToolUse stdin/exit-code contract as `agentshield hook`
— same block messages, same exit codes — but gets its verdict from
shield-server over HTTP. Codex CLI sends the same payload shape as Claude
Code, so one client covers both.

On each endpoint, register it as the `PreToolUse` hook (Claude Code
`settings.json`; Codex needs its one-time `/hooks` approval as usual):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {"type": "command", "command": "python3 /path/to/clients/agentshield-remote-hook.py"}
        ]
      }
    ]
  }
}
```

Client configuration (environment, e.g. in the hook entry's `env` or the
shell profile):

| Variable | Default | Meaning |
|---|---|---|
| `AGENTSHIELD_SERVER_URL` | `http://127.0.0.1:8383` | shield-server base URL |
| `AGENTSHIELD_SERVER_TOKEN` | — | bearer token, when the server requires one |
| `AGENTSHIELD_REMOTE_TIMEOUT_SECONDS` | `5` | per-evaluation HTTP timeout |
| `AGENTSHIELD_REMOTE_FAIL_CLOSED` | off | `1` = block when the server is unreachable (default fail-open, matching the local hook) |

Behavior mapping (kept in lock-step with `internal/cli/hook.go`):
`Bash` tool calls go to the shell surface; every other tool call goes to the
MCP surface. BLOCK → exit 2 with the standard block message on stderr;
ALLOW/AUDIT → exit 0, with genuine MCP AUDITs surfaced on stderr and
audit-only-mode downgrades kept silent (#1952 semantics).

**The contract is integration-tested**, not assumed:
`cmd/shield-server/hook_client_integration_test.go` execs the real script
against the real server with real payload shapes — benign/destructive Bash,
Codex `turn_id` variant, MCP credential read, bearer-token auth, fail-open
and fail-closed with the server down. `go test -run TestRemoteHook
./cmd/shield-server/` runs it in ~5s; CI picks it up via `./cmd/...`.

Manual live check on a scratch project:

```bash
./build/shield-server &                                   # terminal 1
# terminal 2: add the hook JSON above to <scratch>/.claude/settings.json,
# start a Claude Code session there, ask it to run any command, and watch
# ~/.agentshield/audit.jsonl gain source="claude-code-remote-hook" events.
```

## Security model (Phase 0)

- **Loopback by default.** Non-loopback binding requires a static bearer
  token (`Authorization: Bearer …`, constant-time compare).
- **Fail-safe, not fail-closed.** Pack load failures degrade to warnings +
  `degraded: true`; managed-mode fail-closed semantics arrive with Phase 1.
- Command text is sensitive: deploy in the customer's VPC when the commands
  themselves must not leave the org.

## Tests

```bash
go test -race ./cmd/shield-server/     # ~5s — do NOT run the full repo suite for this
```
