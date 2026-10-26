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

`--mode` is normalised exactly as `agentshield.yaml`'s `mode:` is: only the
exact values `enforce` and `audit-only` are recognised, and anything else
enforces with a startup warning and is reported as `"mode": "enforce"`
(#4356; before, the unrecognised string itself was reported). In
`audit-only` mode the downgrade applies to the final verdict, after every
block source including `value_limits`: a call enforce mode would block
answers `AUDIT` with `original_decision`, and with the same `rules`,
`reasons` and `taxonomy` enforce mode reports. The exception is
self-protection: a BLOCK that a self-protection rule decided, or a BLOCK on a
call or command that changes AgentShield's state or an agent's hook or MCP
configuration file (shell and MCP alike), is answered `BLOCK` in either mode,
exactly as enforce mode answers it, with no `original_decision`. A read of
those files is not a change and is answered `AUDIT`.

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

## Hooking up GitHub Copilot CLI on Windows — no binary, no Python

`clients/agentshield-remote-hook.ps1` is the PowerShell twin of the Python
client (#4244). A Windows host needs nothing installed: AgentShield releases
are darwin/linux only, and this client needs only PowerShell. It runs on
Windows PowerShell 5.1 and PowerShell 7+, and accepts both of Copilot CLI's
hook dialects:

- **Claude-compatible** (`"PreToolUse"`, PascalCase): snake_case
  `tool_name` / `tool_input`. Copilot maps its tools to Claude names, and
  **both `bash` and `powershell` arrive as `Bash`**, `view` as `Read`,
  `create` as `Write`. Recommended, since it is the same shape every other
  client handles.
- **native** (`"preToolUse"`, camelCase): `toolName` / `toolArgs` with
  runtime tool names (`bash`, `powershell`, `view`, `create`, ...).

Register it in `.github/hooks/agentshield.json` (repo) or
`%USERPROFILE%\.copilot\hooks\` (user):

```json
{
  "version": 1,
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "powershell": "pwsh -NoProfile -NonInteractive -File C:\\tools\\agentshield-remote-hook.ps1",
        "env": {"AGENTSHIELD_SERVER_URL": "https://shield.internal:8383"},
        "timeoutSec": 30
      }
    ]
  }
}
```

Use `-File`, not `-Command`: `-File` makes the script's `exit 2` the process
exit code. On a host with only Windows PowerShell, use
`powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ...`.

**Execution policy.** Windows PowerShell's default policy (`Restricted`)
refuses `.ps1` files, hence `-ExecutionPolicy Bypass` above.
PowerShell 7's default (`RemoteSigned`) refuses a script that still carries a
downloaded-from-the-internet mark. Run `Unblock-File` on the copied script once,
or sign it. Otherwise the hook errors on every call, and Copilot treats a hook
error as a deny.

For IT-managed rollout, the same entry can go in a **policy hook**
(`C:\ProgramData\GitHub\Copilot\policy.d\*.json` or
`HKLM\Software\Policies\GitHub\Copilot`). Policy hooks load before all others,
and developers cannot disable them with `disableAllHooks`.

**Verdict output, and why exit codes need care here.**
- BLOCK writes `{"permissionDecision":"deny","permissionDecisionReason":...}`
  to stdout, the block message to stderr, and exits 2. Copilot treats exit 2
  as a deny and shows the reason; Claude Code reads stderr on exit 2.
- ALLOW and AUDIT exit 0 with **empty stdout**.
- **Copilot DENIES on any other non-zero exit**, the opposite of Claude Code.
  So every failure path in the client (unparseable input, server down, HTTP
  error) ends in an explicit `exit 0` plus a stderr warning, unless
  `AGENTSHIELD_REMOTE_FAIL_CLOSED=1` asks for a block.
- A hook timeout is fail-open in Copilot.

Configuration: the same variables as the Python client, plus
`AGENTSHIELD_AGENT_ID`. It is the identity recorded on every verdict, defaults
to `copilot-cli` (`codex` when the payload carries `turn_id`), and should be
overridden when the client is used from another harness.
Set it in the hook entry's `env`, never in a shell profile: the local
`agentshield hook` honours the same variable (`agentshield setup copilot-cli`
writes it into Copilot's hook entry), so a global export would label every
harness's receipts, Claude Code's included, as the exported agent.

**Limitation (#4245).** The `powershell` tool's command text is evaluated by
the shell pipeline, whose analyzers parse POSIX shell. Most PowerShell attack
shapes get the default AUDIT: recorded, not blocked. File and MCP tool calls
are fully evaluated, Windows backslash paths included (#4243), subject to
#4248 (most credential rules match only MCP tool names).

**Tested.**
- **Integration suite:**
  - `cmd/shield-server/hook_client_pwsh_integration_test.go` runs the real
    script under `pwsh` against the real server, with both dialects;
  - it covers block/allow/MCP, token, fail-open/closed, pass-through
    warnings, identity, a UTF-8 round trip, and exit-code parity with the
    Python client;
  - it skips without `pwsh`, unless `AGENTSHIELD_REQUIRE_PWSH=1`, which
    turns a missing `pwsh` into a failure.
- **Windows PowerShell 5.1:** compatibility is checked statically with
  PSScriptAnalyzer's `UseCompatibleSyntax`, `UseCompatibleCommands` and
  `UseCompatibleTypes` against the `win-48 ... 5.1` profile (0 findings).
- **Not yet verified on a real Windows host or a live Copilot CLI session:**
  the 5.1 runtime itself, Windows console encodings, how Copilot spawns the
  hook, and Copilot's actual `toolArgs` names. The client warns on stderr
  when a shell tool call has no `command` argument instead of passing it
  silently.

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
AGENTSHIELD_REQUIRE_PWSH=1 go test -run TestPwshHook ./cmd/shield-server/   # PowerShell client; fails if pwsh is missing
```
