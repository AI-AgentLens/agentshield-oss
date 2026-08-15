#!/usr/bin/env python3
"""AgentShield remote hook — agentless thin client for Claude Code and Codex CLI.

Statement of purpose (point-of-coupling): this script is the "no binary on the
host" deployment mode (issue #3315 Phase 1). It speaks the same PreToolUse
stdin/exit-code contract as `agentshield hook` (internal/cli/hook.go — keep the
two in lock-step; the integration test in cmd/shield-server pins the contract),
but delegates the verdict to a shield-server over HTTP instead of evaluating
in-process. Python stdlib only — the entire point is that endpoints need
nothing installed beyond an interpreter they already have.

Harness support: Claude Code and Codex CLI (Codex sends the same PreToolUse
payload plus turn_id). Gemini CLI / Cursor / Windsurf dialects are NOT handled
here — use the local binary hook for those until a customer pulls them.

Configuration (environment):
  AGENTSHIELD_SERVER_URL              default http://127.0.0.1:8383
  AGENTSHIELD_SERVER_TOKEN            bearer token, if the server requires one
  AGENTSHIELD_REMOTE_TIMEOUT_SECONDS  default 5
  AGENTSHIELD_REMOTE_FAIL_CLOSED      "1" = block when the server is unreachable
                                      (default: fail open, matching the local
                                      hook's non-managed behavior)

Claude Code / Codex settings hook entry:
  {"type": "command", "command": "python3 /path/to/agentshield-remote-hook.py"}

Exit codes (the harness contract): 0 = allow / audit, 2 = block.
This client EVALUATES via the server and never executes anything.
"""

import getpass
import json
import os
import sys
import urllib.error
import urllib.request

BLOCK_EXIT = 2


def warn(msg: str) -> None:
    print(f"[AgentShield] warning: {msg}", file=sys.stderr)


def fail_open_or_closed(msg: str) -> int:
    """Server unreachable / unusable: mirror the local hook's fail-open default,
    with an explicit opt-in to fail closed for managed environments."""
    if os.environ.get("AGENTSHIELD_REMOTE_FAIL_CLOSED") == "1":
        print("\U0001F6E1️ AgentShield BLOCKED this action", file=sys.stderr)
        print(f"   Reason: shield-server unreachable and fail-closed is enabled ({msg})", file=sys.stderr)
        return BLOCK_EXIT
    warn(f"{msg} — allowing (fail open; set AGENTSHIELD_REMOTE_FAIL_CLOSED=1 to block instead)")
    return 0


def evaluate(request_body: dict) -> dict:
    url = os.environ.get("AGENTSHIELD_SERVER_URL", "http://127.0.0.1:8383").rstrip("/")
    timeout = float(os.environ.get("AGENTSHIELD_REMOTE_TIMEOUT_SECONDS", "5"))
    req = urllib.request.Request(
        url + "/v1/evaluate",
        data=json.dumps(request_body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    token = os.environ.get("AGENTSHIELD_SERVER_TOKEN", "")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def print_block(header: str, verdict: dict) -> None:
    # Same shape the local hook prints (hook.go) so developers see one format
    # regardless of deployment mode.
    print(header, file=sys.stderr)
    rules = verdict.get("rules") or []
    if rules:
        print(f"   Rule: {', '.join(rules)}", file=sys.stderr)
    for reason in verdict.get("reasons") or []:
        print(f"   Reason: {reason}", file=sys.stderr)
    remediation = verdict.get("remediation") or ""
    if remediation:
        print(remediation, file=sys.stderr, end="")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        warn(f"could not parse hook input: {e}")
        return 0  # fail open, mirroring the local hook

    if not isinstance(payload, dict) or not payload.get("hook_event_name"):
        return 0  # not a PreToolUse payload this client understands — pass through

    tool_name = payload.get("tool_name") or ""
    tool_input = payload.get("tool_input") or {}
    is_codex = bool(payload.get("turn_id"))

    identity = {
        "session_id": payload.get("session_id") or payload.get("trajectory_id") or "",
        "agent_id": "codex" if is_codex else "claude-code",
        "principal": getpass.getuser(),
        "source": "codex-remote-hook" if is_codex else "claude-code-remote-hook",
    }

    if tool_name == "Bash":
        command = tool_input.get("command") if isinstance(tool_input, dict) else ""
        if not command:
            return 0
        body = {"command": command, "cwd": payload.get("cwd") or os.getcwd(), **identity}
        try:
            verdict = evaluate(body)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError, TimeoutError) as e:
            return fail_open_or_closed(f"shield-server evaluation failed: {e}")
        if verdict.get("decision") == "BLOCK":
            print_block("\U0001F6E1️ AgentShield BLOCKED this command", verdict)
            return BLOCK_EXIT
        return 0

    # Every non-Bash tool goes through MCP policy, mirroring hook.go's
    # handleClaudeCodeMCPCall (tool_input becomes the arguments map).
    arguments = tool_input if isinstance(tool_input, dict) else {}
    body = {"tool_name": tool_name, "arguments": arguments, **identity}
    try:
        verdict = evaluate(body)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError, TimeoutError) as e:
        return fail_open_or_closed(f"shield-server evaluation failed: {e}")

    decision = verdict.get("decision")
    if decision == "BLOCK":
        print_block(f"\U0001F6E1️ AgentShield BLOCKED MCP tool call: {tool_name}", verdict)
        return BLOCK_EXIT
    if decision == "AUDIT" and not verdict.get("original_decision"):
        # Real AUDIT stays visible; audit-only-mode downgrades stay silent —
        # exactly the #1952 semantics the local hook implements.
        print(f"[AgentShield] AUDIT MCP tool: {tool_name}", file=sys.stderr)
        rules = verdict.get("rules") or []
        if rules:
            print(f"   Rule: {', '.join(rules)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
