#!/usr/bin/env bash
# integration-test-setup.sh — Test IDE setup, hook routing, and disable cycle.
#
# Runs in a golang:alpine Docker container. Tests:
#   1. Build from source
#   2. Setup each IDE (creates config files)
#   3. Idempotent re-setup (no duplicates)
#   4. Hook payload routing (pipe stdin → agentshield hook → correct response)
#   5. Disable (clean removal, existing settings preserved)
#
# Usage:
#   ./scripts/integration-test-setup.sh
#
# Prerequisites:
#   - Docker installed and running

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== AgentShield Setup Integration Test ==="
echo "Source: $REPO_ROOT"
echo ""

# Stage a clean copy via git archive
STAGING=$(mktemp -d)
trap "rm -rf $STAGING" EXIT

echo "Staging repo content..."
git archive HEAD | tar -x -C "$STAGING"

# Write the inner test script to staging so it's available in the container
cat > "$STAGING/_run_tests.sh" << 'INNER_SCRIPT'
#!/bin/sh
# No set -e: we handle pass/fail explicitly in each test assertion.
# Only the build step uses explicit error checking.

PASS=0
FAIL=0
TESTS=""

pass() { PASS=$((PASS+1)); TESTS="$TESTS\n  PASS: $1"; echo "  ✅ $1"; }
fail() { FAIL=$((FAIL+1)); TESTS="$TESTS\n  FAIL: $1"; echo "  ❌ $1"; }

# Helper: pipe JSON to agentshield hook, capture exit code
hook_eval() {
    local json="$1"
    printf '%s' "$json" | agentshield hook > /tmp/_hook_stdout 2> /tmp/_hook_stderr
    echo $?
}

# --- Build ---
echo "=== [1/6] Build from source ==="
apk add --no-cache bash git > /dev/null 2>&1
cp -r /agentshield /tmp/agentshield
cd /tmp/agentshield
go build -o /usr/local/bin/agentshield ./cmd/agentshield || { echo "BUILD FAILED"; exit 1; }
echo "  Build: OK"

# Pre-create directories that IDEs would normally create
mkdir -p "$HOME/.claude" "$HOME/.codeium/windsurf" "$HOME/.cursor" \
         "$HOME/.gemini" "$HOME/.codex" "$HOME/.agentshield"
echo ""

# --- Claude Code setup ---
echo "=== [2/6] Claude Code setup ==="

# 2a: Setup into empty settings
mkdir -p "$HOME/.claude"
agentshield setup claude-code > /dev/null 2>&1 || true
if [ -f "$HOME/.claude/settings.json" ] && grep -q "agentshield hook" "$HOME/.claude/settings.json"; then
    pass "claude-code: hook installed"
else
    fail "claude-code: hook not found in settings.json"
fi

# 2b: Setup with pre-existing settings (must not destroy them)
cat > "$HOME/.claude/settings.json" <<SETTINGS
{
  "permissions": {
    "allow": ["Bash(git *)"]
  },
  "hooks": {
    "PostToolUse": [{"hooks": [{"type": "command", "command": "echo done"}]}]
  }
}
SETTINGS
agentshield setup claude-code > /dev/null 2>&1
if grep -q '"allow"' "$HOME/.claude/settings.json" && \
   grep -q "PostToolUse" "$HOME/.claude/settings.json" && \
   grep -q "agentshield hook" "$HOME/.claude/settings.json"; then
    pass "claude-code: merged without destroying existing settings"
else
    fail "claude-code: merge destroyed existing settings"
fi

# 2c: Idempotent re-run (no duplicate entries)
agentshield setup claude-code > /dev/null 2>&1
COUNT=$(grep -c "agentshield hook" "$HOME/.claude/settings.json")
if [ "$COUNT" -eq 1 ]; then
    pass "claude-code: idempotent (no duplicate)"
else
    fail "claude-code: duplicate entries ($COUNT found)"
fi

# 2d: Hook payload routing — safe Bash command
EXIT=$(hook_eval '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hello"}}')
if [ "$EXIT" = "0" ]; then
    pass "claude-code: hook allows safe Bash command (exit 0)"
else
    fail "claude-code: hook returned exit $EXIT for safe command"
fi

# 2e: Hook payload routing — dangerous command (should block)
EXIT=$(hook_eval '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}')
if [ "$EXIT" = "2" ]; then
    pass "claude-code: hook blocks dangerous command (exit 2)"
else
    fail "claude-code: hook returned exit $EXIT for rm -rf / (expected 2)"
fi

# 2f: Hook payload routing — MCP tool call (non-Bash)
EXIT=$(hook_eval '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/etc/shadow"}}')
if [ "$EXIT" = "0" ] || [ "$EXIT" = "2" ]; then
    pass "claude-code: hook handles MCP tool call (exit $EXIT)"
else
    fail "claude-code: hook crashed on MCP tool call (exit $EXIT)"
fi

# 2g: Disable — removes our hook, preserves others
agentshield setup claude-code --disable > /dev/null 2>&1
if grep -q "agentshield hook" "$HOME/.claude/settings.json" 2>/dev/null; then
    fail "claude-code: disable did not remove hook"
else
    if grep -q "PostToolUse" "$HOME/.claude/settings.json" && \
       grep -q '"allow"' "$HOME/.claude/settings.json"; then
        pass "claude-code: disable removed hook, preserved other settings"
    else
        fail "claude-code: disable damaged other settings"
    fi
fi
echo ""

# --- Windsurf setup ---
echo "=== [3/6] Windsurf setup ==="

mkdir -p "$HOME/.codeium/windsurf"
agentshield setup windsurf > /dev/null 2>&1
if grep -q "agentshield hook" "$HOME/.codeium/windsurf/hooks.json"; then
    pass "windsurf: hook installed"
else
    fail "windsurf: hook not found"
fi

EXIT=$(hook_eval '{"agent_action_name":"pre_run_command","tool_info":{"command_line":"echo hello"}}')
if [ "$EXIT" = "0" ]; then
    pass "windsurf: hook allows safe command"
else
    fail "windsurf: hook returned exit $EXIT for safe command"
fi

EXIT=$(hook_eval '{"agent_action_name":"pre_run_command","tool_info":{"command_line":"rm -rf /"}}')
if [ "$EXIT" = "2" ]; then
    pass "windsurf: hook blocks dangerous command"
else
    fail "windsurf: hook returned exit $EXIT for rm -rf / (expected 2)"
fi

agentshield setup windsurf --disable > /dev/null 2>&1
if [ ! -f "$HOME/.codeium/windsurf/hooks.json" ] && [ -f "$HOME/.codeium/windsurf/hooks.json.bak" ]; then
    pass "windsurf: disable clean (backup created)"
else
    fail "windsurf: disable issue"
fi
echo ""

# --- Cursor setup ---
echo "=== [4/6] Cursor setup ==="

mkdir -p "$HOME/.cursor"
agentshield setup cursor > /dev/null 2>&1
if grep -q "agentshield hook" "$HOME/.cursor/hooks.json"; then
    pass "cursor: hook installed"
else
    fail "cursor: hook not found"
fi

EXIT=$(hook_eval '{"command":"echo hello","cwd":"/tmp"}')
if [ "$EXIT" = "0" ]; then
    pass "cursor: hook allows safe command"
else
    fail "cursor: hook returned exit $EXIT for safe command"
fi

EXIT=$(hook_eval '{"command":"rm -rf /","cwd":"/tmp"}')
if [ "$EXIT" = "2" ]; then
    pass "cursor: hook blocks dangerous command"
else
    # Cursor may return JSON deny on stdout instead of exit 2
    if grep -q "deny" /tmp/_hook_stdout 2>/dev/null; then
        pass "cursor: hook blocks dangerous command (JSON deny)"
    else
        fail "cursor: did not block rm -rf / (exit $EXIT)"
    fi
fi

agentshield setup cursor --disable > /dev/null 2>&1
if [ -f "$HOME/.cursor/hooks.json.bak" ]; then
    pass "cursor: disable clean (backup created)"
else
    fail "cursor: disable did not create backup"
fi
echo ""

# --- Gemini CLI setup ---
echo "=== [5/6] Gemini CLI setup ==="

agentshield setup gemini-cli > /dev/null 2>&1
if [ -f "$HOME/.gemini/settings.json" ] && grep -q "agentshield" "$HOME/.gemini/settings.json"; then
    pass "gemini-cli: hook installed"
else
    fail "gemini-cli: hook not found"
fi

# Gemini hook payload — returns JSON with decision on stdout
hook_eval '{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"echo hello","dir_path":"/tmp"}}' > /dev/null
if grep -q "allow" /tmp/_hook_stdout; then
    pass "gemini-cli: hook allows safe command (JSON allow)"
else
    fail "gemini-cli: unexpected response for safe command"
fi

hook_eval '{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"rm -rf /","dir_path":"/tmp"}}' > /dev/null
if grep -q "deny" /tmp/_hook_stdout; then
    pass "gemini-cli: hook blocks dangerous command (JSON deny)"
else
    fail "gemini-cli: did not block rm -rf /"
fi

# Idempotent + disable
agentshield setup gemini-cli > /dev/null 2>&1
COUNT=$(grep -c "agentshield" "$HOME/.gemini/settings.json")
if [ "$COUNT" -le 2 ]; then
    pass "gemini-cli: idempotent"
else
    fail "gemini-cli: duplicate entries"
fi

agentshield setup gemini-cli --disable > /dev/null 2>&1
if grep -q "agentshield" "$HOME/.gemini/settings.json" 2>/dev/null; then
    fail "gemini-cli: disable did not remove hook"
else
    pass "gemini-cli: disable clean"
fi
echo ""

# --- Codex setup ---
echo "=== [6/6] Codex setup ==="

agentshield setup codex > /dev/null 2>&1
if [ -f "$HOME/.codex/hooks.json" ]; then
    pass "codex: hook installed"
else
    fail "codex: hook not found"
fi

agentshield setup codex --disable > /dev/null 2>&1
if [ -f "$HOME/.codex/hooks.json.bak" ]; then
    pass "codex: disable clean (backup created)"
else
    fail "codex: disable did not create backup"
fi
echo ""

# --- Summary ---
echo "========================================="
echo "  RESULTS: $PASS passed, $FAIL failed"
echo "========================================="
printf "$TESTS\n"
echo ""
if [ "$FAIL" -gt 0 ]; then
    echo "SETUP INTEGRATION TEST: FAILED"
    exit 1
else
    echo "SETUP INTEGRATION TEST: PASSED"
fi
INNER_SCRIPT

echo ""
echo "Running Docker setup integration test..."
echo ""

docker run --rm \
    -v "$STAGING:/agentshield:ro" \
    golang:alpine \
    sh /agentshield/_run_tests.sh

RESULT=$?
echo ""
if [ $RESULT -eq 0 ]; then
    echo "Setup integration test: PASSED"
else
    echo "Setup integration test: FAILED (exit code $RESULT)"
    exit 1
fi
