#!/usr/bin/env bash
# Fresh-Linux-user walkthrough of agentshield-oss/README.md.
#
# Designed to run inside `homebrew/brew:latest` with no agentshield preinstalled.
# This is the first thing a former colleague will see — it must work end to end
# without any surprises.
#
# Steps 1–8 mirror the README literally. Steps 9–12 cover behaviors that
# previously required manual verification and now run automatically.
#
# Usage (CI / dogfooding):
#   docker run --rm -v $PWD/scripts/oss-walkthrough-test.sh:/walk.sh:ro \
#       homebrew/brew:latest bash /walk.sh
#
# Or via Makefile: make test-oss-walkthrough

set +e  # collect every gap; do not bail on first failure

step()    { printf "\n\033[1;36m=== %s ===\033[0m\n" "$1"; }
expect()  { printf "  (expecting: %s)\n" "$1"; }
pass()    { printf "  \033[1;32m[PASS]\033[0m %s\n" "$1"; PASSED=$((PASSED+1)); }
fail()    { printf "  \033[1;31m[FAIL]\033[0m %s\n" "$1"; FAILED=$((FAILED+1)); FAILURES="$FAILURES\n  - $1"; }
skip()    { printf "  \033[1;33m[SKIP]\033[0m %s\n" "$1"; SKIPPED=$((SKIPPED+1)); }

PASSED=0
FAILED=0
SKIPPED=0
FAILURES=""

# ── HOME sandbox guard ─────────────────────────────────────────────────────
# This script writes to $HOME/.claude/settings.json and $HOME/.agentshield/policy.yaml.
# In Docker (homebrew/brew:latest) that's fine — container is ephemeral. On a real dev
# host it would clobber the user's real Claude Code config.
#
#   - Default: if real state exists under $HOME, redirect $HOME to a tempdir.
#   - WALK_HOME=/path/to/dir   → use that dir (e.g., a dedicated test sandbox).
#   - WALK_FORCE_REAL_HOME=1   → run against the real $HOME (mutations persist; opt-in only).
#
if [ "${WALK_FORCE_REAL_HOME:-0}" = "1" ]; then
    printf "\033[1;33m⚠  WALK_FORCE_REAL_HOME=1 — mutations will persist in your real \$HOME\033[0m\n"
elif [ -n "${WALK_HOME:-}" ]; then
    mkdir -p "$WALK_HOME/.claude" "$WALK_HOME/.agentshield"
    export HOME="$WALK_HOME"
    printf "\033[1;33m⚠  Using WALK_HOME sandbox: %s\033[0m\n" "$HOME"
elif [ -f "$HOME/.claude/settings.json" ] || [ -f "$HOME/.agentshield/policy.yaml" ]; then
    WALK_HOME=$(mktemp -d -t agentshield-walk-XXXXXX)
    mkdir -p "$WALK_HOME/.claude" "$WALK_HOME/.agentshield"
    export HOME="$WALK_HOME"
    printf "\033[1;33m⚠  Detected real Claude/agentshield state under \$HOME — sandboxing into:\033[0m\n"
    printf "    %s\n" "$HOME"
    printf "    (override with WALK_HOME=/path or WALK_FORCE_REAL_HOME=1)\n"
fi

# DEV_BUILD is determined just-in-time inside STEP 4, after STEP 1 has put
# agentshield on PATH. A dev build (e.g. a symlink from `make deploy` to
# ./build/agentshield) doesn't have the cask-shipped wrapper script adjacent
# to it, so the wrapper-detection in STEP 4 would fail spuriously — we SKIP
# that one assertion when DEV_BUILD=1.
DEV_BUILD=0

# ── Helper: fire a Claude-Code-format PreToolUse hook event ────────────────
# Echoes Claude Code's JSON contract to `agentshield hook` and prints the
# decision plus exit code. This is the loop that fires in real Claude Code.
hook_fire() {
    local cmd="$1"
    printf '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"%s"}}' "$cmd" \
        | agentshield hook 2>&1
    return $?
}

step "STEP 0 — environment"
cat /etc/os-release | grep -E "PRETTY_NAME|^NAME" | head -2
echo "user: $(whoami)  home: $HOME"

step "STEP 1 — README Try It: brew tap + install"
expect "tap added, agentshield binary in PATH"
# Brew env tuning + retry loop guard against ghcr.io bottle-download SSL EOFs
# at nightly hours (~9PM EDT). Two consecutive nightlies (5/20 + 5/21) failed
# here on the `go` keg download, not on our formula.
export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_ANALYTICS=1
export HOMEBREW_CURL_RETRIES=5
export HOMEBREW_DOWNLOAD_CONCURRENCY=1
# Pre-emptive Tap Trust: Homebrew gates non-official casks now (5.1.15+) and
# extends to formulae at 5.2.0/6.0.0. Trusting the OSS tap here is a no-op on
# current Homebrew and keeps this walkthrough green when the formula gate lands.
brew tap AI-AgentLens/oss 2>&1 | tail -3
brew trust AI-AgentLens/oss 2>&1 | tail -2 || true
for attempt in 1 2 3; do
    if brew install AI-AgentLens/oss/agentshield 2>&1 | tail -5; then
        break
    fi
    if [ $attempt -eq 3 ]; then
        echo "  brew install failed after 3 attempts (likely ghcr.io bottle download issue)" >&2
        break
    fi
    echo "  brew install attempt $attempt failed; sleeping 30s before retry..." >&2
    sleep 30
done
which agentshield && agentshield --help 2>&1 | head -3
which agentshield >/dev/null && pass "agentshield in PATH" || fail "agentshield not in PATH"

step "STEP 2 — check --shell examples (3 from README)"
expect "BLOCK exit 2, BLOCK exit 2, ALLOW exit 0"
SSH_PATH="cat ~/.s""sh/id_rsa"
agentshield check --shell "rm -rf /";          rc=$?; [ $rc -eq 2 ] && pass "rm -rf / blocked (exit 2)"   || fail "rm -rf / wrong exit $rc"
agentshield check --shell "$SSH_PATH";         rc=$?; [ $rc -eq 2 ] && pass "ssh-key read blocked (exit 2)" || fail "ssh-key read wrong exit $rc"
agentshield check --shell "ls -la";            rc=$?; [ $rc -eq 0 ] && pass "ls -la allowed (exit 0)"      || fail "ls -la wrong exit $rc"

step "STEP 3 — mcp-eval examples (2 from README)"
expect "BLOCK exit 2 for ssh path, AUDIT exit 0 for weather"
SSH_ARG="path=/home/user/.s""sh/id_rsa"
agentshield mcp-eval --tool read_file --arg "$SSH_ARG"; rc=$?; [ $rc -eq 2 ] && pass "mcp ssh-key blocked"     || fail "mcp ssh-key wrong exit $rc"
agentshield mcp-eval --tool get_weather --arg location=NYC; rc=$?; [ $rc -eq 0 ] && pass "mcp weather audited" || fail "mcp weather wrong exit $rc"

step "STEP 4 — Protect Claude Code: setup + scan"
expect "hook written; scan all-pass; wrapper detected"
mkdir -p "$HOME/.agentshield"
if agentshield version 2>&1 | grep -qE "0\.0\.|^AgentShield 0\.1\.0-dev|-dev$"; then
    DEV_BUILD=1
fi
SETUP_OUT=$(agentshield setup claude-code 2>&1)
echo "$SETUP_OUT" | tail -8
[ -f "$HOME/.claude/settings.json" ] && pass "settings.json created" || fail "settings.json missing"
if [ "$DEV_BUILD" = "1" ]; then
    skip "wrapper detection (dev build — wrapper bundled with cask isn't adjacent to dev binary)"
else
    echo "$SETUP_OUT" | grep -qE "Wrapper:[[:space:]]+✅" && pass "setup: wrapper detected"  || fail "setup: Wrapper line missing or warning"
fi
SCAN_OUT=$(agentshield scan 2>&1)
echo "$SCAN_OUT" | grep -q "All 17 tests passed"     && pass "scan: 17/17 self-tests pass" || fail "scan self-tests did not all pass"

step "STEP 5 — Add A Local Rule"
expect "BLOCK on psql prod.db with custom rule"
cat > "$HOME/.agentshield/policy.yaml" <<EOF
version: "0.1"
rules:
  - id: block-production-db
    match:
      command_regex: "psql.*prod"
    decision: "BLOCK"
    reason: "Direct production database access is not allowed."
EOF
agentshield check --shell "psql prod.db" --policy "$HOME/.agentshield/policy.yaml"; rc=$?
[ $rc -eq 2 ] && pass "custom rule fires via --policy" || fail "custom rule did not block via --policy (exit $rc)"

step "STEP 6 — diagnostics commands from README"
expect "log shows helpful empty state, rule list / pause / resume work"
LOG_OUT=$(agentshield log --last 5 2>&1)
echo "$LOG_OUT" | grep -q "agentshield check"  && pass "log empty state mentions check"  || fail "log empty state missing check hint"
echo "$LOG_OUT" | grep -q "agentshield mcp-eval" && pass "log empty state mentions mcp-eval" || fail "log empty state missing mcp-eval hint"
agentshield rule list >/dev/null 2>&1            && pass "rule list returns ok"         || fail "rule list failed"
agentshield pause 1 >/dev/null 2>&1              && pass "pause 1 returns ok"           || fail "pause failed"
agentshield resume >/dev/null 2>&1               && pass "resume returns ok"            || fail "resume failed"

step "STEP 7 — disable hook (cleanup path from README)"
expect "hook removed cleanly"
agentshield setup claude-code --disable >/dev/null 2>&1
SETTINGS=$(cat "$HOME/.claude/settings.json" 2>/dev/null)
echo "$SETTINGS" | grep -q "agentshield hook" && fail "hook still present after disable" || pass "hook removed cleanly"
agentshield setup claude-code >/dev/null 2>&1   # re-enable for steps 9-12

step "STEP 8 — README links"
expect "policy-guide.md returns 200; rule-request issue link reachable"
curl -fsI https://raw.githubusercontent.com/AI-AgentLens/agentshield-oss/main/docs/policy-guide.md \
    >/dev/null 2>&1 && pass "policy-guide.md is reachable" || fail "policy-guide.md unreachable"
curl -fsI -o /dev/null -w "%{http_code}" "https://github.com/AI-AgentLens/agentshield-oss/issues/new?template=rule-request.yml" 2>/dev/null \
    | grep -qE "^(200|302)$" && pass "rule-request issue link reachable" || fail "rule-request issue link broken"

# ─────────────────────────────────────────────────────────────────────────
# STEPS 9-12: Behaviors that previously required manual verification.
# Now automated so the pre-invite check is one command.
# ─────────────────────────────────────────────────────────────────────────

step "STEP 9 — Hook JSON contract (Claude Code PreToolUse simulation)"
expect "BLOCK rendered cleanly to stderr, no stack trace, exit 2"
HOOK_OUT=$(hook_fire "rm -rf /")
HOOK_RC=$?
[ $HOOK_RC -eq 2 ]                                    && pass "hook exits 2 on BLOCK"                 || fail "hook exit code was $HOOK_RC, expected 2"
echo "$HOOK_OUT" | grep -qE "AgentShield BLOCKED|BLOCKED this command" && pass "hook stderr shows clear BLOCK header"   || fail "hook stderr missing clear BLOCK header"
echo "$HOOK_OUT" | grep -qE "panic:|goroutine [0-9]+ \[running\]"      && fail "hook leaked Go stack trace"             || pass "no Go stack trace in hook output"
echo "$HOOK_OUT" | grep -qE "Rule:|Reason:"                             && pass "hook output names Rule + Reason"        || fail "hook output missing Rule/Reason field"

step "STEP 10 — setup against an EXISTING settings.json (merge, no clobber)"
expect "existing pre-existing-hook + MCP servers preserved alongside agentshield"
agentshield setup claude-code --disable >/dev/null 2>&1
mkdir -p "$HOME/.claude"
cat > "$HOME/.claude/settings.json" <<'EOF'
{
  "mcpServers": {
    "my-existing-server": {
      "command": "/usr/local/bin/my-mcp-server",
      "args": ["--port", "8080"]
    }
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "/usr/local/bin/my-prior-hook" }
        ]
      }
    ]
  }
}
EOF
agentshield setup claude-code >/dev/null 2>&1
MERGED=$(cat "$HOME/.claude/settings.json")
echo "$MERGED" | grep -q "my-existing-server"      && pass "existing MCP server preserved"      || fail "MCP server was dropped"
echo "$MERGED" | grep -q "my-prior-hook"           && pass "existing PreToolUse hook preserved" || fail "prior PreToolUse hook was dropped"
echo "$MERGED" | grep -q "agentshield hook"        && pass "agentshield hook added"             || fail "agentshield hook was not added"

step "STEP 11 — Custom rule auto-loads via the hook (not just --policy)"
expect "psql prod.db blocked when policy.yaml exists at default path"
cat > "$HOME/.agentshield/policy.yaml" <<EOF
version: "0.1"
rules:
  - id: block-production-db
    match:
      command_regex: "psql.*prod"
    decision: "BLOCK"
    reason: "Direct production database access is not allowed."
EOF
HOOK_OUT=$(hook_fire "psql prod.db")
HOOK_RC=$?
[ $HOOK_RC -eq 2 ]                                  && pass "hook BLOCKs psql prod.db (auto-loaded policy)" || fail "hook did NOT block psql prod.db (exit $HOOK_RC) — policy.yaml not auto-loaded"
echo "$HOOK_OUT" | grep -q "block-production-db"    && pass "hook reports custom rule ID"                   || fail "hook did not name block-production-db rule"

step "STEP 12 — agentshield rule disable round-trip via hook"
expect "BLOCK → disable → ALLOW → re-enable → BLOCK"
hook_fire "psql prod.db" >/dev/null 2>&1; rc1=$?
[ $rc1 -eq 2 ]                                       && pass "round-trip pre-disable: BLOCK"          || fail "round-trip pre-disable wrong exit $rc1"
agentshield rule disable block-production-db >/dev/null 2>&1
hook_fire "psql prod.db" >/dev/null 2>&1; rc2=$?
[ $rc2 -ne 2 ]                                       && pass "round-trip after disable: not BLOCK"    || fail "round-trip after disable still BLOCKed (exit $rc2)"
agentshield rule allow   block-production-db >/dev/null 2>&1
hook_fire "psql prod.db" >/dev/null 2>&1; rc3=$?
[ $rc3 -eq 2 ]                                       && pass "round-trip after re-enable: BLOCK"      || fail "round-trip after re-enable wrong exit $rc3"

# ─────────────────────────────────────────────────────────────────────────
echo ""
printf "\033[1m═══ Walkthrough Summary ═══\033[0m\n"
printf "  Passed:  \033[1;32m%d\033[0m\n" "$PASSED"
printf "  Failed:  \033[1;31m%d\033[0m\n" "$FAILED"
if [ "$SKIPPED" -gt 0 ]; then
    printf "  Skipped: \033[1;33m%d\033[0m (env-specific assertions)\n" "$SKIPPED"
fi
if [ "$FAILED" -gt 0 ]; then
    printf "\nFailures:%b\n" "$FAILURES"
    exit 1
fi
echo ""
echo "All checks passed — README walkthrough is ready for OSS users."
