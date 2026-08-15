#!/usr/bin/env bash
# integration-test-e2e.sh — Full friend-install E2E (cask + login + update + block)
#
# Simulates a brand-new friend running the documented onboarding:
#   brew tap AI-AgentLens/tap
#   brew install --cask agentshield
#   agentshield login                  (simulated — writes credentials.json from env)
#   agentshield update                 (downloads premium packs from SaaS)
#   telnet localhost 23                (must BLOCK via premium rule ne-block-telnet)
#
# Unlike integration-test-cask.sh (which tests only the embedded community path),
# this script exercises the SaaS premium delivery pipeline end-to-end.
#
# Required env:
#   AGENTSHIELD_TEST_TOKEN  — a valid API token for app.aiagentlens.com
#
# Optional env:
#   TAP          default: AI-AgentLens/tap
#   IMAGE        default: homebrew/brew
#   SERVER       default: https://app.aiagentlens.com
#
# Usage:
#   AGENTSHIELD_TEST_TOKEN=$(jq -r .token ~/.agentshield/credentials.json) \
#     ./scripts/integration-test-e2e.sh

set -euo pipefail

: "${AGENTSHIELD_TEST_TOKEN:?Set AGENTSHIELD_TEST_TOKEN to a valid API token (e.g. from ~/.agentshield/credentials.json)}"

TAP="${TAP:-AI-AgentLens/tap}"
IMAGE="${IMAGE:-homebrew/brew}"
SERVER="${SERVER:-https://app.aiagentlens.com}"

echo "═══════════════════════════════════════════════════════════"
echo "  AgentShield — Friend-Install E2E (with premium)"
echo "  Tap:    $TAP"
echo "  Image:  $IMAGE"
echo "  Server: $SERVER"
echo "═══════════════════════════════════════════════════════════"
echo ""

INNER=$(cat <<'INNER_EOF'
#!/bin/bash
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
PASS=0; FAIL=0
pass() { echo -e "  ${GREEN}PASS${NC}: $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}FAIL${NC}: $1"; FAIL=$((FAIL+1)); }
info() { echo -e "  ${YELLOW}INFO${NC}: $1"; }

TAP="$1"
SERVER="$2"
TOKEN="$3"

# ── Step 1: tap + install ─────────────────────────────────────
echo "── Step 1: brew tap + install --cask ──────────────────────"
brew tap "$TAP" 2>&1 | tail -3
# Homebrew 5.1.15+ (Tap Trust) refuses to load casks from non-official taps
# without explicit trust. Mirrors the step real users now run (see install
# docs / GettingStartedWizard). `|| true` = harmless no-op on older Homebrew.
brew trust "$TAP" 2>&1 | tail -3 || true
brew install --cask agentshield 2>&1 | tail -5 || {
    info "cask install failed (Linuxbrew often rejects casks); falling back to formula"
    brew install agentshield 2>&1 | tail -5 || { fail "install failed"; exit 1; }
}
command -v agentshield >/dev/null && pass "agentshield on PATH" || { fail "agentshield not on PATH"; exit 1; }
echo ""

# ── Step 2: simulate login (write credentials.json) ───────────
# Drives the same creds format that `agentshield login` writes, so the rest of
# the flow runs without prompting. This is the only concession to automation.
echo "── Step 2: seed credentials.json (simulates agentshield login) ──"
mkdir -p ~/.agentshield
cat > ~/.agentshield/credentials.json <<CREDS
{"server":"$SERVER","token":"$TOKEN"}
CREDS
chmod 600 ~/.agentshield/credentials.json
pass "credentials.json written"
echo ""

# ── Step 3: agentshield update ────────────────────────────────
echo "── Step 3: agentshield update (download premium packs) ───"
UPDATE_OUT=$(agentshield update 2>&1) || { fail "agentshield update exited non-zero"; echo "$UPDATE_OUT"; exit 1; }
echo "$UPDATE_OUT"

if echo "$UPDATE_OUT" | grep -qE "No premium packs available"; then
    fail "SaaS returned empty manifest — /api/packs broken (check premium-packs dir in container)"
    exit 1
fi

if echo "$UPDATE_OUT" | grep -qE "(installed|updated|up to date)"; then
    pass "update completed"
else
    fail "update output unexpected"
fi

# Verify at least the network-egress pack landed (contains ne-block-telnet)
if [ -f ~/.agentshield/packs/network-egress.yaml ]; then
    pass "network-egress.yaml present on disk"
else
    fail "network-egress.yaml missing after update"
fi
echo ""

# ── Step 4: the killer assertion — telnet must now BLOCK ──────
# ne-block-telnet is a PREMIUM rule. If this fires, the full pipeline works:
# SaaS bake → /api/packs serves → agentshield update downloads → engine loads
# premium rule → hook blocks. Break any link and this test fails.
echo "── Step 4: premium rule fires (hook blocks telnet) ───────"
HOOK_INPUT='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"telnet localhost 23"}}'
HOOK_EXIT=0
echo "$HOOK_INPUT" | agentshield hook >/dev/null 2>&1 || HOOK_EXIT=$?
if [ "$HOOK_EXIT" -eq 2 ]; then
    pass "telnet localhost 23 BLOCKED (premium ne-block-telnet active)"
else
    fail "telnet localhost 23 NOT blocked (got hook exit $HOOK_EXIT) — premium pipeline broken"
fi
echo ""

# ── Step 5: community baseline still works ────────────────────
# Paranoia: make sure adding premium didn't break the community path.
echo "── Step 5: community baseline (chmod 777 still blocked) ──"
COMMUNITY_INPUT='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"chmod 777 /etc/passwd"}}'
COMMUNITY_EXIT=0
echo "$COMMUNITY_INPUT" | agentshield hook >/dev/null 2>&1 || COMMUNITY_EXIT=$?
if [ "$COMMUNITY_EXIT" -eq 2 ]; then
    pass "chmod 777 blocked (community path intact)"
else
    fail "chmod 777 NOT blocked — community regression"
fi
echo ""

# ── Summary ────────────────────────────────────────────────────
echo "═══════════════════════════════════════════════════════════"
echo -e "  Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
echo "═══════════════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ]
INNER_EOF
)

TMP_INNER=$(mktemp -t e2e-inner.XXXXXX.sh)
trap 'rm -f "$TMP_INNER"' EXIT
printf '%s\n' "$INNER" > "$TMP_INNER"
chmod +x "$TMP_INNER"

docker run --rm \
    -v "$TMP_INNER:/test.sh:ro" \
    "$IMAGE" bash /test.sh "$TAP" "$SERVER" "$AGENTSHIELD_TEST_TOKEN"
