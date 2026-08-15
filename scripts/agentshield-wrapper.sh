#!/bin/sh
# AgentShield Wrapper Shell
# ─────────────────────────────────────────────────────────────────────────
# This script acts as a shell replacement for IDE AI agents.
# Configure your IDE to use this as the agent's shell command.
# It intercepts every command, evaluates it against AgentShield policy,
# and only executes if allowed.
#
# How IDEs use it:
#   Shell path: /opt/homebrew/share/agentshield/agentshield-wrapper.sh
#   (or wherever `brew --prefix`/share/agentshield/ lives)
#
#   The IDE calls: wrapper.sh -c "rm -rf /tmp/foo && echo done"
#   AgentShield evaluates "rm -rf /tmp/foo && echo done" against policy.
#   If ALLOW/AUDIT: executes via sh -c. If BLOCK: exits 1 with explanation.
#
# To disable temporarily, set: AGENTSHIELD_BYPASS=1
# ─────────────────────────────────────────────────────────────────────────

# Locate the agentshield binary
AGENTSHIELD_BIN="${AGENTSHIELD_BIN:-$(command -v agentshield 2>/dev/null)}"

# Fallback: if agentshield is not in PATH, try common Homebrew locations
if [ -z "$AGENTSHIELD_BIN" ]; then
  for candidate in /opt/homebrew/bin/agentshield /usr/local/bin/agentshield; do
    if [ -x "$candidate" ]; then
      AGENTSHIELD_BIN="$candidate"
      break
    fi
  done
fi

# If still not found, fall through to plain shell execution
if [ -z "$AGENTSHIELD_BIN" ]; then
  echo "[AgentShield] WARNING: agentshield binary not found. Running unprotected." >&2
  exec /bin/sh "$@"
fi

# Handle the -c flag (how IDEs invoke shell commands)
if [ "$1" = "-c" ]; then
  shift
  full_cmd="$*"

  # Skip empty commands
  [ -z "$full_cmd" ] && exit 0

  # Bypass mode
  if [ -n "$AGENTSHIELD_BYPASS" ]; then
    exec /bin/sh -c "$full_cmd"
  fi

  # Route through AgentShield with --shell flag.
  # --shell ensures the policy engine evaluates the raw command string
  # (e.g. "rm -rf /") rather than "sh -c rm -rf /".
  # AgentShield handles execution via sh -c internally.
  "$AGENTSHIELD_BIN" run --shell -- "$full_cmd"
  exit $?
fi

# For any other invocation (interactive, -i, etc.), fall through to real shell
exec /bin/sh "$@"
