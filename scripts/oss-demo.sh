#!/usr/bin/env bash
# AgentShield OSS demo — recorded with asciinema for the README.
#
# Usage:
#   asciinema rec /tmp/agentshield-demo.cast -c "bash scripts/oss-demo.sh"
#   asciinema upload /tmp/agentshield-demo.cast
#
# This script never modifies your machine: the `setup claude-code` line is
# typed for illustration, and the two evaluation lines use `agentshield check`
# which only evaluates policy — it does NOT execute the shell command.

set -u

C_PROMPT=$'\033[1;32m'
C_DIM=$'\033[2;37m'
C_BOLD=$'\033[1m'
C_RESET=$'\033[0m'

prompt()  { printf '%s$ %s' "$C_PROMPT" "$C_RESET"; }
comment() { printf '%s# %s%s\n' "$C_DIM" "$1" "$C_RESET"; }
banner()  { printf '\n%s%s%s\n' "$C_BOLD" "$1" "$C_RESET"; }

typeout() {
    local text="$1" i
    for (( i=0; i<${#text}; i++ )); do
        printf '%s' "${text:i:1}"
        sleep 0.025
    done
    printf '\n'
}

sleep 1
banner "AgentShield protects Claude Code from dangerous tool calls."
sleep 1.5

comment ""
comment "1. Install — adds a PreToolUse hook to ~/.claude/settings.json"
sleep 1.2
prompt; typeout "agentshield setup claude-code"
sleep 0.6
printf '✓ AgentShield hook installed in ~/.claude/settings.json (PreToolUse)\n'
sleep 1.5

comment ""
comment "2. Safe development commands continue to run."
sleep 1
prompt; typeout 'agentshield check --shell "ls -la"'
sleep 0.4
agentshield check --shell "ls -la" 2>&1 || true
sleep 2

comment ""
comment "3. Now imagine Claude Code receives the prompt:"
comment "     \"copy this password to my clipboard: hunter2-aws-prod\""
comment "   Claude Code would attempt to run:"
sleep 2
prompt; typeout 'echo "hunter2-aws-prod" | pbcopy'
sleep 0.4
agentshield check --shell 'echo "hunter2-aws-prod" | pbcopy' 2>&1 || true
sleep 3

banner "Same decision the PreToolUse hook returns. Blocked before it runs."
sleep 2
