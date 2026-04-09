#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# AgentShield — Local Build & Install
# ─────────────────────────────────────────────────────────────────────────────
# Builds from the local clone, installs the binary, policy packs, wrapper
# script, and optionally configures IDE hooks.
#
# Usage:
#   cd AI_Agent_Shield && ./scripts/install-local.sh
#   # or from anywhere:
#   ./path/to/AI_Agent_Shield/scripts/install-local.sh
#
# Options:
#   --hooks <list>   Comma-separated IDEs to configure (non-interactive)
#                    e.g. --hooks claude-code,gemini-cli,codex
#                    Available: claude-code, gemini-cli, codex, cursor, windsurf, openclaw
#   --hooks all      Configure all supported IDEs
# ─────────────────────────────────────────────────────────────────────────────

# ── Parse arguments ──────────────────────────────────────────────────────────
HOOKS_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --hooks)
      HOOKS_ARG="$2"
      shift 2
      ;;
    --hooks=*)
      HOOKS_ARG="${1#*=}"
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Usage: $0 [--hooks claude-code,gemini-cli,codex]" >&2
      exit 1
      ;;
  esac
done

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
SHARE_DIR="${SHARE_DIR:-/usr/local/share/agentshield}"
CONFIG_DIR="${HOME}/.agentshield"
BINARY="agentshield"
BUILD_DIR="./build"

# ── Colors ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  BOLD='\033[1m'
  GREEN='\033[32m'
  YELLOW='\033[33m'
  RED='\033[31m'
  CYAN='\033[36m'
  RESET='\033[0m'
else
  BOLD='' GREEN='' YELLOW='' RED='' CYAN='' RESET=''
fi

info()  { echo -e "${BOLD}${CYAN}==>${RESET} $*"; }
ok()    { echo -e "  ${GREEN}✓${RESET} $*"; }
warn()  { echo -e "  ${YELLOW}!${RESET} $*"; }
fail()  { echo -e "  ${RED}✗${RESET} $*"; exit 1; }

# ── Resolve repo root ───────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Verify we're in the right repo
if [[ ! -f "${REPO_ROOT}/cmd/agentshield/main.go" ]]; then
  fail "Cannot find cmd/agentshield/main.go — are you in the AgentShield repo?"
fi

cd "${REPO_ROOT}"

echo ""
echo -e "${BOLD}AgentShield — Local Installer${RESET}"
echo "─────────────────────────────────────────────"
echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 1. Pre-flight checks
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
info "Pre-flight checks"

# Check Go is installed
if ! command -v go &>/dev/null; then
  fail "Go is not installed. Install Go 1.23+ from https://go.dev/dl/"
fi

# Check Go version >= 1.23
GO_VERSION="$(go version | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | sed 's/go//')"
GO_MAJOR="${GO_VERSION%%.*}"
GO_MINOR="${GO_VERSION#*.}"
if [[ "${GO_MAJOR}" -lt 1 ]] || { [[ "${GO_MAJOR}" -eq 1 ]] && [[ "${GO_MINOR}" -lt 23 ]]; }; then
  fail "Go ${GO_VERSION} found, but 1.23+ is required."
fi
ok "Go ${GO_VERSION}"

# Check git (for commit hash in version string)
if command -v git &>/dev/null && [[ -d .git ]]; then
  ok "Git repo detected"
else
  warn "Not a git repo — commit hash will be 'unknown'"
fi

echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 2. Build
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
info "Building agentshield"

VERSION="${VERSION:-0.1.0-dev}"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
BUILD_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

LDFLAGS="-X 'github.com/security-researcher-ca/agentshield/internal/cli.Version=${VERSION}'"
LDFLAGS="${LDFLAGS} -X 'github.com/security-researcher-ca/agentshield/internal/cli.GitCommit=${GIT_COMMIT}'"
LDFLAGS="${LDFLAGS} -X 'github.com/security-researcher-ca/agentshield/internal/cli.BuildDate=${BUILD_DATE}'"

mkdir -p "${BUILD_DIR}"
go build -ldflags "${LDFLAGS}" -o "${BUILD_DIR}/${BINARY}" ./cmd/agentshield

ok "Built ${BUILD_DIR}/${BINARY}  (${VERSION}, ${GIT_COMMIT}, ${BUILD_DATE})"
echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3. Install binary
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
info "Installing binary to ${INSTALL_DIR}"

install_with_privilege() {
  local src="$1" dst="$2"
  if [[ -w "$(dirname "$dst")" ]]; then
    cp "$src" "$dst"
  else
    warn "Requires sudo to write to $(dirname "$dst")"
    sudo cp "$src" "$dst"
  fi
}

install_with_privilege "${BUILD_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
chmod +x "${INSTALL_DIR}/${BINARY}"
ok "Installed ${INSTALL_DIR}/${BINARY}"
echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 4. Create config directory
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
info "Setting up config directory"

mkdir -p "${CONFIG_DIR}/packs"
mkdir -p "${CONFIG_DIR}/mcp-packs"
ok "Created ${CONFIG_DIR}/ with packs/ and mcp-packs/"
echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 5. Install policy packs
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
info "Installing policy packs"

PACK_COUNT=0
for pack in "${REPO_ROOT}"/packs/*.yaml; do
  [[ -f "$pack" ]] || continue
  cp "$pack" "${CONFIG_DIR}/packs/"
  ok "$(basename "$pack")"
  PACK_COUNT=$((PACK_COUNT + 1))
done

if [[ "$PACK_COUNT" -eq 0 ]]; then
  warn "No policy packs found in packs/"
else
  ok "${PACK_COUNT} policy pack(s) installed to ${CONFIG_DIR}/packs/"
fi
echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 6. Install MCP packs
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
info "Installing MCP packs"

MCP_COUNT=0
for pack in "${REPO_ROOT}"/packs/mcp/*.yaml; do
  [[ -f "$pack" ]] || continue
  cp "$pack" "${CONFIG_DIR}/mcp-packs/"
  ok "$(basename "$pack")"
  MCP_COUNT=$((MCP_COUNT + 1))
done

if [[ "$MCP_COUNT" -eq 0 ]]; then
  warn "No MCP packs found in packs/mcp/"
else
  ok "${MCP_COUNT} MCP pack(s) installed to ${CONFIG_DIR}/mcp-packs/"
fi
echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 7. Install wrapper script
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
info "Installing wrapper script"

if [[ -f "${REPO_ROOT}/scripts/agentshield-wrapper.sh" ]]; then
  if [[ -w "$(dirname "${SHARE_DIR}")" ]]; then
    mkdir -p "${SHARE_DIR}"
  else
    warn "Requires sudo to create ${SHARE_DIR}"
    sudo mkdir -p "${SHARE_DIR}"
  fi
  install_with_privilege "${REPO_ROOT}/scripts/agentshield-wrapper.sh" "${SHARE_DIR}/agentshield-wrapper.sh"
  chmod +x "${SHARE_DIR}/agentshield-wrapper.sh"
  ok "Installed ${SHARE_DIR}/agentshield-wrapper.sh"
else
  warn "Wrapper script not found, skipping"
fi
echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 8. Install default policy
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
info "Installing default policy"

if [[ -f "${CONFIG_DIR}/policy.yaml" ]]; then
  warn "Policy already exists at ${CONFIG_DIR}/policy.yaml — skipping (won't overwrite)"
elif [[ -f "${REPO_ROOT}/configs/default_policy.yaml" ]]; then
  cp "${REPO_ROOT}/configs/default_policy.yaml" "${CONFIG_DIR}/policy.yaml"
  ok "Installed default policy to ${CONFIG_DIR}/policy.yaml"
else
  warn "No default_policy.yaml found in configs/"
fi
echo ""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 9. IDE hook setup
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
info "IDE hook setup"

ALL_IDES=("claude-code" "gemini-cli" "codex" "cursor" "windsurf" "openclaw")
ALL_IDE_LABELS=("Claude Code" "Gemini CLI" "Codex CLI" "Cursor" "Windsurf" "OpenClaw")

setup_ide_hooks() {
  local -a ides=("$@")
  for ide in "${ides[@]}"; do
    info "Configuring ${ide}..."
    if "${INSTALL_DIR}/${BINARY}" setup "$ide" 2>&1 | sed 's/^/    /'; then
      ok "${ide} configured"
    else
      warn "Failed to configure ${ide} — you can retry with: agentshield setup ${ide}"
    fi
    echo ""
  done
}

if [[ -n "${HOOKS_ARG}" ]]; then
  # Non-interactive: --hooks flag provided
  selected_ides=()
  if [[ "${HOOKS_ARG}" == "all" ]]; then
    selected_ides=("${ALL_IDES[@]}")
  else
    IFS=',' read -ra requested <<< "${HOOKS_ARG}"
    for req in "${requested[@]}"; do
      req="$(echo "$req" | tr -d ' ')"
      # Validate the IDE name
      valid=false
      for known in "${ALL_IDES[@]}"; do
        if [[ "$req" == "$known" ]]; then
          valid=true
          break
        fi
      done
      if [[ "$valid" == true ]]; then
        selected_ides+=("$req")
      else
        warn "Unknown IDE: ${req} (available: ${ALL_IDES[*]})"
      fi
    done
  fi

  if [[ ${#selected_ides[@]} -gt 0 ]]; then
    echo ""
    setup_ide_hooks "${selected_ides[@]}"
  else
    warn "No valid IDEs specified"
    echo ""
  fi

elif [[ -t 0 ]]; then
  # Interactive — ask user which IDEs to configure
  echo "  Which IDEs would you like to configure?"
  echo ""
  for i in "${!ALL_IDES[@]}"; do
    echo "    $((i + 1))) ${ALL_IDE_LABELS[$i]}"
  done
  echo "    a) All"
  echo "    s) Skip"
  echo ""
  read -rp "  Choose [1-${#ALL_IDES[@]}/a/s] (default: s): " ide_choice
  ide_choice="${ide_choice:-s}"

  selected_ides=()
  case "$ide_choice" in
    a|A)
      selected_ides=("${ALL_IDES[@]}")
      ;;
    s|S|"")
      selected_ides=()
      ;;
    *)
      # Parse comma-separated or single number
      IFS=',' read -ra choices <<< "$ide_choice"
      for c in "${choices[@]}"; do
        c="$(echo "$c" | tr -d ' ')"
        if [[ "$c" =~ ^[0-9]+$ ]] && [[ "$c" -ge 1 ]] && [[ "$c" -le "${#ALL_IDES[@]}" ]]; then
          selected_ides+=("${ALL_IDES[$((c - 1))]}")
        fi
      done
      ;;
  esac

  echo ""
  if [[ ${#selected_ides[@]} -gt 0 ]]; then
    setup_ide_hooks "${selected_ides[@]}"
  else
    warn "Skipped IDE setup — run 'agentshield setup <ide>' later"
    echo "  Available: ${ALL_IDES[*]}"
    echo ""
  fi

else
  # Non-interactive without --hooks — skip IDE setup
  warn "Non-interactive mode — use --hooks to configure IDEs"
  echo "  Example: $0 --hooks claude-code,gemini-cli,codex"
  echo "  Available: ${ALL_IDES[*]}"
  echo ""
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 10. Verify installation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
info "Verifying installation"

# Check binary is in PATH
WHICH_RESULT="$(command -v agentshield 2>/dev/null || true)"
if [[ -n "$WHICH_RESULT" ]]; then
  ok "which agentshield → ${WHICH_RESULT}"
else
  warn "agentshield not found in PATH — you may need to add ${INSTALL_DIR} to PATH"
fi

# Version check
echo ""
"${INSTALL_DIR}/${BINARY}" version 2>&1 | sed 's/^/    /'
echo ""

# Self-test
info "Running self-test (agentshield scan)"
echo ""
if "${INSTALL_DIR}/${BINARY}" scan 2>&1 | sed 's/^/    /'; then
  echo ""
  ok "Self-test passed"
else
  echo ""
  warn "Self-test had failures — check output above"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Done
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo "─────────────────────────────────────────────"
echo -e "${BOLD}${GREEN}AgentShield installed successfully!${RESET}"
echo ""
echo "  Binary:   ${INSTALL_DIR}/${BINARY}"
echo "  Config:   ${CONFIG_DIR}/"
echo "  Wrapper:  ${SHARE_DIR}/agentshield-wrapper.sh"
echo ""
echo "  Quick commands:"
echo "    agentshield version"
echo "    agentshield scan"
echo "    agentshield setup <ide>            # install PreToolUse hook"
echo "    agentshield mcp-eval --tool read_file --arg path=~/.ssh/id_rsa"
echo "    agentshield status"
echo ""
