#!/usr/bin/env bash
set -euo pipefail

# AgentShield Installer
# Usage: curl -sSL https://raw.githubusercontent.com/security-researcher-ca/AI_Agent_Shield/main/scripts/install.sh | bash

REPO="security-researcher-ca/AI_Agent_Shield"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY="agentshield"

echo "Installing AgentShield..."

# Detect OS and arch
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  arm64)   ARCH="arm64" ;;
  *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Get latest release tag
LATEST=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
if [[ -z "$LATEST" ]]; then
  echo "Failed to fetch latest release. Check https://github.com/${REPO}/releases"
  exit 1
fi

TARBALL="${BINARY}_${LATEST}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/v${LATEST}/${TARBALL}"

echo "  Version:  v${LATEST}"
echo "  OS/Arch:  ${OS}/${ARCH}"
echo "  URL:      ${URL}"

# Download and install
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

curl -sSL "$URL" -o "${TMPDIR}/${TARBALL}"
tar xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

if [[ -w "$INSTALL_DIR" ]]; then
  cp "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  echo "  Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo cp "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

chmod +x "${INSTALL_DIR}/${BINARY}"

echo ""
echo "AgentShield v${LATEST} installed to ${INSTALL_DIR}/${BINARY}"
echo ""
echo "Quick start:"
echo "  agentshield version"
echo "  agentshield scan                    # self-test the policy engine"
echo "  agentshield setup <ide>             # install PreToolUse hook"
echo "  agentshield log --decision BLOCK    # review blocked commands"
