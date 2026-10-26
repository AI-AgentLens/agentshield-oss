#!/bin/bash
# Generates the Homebrew cask file for agentshield.
# Usage: ./scripts/generate-cask.sh <version> <dist_dir> <output_file>
# Example: ./scripts/generate-cask.sh v0.2.9 dist /tmp/agentshield.rb

set -euo pipefail

VERSION="$1"
DIST_DIR="$2"
OUTPUT="$3"

VER_NUM="${VERSION#v}"
BASE_URL="https://aiagentlens.com/releases/${VERSION}"

SHA_DARWIN_AMD64=$(sha256sum "${DIST_DIR}/agentshield_${VER_NUM}_darwin_amd64.tar.gz" | cut -d' ' -f1)
SHA_DARWIN_ARM64=$(sha256sum "${DIST_DIR}/agentshield_${VER_NUM}_darwin_arm64.tar.gz" | cut -d' ' -f1)
SHA_LINUX_AMD64=$(sha256sum "${DIST_DIR}/agentshield_${VER_NUM}_linux_amd64.tar.gz" | cut -d' ' -f1)
SHA_LINUX_ARM64=$(sha256sum "${DIST_DIR}/agentshield_${VER_NUM}_linux_arm64.tar.gz" | cut -d' ' -f1)

cat > "${OUTPUT}" <<CASKEOF
cask "agentshield" do
  name "agentshield"
  desc "Runtime security gateway and compliance scanner for LLM agents"
  homepage "https://aiagentlens.com"
  version "${VER_NUM}"

  livecheck do
    skip "Auto-updated by CI on release."
  end

  binary "agentshield"
  binary "agentcompliance"

  on_macos do
    on_intel do
      url "${BASE_URL}/agentshield_${VER_NUM}_darwin_amd64.tar.gz"
      sha256 "${SHA_DARWIN_AMD64}"
    end
    on_arm do
      url "${BASE_URL}/agentshield_${VER_NUM}_darwin_arm64.tar.gz"
      sha256 "${SHA_DARWIN_ARM64}"
    end
  end

  on_linux do
    on_intel do
      url "${BASE_URL}/agentshield_${VER_NUM}_linux_amd64.tar.gz"
      sha256 "${SHA_LINUX_AMD64}"
    end
    on_arm do
      url "${BASE_URL}/agentshield_${VER_NUM}_linux_arm64.tar.gz"
      sha256 "${SHA_LINUX_ARM64}"
    end
  end

  # Stop the heartbeat daemon before upgrading so the old binary doesn't keep
  # running as a zombie after brew replaces it.
  preflight do
    if OS.mac?
      plist = File.expand_path("~/Library/LaunchAgents/com.aiagentlens.agentshield.plist")
      if File.exist?(plist)
        system_command "/bin/launchctl", args: ["bootout", "gui/#{Process.uid}/com.aiagentlens.agentshield"], print_stderr: false
        File.delete(plist) if File.exist?(plist)
      end
    end
  end

  postflight do
    if OS.mac?
      system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "#{staged_path}/agentshield"]
      system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "#{staged_path}/agentcompliance"]
    end
  end

  uninstall launchctl: "com.aiagentlens.agentshield",
            delete:    "~/Library/LaunchAgents/com.aiagentlens.agentshield.plist"

  # brew uninstall --zap removes the agent hooks that agentshield setup wrote
  # (#4491). Zap only, never uninstall: Homebrew runs uninstall stanzas and
  # uninstall flight blocks on every upgrade and reinstall (Cask::Installer
  # start_upgrade -> uninstall_artifacts), so removing hooks there would strip
  # protection on each brew upgrade. Zap runs only on brew uninstall --zap,
  # before the binary link and the Caskroom are removed, so the staged binary
  # still runs. Each agent is non-fatal: a managed host refuses --disable and
  # keeps its hooks, which belong to the MDM. ~/.agentshield is kept on
  # purpose: it holds the audit log, which is evidence.
  zap script: {
    executable:   "/bin/sh",
    args:         ["-c", <<~'SH', "#{staged_path}/agentshield"],
      bin="\$0"
      PATH="\$(dirname "\$bin"):\$PATH"; export PATH
      for agent in claude-code gemini-cli codex copilot-cli windsurf cursor openclaw mcp; do
        echo "==> agentshield setup \$agent --disable"
        "\$bin" setup "\$agent" --disable || echo "    not removed (exit \$?); on a managed host your administrator removes it"
      done
      echo "==> ~/.agentshield kept (policy and audit log)"
    SH
    must_succeed: false,
  }

  caveats <<~EOS
    Two tools installed:
      agentshield      — Runtime security gateway for AI agents
      agentcompliance  — Local compliance scanner (semgrep-based)

    Quick start:
      agentshield setup
      agentshield login

    To uninstall and remove the agent hooks setup wrote:
      brew uninstall --zap --cask agentshield
    A plain brew uninstall leaves the hooks. ~/.agentshield (audit log) is kept.
  EOS
end
CASKEOF

echo "Cask generated at ${OUTPUT}"
