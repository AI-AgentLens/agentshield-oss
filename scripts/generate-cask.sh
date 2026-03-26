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

  postflight do
    if OS.mac?
      system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "#{staged_path}/agentshield"]
      system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "#{staged_path}/agentcompliance"]
    end
  end

  caveats <<~EOS
    Two tools installed:
      agentshield      — Runtime security gateway for AI agents
      agentcompliance  — Local compliance scanner (semgrep-based)

    Quick start:
      agentshield setup
      agentshield login
  EOS
end
CASKEOF

echo "Cask generated at ${OUTPUT}"
