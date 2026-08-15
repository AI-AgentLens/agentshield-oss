#!/bin/bash
# Build a DMG installer for AgentShield.
# Usage: ./scripts/build-dmg.sh [arch]
# arch: arm64 (default) or amd64
# Produces: build/AgentShield-<version>-<arch>.dmg

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ARCH="${1:-arm64}"
VERSION="${VERSION:-dev}"
BUILD_DIR="${PROJECT_DIR}/build"
APP_NAME="AgentShield"
APP_BUNDLE="${BUILD_DIR}/${APP_NAME}.app"
# Filename matches what the website links to: AgentShield-darwin-arm64.dmg
DMG_NAME="${APP_NAME}-darwin-${ARCH}"
DMG_PATH="${BUILD_DIR}/${DMG_NAME}.dmg"
DMG_STAGING="${BUILD_DIR}/dmg-staging"

# Build the .app first if it doesn't exist
if [[ ! -d "$APP_BUNDLE" ]]; then
    echo "Building .app bundle first..."
    VERSION="$VERSION" "${SCRIPT_DIR}/build-app.sh" "$ARCH"
fi

echo "Creating DMG: ${DMG_NAME}.dmg..."

# Clean staging area
rm -rf "$DMG_STAGING"
mkdir -p "$DMG_STAGING"

# Copy app to staging
cp -R "$APP_BUNDLE" "$DMG_STAGING/"

# Create Applications symlink for drag-to-install
ln -s /Applications "$DMG_STAGING/Applications"

# Create a background instructions file
cat > "$DMG_STAGING/.background_readme.txt" <<'EOF'
Drag AgentShield to Applications to install.

Then open Terminal and run:
  agentshield setup
  agentshield login

Or install via Homebrew:
  brew tap AI-AgentLens/tap && brew install agentshield
EOF

# Remove any existing DMG
rm -f "$DMG_PATH"

# Create DMG
hdiutil create \
    -volname "$APP_NAME" \
    -srcfolder "$DMG_STAGING" \
    -ov \
    -format UDZO \
    -imagekey zlib-level=9 \
    "$DMG_PATH"

# Cleanup staging
rm -rf "$DMG_STAGING"

echo "✅ DMG created: ${DMG_PATH}"
ls -lh "$DMG_PATH"

# Output sha256 for release notes
echo ""
echo "SHA256:"
shasum -a 256 "$DMG_PATH"
