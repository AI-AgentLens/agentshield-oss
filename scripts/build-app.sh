#!/bin/bash
# Build AgentShield.app macOS application bundle.
# Usage: ./scripts/build-app.sh [arch]
# arch: arm64 (default) or amd64
# Requires: the Go binary already built in ./build/ or ./dist/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ARCH="${1:-arm64}"
VERSION="${VERSION:-dev}"
BUILD_DIR="${PROJECT_DIR}/build"
APP_NAME="AgentShield"
APP_BUNDLE="${BUILD_DIR}/${APP_NAME}.app"
BUNDLE_ID="com.aiagentlens.agentshield"

echo "Building ${APP_NAME}.app (${ARCH})..."

# Find the binary
BINARY=""
for candidate in \
    "${BUILD_DIR}/agentshield" \
    "${PROJECT_DIR}/dist/agentshield_darwin_${ARCH}/agentshield" \
    "${PROJECT_DIR}/dist/agentshield_darwin_${ARCH}_v1/agentshield"; do
    if [[ -f "$candidate" ]]; then
        BINARY="$candidate"
        break
    fi
done

if [[ -z "$BINARY" ]]; then
    echo "No binary found. Building..."
    cd "$PROJECT_DIR"
    make build
    BINARY="${BUILD_DIR}/agentshield"
fi

# Find icon
ICON="${PROJECT_DIR}/assets/icon.icns"
if [[ ! -f "$ICON" ]]; then
    echo "Warning: icon.icns not found at ${ICON}, building without icon"
    ICON=""
fi

# Clean previous bundle
rm -rf "$APP_BUNDLE"

# Create .app structure
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

# Copy binary
cp "$BINARY" "${APP_BUNDLE}/Contents/MacOS/agentshield"
chmod +x "${APP_BUNDLE}/Contents/MacOS/agentshield"

# Copy companion binary if available
for compliance_bin in \
    "${BUILD_DIR}/agentcompliance" \
    "${PROJECT_DIR}/compliance-bin/agentcompliance_darwin_${ARCH}/agentcompliance"; do
    if [[ -f "$compliance_bin" ]]; then
        cp "$compliance_bin" "${APP_BUNDLE}/Contents/MacOS/agentcompliance"
        chmod +x "${APP_BUNDLE}/Contents/MacOS/agentcompliance"
        break
    fi
done

# Copy icon
if [[ -n "$ICON" ]]; then
    cp "$ICON" "${APP_BUNDLE}/Contents/Resources/AppIcon.icns"
fi

# Copy policy packs
if [[ -d "${PROJECT_DIR}/packs" ]]; then
    mkdir -p "${APP_BUNDLE}/Contents/Resources/packs/mcp"
    cp "${PROJECT_DIR}/packs/"*.yaml "${APP_BUNDLE}/Contents/Resources/packs/" 2>/dev/null || true
    cp "${PROJECT_DIR}/packs/community/mcp/"*.yaml "${APP_BUNDLE}/Contents/Resources/packs/mcp/" 2>/dev/null || true
fi

# Copy default config
if [[ -f "${PROJECT_DIR}/configs/default_policy.yaml" ]]; then
    mkdir -p "${APP_BUNDLE}/Contents/Resources/configs"
    cp "${PROJECT_DIR}/configs/default_policy.yaml" "${APP_BUNDLE}/Contents/Resources/configs/"
fi

# Create launcher script that sets up PATH symlinks on first run
# Note: macOS filesystem is case-insensitive, so we use "launcher" not "AgentShield"
cat > "${APP_BUNDLE}/Contents/MacOS/launcher" <<'LAUNCHER'
#!/bin/bash
# AgentShield launcher — installs CLI tools to PATH and opens terminal
DIR="$(cd "$(dirname "$0")" && pwd)"

# Symlink binaries into /usr/local/bin (or /opt/homebrew/bin on ARM)
if [[ "$(uname -m)" == "arm64" ]]; then
    BIN_DIR="/opt/homebrew/bin"
else
    BIN_DIR="/usr/local/bin"
fi

mkdir -p "$BIN_DIR" 2>/dev/null || true

# Only create symlinks if they don't already exist or point elsewhere
for tool in agentshield agentcompliance; do
    src="${DIR}/${tool}"
    dst="${BIN_DIR}/${tool}"
    if [[ -f "$src" ]]; then
        if [[ ! -e "$dst" ]] || [[ "$(readlink "$dst" 2>/dev/null)" != "$src" ]]; then
            ln -sf "$src" "$dst" 2>/dev/null || sudo ln -sf "$src" "$dst"
        fi
    fi
done

# Copy packs to ~/.agentshield if not present
RESOURCES="$(cd "${DIR}/../Resources" && pwd)"
if [[ -d "${RESOURCES}/packs" ]] && [[ ! -d "$HOME/.agentshield/packs" ]]; then
    mkdir -p "$HOME/.agentshield/packs/mcp"
    cp -n "${RESOURCES}/packs/"*.yaml "$HOME/.agentshield/packs/" 2>/dev/null || true
    cp -n "${RESOURCES}/packs/mcp/"*.yaml "$HOME/.agentshield/packs/mcp/" 2>/dev/null || true
fi

# If launched from Finder (no terminal), open Terminal with setup
if [[ -z "${TERM_PROGRAM:-}" ]] && [[ -z "${SSH_CLIENT:-}" ]]; then
    osascript -e "
        tell application \"Terminal\"
            activate
            do script \"echo '✅ AgentShield installed. Run: agentshield setup' && agentshield version\"
        end tell
    "
else
    # Already in terminal, just run
    exec "${DIR}/agentshield" "$@"
fi
LAUNCHER
chmod +x "${APP_BUNDLE}/Contents/MacOS/launcher"

# Create Info.plist
cat > "${APP_BUNDLE}/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>launcher</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundleDisplayName</key>
    <string>${APP_NAME}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright © 2026 AI Agent Lens. Apache 2.0 License.</string>
</dict>
</plist>
PLIST

echo "✅ Built: ${APP_BUNDLE}"
echo "   Binary: ${APP_BUNDLE}/Contents/MacOS/agentshield"
echo "   Launcher: ${APP_BUNDLE}/Contents/MacOS/launcher"
ls -la "${APP_BUNDLE}/Contents/MacOS/"
