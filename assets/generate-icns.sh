#!/bin/bash
# Generate .icns from icon.svg
# Requires: brew install librsvg (for rsvg-convert)
# Alternative: use sips if you have a PNG already

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SVG="$SCRIPT_DIR/icon.svg"
ICONSET="$SCRIPT_DIR/icon.iconset"
ICNS="$SCRIPT_DIR/icon.icns"

# Check for rsvg-convert
if ! command -v rsvg-convert &>/dev/null; then
    echo "Installing librsvg (for rsvg-convert)..."
    brew install librsvg
fi

# Create iconset directory
rm -rf "$ICONSET"
mkdir -p "$ICONSET"

# Generate all required sizes
sizes=(16 32 64 128 256 512 1024)
for size in "${sizes[@]}"; do
    rsvg-convert -w "$size" -h "$size" "$SVG" -o "$ICONSET/icon_${size}x${size}.png"
done

# Rename to Apple's expected naming convention
cp "$ICONSET/icon_16x16.png"     "$ICONSET/icon_16x16.png"
cp "$ICONSET/icon_32x32.png"     "$ICONSET/icon_16x16@2x.png"
cp "$ICONSET/icon_32x32.png"     "$ICONSET/icon_32x32.png"
cp "$ICONSET/icon_64x64.png"     "$ICONSET/icon_32x32@2x.png"
cp "$ICONSET/icon_128x128.png"   "$ICONSET/icon_128x128.png"
cp "$ICONSET/icon_256x256.png"   "$ICONSET/icon_128x128@2x.png"
cp "$ICONSET/icon_256x256.png"   "$ICONSET/icon_256x256.png"
cp "$ICONSET/icon_512x512.png"   "$ICONSET/icon_256x256@2x.png"
cp "$ICONSET/icon_512x512.png"   "$ICONSET/icon_512x512.png"
cp "$ICONSET/icon_1024x1024.png" "$ICONSET/icon_512x512@2x.png"

# Remove non-standard names
rm -f "$ICONSET/icon_64x64.png" "$ICONSET/icon_1024x1024.png"

# Generate .icns
iconutil -c icns "$ICONSET" -o "$ICNS"

echo "Generated: $ICNS"

# Cleanup
rm -rf "$ICONSET"

echo "Done! Icon at: $ICNS"
