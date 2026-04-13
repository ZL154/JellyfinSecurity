#!/bin/bash
# Build and package the Jellyfin 2FA plugin

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/src/Jellyfin.Plugin.TwoFactorAuth"
OUTPUT_DIR="$SCRIPT_DIR/dist/TwoFactorAuth"

# Clean output
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Build
echo "Building plugin (Release)..."
dotnet publish "$PROJECT_DIR" -c Release -o "$SCRIPT_DIR/dist/publish" --nologo

# Copy only the required files
for file in Jellyfin.Plugin.TwoFactorAuth.dll Otp.NET.dll QRCoder.dll; do
    cp "$SCRIPT_DIR/dist/publish/$file" "$OUTPUT_DIR/"
done

# Copy meta.json
cp "$PROJECT_DIR/meta.json" "$OUTPUT_DIR/"

echo ""
echo "Plugin built to: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"

# Install if --install flag passed
if [ "$1" = "--install" ]; then
    PLUGIN_DIR="${JELLYFIN_DATA:-$HOME/.local/share/jellyfin}/plugins/TwoFactorAuth"
    rm -rf "$PLUGIN_DIR"
    cp -r "$OUTPUT_DIR" "$PLUGIN_DIR"
    echo ""
    echo "Installed to: $PLUGIN_DIR"
    echo "Restart Jellyfin to load the plugin."
fi
