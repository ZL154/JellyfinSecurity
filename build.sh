#!/bin/bash
# Build and package the Jellyfin 2FA plugin (fat package by default)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/src/Jellyfin.Plugin.TwoFactorAuth"
MODE="${1:-fat}"
INSTALL_FLAG="${2:-}"
OUTPUT_DIR="$SCRIPT_DIR/dist/TwoFactorAuth"

if [ "$MODE" = "--install" ]; then
    MODE="fat"
    INSTALL_FLAG="--install"
fi

if [ "$MODE" = "fat" ]; then
    RIDS=(linux-x64 linux-arm64 linux-musl-x64)
else
    RIDS=("$MODE")
    OUTPUT_DIR="$SCRIPT_DIR/dist/TwoFactorAuth-$MODE"
fi

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Build managed assemblies once without RID (architecture-agnostic).
BASE_PUBLISH_DIR="$SCRIPT_DIR/dist/publish-base"
rm -rf "$BASE_PUBLISH_DIR"
echo "Building managed plugin (Release, no RID)..."
dotnet publish "$PROJECT_DIR" -c Release --self-contained false -o "$BASE_PUBLISH_DIR" --nologo

for file in \
    Jellyfin.Plugin.TwoFactorAuth.dll \
    Otp.NET.dll \
    QRCoder.dll \
    Fido2.dll \
    Fido2.Models.dll \
    NSec.Cryptography.dll \
    System.Formats.Cbor.dll \
    MaxMind.Db.dll \
    QuestPDF.dll \
    IdentityModel.OidcClient.dll \
    IdentityModel.dll \
    Microsoft.IdentityModel.Abstractions.dll \
    Microsoft.IdentityModel.JsonWebTokens.dll \
    Microsoft.IdentityModel.Logging.dll \
    Microsoft.IdentityModel.Tokens.dll \
    System.IdentityModel.Tokens.Jwt.dll \
; do
    if [ -f "$BASE_PUBLISH_DIR/$file" ]; then
        cp "$BASE_PUBLISH_DIR/$file" "$OUTPUT_DIR/"
    fi
done

for RID in "${RIDS[@]}"; do
    PUBLISH_DIR="$SCRIPT_DIR/dist/publish-$RID"
    rm -rf "$PUBLISH_DIR"
    echo "Building plugin (Release, RID=$RID)..."
    dotnet publish "$PROJECT_DIR" -c Release -r "$RID" --self-contained false -o "$PUBLISH_DIR" --nologo

    NATIVE_DIR="$PUBLISH_DIR/runtimes/$RID/native"
    TARGET_NATIVE_DIR="$OUTPUT_DIR/runtimes/$RID/native"
    mkdir -p "$TARGET_NATIVE_DIR"

    # Some packages place native libs under runtimes/<rid>/native, others at publish root.
    if [ -d "$NATIVE_DIR" ]; then
        cp "$NATIVE_DIR"/* "$TARGET_NATIVE_DIR/" 2>/dev/null || true
    fi
    cp "$PUBLISH_DIR"/*.so "$TARGET_NATIVE_DIR/" 2>/dev/null || true

    # Jellyfin/.NET in this plugin scenario probes native libs from plugin root.
    # Keep a copy at root to avoid QuestPDF load failures in containers.
    cp "$PUBLISH_DIR"/*.so "$OUTPUT_DIR/" 2>/dev/null || true
done

# Copy meta.json
cp "$PROJECT_DIR/meta.json" "$OUTPUT_DIR/"

echo ""
echo "Plugin built to: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"

# Install if --install flag passed
if [ "$INSTALL_FLAG" = "--install" ]; then
    PLUGIN_DIR="${JELLYFIN_DATA:-$HOME/.local/share/jellyfin}/plugins/TwoFactorAuth"
    rm -rf "$PLUGIN_DIR"
    cp -r "$OUTPUT_DIR" "$PLUGIN_DIR"
    echo ""
    echo "Installed to: $PLUGIN_DIR"
    echo "Restart Jellyfin to load the plugin."
fi
