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

# Copy plugin DLL + non-Jellyfin runtime dependencies. Anything Jellyfin
# already provides (System.*, Microsoft.*) must NOT be copied — Jellyfin
# rejects plugin assemblies whose names collide with the host. The list
# below tracks PackageReferences in Jellyfin.Plugin.TwoFactorAuth.csproj.
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
; do
    if [ -f "$SCRIPT_DIR/dist/publish/$file" ]; then
        cp "$SCRIPT_DIR/dist/publish/$file" "$OUTPUT_DIR/"
    fi
done

# Native libraries — Fido2's NSec.Cryptography depends on libsodium and
# QuestPDF needs libQuestPdfSkia. Both ship as platform-specific binaries
# under runtimes/<rid>/native/. Copy the matching ones for the deployment
# OS so they sit next to the DLLs (which is where the .NET runtime probes).
# For a Linux Docker target (the primary deployment), copy linux-x64.
NATIVE_DIR_LINUX="$SCRIPT_DIR/dist/publish/runtimes/linux-x64/native"
if [ -d "$NATIVE_DIR_LINUX" ]; then
    mkdir -p "$OUTPUT_DIR/runtimes/linux-x64/native"
    cp "$NATIVE_DIR_LINUX"/*.so "$OUTPUT_DIR/runtimes/linux-x64/native/" 2>/dev/null || true
fi
# NOTE: Jellyfin's plugin manager scans EVERY .dll under the plugin dir as
# if it's a managed assembly, including ones in runtimes/<rid>/native/.
# Windows native .dlls (libgcc_s_seh-1.dll, libsodium.dll, qpdf.dll, etc.)
# are unmanaged binaries — when Jellyfin tries to load them as managed
# assemblies it throws and disables the whole plugin. We therefore only
# bundle the Linux .so set (the primary deployment target). Admins on
# Windows / macOS need a runtime that supplies libsodium and a Skia native
# (or use the Docker image). Documented in README.

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
