#!/bin/bash -eu
# ClusterFuzzLite build script — runs inside the OSS-Fuzz base-builder-csharp
# image with $SRC pointing at the repo root, $OUT pointing at the artifact
# directory libFuzzer will read from, and $WORK as a scratch dir.
#
# Layout when ClusterFuzzLite runs us:
#   $SRC/JellyfinSecurity/      -- repo (COPYed in Dockerfile)
#   $OUT/                       -- libFuzzer puts the final binaries here
#   $WORK/                      -- scratch for builds, instrumented assemblies

cd "$SRC/JellyfinSecurity"

# 1. Publish the harness against the plugin's actual runtime DLLs.
dotnet publish tests/Jellyfin.Plugin.TwoFactorAuth.Fuzz \
    -c Release \
    -o "$WORK/publish" \
    --self-contained false \
    --nologo

# 2. Instrument the plugin assembly with SharpFuzz coverage probes. The
#    `sharpfuzz` CLI is preinstalled in the OSS-Fuzz csharp base image; it
#    rewrites the target DLL in place so libFuzzer can drive coverage-guided
#    fuzzing through the harness.
sharpfuzz "$WORK/publish/Jellyfin.Plugin.TwoFactorAuth.dll"

# 3. Stage the harness + its runtime deps into $OUT/PickRealClientIpFuzzer/
#    so libFuzzer can launch the harness from a single directory.
fuzzer_name="PickRealClientIpFuzzer"
mkdir -p "$OUT/$fuzzer_name"
cp -r "$WORK/publish/." "$OUT/$fuzzer_name/"

# 4. Create the libFuzzer launcher script CFLite expects at $OUT/<name>.
#    The launcher runs the .NET harness assembly which calls Fuzzer.Run().
cat > "$OUT/$fuzzer_name" <<EOF
#!/bin/bash
this_dir=\$(dirname "\$0")
LD_LIBRARY_PATH="\$this_dir/$fuzzer_name" \\
  dotnet "\$this_dir/$fuzzer_name/Jellyfin.Plugin.TwoFactorAuth.Fuzz.dll" "\$@"
EOF
chmod +x "$OUT/$fuzzer_name"
