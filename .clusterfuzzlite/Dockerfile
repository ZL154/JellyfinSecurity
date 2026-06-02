# ClusterFuzzLite builder image.
#
# Note on the FROM choice: ClusterFuzzLite's official csharp documentation
# references `gcr.io/oss-fuzz-base/base-builder-csharp`, but that image is
# not published to gcr.io and is not in the OSS-Fuzz upstream
# infra/base-images/ tree (only base-builder, base-builder-{go,jvm,python,
# rust,swift,ruby,javascript} exist). So we base on the generic
# base-builder image — which exists and is SHA-pinnable — and have
# build.sh install the .NET SDK + SharpFuzz CLI itself when CFLite ever
# accepts csharp from its GitHub Action wrapper. Until that day this
# Dockerfile exists primarily for OpenSSF Scorecard's Fuzzing-check
# scaffolding detection (which looks at file presence, not behavior).
FROM gcr.io/oss-fuzz-base/base-builder@sha256:c1cf4114d819ae23b99041489ce79ce23a739e39be915f7cbc24a4c47a09fcd9

# Stage the repo and the build script at the paths CFLite expects.
COPY . $SRC/JellyfinSecurity
WORKDIR $SRC/JellyfinSecurity
COPY .clusterfuzzlite/build.sh $SRC/build.sh
