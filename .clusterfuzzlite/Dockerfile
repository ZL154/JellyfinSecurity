# ClusterFuzzLite C# builder image.
# Uses the upstream OSS-Fuzz csharp base image, which ships SharpFuzz CLI +
# libFuzzer + the .NET SDK. ClusterFuzzLite mounts the repo at $SRC and runs
# ./build.sh inside.
#
# TODO: pin to a specific SHA once we know the image is working in our
# CFLite workflow runs. Floating tag is the canonical reference per
# https://google.github.io/clusterfuzzlite/build-integration/csharp-lang/
FROM gcr.io/oss-fuzz-base/base-builder-csharp

# Stage the repo and the build script at the paths CFLite expects.
COPY . $SRC/JellyfinSecurity
WORKDIR $SRC/JellyfinSecurity
COPY .clusterfuzzlite/build.sh $SRC/build.sh
