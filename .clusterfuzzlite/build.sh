#!/bin/bash -eu
# Builds the package and compiles every fuzz target in fuzz/ with Jazzer.js.

cd "$SRC/signal-protocol-js"

# The committed lockfile is written by npm 11. The base image ships an older
# npm major, which computes a different dependency tree and rejects the
# lockfile, so align with the npm major the CI and release pipelines use.
npm install -g npm@11

npm ci --ignore-scripts
npm run build

# Jazzer.js is only needed inside the fuzzing container, so it is not a
# package devDependency. Pinned to 2.1.0: it compiles its libFuzzer addon
# from source at install time (hence no --ignore-scripts), which is the only
# arrangement that works on this base image — the 4.x prebuilt binaries
# require a newer glibc than the image carries.
npm install --no-save @jazzer.js/core@2.1.0

for fuzz_target in fuzz/fuzz-*.js; do
  compile_javascript_fuzzer signal-protocol-js "$fuzz_target" --sync
done
