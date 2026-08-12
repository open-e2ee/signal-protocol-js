#!/bin/bash -eu
# Builds the package and compiles every fuzz target in fuzz/ with Jazzer.js.

cd "$SRC/signal-protocol-js"

# The committed repository lockfile is written by npm 11, and the base
# image's npm 10 computes a different peer tree and rejects it. npm 11 is
# fetched as a checksum-pinned tarball and run in place: a lockfile entry
# for the npm package would put npm's own vendored dependency tree on the
# repository's vulnerability-scanning surface.
NPM_VERSION=11.19.0
NPM_SHA256=31e9770f7dc71119a58509353b27917557aaf0ac9b5ef1a0465ee7d8ec67ae75
curl -fsSL -o /tmp/npm.tgz "https://registry.npmjs.org/npm/-/npm-${NPM_VERSION}.tgz"
echo "${NPM_SHA256}  /tmp/npm.tgz" | sha256sum -c -
mkdir -p /tmp/npm11
tar -xzf /tmp/npm.tgz -C /tmp/npm11 --strip-components=1
npm11() { node /tmp/npm11/bin/npm-cli.js "$@"; }

npm11 ci --ignore-scripts
npm11 run build

# Jazzer.js is only needed inside this container, so it is pinned by the
# tooling lockfile rather than carried as a package devDependency, and
# installed with npm ci so the download is integrity-checked. The relative
# symlink makes the wrapper's node_modules/@jazzer.js/core/dist/cli.js path
# resolve, and stays valid inside the $OUT copy because the tooling
# directory travels with the project.
(cd .clusterfuzzlite/tooling && npm11 ci)
ln -s ../.clusterfuzzlite/tooling/node_modules/@jazzer.js node_modules/@jazzer.js

for fuzz_target in fuzz/fuzz-*.js; do
  compile_javascript_fuzzer signal-protocol-js "$fuzz_target" --sync
done
