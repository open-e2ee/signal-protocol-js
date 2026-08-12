# ClusterFuzzLite build environment. The fuzz targets live in fuzz/ and run
# against the compiled dist/ output, built inside this container by build.sh.
# The Ubuntu 24.04 variant matches project.yaml's base_os_version: its glibc
# is new enough for Jazzer.js 4.0.0's prebuilt libFuzzer addon.
FROM gcr.io/oss-fuzz-base/base-builder-javascript:ubuntu-24-04@sha256:9478c400c7b710a74ed26b7ea71c02e4ee9a0d44dee5aa0fdf6b7b20f402e6f7

COPY . $SRC/signal-protocol-js
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/signal-protocol-js
