# ClusterFuzzLite build environment. The fuzz targets live in fuzz/ and run
# against the compiled dist/ output, built inside this container by build.sh.
FROM gcr.io/oss-fuzz-base/base-builder-javascript

COPY . $SRC/signal-protocol-js
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/signal-protocol-js
