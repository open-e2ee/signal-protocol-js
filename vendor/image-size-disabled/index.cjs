'use strict';

// Replaces the `image-size` package, which has open denial-of-service
// advisories (GHSA-w3rx-r6r6-pgpr, GHSA-5p2g-fcmc-qvqq) and no fixed release
// in any version. It reaches this dependency graph only through Metro's
// image-asset pipeline, and nothing in this repository bundles image assets.
// Fail loudly if that ever changes.
function disabled() {
  throw new Error(
    'image-size is disabled in this repository: the package has unfixed ' +
      'denial-of-service advisories and nothing here parses image assets. ' +
      'See the "overrides" entry in package.json.'
  );
}

module.exports = disabled;
module.exports.imageSize = disabled;
module.exports.default = disabled;
