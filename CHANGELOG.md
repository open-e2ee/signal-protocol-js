# Changelog

## 0.1.0-alpha.1

- Initial public alpha for the OpenE2EE Signal Protocol SDK's independently versioned,
  Signal Protocol-based APIs.
- Public package surface is dist-first with explicit platform and backend subpaths.
- Remote object uploads separate retry `requestId`s, canonical `objectId`s, and
  private provider keys. The Convex R2 integration accepts generated app modules
  directly and provides an optional server-only broker helper.
- ML-KEM Braid HEK follows the normative
  `SHA3-256(ek_seed || ek_vector)` order. Pre-release Braid sessions created
  with any earlier nonconforming order must be reset.
