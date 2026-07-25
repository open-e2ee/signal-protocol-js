# Changelog

## 0.1.0-alpha.2

- **Fixed: every first message from a new contact was reported as an identity
  key change.** The receiver pinned a device's identity as the bare 32-byte
  X25519 key but compared incoming PreKeyMessages against the 67-byte versioned
  X25519 + Ed25519 composite tuple. The two encodings could never be equal, so
  first contact logged a SECURITY warning, fired `onIdentityKeyChanged` and
  `onSecurityEvent('identity_key_changed')`, and set `pendingVerification` -
  which gates sending. Apps surfacing those events showed a "safety number
  changed" warning to users who had never talked before, training them to
  dismiss the one warning that matters. First contact is now trust-on-first-use
  as documented; a genuine identity change on an already-pinned device still
  raises the event.
- **`DeviceRecord.identityKey` is now always the 67-byte composite tuple**, the
  same identity the relay publishes and safety numbers are computed over, so
  pinning and verification finally refer to the same thing. Zero length still
  means unpinned. `SesameManager.addDevice()` and `syncDeviceList()` reject
  identity bytes that are not a valid composite tuple instead of pinning a
  partial key. **Breaking for persisted state:** device records written by
  `0.1.0-alpha.1` hold 32-byte keys and will be treated as a changed identity.
  No migration is provided - this is pre-`1.0` and the alpha is not deployed;
  clear device records or re-pair.
- Fixed the mock storage adapter unpinning a device as soon as its session was
  archived, and dropping `pendingVerification`, which defeated the send gate.
- Fixed `syncDeviceList()` treating a device list carrying no identity keys as
  an identity change for every device, dropping live sessions and raising a
  security event on each sync.
- Added `keys.canonicalizeDeviceIdentityKey()`, `keys.isValidDeviceIdentityKey()`,
  `keys.compareDeviceIdentityKeys()`, and `keys.UNPINNED_DEVICE_IDENTITY_KEY`.
- Docs: signed prekey and Kyber last-resort prekey rotation is driven by
  `KEY_REFRESH_INTERVAL_MS_DEFAULT` (2 days), not the weekly cadence the JSDoc
  and prekey docs claimed. `docs/ERROR_HANDLING.md` no longer references a
  `signal.trustIdentity()` method that does not exist; the real API is
  `acceptIdentityRotation()`.

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
