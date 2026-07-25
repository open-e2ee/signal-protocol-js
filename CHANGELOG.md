# Changelog

## 0.1.0-alpha.5

- **Breaking (wording and one error message): "Signal" is no longer used as a
  loose shorthand.** Prose names the specifications "the Signal Protocol", the
  product "Signal Messenger", and the reference implementation `libsignal`;
  shipped source comments say "the reference implementation". Compatibility
  shorthand such as "Signal-style", "Signal-aligned", and "Signal-grade" is
  gone. Protocol domain-separation strings are untouched and remain
  byte-identical. The Expo storage error message no longer carries a "Signal
  Protocol " prefix; it now reads `Expo storage DB bindings not configured.
  Configure them from the host app before using Expo storage.` Anything
  matching on that text must be updated.
- Corrected GroupsV2 source comments that described the permission model as
  server-enforced. The checks in `access-control.ts` run on the client over
  already-decrypted state and bind an honest client, not a hostile one — the
  server sees only opaque state and a version number. Change application order
  is this SDK's own choice, taken from the proto field numbering for
  determinism, not an order the specifications define; and the SDK does not
  encrypt avatar content.
- Changed the exported in-memory relay to upsert EC and KEM one-time prekeys by
  `keyId`. Re-uploading a batch is now idempotent; consumers that relied on
  duplicate uploads inflating prekey counts will observe the corrected count.
- Changed the exported in-memory relay to enforce device IDs 1-5 and the
  production-contract `Maximum devices limit reached` error. Removed and
  disabled devices are excluded from active fanout, and unknown users now have
  no invented device.
- Fixed `MockSignalRelayServer.clear()` retaining idempotency receipts, which
  made a reused `clientMessageId` look already accepted after reset.
- Fixed the exported mock store and relay to structured-clone mutable values at
  every persistence/API boundary, matching serialization ownership in durable
  adapters for sessions, users, devices, prekeys, sender keys, and envelopes.
- Added opt-in, seeded mock failure controls for latency, disconnect/reconnect,
  duplicate and reordered delivery, storage writes, authorization rejection,
  and one-time-prekey exhaustion. Default construction is unchanged.
- Fixed duplicate relay delivery requesting a SESAME resend after the session
  layer had already rejected the replay, which could surface plaintext twice.
  Duplicate envelopes are now acknowledged without a retry request.
- Fixed session-establishment persistence failures being misreported as a
  problem with the peer. An adapter failure at the atomic commit seam now
  surfaces as `KEY_STORAGE_ERROR` with the adapter failure retained as the
  cause, instead of `RECIPIENT_NOT_REGISTERED` or `INVALID_PREKEY_BUNDLE`, so
  applications retry their own storage rather than refetching a bundle.
- Added shared storage contracts for Mock, Node, Web/IndexedDB, and Expo
  adapters, plus an extensible relay contract. Fixed Web/IndexedDB `UserRecord`
  decoding so `DeviceRecord.identityKey` remains an owned `Uint8Array`.
- Documentation now labels mock examples as real protocol and cryptography over
  simulated in-memory infrastructure. CI executes every classified mock snippet
  from the shipped onboarding, recipe, composition, and pricing docs against
  the packed package.
- Fixed the npm publish workflow folding registry warnings into the value it
  read as the current `latest` version. A warning containing a hyphen parsed as
  a prerelease, which after a stable release would have routed a prerelease to
  the `latest` dist-tag.

## 0.1.0-alpha.4

- **Security: a forged message header could force unbounded key derivation
  before authentication.** When an inbound message triggered a DH ratchet, the
  loop that drains the previous receiving chain ran once per message claimed by
  the header's `previousCounter` field — an attacker-controlled value that is
  not authenticated, and cannot be, because the message key that would
  authenticate it is what the loop derives. A single forged header could
  therefore pin a CPU and grow the session record without bound, from an
  unauthenticated sender. The catch-up is now bounded by the same skip limit
  that already governed the current chain, and rejects before deriving or
  storing anything.
- **Fixed: registration IDs could be generated as `16384`,** one past the 14
  bits the wire format reserves. Multi-recipient sealed sender masks with
  `0x3FFF` rather than rejecting, so such an ID was written to the wire as `0`,
  affecting roughly 1 install in 16,384. The range is now `[1, 16383]`.
- Fixed: the `AuthCredentialPresentation` documentation stated its privacy
  property backwards, describing the server as able to decrypt the ACI and PNI
  ciphertexts to learn which member is authenticating. The server verifies the
  proof without learning the member; only holders of the group's secret params
  can decrypt. The comment ships in the public package.
- Docs: `docs/DEVIATIONS.md` records where this profile follows, deliberately
  departs from, and extends the Signal Protocol specifications, and states
  plainly that the SDK is not wire-compatible with Signal Messenger or
  `libsignal`.

## 0.1.0-alpha.3

- Fix: the first inbound responder session is no longer archived into itself
  when a storage adapter surfaces device records synthesized from live protocol
  state; SESAME device state is snapshotted before protocol decryption, so a
  brand-new session can never appear pre-existing. Receiving on that session
  now records responder metadata correctly.
- Tests: the SESAME "Receiving Messages" spec suite now exercises the real
  SesameManager end to end (previously a file-local mock), covering active-
  session receive, responder synchronization, delayed and out-of-order
  delivery, transactional PreKey persistence, and identity replacement.

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
