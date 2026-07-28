# Changelog

## 0.1.0-alpha.7

- **Security (Convex group server):** structured rejection data now survives
  real deployments. Engine rejections and the adapter's own conflict and
  missing-group rejections are thrown as `ConvexError` values carrying
  `{ code, status, message }`; production Convex strips custom properties
  from plain errors, which silently disabled the client's documented
  `VERSION_CONFLICT` rebase-and-retry path on live deployments.
- Fixed the Convex group server reading snapshots and changes through a
  partial index range with a post-filter, which scanned every stored row for
  the group on each lookup; catch-up reads for long-lived groups could exceed
  Convex transaction limits and permanently fail. Snapshot lookups now use
  the full compound index and change reads constrain the version range in
  the index.
- **Security (groups):** the pending-member, requesting-member, and
  banned-member collections are now bounded by the same 1000-entry limit as
  full members, enforced during change application and on every validated
  state, with the client-side structural validation mirroring the caps. A
  single change could previously inflate a group's stored state without
  bound.
- The Convex group server now derives its server parameters once per isolate
  and caches them keyed by the environment secret, instead of re-deriving on
  every request; the deployment seed is also zeroized when validation of the
  configured secret fails, and `identify()` returning no identity is
  rejected with a structured `UNAUTHORIZED` error instead of a `TypeError`.
- Fixed `oe-groups trust-root` failing on Windows by importing its runtime
  modules via `file://` URLs.
- **Security (relay group bridge):** `ConvexSignalProtocolRelayServer.submitGroupChange`
  now rejects legacy six-argument submissions carrying a caller-selected
  epoch, matching `ConvexGroupServer`'s S13 guard; the relay bridge is now
  certified by its own run of the §14 conformance suite, and endorsement
  issuance is cryptographically verified against the reference server in the
  parity suite.
- Documented that the Convex group-server modules must be mounted inside the
  relay's generated `api.signal` namespace (`convex/signal/groups.ts` and
  `convex/signal/zkAuth.ts`); the previous top-level placement compiled
  cleanly but never enabled the relay's `groupServer` capability. Also
  documented snapshot-retention growth, the placeholder-PNI prohibition for
  `identify()`, and updated `docs/DEVIATIONS.md` to describe the enforcing
  group server and its unblinded profile-key issuance deviation.
- Added the production `defineConvexGroupServer` integration at
  `@open-e2ee/signal-protocol-sdk/remote/relay/convex/server`, including
  package-scoped canonical-state, signed-change, and historical-snapshot
  tables; S1–S14 enforcement; auth/profile-key credential issuance;
  group-send endorsements; environment-secret custody; and the
  `oe-groups trust-root` CLI. Profile-key credential issuance receives the
  raw profile key and is not blinded. The public
  `ConvexSignalProtocolRelayApi` now makes `groups` and `zkAuth` optional,
  and the relay advertises its `groupServer` capability only when both API
  modules are configured.
- **Breaking (groups):** client configuration now accepts one versioned,
  serialized `trustRoot` instead of separate credential, change-signing,
  profile-key credential, and endorsement trust fields. Group identities are
  derived from the client's own identity configuration, and group state
  defaults to the SDK storage layer. Relays may expose an optional
  `groupServer` capability containing the server and credential-issuance
  transports; clients use it automatically while retaining explicit server
  and issuer overrides for custom deployments. Configuring groups without
  either the relay capability or complete explicit overrides now fails with a
  targeted configuration error, and configured endorsement verification must
  match the endorsement root in the pinned blob. No compatibility aliases are
  provided.
- **Breaking (groups): removed the borrowed `v2` naming from the group
  system.** `GroupsV2Manager` is now `GroupManager`,
  `GroupsV2ManagerOptions` is now `GroupManagerOptions`, the client
  configuration key is now `groups`, and the client group methods no longer
  carry a `V2` suffix. The implementation now lives entirely under
  `internal/groups/`. No compatibility aliases are provided.
- **Breaking (group identifiers):** `GROUP_V2_PREFIX` is now
  `GROUP_ID_PREFIX`, and group IDs use the package-owned
  `open-e2ee:group:` prefix. The pre-launch prefix has no migration or
  dual-read path.
- **Breaking (group validation):** `validateChange` is now
  `validateChangeStructure` to make clear that it checks well-formedness, not
  authorization. It now rejects already-banned additions and promotion
  targets that are absent after explicit ACI/PNI-to-ServiceId widening.
- **Breaking (group membership):** group setup now requires the account's
  profile-key credential issuer, trust root, and 32-byte profile key.
  `createGroup()` and `addGroupMember()` accept either a target with verified
  presentation material for an immediate add or a ServiceId-only invitation;
  invited targets call `acceptGroupMemberInvitation()` and present their own
  profile key. The old `{ aciBytes, profileKey }` direct-add path is removed,
  and runtime inputs must match exactly one variant's complete field and byte
  domains instead of being omitted, partially discarded, or processed
  ambiguously.
- Fixed pending-member promotion comparing 16-byte ACI/PNI values directly
  with 17-byte ServiceIds, silently skipping valid promotions. Promotions now
  fail when the pending entry is absent or the destination is already a
  member, preserve the invited role, and apply in the normative action order.
- Fixed `AccessRequired.ANY` excluding non-members, and implemented the full
  target-sensitive group authorization table including self-leave,
  self-decline, self-withdraw, invite-link requests, and member-label access.
- Fixed group mutations encoding their editor as a raw 16-byte ACI instead of
  a canonical 17-byte ServiceId, and consistently use full ServiceIds for
  authorization principals and banned-member checks.
- Fixed encrypted group state storing only the 32-byte group identifier in
  `publicKey`; it now stores the canonical 96-byte serialized
  `GroupPublicParams` required for credential verification.
- **Breaking (group server contract):** group changes now carry exact
  server-accepted `actions`, `changeEpoch`, and the independently presented
  invite-link password; clients no longer submit a replacement encrypted
  snapshot. Group servers must also implement the password-gated reduced
  `getGroupJoinInfo` read and exact-version `getGroup` snapshots for race-safe
  post-join baselines. Every full-state response now carries a
  `baselineSignature` over its group ID, version, and exact encrypted-state
  bytes; clients accept signed snapshots only for a first baseline or after
  their own verified revocation ends an entitlement span. Change submissions
  no longer carry a caller-selected epoch: the server derives epoch 0, 5, or
  6 from the canonical accepted actions and signs it, and clients recompute
  the same value exactly before applying the change.
- **Security (groups):** every applied change is now checked for its server
  signature, group binding, strict sequence, pre-state authorization, and
  structural validity. Signatures bind the exact accepted actions together
  with their compatibility epoch.
- **Breaking (group state storage):** `IGroupStateStore` now atomically stores
  accepted state with a durable sender-key rotation barrier and exposes
  revision-checked barrier read/clear methods. Removal, ban, and termination
  block every group-send path until rotation succeeds, including after
  callback failure or client reconstruction. Endorsement invalidation remains
  non-fatal.
- **Security (group sending):** managed groups now require verified accepted
  state at send time showing an unterminated group, current ACI membership,
  and no ban on either of the sender's own identifiers. A stored master key
  with missing state fails closed until sync restores a verified baseline;
  ad-hoc sender-key groups with no group master key remain unaffected.
- **Security (group governance):** every non-terminated group must retain at
  least one stored administrator. Creation, server-side atomic application,
  complete-state client transitions, and signed baselines enforce the same
  result-state invariant; last administrators may leave only while installing
  a successor atomically. The deliberately member-free invite-link projection
  remains private and is exempt only for its single additive self-join or
  self-request action, with direct membership installed through the complete
  signed baseline that follows.
- **Security (groups):** authentication credentials now represent a missing
  PNI as true absence instead of a shared nil-UUID principal. Issuance and
  client encryption/decryption reject nil identifiers; the reference server
  applies ACI/PNI alias matching to roles, reads, bans, deterministic
  attribution, and requester-specific pending status without attempting to
  decrypt opaque identifiers.
- **Security (groups):** access-control fields now enforce their
  specification-defined domains on creation, mutation, and decryption.
  Out-of-domain hostile state fails closed, so `members = ANY` cannot become a
  password-free self-add or third-party recruitment path.
- **Security (groups):** every creation or action path that introduces or
  changes a profile-key ciphertext now requires a credential presentation
  bound to the submitted ACI, profile key, and group. Missing, empty, or
  mismatched proofs are rejected, pending invitations carry no profile
  material, and verified request credentials are stripped before state or
  signed history is persisted.
- **Security (group creation):** creation submissions no longer carry
  client-asserted invitation provenance or pre-existing requesting and banned
  entries. The enforcing server derives the creator and timestamp, signs only
  canonical version zero, and the creator verifies and caches that exact
  baseline instead of its optimistic submission.
- **Security (groups):** group actions now have exact per-action field
  surfaces. The reference relay rejects client-asserted inviters, timestamps,
  join revisions, labels, and PNIs where those fields are not defined; derives
  accepted provenance and join metadata itself; and signs only that canonical
  form. One shared exhaustive wire-domain validator makes the reference server
  reject malformed submissions before applying or signing and makes clients
  reject malformed signed actions and baselines before decrypting or
  installing them, including wrong primitive, container, byte, enum,
  timestamp, and join-revision types.
- **Security (groups):** nil or undecryptable pending, requesting, and banned
  entry targets are now retained byte-for-byte as inert quarantined entries
  instead of making a signed revision permanently unappliable. Activation
  targets remain strict, and administrator delete actions can remove
  quarantined entries by their preserved ciphertext.
- **Security (groups):** change-log reads in the executable reference server
  are authorized at the requested historical snapshot and include the first
  signed transition that removes, bans, or un-invites the requester, while
  withholding every later transition.
- Fixed PNI-to-ACI promotion when both ACI- and PNI-keyed invitations exist.
  Equal-role aliases are consumed atomically into one ACI member; conflicting
  roles are rejected by both authorization monitors and can be resolved by
  declining either invitation before promotion. Self-decline attribution now
  follows the invitation alias named by the action, including when the same
  requester also matches an ACI membership.
- **Breaking (groups):** omitting `serverSigningPublicKey` no longer silently
  selects unsigned group history. Deployments without a conforming signing
  server must explicitly set `allowUnauthenticatedGroupHistory: true`, which
  continues to emit the documented security warning.
- The development-only in-memory relay is now the executable reference for the
  complete encrypted group-server authorization contract: zk presentation
  verification, server-derived requester attribution, pre-state authorization,
  atomic sequencing, group binding, exact-byte signing, reduced invite reads,
  independent invite-password checks, ACI/PNI field separation, and
  representation-independent structural validation. Repeated invite joins are
  idempotent. No production enforcing group server is supplied; explicitly
  opting into operation without a pinned signing key emits the documented
  non-conforming-deployment warning.
- Fixed `deserializeGroupPublicParams()` calling CommonJS `require()` from the
  ESM package, which crashed the first real server-side group credential
  verification before the proof could be checked.

## 0.1.0-alpha.6

- **Breaking (key derivation): the X3DH and PQXDH info strings now name this
  application and this KEM.** `X3DH_INFO_DEFAULT` becomes `OpenE2EE` and
  `PQXDH_INFO_DEFAULT` becomes `OpenE2EE_X25519_SHA-256_ML-KEM-1024`; they were
  `WhisperText` and `WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024`. Both
  parameters were wrong. PQXDH §2.2 requires the info string to name the
  `pqkem` actually in use, and the SDK runs ML-KEM-1024 (FIPS 203), not
  round-3 CRYSTALS-Kyber — so two implementations feeding an identical label
  derived *different* shared secrets, which is precisely what the info string
  exists to prevent. And §2.1 defines `info` as an identifier of the
  application deriving the key; this SDK is not Signal Messenger. **Sessions
  established under the old labels derive a different `SK` and cannot be
  continued** — clear session state or re-establish. Nothing else about the
  derivation changed. An application that needs `libsignal`'s known-answer
  vectors can still set `protocolStrategy.keyExchangeInfoString` to the old
  label explicitly. `docs/DEVIATIONS.md` §2.1 recorded this as an open
  specification violation and now records it as fixed.
- **Breaking (naming): every remaining exported identifier spelled `Signal`
  now spells `SignalProtocol`.** "Signal" alone names a product and an
  organization this project has no affiliation with; the specifications it
  implements are the Signal Protocol, and the exported names now say so. This
  renames roughly ninety exports — `MockSignalStore` to
  `MockSignalProtocolStore`, `ISignalLocalStore` to `ISignalProtocolLocalStore`,
  `SignalServiceCipher` to `SignalProtocolServiceCipher`, `defaultSignalLogger`
  to `defaultSignalProtocolLogger`, `SignalMessage` and `PreKeySignalMessage` to
  `SignalProtocolMessage` and `PreKeySignalProtocolMessage`, and so on
  throughout. No aliases are provided. Nothing on the wire changes: the message
  type names were protobuf type labels, which protobuf does not serialize, and
  every domain-separation and key-derivation constant is untouched — including
  the `Signal_ZKGroup_*`, `Signal_ZKCredential_*`, and `Signal_PQCKA_*`
  families, which are byte inputs to key derivation rather than names.
- The public-surface guard now asserts that each retired name stays absent, and
  is typechecked in CI. It is entirely type-level, so running it under jest —
  which transpiles without typechecking — could never have failed; only `tsc`
  can catch a reintroduced name.
- **Breaking (`SessionEstablisher`): `failedDeviceErrors` is now required.** The
  exported `SessionEstablisher` type declared it optional, so an implementation
  could return a result that said nothing about which devices failed and why.
  Every implementation must now return the array; return `[]` when nothing
  failed. Implementations that already populate it need no change.
- Changed device establishment to surface a failing device's own error instead
  of a generic wrapper, and to route it through the retry classifier so a
  transient failure is retried rather than failing the whole send on the first
  attempt.
- Fixed the retry classifier treating permanent session-establishment failures
  as retryable. `UNTRUSTED_IDENTITY`, `SIGNATURE_VERIFICATION_FAILED`,
  `RECIPIENT_NOT_REGISTERED`, and `PREKEY_FETCH_RATE_LIMITED` now fail
  immediately. They reach the classifier only because of the change above;
  retrying a security event delays it reaching the caller, and retrying a
  prekey-drainage rate limit aggravates the condition it reports.
- Fixed the exported in-memory relay delivering reorder-buffered envelopes to a
  first subscriber, which duplicated messages that reordering had already held
  back, and fixed reorder state being lost when a subscriber was replaced.

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
- Corrected group-system source comments that described the permission model as
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
- Fixed `MockSignalProtocolRelayServer.clear()` retaining idempotency receipts, which
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
