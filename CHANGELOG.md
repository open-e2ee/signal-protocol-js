# Changelog

## 0.2.2

- **The unfixable `image-size` development dependency is replaced with an
  inert local stub.** Both open advisories against `image-size` cover every
  released version and have no fix. The package reaches the tree only
  through Metro's image-asset pipeline, which nothing in this repository
  exercises. An npm override now points it at a local package that throws
  on use, so the development install carries no known-vulnerable code and
  `npm audit` reports clean across the whole tree.

- **Continuous fuzzing runs against the parser seams.** ClusterFuzzLite
  builds Jazzer.js fuzz targets over the wire-message, sender-key,
  sealed-sender, and post-quantum ratchet decoders, the base64 conversions,
  and the persistent session-record codec, on every push, pull request, and
  manual dispatch. Writing the targets' rejection contract surfaced one
  defect, fixed here: a session record with a malformed map encoding
  escaped the codec as a `TypeError` instead of its controlled error.

- **The README carries the OpenSSF Best Practices badge.** The project
  earned the passing level at bestpractices.dev (project 14043).

- **`SECURITY.md` states the supported release line correctly.** The
  supported-versions table had not moved past 0.1.x; it now names 0.2.x
  and states the no-backports rule.

## 0.2.1

- **Two GitHub code-scanning findings in shipped code are fixed.** The
  URL-safe base64 conversions stripped trailing `=` padding with a `/=+$/`
  replace, which backtracks quadratically on input that is mostly `=`
  characters; padding is now stripped by index in linear time. The Node
  store's `getKey` probed the key file with `access()` before reading it,
  leaving a race window between the check and the read; it now reads
  directly and treats `ENOENT` as an absent key. Neither fix changes
  observable behavior on well-formed input. The scan's prototype-pollution
  alerts against the Node sender-key trees were confirmed false positives:
  every decoded dictionary level is rebuilt with a null prototype before it
  is indexed, and the full-interface tests already prove `__proto__` keys
  round-trip as plain data.

- **Vulnerable development-dependency versions are updated.** `js-yaml`,
  `nanoid`, `postcss`, and `brace-expansion` move past their published
  denial-of-service advisories. The two `image-size` advisories have no
  fixed release yet; they sit behind Metro's dev-time asset parsing and do
  not reach the published package, whose production dependencies audit
  clean.

- **`@noble/ciphers` moves to 2.3.0.** A routine minor update of the
  symmetric-cipher dependency, applied internally so the public Dependabot
  pull request can close against this release.

## 0.2.0

- **ML-KEM Braid key-agreement progress is now observable.** A new
  `protocolStrategy.onBraidProgress` callback reports a `BraidProgressEvent`
  after every braid-mode send and receive: the chunks this side has carried in
  the current epoch, the chunks the open transfers account for, the epoch, and
  whether the operation produced the epoch secret. Braid mode spreads one
  ML-KEM key agreement across many messages, and until now the chunk counts
  lived entirely inside the state machine, so a host had no way to show or log
  how far a ratchet had travelled. A direct-mode session never raises the
  callback. The hook is guarded exactly as `onProtocolSelected` is: a consumer
  that throws is logged and the protocol path continues.

- **The web store's atomic commits leave no window for a partial commit
  under tab death.** A dying page closes its IndexedDB connection
  gracefully, and a transaction that is idle at an await boundary then
  commits the writes it already holds. The atomic session/trust commit
  awaited each write in turn, so a tab death after the session write could
  commit the session while the consumed one-time prekey survived — CI
  observed exactly that once in Firefox. The identity-rotation commit
  deleted sessions through an awaited cursor walk, with the same windows
  between the new pin and each deletion. Both commits now enter every
  mutation in one synchronous batch before any settles, and a structural
  browser test fails on every run — no kill timing required — if a commit
  regains an await boundary between writes.

- **ML-KEM Braid key agreement completes.** A braid session now reaches its
  first epoch on both sides; before this it could not complete one at all,
  failing at the 66th alternating message with `Future epoch requested`.
  Braid is the default SCKA mode, so this was the default path. The two sides
  derive an epoch secret at very different times by design — the encapsulator
  from a single `Encaps1` over the header, the decapsulator only after
  `Decaps` over the full `ct1 ‖ ct2` — and everything sent across that gap has
  to go out under the epoch the peer can still follow. `spqrSend` took that
  epoch from the chunk it was emitting, so it lost it on exactly the messages
  that carry no chunk: once its ciphertext is acknowledged, a sender has
  nothing left to send until the encapsulation-key transfer finishes. It then
  fell back to its own SPQR epoch, which had already advanced, and the peer
  rejected the message. The braid state machine reports the epoch it is
  sending under on every send, including the empty ones, and `spqrSend` now
  uses that for both the message-key derivation and the wire epoch. No wire
  format, serialized state, or public API changes.

- **Session state survives cloning under a cross-realm `structuredClone`.**
  `cloneProtocolState` now checks once whether the ambient `structuredClone`
  returns objects of the calling realm, and falls back to its portable clone
  when it does not. Reached across a realm boundary — the arrangement a Node
  `vm` context produces, and one Jest builds for everything it runs —
  `structuredClone` returns a working `Map` whose prototype belongs to the
  other realm, so `instanceof Map` reports false for it everywhere downstream.
  Two silent losses followed: the session codec wrote such a `Map` as `{}`,
  and the portable clone rebuilt it as a prototype-only husk whose `size`
  getter throws. ML-KEM Braid felt this first, because its decoders are the
  only protocol state held in a `Map` that has to survive many clones — a
  receiving decoder discarded every chunk it had accepted, held at one chunk
  forever, and the key agreement could never complete. Single-realm hosts, the
  browser and React Native included, always took and still take the native
  path.

- **Restoring a braid encoder state now rejects a malformed polynomial.** Each
  `polys` element is a run of big-endian 16-bit coefficients. An odd-length
  element read one byte past the end. The resulting
  `undefined` folded into the low half of a coefficient. A truncated state
  therefore decoded to a polynomial with a fabricated final term. The decoder
  now refuses empty and odd-length elements, as the reference does.

- **Encoding a braid message now rejects a chunk that is not 32 bytes.** The
  slot holds exactly 32 bytes. A shorter chunk left the rest of the slot zeroed and
  encoded a chunk the sender never held. A longer chunk raised a bounds error
  that named no field. Both now fail and report the length offered. The braid
  state machine only ever produces 32-byte chunks.

- **Deriving an SPQR send key now rejects a zeroed chain key.** Two paths
  install one. An epoch advance for receiving alone installs a zeroed send
  chain key. Pruning writes one over each retired send chain. Deriving from
  either would key a message from a known constant. No production path reached
  that state, so the check is defence in depth.

- **The unused SPQR binary header codec is gone.** `serializeSPQRHeaderBinary`
  and `deserializeSPQRHeaderBinary` emitted an unversioned framing. No
  production path used it. The documented wire format does not describe it. Use
  the protobuf codec, which carries the version capability.

## 0.1.0

- **First non-prerelease release.** Identical in code to `0.1.0-alpha.14`;
  the version graduates the `0.1.0-alpha` series. The alpha label is retired
  because the condition it described no longer holds: every shipped store
  adapter now carries the full `ISignalProtocolLocalStore` contract with its
  graduation checklist running as continuous CI gates — the storage contract
  suites in real Chromium, Firefox, and WebKit, the backend-conformance kit
  on Hermes, and the interruption, storage-pressure, multi-tab, and soak
  suites. The `0.x` caveat stands: public APIs and persisted formats may
  change before `1.0`.

## 0.1.0-alpha.14

- **`ReactNativeSignalProtocolStore` is no longer experimental.** Every gate
  on its graduation checklist now runs continuously. A new
  backend-conformance kit — `runBackendConformance` and
  `assertBackendConformance`, exported from the package — executes thirteen
  cases against any `ReactNativeKeyValueStorage` implementation: round-trips,
  key listing, batch removal, in-order atomic application, checks evaluated
  against pre-batch state, null-guarded creation, all-or-nothing failure,
  exact-userId session removal with in-batch visibility, a single winner
  between concurrent guarded batches, and durability across reopen. Negative
  tests prove the kit catches a non-atomic backend, a prefix-matching
  session removal, and an unserialized backend. A new
  `createReferenceReactNativeBackend` — the executable specification of the
  backend contract — passes the kit on the Hermes engine React Native ships
  with, in a new CI gate that runs the bundled kit on the sha256-pinned
  Hermes CLI and requires an explicit pass sentinel, because Hermes exits 0
  on an unhandled async rejection. Interruption and storage-pressure jest
  suites drive the adapter over the reference backend: a simulated process
  kill before commit leaves every atomic security write all-or-nothing and
  a retry after reopen lands it whole, and quota exhaustion is exercised
  through every write path.

- **Quota exhaustion in the React Native store now surfaces as a typed
  error.** The backend contract gains a documented quota signal: a backend
  rejects the failing write with an error named `QuotaExceededError` and
  commits nothing. The adapter maps that signal to the public
  `StorageQuotaExceededError` (code `STORAGE_QUOTA_EXCEEDED`) at the same
  adapter-boundary seam the browser store uses, so both stores report
  storage pressure identically.

## 0.1.0-alpha.13

- **`IndexedDbSignalProtocolStore` is no longer experimental.** Every gate
  on its graduation checklist now runs continuously: the storage contract
  suites in real Chromium, Firefox, and WebKit; the multi-tab
  compare-and-set suite; the interruption suite; the storage-pressure
  suite; and a new soak gate. The soak drives 2,000 full
  construct/initialize/write/read/close cycles through the adapter in one
  real Chromium page, samples renderer memory — including ArrayBuffer
  backing stores, which plain JS-heap readings miss — after forced
  garbage collection, and fails if the late-run median of memory or
  per-cycle latency grows beyond a small tolerance over the early-run
  median. Injecting a per-cycle leak into the adapter turns both
  detectors red. `npm run soak:web-store` runs longer sessions on demand.
  The React Native adapter remains experimental; its checklist is
  unchanged.

- **Quota exhaustion in the browser store now surfaces as a typed error.**
  A write that exhausts the origin's storage quota rejects with the new
  public `StorageQuotaExceededError` (code `STORAGE_QUOTA_EXCEEDED`)
  instead of the raw engine `QuotaExceededError`. The mapping lives at the
  adapter boundary — one seam covering every store method, matched by
  error name so it holds across engines — and because every write commits
  in one atomic transaction, the typed error always means the write did
  not persist, never a partial record. A jest suite drives quota-shaped
  backend failures through every write path, and a new Chromium
  storage-pressure spec in the real-browser gate clamps the origin's
  quota, exhausts it against the real engine, and asserts the typed
  rejection, intact prior state, and a clean retry once space frees.

- The real-browser gate now includes an interruption suite: a Playwright
  spec destroys a real tab while a write is in flight — an atomic
  session/trust commit, an identity rotation, a fresh-database bootstrap,
  and a prekey batch — then reopens the store from a fresh tab and asserts
  it is readable and each atomic security commit landed all-or-nothing,
  never partially. The kills are sampled at several points inside each
  write, in all three engines, and a deterministic structural test backs
  them: each atomic security commit must open exactly one readwrite
  transaction, which is what makes every kill land all-or-nothing. Tearing
  either commit into two transactions turns the structural test red on
  every run.

- **Two tabs no longer race the IndexedDB store into silent data loss.** Two
  cross-connection races existed in the browser adapter. First, the database
  encryption key bootstrap read then wrote in separate transactions, so two
  tabs initializing a fresh database concurrently could each generate a
  different key — records written by the losing tab then failed authenticated
  decryption everywhere else. Second, first-contact trust pinning checked
  then wrote in separate transactions, so two tabs pinning different
  identities were both told `NEW_IDENTITY` while one pin silently replaced
  the other. Both paths now create through IndexedDB's `add()`, which refuses
  to overwrite: the bootstrap loser adopts the winner's key, and a
  first-contact loser re-evaluates its candidate against the pin that won.
  Rotation, verification, and the atomic session/trust commit already
  performed their compare-and-set inside a single transaction and are
  unchanged.

- The real-browser gate now includes a multi-tab compare-and-set suite: a
  Playwright spec drives two tabs — two live IndexedDB connections on one
  origin — through concurrent key bootstrap, first-contact pinning,
  rotations, verification-versus-rotation, and one-time-prekey consumption,
  in all three engines. The two races above are what this suite caught, and
  reverting either fix turns it red.

- **Reading sessions or group sender keys no longer fails on Firefox and
  WebKit.** `getSessionsForUser` and `getAllSenderKeysForGroup` in the
  IndexedDB store decrypted each row inside the cursor loop. An IndexedDB
  transaction deactivates the moment the event loop turns to anything that is
  not one of its own requests, so awaiting Web Crypto mid-iteration let the
  transaction commit and the next cursor advance threw
  `TransactionInactiveError`. Chromium's laxer transaction lifetime and the
  fake-indexeddb test double both tolerated the pattern, which is how it went
  unseen. Both methods now collect the encrypted rows inside the transaction
  and decrypt after it completes, the pattern the prekey reads already used.
  No key agreement, payload, or wire byte changed.

- **`IndexedDbSignalProtocolStore.close()`.** The store held its database
  connection open for the life of the page, and an open connection blocks
  deletion and version upgrades of the database from anywhere else — so an
  application signing out or clearing local state had no supported way to
  release it. `close()` closes the connection and drops the in-memory
  database key; call `initialize()` again before any other operation.

- The storage contract suites now also run against
  `IndexedDbSignalProtocolStore` inside real Chromium, Firefox, and WebKit
  pages on every change to the source repository. The suites are the same
  modules the jest gate runs; the Firefox and WebKit failures above are what
  the gate caught on its first run.

## 0.1.0-alpha.12

- **AES-GCM without additional data no longer fails in the browser.** Every
  AES-GCM call built its Web Crypto parameters with `additionalData` always
  present, holding `undefined` when the caller passed no AAD. Node converts
  those parameters through WebIDL, where a member set to `undefined` is
  absent, and accepts them. Chrome parses them by hand: a present
  `additionalData` key must be a BufferSource whatever its value, so the same
  call throws `AeadParams: additionalData: Not a BufferSource`. Device
  provisioning and device transfer pass no AAD at all, so both worked under
  Node and were unusable in a browser. The parameters are now built in one
  place, which omits the member when there is nothing to put in it. No key
  agreement, payload, or wire byte changed.

## 0.1.0-alpha.11

- **BREAKING: device provisioning no longer requires React Native, and
  `getDeviceMetadata` moved to its own subpath.** `device/provisioning`
  statically imported `react-native` and `expo-constants` at module scope.
  Both are optional peer dependencies, so the package's own contract says a
  consumer may have neither — but a static import of an absent package throws
  `ERR_MODULE_NOT_FOUND` before the module runs, which made the entire
  device-linking surface unimportable in Node and in the browser. The two
  imports existed for three fields of one function. Provisioning itself is a
  protocol and already takes the device's description as a
  `LocalDeviceMetadata` parameter, so it is now platform-free, and
  `getDeviceMetadata` lives at
  `@open-e2ee/signal-protocol-sdk/device/expo-metadata`. It is no longer
  re-exported from the `device` barrel. Callers off Expo build the four
  fields themselves; callers on Expo change one import path. No key
  agreement, payload, or wire byte changed.

- **`local/vault` no longer drags Expo SecureStore in behind the
  interface.** The barrel re-exported
  `ExpoSecureStoreSignalProtocolSecretVault`, so importing the vault
  *contract* failed without `expo-secure-store` installed. The barrel now
  exports only `ISignalProtocolLocalSecretVault`; the implementation keeps
  its own subpath, `local/vault/expo-secure-store`, which is where every
  caller in this repository already imported it from.

- **New check: `node ./scripts/smoke-import-surface.mjs`, wired into CI.**
  Packs the package, installs it into a consumer outside the repository whose
  `node_modules` has every optional peer removed, and imports all 59
  published export subpaths. Entry points that are genuinely bound to a
  platform are listed explicitly, and the list is verified in both
  directions, so an exemption that stops being true fails the check rather
  than lingering. Nothing caught the two defects above: the checks that name
  every subpath resolve types without ever loading a module, and the checks
  that load modules run from inside the repository, where the optional peers
  are installed as devDependencies and Node's resolver finds them.

- **Bundling the sealed-sender codec no longer pulls React Native in with
  it.** The codec imported two base64 helpers from the `internal/crypto`
  barrel, and that barrel also exports `generateRandomBytes`, whose
  third-choice runtime fallback is a dynamic `import('expo-crypto')`. The
  fallback is correct — it is how the SDK finds a secure random source on
  Expo, behind two other sources and a `try`/`catch` — but a bundler
  resolves what it can reach without asking whether the branch will run, and
  `expo-crypto` reaches `react-native`, whose entry point is Flow rather than
  TypeScript. Anything bundling the codec for a server or a browser was
  therefore parsing a mobile UI framework, and any bundler without a Flow
  loader stopped there. The helpers now come from `internal/crypto/utils`,
  which imports nothing but types, so the reachable graph ends where the
  encoding does. No encoder, decoder, or byte changed.

## 0.1.0-alpha.10

- **BREAKING: the quickstart adapters are named for what they are —
  in memory, not mocks.** Nothing in either adapter is a test double: the
  protocol and the cryptography are real, and only the infrastructure is
  simulated. The name said otherwise, and readers discounted the quick
  start because of it. The `mock` subpaths are gone rather than aliased —
  this is a pre-1.0 alpha with no customers, so a compatibility layer would
  only preserve the wrong word. Update imports and identifiers:

  | Before | After |
  |---|---|
  | `@open-e2ee/signal-protocol-sdk/local/store/mock` | `@open-e2ee/signal-protocol-sdk/local/store/memory` |
  | `@open-e2ee/signal-protocol-sdk/remote/relay/mock` | `@open-e2ee/signal-protocol-sdk/remote/relay/memory` |
  | `mockStore()` | `inMemoryStore()` |
  | `mockRelay()` | `inMemoryRelay()` |
  | `MockSignalProtocolStore` | `InMemorySignalProtocolStore` |
  | `MockSignalProtocolStoreOptions` | `InMemorySignalProtocolStoreOptions` |
  | `MockSignalProtocolRelayServer` | `InMemorySignalProtocolRelayServer` |
  | `MockSignalProtocolRelayServerOptions` | `InMemorySignalProtocolRelayServerOptions` |
  | `MockStoreFailureController` | `StoreFailureController` |
  | `MockStoreFailureOptions` | `StoreFailureOptions` |
  | `MockRelayFailureController` | `RelayFailureController` |
  | `MockRelayFailureOptions` | `RelayFailureOptions` |
  | `MockStorageWriteError` | `InjectedStorageWriteError` |

  The failure controllers moved with the adapters and kept their behavior.
  They were never test doubles either — they are deterministic, seeded
  failure injection for the documented recovery exercises — so they lost
  the `Mock` prefix instead of the subpath.
  No runtime behavior changed: the storage-failure error message drops the
  word "mock" and `InjectedStorageWriteError` reports the new class name,
  and nothing else on the wire, in storage, or in the failure semantics
  moved. The doc-snippet runner that executes every shipped snippet is now
  `scripts/run-doc-snippets.mjs` with a `doc-snippet:` marker, because the
  snippets it runs were never mock snippets.

- **`protobufjs` is no longer a dependency of the published package**, and
  the eval gate that proves it is now part of CI. The relay's sealed-sender
  certificate issuer was the last module importing it, through
  `protobufjs/minimal`'s `Writer` — which generates no code, so it was never
  what made the SDK throw `EvalError` under a strict Content-Security-Policy,
  but it did pull `protobufjs` and `long` into every install to write four
  fields. Issuance now goes through the same hand-written sealed-sender codec
  that validates the certificates it produces, so the field numbers an
  Ed25519 signature is computed over are described in one module instead of
  two that had to agree. The package declares six direct production
  dependencies and resolves to six packages in total; `protobufjs` remains a
  development dependency, where the wire tests use it as an independent
  oracle. The bytes are unchanged, which is the whole of the risk here — a
  certificate is a signature over exactly these bytes, and any shift would
  have invalidated every one already issued. Golden vectors captured from the
  old writer before the rewrite pin the issued bytes for four shapes,
  including a multi-byte UUID and an expiry above 2^53, and each is
  re-validated through the certificate chain with real keys.

- **A varint that cannot fit a `uint32` is refused at the encoder instead of
  written wrong.** `encodeVarint` stops at five bytes, so it truncated
  anything above 4294967295 — 2^32 came out as `80 00`, which the 64-bit
  decoder then correctly rejected as non-canonical — and it wrote `NaN` as 0
  and `1.5` as 1. All three now throw a named error at the point the mistake
  is made. Callers that need the wider range already have `encodeVarint64`.
  Nothing in this package encoded a value in the refused range.

  One decode-side strictness note that belongs with the wire work above and
  was not recorded when it landed: an unknown field encoded as a group (wire
  types 3 and 4) is rejected rather than skipped, where `protobufjs` skipped
  it. Groups are deprecated, no schema here uses them, and skipping one
  correctly means matching its end tag — a parser state this format has no
  reason to carry.

- **The sealed-sender wire codec is hand-written, and no signed certificate
  region is re-encoded on the way through.** Its five message types and the
  `UnidentifiedSenderMessage.Type` enum were assembled at runtime by
  `protobufjs` reflection, which compiles its encoders with `new Function` —
  the construct a `script-src 'self'` policy blocks — and they are now static
  encoders and decoders over the shared wire primitives. Every byte is
  unchanged, which carries more weight here than anywhere else in the wire
  work: a server certificate's signature is computed over its serialized
  inner bytes and a sender certificate's over its own, so a shift in field
  order, in a nested length prefix, or in whether an explicitly-set zero
  reaches the wire would invalidate every certificate already issued. The
  decoders hand signed regions back as the raw bytes they arrived as, never
  as a re-encoded structure. The 19 committed golden vectors pin all of it in
  both directions. Two decode paths do change, both for messages that were
  already malformed or came from a peer this version does not know: an inner
  message whose `type` names no declared arm — including an absent field,
  which reads as 0 — now decodes to the value that arrived, where reflection
  substituted the enum's first arm and so reported a `PREKEY_MESSAGE` the
  sender never wrote, and callers that route on the value must narrow it with
  `isSealedSenderContentType`; and a message with no `senderCertificate`
  decodes to empty wrapper fields, which certificate validation rejects,
  instead of raising `TypeError` from a null dereference. A third shift is
  smaller still: string fields decode through `TextDecoder`, which maps
  invalid UTF-8 to U+FFFD replacement characters where reflection produced
  other strings — for one shape, an empty string the required-field check
  then rejected. A certificate whose `senderUuid` is not valid UTF-8
  therefore now decodes instead of failing that check; such bytes can only
  exist under a trusted issuer's signature, and every issuer this SDK has
  shipped writes valid UTF-8.

- **The SPQR wire and ratchet-state serializer no longer builds its schema
  at runtime**, so the post-quantum ratchet works under a `script-src 'self'`
  policy. The ML-KEM Braid codec described its eight messages to
  `protobufjs` reflection, which compiles each encoder with `new Function` —
  the one construct a strict Content-Security-Policy forbids, and the reason
  the SDK threw `EvalError` in a hardened browser, an extension service
  worker, or anywhere else code generation is off. The eight messages now
  have hand-written encoders and decoders over the wire primitives, and the
  module imports nothing from `protobufjs`. Every exported function keeps
  its name and signature, and the presence rules that decide what reaches
  the wire are unchanged: an explicitly-set zero is still written, an absent
  field still decodes to its typed zero rather than `undefined`, and the
  `V1Msg` `inner_msg` oneof still emits exactly one arm. That matters more
  than usual here, because the encoder, decoder, and authenticator messages
  are *persisted* ratchet state — an install that upgrades has to decode the
  bytes it wrote before it upgraded. Byte identity is pinned by 49 golden
  vectors covering each message, each oneof arm, empty and maximal repeated
  fields, and epochs at 0, 1, 2^32, 2^53−1, 2^53+1, and 2^64−1.

  Three behaviors moved, each away from silent corruption. A persisted
  decoder chunk that carries an index but no data used to yield a map entry
  holding `undefined`, which surfaced later as a confusing failure inside
  Reed–Solomon reconstruction; it is now rejected where it is read, naming
  the chunk — nothing in this package has ever written that shape, so it can
  only come from corrupt state. Encoding state that violates its declared
  types — a field that is not the `Uint8Array` it claims, a size that is
  negative or above 4294967295 — now throws a named error where the old
  encoder silently wrapped the value and wrote wrong bytes. And
  `isSerializationReady()` now always returns `true`: with static codecs
  there is no schema to build and no not-ready state to report
  (`initSerialization()` stays as an awaitable no-op for callers that
  sequence on it).

- **The Double Ratchet and sender-key message codecs no longer build their
  wire types at runtime.** `SignalProtocolMessage`,
  `PreKeySignalProtocolMessage`, `SenderKeyMessage`, and
  `SenderKeyDistributionMessage` were encoded and decoded through
  `protobufjs` reflection, which compiles each encoder with `new Function` —
  the exact construct a `script-src 'self'` policy blocks. All four are now
  hand-written encoders and `ProtoReader` decode loops over the shared wire
  primitives, and neither module imports `protobufjs`. Nothing on the wire
  moves: the twenty committed golden vectors for these two modules pin every
  byte in both directions, including the behavior that is easiest to lose in
  a rewrite — presence, not value, decides what is written, so a counter of
  0 and a prekey id of 0 stay distinguishable from an absent field, an empty
  bytes field still reaches the wire and is still dropped on decode, and
  unknown fields are still skipped. Decoding is stricter in one respect
  inherited from the primitives: a field whose wire type contradicts its tag
  is now rejected rather than read as its declared type.

- **The protobuf wire primitives now cover 64-bit varints and the field
  shapes the message schemas actually use**, which is the groundwork for
  encoding every message here without `protobufjs` — and so without the
  runtime code generation that a `script-src 'self'` policy blocks. The
  varint helpers stopped at 32 bits in five bytes, so the SPQR epoch, a
  uint64, had no representation that survived a round trip; there are now
  bigint encode and decode functions with a ten-byte ceiling, alongside
  helpers for bool, enum, string, fixed64, embedded-message, and repeated
  fields, and a `ProtoReader` cursor that owns the read-tag-dispatch-skip
  loop every decoder repeats. The existing 32-bit functions are untouched
  and byte-compatible. Two contracts are deliberately stricter than
  `protobufjs`: a varint must be canonically encoded, because these bytes
  are signed and MAC'd and a redundant encoding would make the signed byte
  string malleable; and a field whose wire type contradicts its tag is
  rejected rather than misread. Nothing on the wire moves — no encoder has
  ever emitted the forms now refused.

- **The public repository's snippet check no longer requires an unpublished
  file.** `0.1.0-alpha.8` removed the internal pricing preview from the
  export, but `run-mock-snippets.mjs` — which ships in both repositories —
  still read it unconditionally, so the public "shipped mock snippets" CI job
  failed with ENOENT from the `0.1.0-alpha.9` push onward. The runner now
  validates that file's snippets only where the file exists, which is the
  boundary the export already draws. `ossf/scorecard-action` also moves to
  v2.4.4 (dependabot, applied here so the export carries it).

## 0.1.0-alpha.9

- **BREAKING: the multi-recipient content ceiling is the reference's
  96 KiB, and the shared payload is stored once, not once per
  recipient.** The 256 KiB ceiling was a misreading of the reference,
  which validates what each recipient will *receive* against the same
  96 KiB message-size constant it applies to individual sends — its
  256 KiB constant is an HTTP entity-read cap on the whole request, not
  a content bound. Worse, the fan-out stored a full copy of the shared
  ciphertext in every recipient's row, so one full-size send to a large
  group multiplied itself by the device count inside a single
  transaction — the reference's message store instead inserts one
  shared multi-recipient payload and hands each recipient a pointer,
  and this relay now does the same: per-recipient rows keep only their
  48 bytes of key material, delivery reassembles the exact wire form,
  and the shared payload row shares the message queue's retention.
  Found by this round's adversarial review; the ceiling boundary and
  the once-per-send storage each carry a revert-proven test.

- **The mock relay's send dedup is now sender-scoped, matching the
  Convex backend**, and `clientMessageId` is documented as requiring
  global uniqueness: sealed senders are anonymous by design, so every
  sealed send to a device shares one dedup namespace, and a reused
  counter or timestamp from two senders would silently collapse into
  one stored message.

- **The change-log walk now stops where the tenure ends, not where
  readability ends.** The S10a work narrowed the change log's entry gate to
  members but left the walk's continue condition on the weaker readable
  set, so a removal that left another of the requester's aliases pending —
  an ACI member whose PNI was invited, then the ACI removed — kept serving
  post-tenure history to a principal the group now lists only as invited,
  from any `fromVersion` inside the old tenure. Both gates now share one
  membership predicate: the walk serves through the tenure-ending
  transition, inclusive, and nothing after it. Versioned `getGroup` had the
  sibling misclassification: a requester with no tenure at all fell into
  the same `before_join` refusal as the join-version floor, telling a
  revoked-then-re-invited member that their membership was intact. The
  no-tenure case is now refused as `not_a_member`, `before_join` is raised
  only against a live tenure, and the accepted-join read translates
  `not_a_member` into `GROUP_ACCESS_REVOKED`. Found by this round's
  adversarial review; the alias-removal walk, the versioned-read reasons,
  the empty-page fault, and the snapshot-regression guard each carry a
  revert-proven test, and the S10a catch-up test now proves the snapshot
  mechanism against a server whose log throws.

- **The Node store now implements all of `ISignalProtocolLocalStore`, and the
  compiler enforces it.** `NodeSignalProtocolStore` was missing 37 of the
  interface's 72 members — the whole Sesame device-record, sender-key,
  skipped-sender-key, and message-record surfaces, plus metadata and the
  prekey-recovery helpers — so multi-device linking and both group APIs were
  unavailable to any Node process, and passing the store as `adapters.storage`
  needed a cast. All 37 are implemented against the same encrypted, atomically
  committed state document the adapter already used, and the class now carries
  an `implements ISignalProtocolLocalStore` clause, so a missing member or a
  drifted signature fails the build instead of surfacing as a runtime gap. The
  store also joins the shared storage contract with extended boundaries and the
  shared sender-key resolution contract, which the other adapters already ran.

- **The Node store's registration ID survives a restart.** It was held in an
  in-memory `Map` inside an adapter whose entire purpose is persistence, so
  every process start reported registration ID 0 and every peer read the
  restart as a reinstall. It is now part of the persisted state document,
  keyed by identity type so ACI and PNI stay distinct. Kyber prekey usage
  markers, previously in-memory for the same reason, persist alongside it.

- **BREAKING: the group change log is served in pages.** `getGroupChanges`
  returned the entire remaining log in one response — in practice the
  Convex transport silently truncated its restore at 4096 changes with no
  has-more signal, which is worse: a long log simply stopped syncing. The
  endpoint now returns `{ entries, hasMore }`: at most 64 entries per
  request, `hasMore` set only when the page was cut for size with the
  requester still a member, and each resumed request authorized
  independently at its own `fromVersion` snapshot. A walk that ends at the
  log's tip or at the requester's own tenure-ending transition is complete
  and says so — a removed member never sees `hasMore` dangle past the
  change that removed them. The client sync loop pages until done,
  resuming from the last verified revision, and treats a has-more page
  that served nothing as a server fault rather than looping on it. The
  reference's clients also drive an explicit paging loop off a has-more
  signal, though their resume cursor is server-supplied where ours is the
  client's own last verified revision; the page size here follows the
  shape, not a verified reference constant. The Convex transport bounds
  its storage restore to one page plus the look-ahead entry that decides
  `hasMore`, so the read cost now scales with the page rather than with
  `min(history, 4096)`.

## 0.1.0-alpha.8

- **An internal pricing exploration is no longer published, and business
  planning is now structurally unexportable.** `docs/pricing-preview.html` —
  an internal pricing and revenue exploration — was allowlisted into the
  public export in `0.1.0-alpha.5`. Nothing linked to it and it was never in
  the npm package, but it had no business being public. It is removed from
  the allowlist, and the release policy now refuses any file whose name
  matches pricing, revenue, or business-model patterns, so re-adding one
  becomes a deliberate policy edit instead of a one-line allowlist change.

- **The assurance figures are now a build product.** The figures table in
  `docs/ASSURANCE.md` was hand-maintained and had gone stale across two
  releases. `npm run assurance:update` regenerates it from a real run and
  refuses to write figures from a failing run; `release:verify` refuses to
  cut an export when the figures are more than three days old. The README no
  longer duplicates the numbers — it points at the one generated table.

- **README: the product speaks before the disclaimer.** The Signal
  non-affiliation paragraph moved below the benefit bullets (still above the
  fold); the nav line gains `open-e2ee.dev` and `docs.open-e2ee.dev`, which
  the README previously never linked; the hard-coded patch version — four
  releases stale at time of fix — is replaced by the `0.1.0-alpha` maturity
  line, with the npm badge carrying the exact version; the weekly-downloads
  badge, which renders a near-zero number for a days-old package, is
  replaced by a native-modules count that states a real differentiator.

- **`COMMERCIAL.md` answers the highest-intent click.** Commercial licensing
  previously dead-ended at an email address. The new file states who needs a
  commercial license, what it changes and does not change, the public tiers,
  and how buying works. Shipped in the npm package too.

- **A contribution surface that tells the truth about the export model.**
  `CONTRIBUTING.md` explains that `main` is generated, why PRs are ported
  rather than merged, and that issues are triaged in public;
  `CODE_OF_CONDUCT.md`, issue templates (with a security-reporting
  off-ramp), and a PR template complete the set.

- **Vulnerability reporting: private GitHub reporting and a safe harbor.**
  `SECURITY.md` now offers GitHub private vulnerability reporting alongside
  email, and commits to a good-faith safe harbor for security research.

- **`docs/E2EE.md` grew from a summary into the architecture explainer its
  README billing promises** — server-becomes-relay, device as source of
  truth, identity as device keys, recovery as a product decision, metadata
  visibility, and the new failure modes, each linking to the doc that goes
  deeper. Its "ML-KEM (Kyber)" phrasing is corrected to "ML-KEM (FIPS 203)",
  matching the distinction this changelog drew in `0.1.0-alpha.6`.

- **The npm package no longer ships 1.8 MB of generated API reference.**
  `docs/api` (391 generated files) stays in the repository for browsing but
  leaves the tarball; installs should not pay for reference docs that are
  regenerable and hosted.

- **Supply-chain hardening.** Every workflow action is pinned to a commit
  SHA; dependabot watches npm production dependencies and workflow actions
  weekly; CodeQL runs the security-extended queries on every push, PR, and
  weekly schedule.

- **The composition guide leads with the shipped API.** The "Target
  Composition" section — `deviceStorage`, `createExpoDeviceStorage`,
  `signal.messages.subscribe`, none of which exist in the package — sat above
  the real API at the top of `docs/CLIENT_COMPOSITION.md`, which is exactly
  the position that gets copy-pasted. It moved to the bottom under "Future
  Direction (Not Shipped)" behind an explicit these-imports-fail warning.

- **The Node store README no longer claims an interface the adapter does not
  implement.** `NodeSignalProtocolStore` covers the core single-device
  surface but not the Sesame device-record, sender-key, or message-record
  portions of `ISignalProtocolLocalStore` — and it has no `implements`
  clause, so the compiler was never checking the README's claim. The README
  now states the real coverage and points multi-device and group users at
  the interface docs. Completing the adapter is tracked work; documenting
  the boundary honestly could not wait for it.

- **BREAKING: the group change log is for members; pending principals catch
  up by snapshot.** The change log authorizes at the snapshot at
  `fromVersion`, and a pending-profile-key entry appears in that roster, so
  an invitee could walk the log forward from their invitation — reading, for
  the whole invitation-to-acceptance window, a narration `getGroup` refuses
  them by name, including who made each change. The server now requires the
  requester to be a *member* of the authorizing snapshot (rejecting with the
  distinct reason `not_a_member`), which closes the log to invitees outright
  and, for members, states the tenure bound that the roster check previously
  provided by accident.

  Pending principals do not lose their catch-up path — they lose the log as
  the mechanism. A pending client now advances by fetching the current state
  as a fresh signed baseline, verified and installed whole, which is also
  how the reference ecosystem's clients behave whenever the server does not
  recognize them as a member. Acceptance is unaffected: it was always
  submitted against the current state, which is exactly what the snapshot
  provides. The specification records this as S10a, with the C1/C3 span
  rules restated to make explicit what was previously implicit: a pending
  view is a provisional baseline, not a span with living continuity, and a
  member's span begins at the verified transition or baseline that makes
  them a member.

  One behavioral consequence: an invitee whose invitation is withdrawn no
  longer receives the deletion as a signed change (the log that carried it
  is closed to them). The next catch-up finds the current state refused and
  surfaces `GROUP_ACCESS_REVOKED`, mutating nothing — the cached pending
  view remains the last verified state, and a later re-invitation serves a
  fresh baseline. Members are untouched: removal and ban still arrive as
  verified transitions through the log, never as refusals.

- **A full 256 KiB multi-recipient payload is accepted, as advertised.** The
  content ceilings are enforced on the base64 columns as string-length
  limits, and the multi-recipient limit was computed as `ceil((n / 3) * 4)`
  instead of `4 * ceil(n / 3)` — two characters short of what 256 KiB
  actually encodes to, since 262144 is not a multiple of 3. A payload at
  exactly the advertised ceiling was refused with a 413. The single-recipient
  limit was computed the same way but 96 KiB divides by 3, so only the
  multi-recipient bound was wrong.

- **A FORBIDDEN group read now says which question it answers, and only a
  membership refusal reads as revocation.** Two different rejections share
  the 403 `FORBIDDEN` code on the group read paths: "you may not read this
  group at all" (banned, or absent from the authorizing roster) and "you may
  not read this version of it" (the join-version floor added in the
  removal-revocation work). They differed only in message text, and the
  client treated any `FORBIDDEN` on a pinned baseline read as
  `GROUP_ACCESS_REVOKED` — so a floor rejection, raised while the membership
  itself was fine, would have been reported to the application as a revoked
  membership. The rejections now carry a machine-readable `reason`
  (`not_readable` / `before_join`) alongside the code, the client interprets
  only `not_readable` as revocation and propagates everything else, and the
  conformance tests assert on the reason rather than on message wording.

- **A multi-recipient send may name each device only once, and retry
  requests are rate limited.** The multi-recipient path is deliberately
  exempt from the per-recipient inbound-bytes budget, matching the
  reference, because a group-send token is supposed to price it. That
  exemption assumes one call fans out to *distinct* devices. The reference
  gets that from its wire format, which parses recipients into a map keyed
  by service ID, so duplicates collapse before the handler ever sees them;
  our flat array does not, so one endorsed device repeated a thousand times
  in a single call stored a thousand copies of the ciphertext against an
  unmetered budget. The handler now rejects a repeated `(userId, deviceId)`
  with a 400 rather than collapsing it, since a repeat is a client bug and
  quietly picking between two conflicting key blocks would bury it.

  `sendRetryRequest` was unmetered too, and nothing else on that path bounds
  it: a retry request carries no caller-supplied content to charge by size,
  and it names an original sender the caller never has to have talked to, so
  there is no relationship to check either. It is now counted per requester
  against a token bucket sized for the legitimate case — a client returning
  from a broken session asks for one per message it could not decrypt — and
  refuses only a caller that keeps asking indefinitely.

- **BREAKING: group-send tokens are verified before any account is read, and
  sealed sends carry the recipient identities they claim.** A group-send
  token is a signature over ACIs, but sealed sends name recipients by user
  ID, so the relay resolved every named recipient to its stored ACI — up to
  one indexed read per recipient, a thousand on the multi-recipient path —
  *before* it could check the token. An anonymous caller holding a garbage
  token could bill that work to the deployment on every call, on the one
  path that is deliberately exempt from the per-recipient send budget
  because the token is supposed to be the gate.

  The order is now the reference implementation's, where sealed payloads
  name recipients by service ID and the token is checked against the request
  before any account is touched: the caller supplies the ACI it claims for
  each recipient, the entire cryptographic check runs against those claims
  first, and only then is each claim bound to the recipient's stored
  account. A caller who lies about a binding has necessarily already
  presented a token our own group server issued over the claimed set, so
  the reads it spends were an authenticated member's to spend.

  The claims ride the existing plumbing: the endorsement cache now stores,
  next to each member's endorsement, the ACI it was issued over — the
  identity that is *correct* to claim, as opposed to whatever a later lookup
  would resolve — and the send paths pass them through. This changes the
  app-owned `EndorsementCacheStore` interface (entries are now
  `{ endorsement, aciBytes }` records rather than raw bytes) and adds
  `targetAciBytes` / per-recipient `aciBytes` arguments to the sealed send
  mutations, required when authorizing by group-send token.

- **One ACI, one account.** Nothing stopped two user IDs from registering
  the same ACI: `identify` is host-owned and unvalidated, and the second
  account to claim an ACI would inherit every authorization decision made
  about the first — sealed-sender access, group-send endorsements, identity
  binding. The `accounts` table now has an `aciBytes` index and
  `rememberAccount` refuses a claim on an ACI already registered to a
  different user ID with a 409 `CONFLICT`. A deployment that already holds
  duplicate-ACI rows keeps working — the check reads one claimant and the
  duplicate surfaces as the intended 409 rather than an untyped error — but
  which of the two accounts is refused depends on index order, so resolve
  such rows deliberately before deploying.

- **Removal and ban now revoke historical group-state reads.** `getGroup` with
  an explicit version authorized the requester against the roster of the
  *requested* snapshot, so anyone removed or banned at version N could keep
  fetching every snapshot of their former tenure indefinitely — a removal that
  does not revoke read access is not a removal. The server now authorizes
  every full-state read against the group as it is *now*, and adds the floor
  that snapshot-based authorization used to provide by accident: a member may
  not read state from before the version they joined at, so membership grants
  the group from when you joined, not its history.

  The change log deliberately keeps snapshot-at-`fromVersion` authorization,
  as the group specification already required: the walk serves entries only
  while the requester stays readable and stops at — and includes — the change
  that removed them, which is how a polling member learns of their removal.
  Authorizing the log at the current state would 403 them into silence. What
  this leaves reachable to a former member is bounded and not new: changes
  from within their own tenure, ending at their removal — bytes they were
  served while entitled.

  One client-visible consequence: a join that is accepted and then revoked
  before the joiner reads its baseline snapshot — an admin removing them in
  the race window — now fails with `GROUP_ACCESS_REVOKED` instead of
  reporting a membership the client could never verify or use. Nothing is
  installed locally, and the principal becomes the ordinary re-entitlement
  case: a later re-add serves a fresh signed baseline.

  An invitation grants the current state and nothing else. A
  pending-profile-key entry entitles its holder to read the group as it is —
  acceptance needs that — but it is not a tenure, and its wire format pins
  `joinedAtVersion` to zero, so deriving a history floor from it would read
  as "joined at the beginning of time". An invitee who never accepts holds
  the group master key, so every snapshot the server serves them decrypts;
  versioned reads are therefore refused outright for pending principals.

  This bounds `getGroup` only. The change log authorizes against the
  snapshot at `fromVersion`, and a pending-profile-key entry appears in that
  roster, so an invitee can still walk the log forward from their
  invitation — a window during which they could already fetch the current
  state at will, though the log additionally names who made each change.
  Flooring the log would deny a pending member the entries they need to
  reach the state their acceptance is submitted against, so closing that
  window means changing how pending members catch up, not adding a check.

- **The relay's send paths are bounded: per-recipient inbound budget, a
  content-size ceiling, and a device-existence check on sealed sends.** None
  of the component's send paths was rate limited or size limited, so one
  caller — anonymous on the sealed path, any authenticated account on the
  identified one — could grow a victim's message queue without bound for the
  full seven-day retention window. Three bounds close this, each matching the
  reference implementation's shape: message content is capped at 96 KiB for a
  single-recipient envelope and 256 KiB for the shared multi-recipient
  payload; single-recipient sends spend from a per-*recipient* byte budget
  (4 MiB burst, 1 MiB/minute sustained) — keyed by the target because a
  sealed sender is anonymous by design, so a per-sender limit on that path is
  either meaningless or a hole; and `sendUnidentified` now refuses a target
  device that does not exist, the check its multi-recipient sibling always
  had. The multi-recipient path is deliberately not metered, also matching
  the reference: the group-send token already prices it, and a per-recipient
  budget there would let one noisy group partially starve delivery to its
  quietest member.

  The shared bucket is bounded from the sender side too. Keying by target is
  forced on the sealed path — the sender is anonymous by design — but on the
  identified path the sender is known, and a single authenticated account
  must not be able to drain a victim's whole budget and starve every other
  sender: identified sends also spend a per-(sender, recipient) sub-limit of
  a quarter of the shared bucket. Neither bucket can be spent by a request
  that goes on to fail: the charges are written in the mutation's own
  transaction, so a send that 410s on the stale-device check — or trips the
  other limit — rolls its charge back with everything else.

- **The `STALE_DEVICE` error no longer discloses the recipient's current
  registration ID.** The 410 thrown when a sender's view of a device is stale
  echoed back `currentRegistrationId` — the live value — to any
  account-authenticated caller, with no rate limit. That is the same read the
  prekey-bundle fetch serves, minus its rate limiter: a free oracle for
  watching registration-ID changes (device reinstalls) on arbitrary devices.
  The error now names the stale device and nothing else, which is the
  reference implementation's 410 body; the sender's recovery path is
  unchanged, since recovering means re-fetching the bundle anyway.

- **BREAKING: no group identifier travels on a message envelope any more.**
  Every relayed message carried a plaintext `groupId` alongside its target, and
  the relay stored it on each `messages` row for the seven-day retention
  window. Grouping those rows by that column yielded the set of accounts that
  received traffic for a group, so a relay operator could reconstruct rosters
  without breaking any encryption. The column is gone, and so are the `groupId`
  arguments on `messages.send`, `sendUnidentified`, and
  `sendMultiRecipientUnidentified`, and the field on the envelopes those
  functions return.

  What replaces it is a message type. A group message is now typed
  `sender_key`, which tells the receiver to decrypt the payload as a framed
  SenderKeyMessage — and nothing else. The receiver reads the frame's
  distribution identifier, which is opaque, and resolves the group against its
  own sender key store. The envelope says how to decrypt, never which group.
  This also removes a small trust problem: the receiver no longer selects a
  sender key using a group id the sender asserted.

  This closes the group's *name*, not the group *partition*. The distribution
  identifier is unencrypted and stable for the life of a sender key, one send
  produces byte-identical ciphertext on every recipient's row, and the
  multi-recipient sealed path hands the relay a roster. A relay can still
  partition delivery pairs into unlabeled groups; it can no longer put a
  meaningful, cross-send label on one. The component README states the
  remaining channels explicitly.

  Sealed sender needed its own channel for this, because the outer envelope of
  a sealed message is always `unidentified_sender` and cannot carry an inner
  type. Sealed envelopes now begin with a content-type byte inside the seal,
  matching the `Type` enum of the reference implementation's
  `UnidentifiedSenderMessage.Message` (`PREKEY_MESSAGE`, `MESSAGE`,
  `SENDERKEY_MESSAGE`, `PLAINTEXT_CONTENT`), and `SealOptions.groupId` —
  encrypted, never populated by the send path — is removed in favour of
  `contentType`. This is a wire-format change to sealed sender for both V1 and
  V2.

  Deploying this against an existing Convex deployment needs a manual step:
  Convex validates stored documents against the new schema during the push,
  before any of your code runs, so a `messages` row still carrying a `groupId`
  fails the deploy and no migration can run ahead of it. Clear the `messages`
  table — or stop sending and let the seven-day retention window drain it —
  before deploying. Messages are transient and clients re-request undelivered
  ones. See "Upgrading" in the component README.

- **Fixed: on React Native, one member's sender key could permanently break
  another's group messages.** The store indexes sender keys by the frame's
  distribution identifier so a receiver can resolve a group without being told
  which one. Every other adapter scopes that index by sender; the React Native
  adapter keyed a flat pointer on the identifier alone, so a second sender
  presenting the same identifier overwrote the first, and the displaced
  sender's group messages failed to decrypt until it rotated. Distribution
  identifiers are chosen by their sender and travel in the clear, so this was
  reachable by any account sharing a group with the victim. The pointer key is
  now scoped by sender and device.

- **Fixed: on React Native, a host that issues colon-scoped user IDs could not
  receive group messages at all.** The adapter joins composite storage keys on
  `:` and split the sender key record key from the right, which silently
  mis-assigns the components when a user ID contains a `:` of its own — and
  nothing constrains user IDs, since they come from the host application's
  identify hook, where a tenant- or issuer-scoped subject is ordinary. Every
  group message resolved to nothing on such a deployment, deterministically and
  permanently. The same join made a group ID a prefix of `<groupId>:<sub>`, so
  deleting a group's sender keys also swept any group whose ID extended it.

  Key components are now percent-escaped before they are joined, so no
  identifier can carry a separator into a key or a scan prefix. This also
  retires the residue left by the sender-scoping fix above, which had only
  pushed the collision behind the same assumption.

  Sender key records and pointers are unaffected on upgrade for a deployment
  whose IDs contain neither `:` nor `%`, because such values escape to
  themselves; only the values that were already broken move. Retry records are
  different, and do move for everyone: their key is scanned by session ID, and
  a session ID is `<userId>:<deviceId>`, so it always carries a separator. That
  separator was load-bearing in the same way — a session ID of `alice:1` has
  scan prefix `alice:1:`, which also matches the records of user `alice:1` on
  device 2 — so the escaping applies there too.

  The cost is that retry records written before the upgrade are not reachable
  by session ID afterwards, so a retry request for a message sent before the
  upgrade cannot be served and the sender's peer re-requests or gives up. They
  are not leaked: the expiry sweep and the clear-all path scan the whole record
  prefix and filter on the stored timestamp, so they are reaped on the normal
  retention schedule regardless of key format.

- **BREAKING: the `plaintext_content` envelope type is removed.** It was in the
  relay's message-type union and the client's accepted list, but no send path
  ever produced one and neither decrypt path handled one — an envelope carrying
  it fell through to the pairwise ratchet and failed there. The reference uses
  the corresponding sealed content type to carry a decryption-error receipt
  when no session exists; this SDK delivers those over a dedicated relay
  channel instead, so the type has no role here. The sealed-sender parser now
  rejects the content-type byte outright rather than mapping it to an envelope
  type with no handler. `docs/DEVIATIONS.md` §6.2 records the difference.

  The literal is also gone from the relay's stored `messageType` union, so it
  carries the same deploy-time hazard as the `groupId` removal above: a stored
  row whose `messageType` is `plaintext_content` fails Convex schema validation
  during the push. Clearing the `messages` table handles both at once.

- **Sealed sender reads its content-type enum through a static import.** Four
  call sites in `client/sealed-sender-ops.ts` and
  `client/signal-service-cipher.ts` reached for
  `internal/protocol/sealed-sender/types` with `await import(...)` on every
  seal and unseal, to read `SealedSenderContentType` and the V2 version bytes.
  Two of them were already redundant with a static import of the same module at
  the top of the same file, and `client/client.ts` had none. This is a
  consistency and readability change, not a bug fix: the module has runtime
  exports, so a resolved dynamic import always carries the enum.

- **Sealed sender envelope parsing is now canonical and validated.** Both the
  V1 and V2 inner-envelope parsers accepted a payload with trailing bytes, an
  unrecognised content-type byte, a truncated varint, or a missing content
  hint. Parsing runs after authentication, so none of these was reachable by an
  attacker, but two distinct byte strings could parse to identical content and
  an unknown content type fell through to a routing default. The parsers now
  reject all four, and the content hint is a required field rather than an
  optional one.

- **`maxSenderKeyAge` is bounded at 90 days.** The age-based rotation policy
  already expired locally generated sender keys after a configurable interval,
  defaulting to the 14 days the reference implementation uses, and the group
  send path caught that expiry to rotate and redistribute before retrying. The
  interval itself was unbounded, so a host could configure an age no key would
  reach and switch rotation off without saying so. It is now clamped to 90
  days, the same ceiling the reference applies to its own remotely configured
  value — the difference being that this value comes from the host application
  rather than from the SDK, which is what makes the clamp load-bearing rather
  than belt-and-braces. A sender key is the group material no ratchet
  refreshes, so a member who holds it can read everything sent under it until
  it rotates; membership changes normally force that sooner, and the age bound
  is what covers a group whose membership never changes. A configured value
  that is not a positive finite number now falls back to the default instead of
  being used, since such a value states no policy at all and a zero is far more
  often an unset field than a request to rotate constantly. Both the clamp and
  the fallback log a warning.

- **`maxSenderKeyAge` is also bounded below, at one hour.** The interval had no
  lower bound, and one that is too short fails in a way that is worse than not
  rotating: expiry is enforced on the send path, which answers it by rotating
  the key and fanning a distribution message out to every other member over
  sequential network calls, then retrying the encrypt — against the age of the
  key it just created. Configure an interval shorter than that fan-out takes
  and the retry finds the new key expired too, so every group send fails
  permanently, having burned a rotation and a message to every member on each
  attempt. Since the field is milliseconds, a host that means fourteen days and
  passes `14` reaches this, and it does so without ever sending a message that
  would reveal the mistake in testing.

  Values below the floor are raised to it with a warning rather than rejected.
  Unlike the ceiling this is not a security bound — rotating sooner is strictly
  safer — so the honest reading of an unreachably short interval is "rotate as
  often as this implementation can actually deliver", which is what a host that
  wants aggressive rotation was asking for. An hour clears the worst realistic
  fan-out by a wide margin while leaving deliberately aggressive policies
  intact, which a bound measured in days would not. `SENDER_KEY_AGE_FLOOR` is
  exported alongside `SENDER_KEY_AGE_CEILING`.

  Note what the clamp leaves you with if you hit it by mistake: a host that
  passes `14` meaning days now rotates hourly, which is a distribution message
  to every member of every group every hour. That is functional but not free,
  and the warning is how you find out it is happening — which is the argument
  for clamping rather than rejecting, since the alternative was group messaging
  that simply did not work.

  Separately, the expiry check no longer skips a locally generated key whose
  stored creation time is missing or non-positive. Such a key is the one whose
  life is genuinely unbounded, so waiving the age check on it exempted exactly
  the case the check exists for; it is now treated as expired, which the send
  path answers by rotating to a key whose age is known.

- **Sender key identifiers are now opaque random UUIDs, closing a group
  metadata leak.** A sender key's id was built as
  `groupId:userId:deviceId:timestamp`, and that id travels the wire as the
  SenderKeyMessage `distribution_uuid` — a field outside the ciphertext that
  every relay on the delivery path reads off each group message. Sealed sender
  does not cover this: it conceals the frame from the relay but not from the
  rest of the path, and a deployment may have it disabled. A passive observer
  could therefore reconstruct group rosters by grouping messages on a field it
  cannot be prevented from reading. Ids are now random UUIDv4s carrying no
  group, sender, device, or clock, matching the reference implementation's
  random distribution UUID. The sender-keys specification states the
  requirement in a new section on identifier opacity. This also fixes a
  rotation bug: receivers detect a rotation by
  comparing the incoming id against their stored state, so two rotations inside
  the same millisecond produced an identical id and the second went unnoticed —
  the rotation tests previously needed a `Date.now()` mock advancing a
  millisecond per call to stay green, and now run against the real clock.
- **BREAKING: the Expo store now keeps sender keys on the device instead of
  sending them to a remote store.** Every sender-key and skipped-key operation
  was proxied to an optional `ISignalProtocolRemoteSenderStateStore`, which
  took the chain key and the sender's private signature key as parameters and
  wrote them to whatever backend the application supplied. Those two values
  together are enough to read every message on a sender's group chain and to
  forge new ones, so a server holding them would nullify group message
  confidentiality and authenticity; the skipped-key methods handed over the
  message keys themselves. The reference implementation keeps its sender key
  store local for exactly this reason. No shipped relay implemented the
  interface, so in practice these calls threw and Expo group messaging did not
  work at all — the fix is a real local implementation, not a guard.

  Sender key records and skipped message keys now live in the Expo store's own
  SQLCipher-encrypted database. The `sender_keys` table holds each record as
  one row so a rotation's current and previous states can never be written
  apart, and its `distribution_id` column is renamed `group_id` to match what
  it has always contained. A new `skipped_sender_keys` table replaces the
  remote skipped-key calls and bounds itself by evicting the lowest chain
  indexes first.

  `ISignalProtocolRemoteSenderStateStore` is removed, along with the `relay`
  option on `expoStore()` and the corresponding `ExpoSignalProtocolStore`
  constructor parameter. `expoStore({ relay })` becomes `expoStore()`. The
  `sender_keys` schema change is not migrated: applications own Expo database
  migrations, and any existing rows hold state that should not have left the
  device.
- **Device teardown no longer orphans key material, and the provisioning cron
  no longer risks stalling.** `purgeDeviceStorage` deleted at most 4096 rows
  per prekey table in a single transaction and stopped there. A device's
  one-time prekeys have no ceiling — the component marks a consumed prekey
  rather than deleting it, and no cron reclaims consumed rows — so a
  long-lived device could exceed that and leave the remainder behind, keyed to
  a deviceId a later link reuses. Teardown now deletes a fixed budget and
  schedules a continuation until nothing remains. The device's identity
  registration is always deleted in the first pass and `fetchPreKeyBundle`
  gates on that row, so the device is unreachable the moment teardown returns
  even while the sweep continues. Separately, the provisioning cleanup cron
  swept 100 sessions per transaction while each `linked_pending_ack` row
  cascades into a full device teardown; a cron that exceeds Convex's
  per-mutation limits does not degrade, it stalls, and expired sessions then
  stop being reaped at all. That sweep now uses a batch of 10 and relies on
  its existing self-reschedule for throughput.
- **Provisioning teardown now identifies the device it linked by an opaque
  token rather than a millisecond timestamp.** Device rows are reused across
  registrations, so rollback matched the device's `linkedAt` stamp to avoid
  reaping a device the user had legitimately re-registered into the freed
  slot. Two links landing in the same millisecond on the same slot produce
  equal stamps, and teardown would then unlink the wrong — newer — device.
  Every registration and link now mints a `linkToken`; it is never returned to
  clients. A test that removes and re-registers without advancing the clock at
  all fails against the old stamp comparison.
- **Removed five exported Convex row types that described tables no consumer
  can read.** `ConvexIdentityKey`, `ConvexEcSignedPreKey`, `ConvexEcPreKey`,
  `ConvexKemPreKey`, and `ConvexKemLastResortPreKey` were unreferenced and
  every one of them disagreed with `component/schema.ts`: all five omitted the
  `identityType` discriminator, `ConvexIdentityKey` claimed a `deviceId` and a
  raw `publicKey` where the real table holds a per-account
  `compositeIdentity`, and both one-time prekey types documented that keys are
  "DELETED when consumed" when the component marks `consumedAt` and leaves the
  row for the sweep. The premise was wrong to begin with — the component's
  tables are isolated, so an application cannot obtain these rows under any
  type. The file header claiming nine component tables, one of them a
  `prekeyBundleFetches` table that no longer exists, is corrected. The
  surviving `FetchedPreKeyBundle` is now derived from the component's own
  return validator instead of hand-written, so it cannot drift again.
- **`ConvexSignalProtocolRelayApi` now carries real argument and return
  types.** Its 43 function references were declared as bare
  `FunctionReference<'mutation'>` / `<'query'>`, so every argument the relay
  adapter passed to the component was `any` and a mismatch surfaced only as a
  runtime validator rejection in the deployment. The type is now *derived*
  from `defineConvexSignalProtocolBackend`'s return type via `ApiFromModules`
  rather than restated by hand, which is what makes it meaningful — a
  hand-written contract can drift from the functions it describes, and this
  one had. The `getProvisioningMessage` return cast is removed as a
  consequence: the reference now carries the component's own return
  validator, so a component change that stops satisfying the interface fails
  to compile instead of being cast away.
- **Fixed sealed-sender fallback detection**, which decided whether to retry a
  failed sealed send on the identified path by testing whether the error
  message contained the substring `'Unauthorized'`. That was wrong in both
  directions: any unrelated failure whose message happened to contain the word
  — a rate limit, an app-level wrapper — downgraded the send to identified
  delivery and disclosed the sender to the relay, while a genuine
  `code: 'UNAUTHORIZED'` rejection whose message did not spell the word went
  undetected and surfaced as a hard send failure. Detection now reads the
  structured `ConvexError` payload; the string contract is removed with no
  fallback.
- **Rewrote `docs/SCHEMA.md`.** It described a 7-table schema the application
  was instructed to define itself, with a multi-tenant `appId` column, index
  names, a `deliveredAt` field, and a `sender_key_distribution` message type
  that exist nowhere in the codebase, plus cleanup crons the component already
  runs. The component owns all sixteen tables; the document now describes what
  is stored, what the relay can and cannot see, and the real retention
  behavior.

- **Sealed sender can now be enabled.** `oe-groups trust-root` exports the
  Ed25519 sender-certificate root alongside the group trust root, printing both
  labelled (`group trust root:` / `sealed sender trust root:`). Previously only
  the group root was printed, so there was no supported way to obtain the value
  clients pin in `sealedSender.trustRoots`; inbound sealed-sender validation
  stayed disabled and every send fell back to identified delivery, disclosing
  the sender to the relay. The derivation now lives in one shared module
  (`internal/protocol/sealed-sender/trust-root`) used by both the CLI and the
  relay's certificate issuance, so the printed root cannot drift from the key
  the deployment signs with, and a contract test pins the two as equal.
  Corrects the `sealedSender` configuration docs, which required a
  `SEALED_SENDER_SIGNING_KEY` environment variable that has never existed.

- **`getProvisioningMessage` now returns `expiresAt`**, the session's absolute
  deadline in epoch milliseconds (`null` when the session is unknown). The
  Convex component already returned it, but the relay interface did not declare
  it and the adapter cast it away, so no client could compute expiry locally.
  The mock relay was brought to parity at the same time: it models the
  acknowledgment's own TTL window granted by `completeProvisioning` — without
  which a link completed near the deadline strands a device the client has
  already persisted keys for — rejects expired sessions in
  `connectNewDevice`, `sendProvisioningMessage`, `completeProvisioning`, and
  `acknowledgeProvisioning`, and reports expiry as a computed status instead of
  writing `expired` from inside a read. The shared relay contract suite now
  pins all three behaviors.
- **Security (Convex component):** the component now declares
  `OE_GROUPS_SERVER_SECRET` as a typed component environment variable and
  reads it through the declared-environment accessor. Convex components are
  isolated from app deployment environment variables, so the previous
  `process.env` read was unreachable in any real `app.use()` install and
  every group, credential-issuance, and sender-certificate call failed at
  runtime; apps must forward the secret with
  `app.use(signalProtocol, { env: { OE_GROUPS_SERVER_SECRET: app.env.OE_GROUPS_SERVER_SECRET } })`.
  The test-only injection seam is now default-deny: it refuses configuration
  outside a recognized test runner instead of allowing it whenever a
  deployment marker is absent.
- **Breaking (relay API):** removed `getGroupMembers` from the relay surface
  — the component, the app wrapper, `ConvexSignalProtocolRelayServer`, the
  mock adapter (including its `setGroupMembers` test seam), and
  `ISignalProtocolRelayServer`. The relay keeps no server-side group
  membership map by design; relayed group sends now require
  `SendOptions.groupMemberUserIds`, which the relay resolves to devices via
  `getActiveDevices`. Group sends without a roster previously dropped the
  message to zero recipients while reporting success.
- Fixed cross-sender message suppression: `clientMessageId` deduplication is
  now scoped to the sending account. The key was previously
  `(targetUserId, targetDeviceId, clientMessageId)`, so two senders that mint
  non-random client message IDs — a counter or a timestamp — silently
  suppressed each other's messages to a shared recipient, and the suppressed
  sender was handed the other sender's message ID and server timestamp.
  Same-sender retries still collapse as before.
- Documented two properties the component does not provide, both previously
  unstated or overstated. **Group metadata privacy:** the relay can still
  approximate a group's recipient set from delivery metadata — `messages` rows
  carry a plaintext `groupId`, and the unencrypted `distributionUuid` in the
  SenderKeyMessage frame embeds `groupId:senderUserId:senderDeviceId` — so the
  component README's previous claim to keep no membership map has been
  corrected to describe what removing `getGroupMembers` actually buys. Closing
  the leak requires opaque distribution identifiers in the sender-key layer and
  is tracked separately. **Device-scoped authorization:** `identify` resolves an
  account, not a device, so every `deviceId` argument is a caller-chosen
  routing selector and any session for an account can drain that account's
  other device queues, send as any of its device IDs, and rotate any of its key
  material.
- Fixed silent message loss for skipped multi-recipient sealed-sender
  recipients: the client now consumes the server's `uuids404` list,
  refreshes those users' device lists, and redelivers per-device instead of
  discarding the field while reporting the send as delivered.
- Fixed provisioning acknowledgment data loss: completing a session now
  grants the acknowledgment its own full session TTL (previously the ack
  deadline was whatever remained of the original five-minute window, and
  the every-minute cleanup cron could delete the freshly linked device
  before the ack arrived), `acknowledgeProvisioning` rejects expired
  sessions instead of racing the cron for the device's survival, and
  session teardown deletes only the device the session created (matched by
  its `linkedAt` stamp) with a full cascade of its key material, queued
  messages, and heartbeats. Dead `patch`-before-`throw` writes that Convex
  transaction rollback always discarded were removed, along with the never
  persisted stored `expired` status; `getProvisioningMessage` now also
  returns `expiresAt` so subscribed clients can compute expiry locally.
- Retry requests now expire with the same seven-day TTL as messages, backed
  by an hourly cleanup cron; `getPendingMessages` and
  `getPendingRetryRequests` filter expired rows at read time instead of
  serving them until the next cron pass.
- Reduced write contention on the per-account identity row: mutations now
  skip the account patch when the caller's identity bytes are unchanged,
  instead of unconditionally rewriting the row (an OCC conflict hotspot
  between a user's own concurrent mutations and sealed sends addressed to
  them).
- Corrected the exported `FetchedPreKeyBundle` type to the actual wire shape
  (`registrationId`, `ecSignedPreKey`, `ecOneTimePreKey`,
  `kemLastResortPreKey`, `kemOneTimePreKey`); the previous declaration
  omitted `registrationId` and named four of five fields incorrectly.
- `getActiveDevices` now caps its device scan at `MAX_DEVICES` instead of a
  hardcoded 5, and the missing-snapshot guard in `getGroupChanges` throws
  structured `ConvexError` data instead of a plain `Error`.
- Extended the installable Convex component to own the complete relay backend,
  adding isolated devices, identity and prekey storage, message and retry
  queues, provisioning sessions, and sender-certificate issuance behind five
  new public wrapper namespaces.
- Added `@convex-dev/rate-limiter` as an optional child component and enforce a
  ten-per-minute prekey-bundle fetch limit for each authenticated
  fetcher/target pair.
- Standardized component rejections on structured `ConvexError` data carrying
  `{ code, status, message }`, including sealed-sender authorization failures
  that retain an `Unauthorized:` message prefix for current client fallback
  handling.
- Added an installable Convex component defined as
  `defineComponent('signalProtocol')`, with isolated group state, change, and
  snapshot tables plus a `defineConvexSignalProtocolBackend()` app-wrapper
  factory. The credential-issuance wrappers resolve application identity and
  pass explicit ACI and optional PNI bytes into the component; group
  operations remain authorized solely by their zero-knowledge presentations
  and carry no caller identity.
- Added the `@open-e2ee/signal-protocol-sdk/convex.config` export for mounting
  the component with `app.use(signalProtocol)`.
- **Breaking (Convex group backend):** removed `defineConvexGroupServer`,
  `defineConvexGroupServerForTest`, `convexGroupServerTables`, and the
  `@open-e2ee/signal-protocol-sdk/remote/relay/convex/server` export. The
  pre-launch factory and app-owned tables are replaced directly by the
  component and wrapper, with no compatibility aliases.

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
  derived _different_ shared secrets, which is precisely what the info string
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
