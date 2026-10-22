# Security Model

> Navigation: [README](../README.md) | [Protocol Policy](./PROTOCOL_POLICY.md) |
> [Architecture](../ARCHITECTURE.md) | [Vulnerability Reporting](../SECURITY.md)

This document describes the security boundary of the current
`@open-e2ee/signal-protocol-sdk` implementation. It is not a claim of canonical Signal
Messenger compatibility, hard constant-time JavaScript execution, guaranteed
memory erasure, or fitness for a particular deployment.

## Reviewability

The design favors narrow state transitions, explicit validation, injectable
adapters, deterministic inputs, and small protocol seams. Those boundaries make
security-sensitive behavior easier to inspect independently and allow
integrators to substitute platform services without changing protocol logic.

## Current Profile Guarantees

The current profile is independently versioned and based on selected public
Signal Protocol specifications. This document states its public security and
compatibility boundary.

### Composite identity

- One canonical X25519 + Ed25519 composite tuple is the trust object for each
  `(userId, identityType)`.
- The SDK selects SESAME's per-user identity-key model and provisions that tuple
  unchanged across linked devices. Registration IDs, prekeys, and sessions are
  device-specific. Generic SESAME still supports both identity-key models.
- A managed device link gives the linked device a fresh registration ID that
  differs from the active device's ID, and a fresh ID for a held PNI record.
  A device that a 12.0.x release linked keeps the ID that it has.
- Trust storage persists the tuple and trust metadata. The SDK derives
  commitments locally, and a redundant supplied commitment must match before
  mutation.
- First contact is `UNVERIFIED_TOFU`, not authenticated identity.
- Replacing either component of a pinned tuple fails closed until rotation is
  explicitly accepted. A retired tuple cannot silently regain trust.
- Authenticated safety-number comparison covers both peers' complete composite
  tuples and only promotes the exact current tuple to `VERIFIED`.

The Ed25519 component creates ordinary RFC 8032 signatures. It does not
implement XEdDSA and cannot consume or produce XEdDSA identity signatures.

### PQXDH and ML-KEM-1024

- Post-quantum session establishment is mandatory.
- PQXDH uses standardized FIPS 203 ML-KEM-1024 behavior.
- Public keys and ciphertexts require exactly `0x0A || raw ML-KEM-1024 bytes`.
  Untagged values, the deployed Kyber1024 `0x08` tag, unknown tags, and wrong
  lengths fail before secret derivation or state commit.
- Prekey signatures cover a domain-separated context. That context contains the
  locally derived composite identity commitment, algorithm tag, key ID, and
  complete tagged public key.
- No classical key agreement exists. A peer that advertises no PQ material
  fails with `PQXDH_REQUIRED`. Malformed or failed PQ processing fails closed.

The `0x0A` encoding is distinct from Signal Messenger deployments that use
round-3 Kyber1024 tagged `0x08`.

### SPQR and ML-KEM Braid

- PQXDH sessions keep SPQR mandatory.
- The default SCKA mode is the specification-defined ML-KEM Braid profile
  using ML-KEM-768 and bounded Reed-Solomon decoding.
- HEK follows the ML-KEM Braid specification:
  `SHA3-256(ek_seed || ek_vector)`.
- FIPS 203 serializes the encapsulation key vector-first, and the braid HEK
  order is seed-first. Braid mode therefore runs ML-KEM-768 with a modified
  encapsulation-key commitment, and the SDK makes no FIPS 203 conformance claim
  for that path.
- The modification reaches only the braid path. Direct ML-KEM-768 SCKA uses
  stock ML-KEM-768, and PQXDH uses standardized FIPS 203 ML-KEM-1024 behavior.
- The SDK applies `KDF_OK` once when raw ML-KEM output enters the epoch
  boundary. Braid output is already an epoch secret and is not derived a second
  time.
- The SDK rejects malformed epoch secrets, roots, chain state, chunks, indexes,
  and wire values before it commits live state.
- Direct ML-KEM-768 SCKA remains an explicit SDK mode for product-reviewed
  constraints. It is not the default.

## Forward and Post-Compromise Security

The Double Ratchet derives a new message key for each chain step and advances
chain state after successful use. The SDK bounds skipped receive keys, and
removes each one after use or expiry. Fresh DH ratchet inputs provide break-in
recovery once an uncompromised ratchet step completes. SPQR adds post-quantum
epoch material to the Triple Ratchet hybrid derivation.

These properties depend on authenticated session establishment, uncompromised
future entropy, correct state persistence, and the application honoring
identity-change and safety-number signals. They do not protect a device while
an attacker controls its process, runtime, storage credentials, or random
source.

Best-effort typed-array overwrites reduce the lifetime of some owned temporary
buffers. They do not make old secrets physically unrecoverable from JavaScript
memory. Copies, strings, engine internals, CPU registers, and garbage-collected
heap pages remain outside the SDK's control.

## JavaScript Timing Boundary

Browser, Node, and Expo/React Native JavaScript engines provide no machine-level
constant-time contract. The implementation uses best-effort source patterns on
selected paths:

- full-scan comparison for equal-length MACs and identity bytes.
- fixed work on both decapsulation candidates, then a masked choice between
  them.
- equal-work rejection padding on selected replay and authentication paths.
- fixed-work rejection handling on selected authentication paths.

These patterns do not prove timing equivalence. Secret-influenced remainder and
compression arithmetic, JIT compilation, allocation, garbage collection,
cache effects, and host scheduling remain observable. The current threat model
does not qualify this JavaScript profile for hostile same-process code or a
high-assurance co-resident timing adversary.

## Memory and Key Disposal

`secureZeroBytes()` and related cleanup calls overwrite only the exact mutable
typed array owned by the caller. They cannot guarantee erasure of:

- earlier or implicit copies.
- immutable Base64 or UTF-8 strings.
- engine temporaries, registers, JIT artifacts, or garbage-collected pages.
- persisted copies held by an adapter or operating system.

Applications should:

- keep long-lived private material in the strongest platform-backed storage
  available.
- minimize plaintext/key lifetimes.
- avoid logging secrets.
- treat a compromised JavaScript runtime as a key compromise.

A qualified native/WASM/Rust/Swift backend is roadmap work when a deployment
requires stronger timing or erasure assurance.

## Storage Boundary

Reviewed: 2026-10-20.

Local adapters own identity keys, contact trust metadata, prekeys, session
records, retry records, and group state. The package requires:

- atomic composite-identity writes and explicit rotation acceptance.
- current session-record format version 4.
- that an adapter reject stale-format writes before it replaces current state.
- that an adapter remove or reject stale persisted session records on read.
- no authoritative cached identity commitment.
- authenticated encryption of records and metadata values in an adapter that
  declares a cipher.

Adapter encryption does not compensate for:

- XSS, malicious dependencies, or compromised application code.
- a stolen unlocked device.
- an attacker who also holds the adapter encryption key.

Browser IndexedDB and caller-provided React Native storage inherit their host
application's security boundary.

Each local store declares its `protection`: how it encrypts its data at rest
(`atRest`) and where it keeps the key (`keyCustody`). Client creation fails
when the store declares no `protection`, an unknown value, or a cipher
without a key. The client derives a level from the declaration, and
[Content Recovery](./PROTOCOL_POLICY.md#content-recovery) uses that level to
decide whether the store may hold resendable content. The built-in stores
declare:

| Store | `atRest` | `keyCustody` | Level |
| --- | --- | --- | --- |
| Expo or React Native SQLite store, default vault | `file-cipher` | `os-keychain` | `protected` |
| Node SQLite store with the Electron safeStorage vault | `file-cipher` | `os-keychain` | `protected` |
| Web SQLite store, default IndexedDB vault | `file-cipher` | `same-origin` | `co-located` |
| `IndexedDbSignalProtocolStore` | `record-cipher` | `same-origin` | `co-located` |
| `KeyValueSignalProtocolStore` | `record-cipher` | The custody of its vault | From the vault |
| Any SQLite store with `encryptionAtRest: false` | `none` | `none` | `none` |
| `InMemorySignalProtocolStore` | `none` | `none` | `none` |

A SQLite store with another vault, and a key-value store, take the custody
that the vault declares. A vault that declares no custody counts as
`same-origin`. An encrypted store with a vault that declares `app-vault` is
`protected`. That declaration is a claim of the application, and the SDK
cannot check it.

The record-cipher stores encrypt each metadata value as well as each record.
Metadata values include group master keys, the device authentication key, and
outbox intents. Metadata key names stay in clear text in these stores. Some
names hold an identifier: a group ID, a recipient user ID, or a message ID. A
reader of the storage can see these identifiers and the number of entries, but
not the values. An encrypted SQLite store keeps the metadata keys and values
inside its file cipher.

A record-cipher store encrypts clear metadata values from an earlier SDK when
it opens. It writes its migration marker last, so a stop during the migration
is safe. When the storage is full, the store still opens, keeps those values
clear, and tries again at the next open. An earlier SDK cannot read the
encrypted values.

Retention and deletion limit how long the store holds content. They do not
erase it. The SQLite stores do not set `secure_delete`, so a deleted row
can stay in free pages of the file and in the SQLite journal until SQLite
writes over it. Flash storage, backups, and the browser storage can also
keep earlier copies. A reader who has an earlier copy and its key can read
content that the store deleted. The SDK does not promise erasure.

A conversion with `convertPlaintext` does not erase the plaintext either.
After it, the old plaintext file can stay in free disk blocks, backups, and
file system snapshots. A reader of such a copy needs no key. The SDK cannot
erase these copies.

The store also keeps receive records: the plaintext of each envelope that
the client decrypted on the Relay subscription path, in
`receiveIncomingEnvelopes`, or in `processIncomingEnvelope`. A record is
written in the same transaction as the ratchet or sender key state, so a
crash before the application handles the message does not lose it. The
content recovery policy does not cover it, so every store keeps it, also a
store with the level `none`. The client deletes a record after the
application handles its content and its E2EE delivery receipt is sent. Content
that waits 30 days runs `onReceiveExpired`, and the client then deletes
its record. No setting changes the 30 days.
A record that waits only for its E2EE delivery receipt is deleted 1 day after
the receipt becomes due, or at its age when that comes first, with no
receipt, no `onMessageDecrypted` call, and no `onReceiveExpired` report,
because the application has its content. When the record is a
resend, its completion still reports `onDeliveryRecovered` through its gate. `maxItems` and `maxBytes` bound how many records the store holds.

### Storage protection audit

Encryption, key custody, and content recovery are separate properties. This
table shows how the built-in configurations combine them:

| Configuration | Encryption | Key custody | Content recovery, default `require-protected` | Receive records | Consequence |
| --- | --- | --- | --- | --- | --- |
| Expo, React Native, or Node SQLite store with a keychain vault | File cipher | Operating system keychain | Kept at `protected` | File cipher | Full content recovery |
| Web SQLite store, default IndexedDB vault | File cipher | `same-origin`, co-located | Off unless `allow-co-located-key` | File cipher | Same custody as `IndexedDbSignalProtocolStore`. A switch between them adds no custody strength |
| `IndexedDbSignalProtocolStore` | Record cipher, AES-256-GCM, on records and metadata values | Key in the same database, co-located | Off unless `allow-co-located-key` | Record cipher | Metadata key names stay in clear text |
| `KeyValueSignalProtocolStore` | Record cipher, AES-256-GCM, on records and metadata values | The custody of its vault, default `same-origin` | Kept with an `os-keychain` or `app-vault` vault. A `same-origin` vault needs `allow-co-located-key` | Record cipher | Metadata key names stay in clear text |
| Any SQLite store with `encryptionAtRest: false` | None | None | Off | Clear text on disk | Same exposure as the sessions on that store |
| `InMemorySignalProtocolStore` | None, process memory only | None | Off | Lost at restart | A message that the client acknowledged but the application did not handle is lost at restart |
| Custom store | As declared | As declared | From the declaration | As declared | The SDK cannot check the stored bytes |

The client checks only the shape of a `protection` declaration. It cannot
check that the bytes on disk are encrypted or where the key is. The client does
not check the class of a store, and managed groups work on a custom store. The
application that supplies a custom store is responsible for these properties:

- `commitSessionTrust` writes the ratchet state and the receive record in one
  transaction. `storeSenderKeyRecord` writes the sender key record and its
  receive effects in one transaction. A failed commit rolls back every write
  in it.
- The store declares `protection` truthfully. When it declares `protected`,
  the key is outside the data store.
- The application does not restore a store from a backup while the client
  runs. An earlier ratchet state makes later messages fail to decrypt.
- The store passes the local store conformance kit from
  `@open-e2ee/signal-protocol-sdk/local/store/conformance`. Give the kit the
  `armWriteFailure` hook, so that the rollback of each atomic commit runs.

Group sender key state never leaves the device. A sender key record holds the
chain key that every message key on that chain derives from, and the sender's
private signature key. Together they are enough to read a sender's group
messages and to forge new ones. No adapter transmits them, and no relay
contract accepts them. The same rule covers the message keys held for
out-of-order group messages. Local adapters bound that skipped-key store so a
peer cannot grow it without limit by skipping ever further ahead.

Relay and remote object-store adapters receive public key material, routing
metadata, and opaque ciphertext required by their contracts. TLS,
authorization, abuse controls, atomic prekey consumption, and access logging
remain deployment responsibilities. The relay is not an identity trust anchor.

Remote object-store upload requests use a retry identifier, not a storage key.
Applications must scope that identifier to the authenticated principal. They
must also own the durable mapping from it to a canonical object identifier and
a private provider key. Applications must also enforce object access, upload
size, and encrypted-object content type on the backend. Presigned URLs are
short-lived
bearer credentials. Never log one, and never expose one beyond the authorized
operation.

## Resource and DoS Controls

Protocol parsers enforce exact structural lengths and explicit input caps.
SPQR limits message jumps, skipped keys, retained epochs, chunk indexes, trace
lengths, and serialized input sizes. Reed-Solomon decoders bound message size,
chunk indexes, shard counts, and allocation before decoding. Retry processing
limits attempts and requires an existing sent-message record unless a narrowly
scoped lifecycle path explicitly bypasses message validation.

These controls reduce amplification and unbounded allocation. They do not
replace application-level request size limits, rate limiting, authentication,
or transport abuse prevention.

## Threat Model

In scope:

- passive network observation.
- active message tampering, replay, reordering, duplication, and truncation.
- malicious or stale relay responses within the adapter contract.
- identity component substitution after the SDK pins trust.
- malformed prekeys, KEM keys/ciphertexts, protocol messages, restored state,
  Braid traces, and Reed-Solomon chunks.
- loss and out-of-order delivery within configured protocol bounds.
- later compromise followed by an uncompromised ratchet recovery step.

Out of scope or only partially mitigated:

- compromised endpoints, JavaScript engines, dependencies, or build pipeline.
- hostile same-process code and high-assurance local timing attackers.
- guaranteed secret erasure from managed memory.
- hardware, physical, speculative-execution, and microarchitectural attacks.
- traffic-analysis resistance beyond the metadata/padding behavior explicitly
  implemented.
- Signal Messenger interoperability outside the exact
  alignments stated in this security model.
- recovery of authenticity on unauthenticated first contact without an
  authenticated safety-number or configured trust mechanism.

## Reporting Vulnerabilities

Follow the private reporting instructions in the root
[security policy](../SECURITY.md). Do not open a public issue for a suspected
vulnerability.
