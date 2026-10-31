# Deviations from the Signal Protocol Specifications

> Navigation: [README](../README.md) | [ARCHITECTURE](../ARCHITECTURE.md) |
> [Security](./SECURITY.md) | [Protocol Policy](./PROTOCOL_POLICY.md) |
> **Deviations**

## What compatibility means here

This SDK implements the same cryptographic core as the published Signal Protocol
specifications:

- X3DH/PQXDH key agreement
- the Double Ratchet
- the ML-KEM Braid post-quantum ratchet
- Sesame multi-device session management
- sealed sender
- the Signal Protocol's zero-knowledge group credential system

In many places it is faithful down to the byte. It uses the same KDF labels, the
same chain-key constants, the same protobuf field numbers, and the same
iteration counts.

It is **not wire-compatible with Signal Messenger or with `libsignal`**, and it
is not intended to be:

- a Signal Messenger client cannot decrypt a message from this SDK
- the two systems cannot exchange identities
- a user cannot check a safety number from this SDK against the number Signal
  Messenger shows
- neither side can migrate a session to the other

This is a distinct wire profile,
`IndependentProfileV1`. It shares the Signal Protocol's cryptographic design and
deliberately does not share its encoding.

That distinction matters in a specific way. Reading "implements X3DH and the
Double Ratchet" reasonably leads someone to expect interoperability. There is
none. Reading "safety numbers compatible with Signal Messenger" invites a second
expectation: that a user could verify a contact against the number Signal
Messenger shows. A user cannot. The two numbers come from different inputs and
will never match.

This document is the complete, honest account of where and why the profile
differs. Each entry names the implementing file, the specification section or
`libsignal` source it departs from, the engineering reason, and the cost. A
deviation sometimes weakens an assurance that a reader of the specification
would reasonably assume. This document says so plainly rather than framing it as
a feature.

Deviations fall into three kinds:

- **Deviation**: does something different from the specification or from
  `libsignal`, deliberately.
- **Extension**: adds a mechanism the specification does not describe.
- **Independent design**: shares a name and a goal with a Signal Protocol system.
  It is the SDK's own construction rather than a port of the corresponding
  `libsignal` system.

A fourth label, **faithful**, appears in the table for an area that follows the
specification closely. Such a row is here only to delimit what the neighboring
deviations do and do not touch.

Companion documents: [Protocol Policy](./PROTOCOL_POLICY.md) states which
protocol modes run and which fail closed. This document states how the profile
differs from the specifications. [Security](./SECURITY.md) states the threat
model and what is out of scope.

---

## Summary

| Area | Specification followed | Deviation or extension | Why | Consequence |
|---|---|---|---|---|
| **Identity keys** | X3DH §2.2; `libsignal` `identity_key.rs` | **Deviation.** A 67-byte composite of separate X25519 and Ed25519 keys replaces the single 33-byte Curve25519 identity key | Avoids XEdDSA, a non-standard signature scheme with no vetted JavaScript implementation; standard Ed25519 is independently verifiable | Two keys to store and rotate; larger identity; **no wire compatibility for any identity-bearing material** |
| **Prekey signatures** | X3DH §2.2, §4.5 | **Deviation.** RFC 8032 Ed25519 over a domain-separated context binding the identity commitment, algorithm tag, and key ID — not XEdDSA over the bare key | Defeats cross-algorithm and cross-key-ID substitution that a bare-key signature does not cover | Strictly stronger binding; signatures are unverifiable by Signal Messenger clients and vice versa |
| **Safety numbers** | `libsignal` `fingerprint.rs` | **Deviation.** Iteration, digit encoding, and the order of the two halves are byte-identical, but the input is a composite-identity commitment under an SDK domain string, and the QR version is `4` | Follows from the composite identity; a single-key fingerprint cannot authenticate both components | **Safety numbers are not comparable to Signal Messenger's.** The low-level single-key path equals `libsignal`'s version 2 fingerprint |
| **PQXDH** | PQXDH rev. 3; X3DH rev. 1 for the shared DH steps | **Faithful** on DH order, the `0xFF`×32 prefix, zero-salt HKDF, KEM-secret position, and PQXDH §2.2's info-string construction. **Deviation:** ML-KEM-1024 (FIPS 203) replaces round-3 Kyber1024 | Standardized ML-KEM preferred over round-3 Kyber. The info string names it, and names this application rather than `libsignal`'s, as §2.1 and §2.2 require. PQXDH is required: no classical X3DH session exists | Wire-incompatible with `libsignal` by construction, and the label now says so. The info string is part of the derivation, so any peer that names a different one derives a different `SK` and cannot complete the handshake |
| **Associated data** | X3DH §3.3 | **Deviation.** `AD` is a domain-separated HMAC input over SHA-256 commitments to both composite identities, not `IK_A ‖ IK_B` | Binds the Ed25519 component, which a raw-key `AD` would leave uncovered | Stronger binding; wire-incompatible |
| **Double Ratchet** | Double Ratchet rev. 4 | **Faithful** on `WhisperRatchet`, `WhisperMessageKeys`, the `0x01`/`0x02` seeds, the 80-byte split, AES-256-CBC, the `0x44` version byte, and 8-byte MAC truncation | — | The ratchet core follows the Double Ratchet specification |
| **Message wire format** | `libsignal` `wire.proto` | **Faithful** field numbers 1–8. **Extension:** fields at 100+ carry identity type and ML-KEM one-time prekey material. **Deviation:** address binding uses variable-length UTF-8 user IDs and 4-byte device IDs instead of 17-byte ServiceIds and 1-byte device IDs | The SDK binds application-defined identifiers, not Signal Messenger ACIs | Wire-incompatible; a Signal Messenger client would silently ignore the added fields |
| **Skipped keys and archiving** | Double Ratchet §2.6, §8.4; `libsignal` `consts.rs` | **Deviation.** The 2000-key cap applies to each receiver chain, as in `libsignal`, and a full chain evicts its lowest index. Skipped keys also expire after 7 days, which `libsignal` does not do. Session records serialize as JSON, not protobuf | Double Ratchet §8.4 recommends the deletion of skipped keys after one week. A held key decrypts its message for as long as it stays, so the expiry bounds what a compromised device state exposes | The worst case is 5 receiver chains of 2000 keys each, in the current session and in each of up to 40 archived sessions. **A message more than 7 days out of order is undecryptable** where `libsignal` decrypts it |
| **Padding** | — | **Extension.** ISO 7816-4 bit padding to 160-byte buckets inside the library | Length hiding by default rather than left to the application | `libsignal` does not pad at this layer; Signal Messenger's apps do. PKCS#7 then adds a block, so ciphertext lands 16 bytes past each boundary |
| **SPQR / ML-KEM Braid** | ML-KEM Braid rev. 1 | **Deviation.** Same protocol, same KDF labels, same Reed–Solomon parameters, byte-identical message framing — except `hek = SHA3-256(ek_seed ‖ ek_vector)`, the operand order the specification states, which is the reverse of `libsignal`'s implementation | The normative text was followed over the executable reference | Wire-visible. Headers, ciphertexts, and shared secrets diverge; a braid session cannot complete a single epoch against `libsignal`'s implementation. Also means the KEM is not FIPS 203 in braid mode |
| **Triple Ratchet** | `libsignal` `triple_ratchet.rs` | **Faithful.** The PQ secret enters as the HKDF salt at message-key expansion, same label, same order | — | The braiding construction follows the ML-KEM Braid specification |
| **Sesame** | Sesame rev. 2 | **Faithful** on deleted devices: a removed device is marked and kept for MAXLATENCY, and its archived sessions still decrypt. **Deviation** on session expiry (§4.2 applies only to unacknowledged sessions) and on device-list currency on the Convex relay only (the sender reads the relay's list at most once per 60 s). The Signal Protocol Relay and the memory relay reject a stale declared device set, as §3.3 requires. **Deviation** on stale-record cleanup timing (§5.1: the cleanup runs after the resume, not after a fetch of the whole mailbox, and the Relay's 30-day TTL cap bounds it). **Extensions:** device transfer, encrypted device names, identity-change gating, a 5-device cap | Product requirements the specification does not address | On the Convex relay, a device linked or removed less than 60 s ago can miss a send or still receive one. A client clock that moves forward against the Relay clock between a removal and the cleanup can lose a message accepted just before the removal. Device transfer copies the identity private key and no ratchet state, so each device starts its own sessions |
| **Device-set reconciliation** | Signal's server `MessageController`; Signal's Desktop client `sendToGroup` | **Deviation** in detail. The answer order, one post for each device of a direct send, a bound on direct sends, no empty sync post, a refusal for each not-found group destination, an acknowledgment marker, and a group body sealed again with the same ciphertext (§5.6) | The Relay takes one destination for each direct body, keeps one record for each account, admits a delivery epoch at most 5 minutes ahead of its clock and at most 24 hours behind it from the release that follows v2026.10.25, and stores each send attempt | A phase that does not match in 10 restarts fails the send with `DeviceSetReconciliationError`. A relay that does not acknowledge the comparison raises `DEVICE_SET_UNCHECKED` |
| **Sealed sender** | `libsignal` `sealed_sender.rs` | **Faithful** on the multi-recipient transport labels, KEM, AES-256-GCM-SIV, binary format, and `0x3FFF` registration-ID mask. **Extension:** sender and server certificates require signed Relay scope and issuer validity under operator-owned Ed25519 roots | Binds anonymous delivery to one Relay deployment and supports explicit issuer rotation and revocation | The transport follows `libsignal`; certificates are not interchangeable with Signal Messenger or another deployment |
| **Delivery token** | `libsignal` `profile_key.rs` | **Faithful.** `deriveAccessKey` follows `libsignal`'s `ProfileKey::derive_access_key`, and reproduces `libsignal`'s published known-answer values | — | Not an SDK invention, despite what the module name suggests |
| **Sender keys** | `libsignal` `sender_keys.rs` | **Deviation.** Protobuf fields, chain seeds, and HKDF-Extract/Expand match. The SDK uses frame version `0x44`, Ed25519 signatures, and UTF-8 distribution identifiers. | The identity profile selects Ed25519. The frame version marks the correction of the former missing Extract. | Message-key derivation matches the reference. Former SDK state and messages require a reset. Frames still differ from Signal Messenger. |
| **Sender-key distribution tracking** | Signal's Android client `SenderKeySharedTable`; Signal's Desktop client `sendToGroup` | **Deviation** in detail. The same events delete rows. A session or key write deletes them in the same write. The row match adds the key ID and compares the registration ID, as Signal's Desktop client does. A replay keeps its group ciphertext | The Relay refuses a second operation under one message ID. The SQLite, IndexedDB, and key-value stores keep the rows in durable storage, and the memory store keeps them in memory by design | A device that a replay adds gets the content only for a `Resendable` send |
| **Cross-tab locks** | Signal's Desktop and Android clients | **Faithful** in a browser: a group send and each session write take a Web Lock named by the store identity, so the tabs and workers of one origin run them one at a time. **Deviation** elsewhere: the lock orders one store object in one process | Signal runs one process for each device. Only the browser stores have a store identity, and Web Locks in Node order one process only | Two processes, or two store objects, that share one database need exclusive access from the application (§7.6) |
| **Group send route** | Signal's server, multi-recipient send | **Faithful** in the SDK: each group send goes to the anonymous group route with a group send token. The Relay still serves an identified group route that no SDK release calls | The Relay removes the identified route forward only | Until the removal, a client that posts to the identified route sends under its account credential, with no device-set check when the post declares none (§7.7) |
| **Groups** | Signal Private Group System | **Independent design.** Real zkgroup primitives underneath; profile-key credential issuance blinds the ACI-bound profile-key attribute, the server validates every change against zero-knowledge presentations and signs the accepted result, and clients verify those signatures | Ships a validating group server with an enforcement contract (S1–S14) specified in-tree | Not wire-compatible with the Signal Private Group System; credentials are not interchangeable. The issuer sees the authenticated ACI and redemption window, but not the raw profile key |
| **Receive order** | Signal's Android client | **Faithful.** The receive queue (`client/receive-queue.ts`) holds back the later records of one conversation, as Android queues its message jobs: group content per group, a sent transcript per destination, and other content per sender account. The commit order stays per sender device | — | A record that waits for its group state holds back the later content of its group from every sender until a fetch of its group or `syncGroup` completes, or until the record expires after 30 days. Direct chats and other groups make progress. A record in hook backoff holds back its conversation until its hook succeeds, it reaches the hook attempt cap of 10, or it expires. Before the queue restores a record, it keys the record by its stored group or by its sender account. A missing sender key does not hold the queue: that content goes to the retry request handler |
| **Receive hook attempt cap** | Signal's Desktop client | **Deviation.** After 10 failed `onMessageDecrypted` attempts, a record no longer holds back its conversation, as on Desktop. Desktop deletes the record at startup. The SDK keeps it, offers it to the hook once at each start, shows the count in `PendingReceive.hookAttempts`, and removes it at `discardPendingReceive` | The hook is application code. A drop loses content whose ratchet step is spent, and an application update can repair the hook | A hook that ends the process on the record ends it once at each start, until the record expires or the application discards it (§8.2) |
| **Receive hook bound** | Signal's Desktop client | **Deviation** in detail. Each application hook that a receive pass awaits has a bound, `receiveHookTimeoutMs`, 2 minutes by default. Desktop bounds its receive dispatch at 2 minutes and its long-running tasks at 30 minutes | A founder ruling sets the bound at 2 minutes. The SDK cannot tell a slow hook from a hung one | A timeout of `onMessageDecrypted` counts as one failed attempt. A timeout of another hook is logged, and the pass continues. A settle after the bound writes nothing (§8.4) |
| **Delivery receipt lifespan** | Signal's Android client | **Faithful.** A stored receipt is sent only within 1 day after it becomes owed, as Android's receipt job lives for 1 day. The receipt is durable across a restart, as on Android | — | A receipt that cannot go out within 1 day is not sent, and no hook reports it (§8.3) |
| **Receive admission bounds** | Signal's Desktop client | **Extension.** Before a decrypt, the receive queue checks `maxItems`, `maxBytes`, and the group share `blockedGroupShare`. The defaults are provisional. Desktop decrypts each envelope as it arrives and bounds stored content only by age and attempts | The SDK shares a storage budget with the application in a browser and on mobile | A refused envelope is not acknowledged. It stays at the Relay and expires there with no local hook. The messages behind it still arrive (§8.5) |
| **zkgroup / zkcredential** | `libsignal` `zkgroup`, `zkcredential`, `poksho` | **Faithful** port of the Ristretto255 KVAC and Sigma-protocol system, verified against `libsignal`'s known-answer vectors. **Deviation:** server parameter derivation is structured as four labeled derivations rather than one seeded derivation | Server keys are the deploying operator's own trust root (each deployment generates its own seed), not Signal Messenger's | The zero-knowledge properties are real. Credentials are not interchangeable with Signal Messenger's |
| **Registration IDs** | `libsignal` `sealed_sender.rs` | **Faithful.** Generated in `[1, 16383]`, strictly inside the 14 bits the wire format reserves | — | — |
| **Linked-device registration IDs** | Signal's device linking | **Faithful** for a new link: the linked device gets its own fresh registration ID. **Deviation:** a device that a 12.0.x release linked keeps the ID of its active device, and a link that a 12.0.x release began keeps its stored ID (§5.7) | A changed ID on a live device fails its next prekey sync. A fresh ID on a link already begun can reserve a second device | Two devices of one account can share a registration ID. The sender-key handoff ledger keys each row by the device, so they stay apart |
| **Linked-device group keys** | Signal's device linking | **Deviation.** The link copies each group master key from the active device's group store in the calling process. A group record that a release before 12.0.0 wrote, and that the active device has not read since, is not copied (§5.8) | The SDK has no storage service, and no master key crosses the Relay | The process that links the device must hold the active device's store. Such an unread group initializes from its first group message |
| **Posting deadline and send progress** | Signal's Android client `IndividualSendJob`; Signal's Desktop client `conversationJobQueue` | **Faithful** on a window of 1 day and on progress at the deadline: an accepted device stays accepted. **Deviation** in detail. The deadline also ends 24 hours after the send timestamp, has no message-expiry term, and never moves on a restart. A lost Relay answer is acceptance-unknown, not failed. An automatic retry posts the stored bytes and epoch. With a store that lists its metadata keys, the SDK replays open sends at start and on reconnect, as the Signal job runners do, and reports each end once through `onSendOutcome`. On a custom store without the listing method, the application replays (§5.9) | The Relay admits an epoch at most 24 hours behind its clock, keeps a fingerprint of each operation, and charges each accepted operation. Custom stores stay supported, so the listing method is optional | A direct send posts nothing at or after its deadline. When the acceptance of a device is not known, the send throws `SendAcceptanceUnknownError`, and a replay or a resend after it can add one charged unit. When the plaintext of an open send is gone, `onSendOutcome` reports `content-required` |

---

## 1. Identity keys and signatures

### 1.1 Composite identity replaces the single Curve25519 key

`libsignal` represents an identity as one Curve25519 public key serialized as
`0x05 ‖ key`, or 33 bytes ([`identity_key.rs:23-49`][ik]). One private key
serves both Diffie-Hellman and, via XEdDSA, signing.

This SDK stores a versioned tuple of two separate keys
(`keys/identity.ts:20-23`, `:66-72`):

```text
0x01                                  version
|| 0x01 || 32-byte X25519 public key   DH component
|| 0x02 || 32-byte Ed25519 public key  signing component
```

67 bytes, X25519 first. Decoding fails closed on any wrong version byte, tag, or
length (`keys/identity.ts:75-96`).

**Why.** XEdDSA ([spec][xeddsa]) lets one Curve25519 key serve both roles by
converting a Montgomery point to an Edwards point at signing time. It is also
non-standard:

- no vetted JavaScript implementation exists
- the conversion has sign-bit handling that is easy to get subtly wrong
- no general-purpose Ed25519 verifier can check the resulting signatures

An explicit Ed25519 key costs 32 bytes and one more key to manage. It buys
signatures that any RFC 8032 implementation can verify, and that auditors can
reason about without first reasoning about curve conversion.

**Cost.** Two keys to generate, store, rotate, and back up. A larger identity on
the wire and at rest. And no wire compatibility for anything that carries an
identity: prekey bundles, initial messages, sender certificates, safety numbers.
`libsignal`'s `IdentityKey::decode` reads the leading `0x01` as an unknown key
type and errors.

A commitment binds the tuple (`keys/identity.ts:98-100`):

```text
SHA-256(UTF8("signal-protocol-js composite identity v1") || CompositeIdentityV1)
```

The SDK never trusts a commitment that arrives from a relay, cache, or caller.
It recomputes the commitment and compares it in constant time
(`keys/identity.ts:103-111`). Every producer of stored identity bytes goes
through a decode/re-encode round trip (`keys/identity.ts:154-161`). Two
encodings of the same key therefore cannot forge an identity-change event.
`libsignal` has no commitment concept, because a single-key format has nothing
to bind together.

**Not ported.** `libsignal`'s ACI↔PNI alternate-identity signature
([`identity_key.rs:61-70`][ik]) has no SDK equivalent. ACI and PNI are fully
independent identities here with independent trust histories. Neither certifies
the other. An application that wants a user's two identities linked must
establish that link itself.

### 1.2 Prekey signatures are Ed25519 over a domain-separated context

`libsignal` signs the bare serialized public key with the identity key via
XEdDSA, and verifies the same way ([`session.rs:199-213`][sess]).

This SDK signs, with the separate Ed25519 key (`keys/prekey-signature.ts:39-45`):

```text
UTF8("signal-protocol-js prekey signature v1")
|| SHA-256 identity commitment
|| algorithm tag (1 byte)
|| key ID (uint32, big-endian)
|| serialized public key
```

ML-KEM prekeys must carry their `0x0A` tag inside the signed bytes
(`keys/prekey-signature.ts:33-38`).

**Why.** A bare-key signature says only that the identity holder signed these 32
bytes. It does not say which algorithm the key is for, which key ID it occupies,
or which identity it belongs to. Binding all three defeats cross-algorithm
substitution (presenting an X25519 signature as an ML-KEM one) and cross-key-ID
substitution. This is strictly stronger than the specification requires.

**Cost.** Wire incompatibility, and a signature format that no Signal Messenger
implementation can verify.

The same Ed25519-instead-of-XEdDSA choice applies to sealed sender certificates
(`internal/protocol/sealed-sender/certificate.ts:59`, `:106`) and to sender key
messages (§7.2).

XEdDSA and VXEdDSA are not implemented, not stubbed, and not claimed anywhere in
this codebase. Where the frozen upstream specification snapshots mention them,
that is upstream text. The SDK's own documentation consistently states that it
uses ordinary Ed25519 instead.

### 1.3 Safety numbers are not comparable to Signal Messenger's

State this without hedging. A safety number from this SDK **will never match**
the safety number Signal Messenger shows for the same two users. A user cannot
verify a contact by reading a number out of one application and comparing it
against the other.

Two independent reasons, either of which is sufficient.

**The SDK computes the user-facing number over a composite commitment.**
The `client.verify()` method uses `generateCompositeSafetyNumber`
(`client/sessions.ts:374`, `:436`). Its per-party hash iterates over
`UTF8("signal-protocol-js composite safety number v1") ‖ type-tagged user ID ‖
SHA-256 identity commitment` (`safety/core.ts:52-54`, `:249-262`). None of that
input exists in `libsignal`'s construction ([`fingerprint.rs:161-192`][fp]).

**The identity material differs.** Even the raw input is a 67-byte two-key tuple
rather than a 33-byte `0x05 ‖ X25519` key.

**The order of the two halves is faithful.** The party whose 30-digit display
string is lower by unsigned byte comparison comes first
(`safety/core.ts:186-226`), as in `libsignal` ([`fingerprint.rs:32-40`][fp]).
The SDK does not compare user identifiers, so neither the locale nor the
UTF-16 code-unit order can change the result. When the two display strings
are equal, the 60 digits do not depend on the order, and the full hash bytes
choose the first fingerprint, so both parties still produce the same hex and
emoji. The SDK's low-level single-key path is therefore byte-identical to
`libsignal`'s version 2 fingerprint (`safety/core.ts:43`).

Other parts *are* faithful. The iteration is byte-for-byte `libsignal`'s: 5200
iterations of SHA-512 over `0x0000 ‖ key ‖ id`, then `hash ‖ key`
(`safety/core.ts:146-152` vs [`fingerprint.rs:170-189`][fp]). So is the digit
encoding (six 5-byte big-endian chunks mod 100000, 30 digits per party). So is
the scannable-fingerprint protobuf layout (`safety/protobuf.ts:94-109`). The
cross-verification swap and constant-time comparison match as well.

The QR format version is the SDK's own: `4` for the composite path
(`safety/core.ts:45-50`), where `libsignal` knows only versions 1 and 2 and
returns `VersionMismatch` for anything else. A distinct version in the same
protobuf namespace is the correct fail-closed choice. A Signal Messenger client
rejects the code rather than misreading it. An earlier SDK ordered the two
halves by user ID under version `3`. A version `3` code reports
`version_mismatch` (`safety/fingerprint.ts:313-316`), so two parties never
compare numbers that two different order rules made.

The SDK also offers an emoji fingerprint (`safety/core.ts:321-435`) and
verification deep links (`safety/url.ts`). Both are extensions with no
`libsignal` counterpart. The emoji form derives from the fingerprint that comes
first only. It therefore encodes roughly half of what the 60-digit number encodes.
Do not present it to users as an equal-strength alternative.

### 1.4 Registration ID range

The SDK generates registration IDs in the closed range `[1, 16383]`
(`keys/generation.ts:43-46`). The wire format reserves exactly 14 bits, and
`libsignal` rejects any ID where `id & 0x3FFF != id`
([`sealed_sender.rs:1508-1515`][ss]). Its own helper generates `[1, 16380]`.

The upper bound is load-bearing rather than cosmetic. The value `16384` is
`0x4000` and does not fit in 14 bits. The SDK's multi-recipient sealed-sender
encoder masks rather than rejects
(`internal/protocol/sealed-sender/multi-recipient-message.ts`), so an ID one above
the range would reach the wire as `0`. The generated range is therefore strictly
narrower than `libsignal`'s accepted range, and a test asserts that every
generated ID survives the mask unchanged.

---

## 2. X3DH and PQXDH

The key agreement is the most faithful area in the codebase. These all match
`libsignal` exactly:

- the DH computation order
- the 32-byte `0xFF` discontinuity prefix
- the zero-filled HKDF salt
- the single-step derivation over the full concatenation
- the KEM shared secret appended last
- the 96-byte output split

- Initiator DH order `DH(IK_A,SPK_B)`, `DH(EK_A,IK_B)`, `DH(EK_A,SPK_B)`,
  `DH(EK_A,OPK_B)`: `internal/protocol/pqxdh/pqxdh.ts:243-264` vs
  [`pqxdh.rs:202-224`][pq]. Spec X3DH §3.3.
- `F = 0xFF × 32` prefix: `internal/protocol/pqxdh/pqxdh.ts:267-271` vs
  [`pqxdh.rs:200`][pq]. Spec X3DH §2.2.
- KEM secret appended after all DH outputs, then one HKDF:
  `internal/protocol/pqxdh/pqxdh.ts:365-374` vs [`pqxdh.rs:226-230`][pq]. Spec
  PQXDH §3.3.

Two hardening extensions go beyond the specification at no interop cost:

- the SDK validates every remote X25519 point before it computes any DH
  (`internal/protocol/pqxdh/pqxdh.ts:219-227`)
- the SDK validates prekey bundles far more strictly than `libsignal` requires
  (`internal/session/handshake.ts:107-138`)

### 2.1 The info strings name this application and this KEM

The SDK uses ML-KEM-1024 (FIPS 203) where `libsignal` uses round-3 Kyber1024,
tagged `0x0A` rather than `0x08` (`internal/crypto/pq/kyber.ts:79`). That much is
deliberate. The SDK prefers the standardized algorithm over the round-3 draft,
and a single unambiguous tag over a legacy fallback.

The info string is the SDK's own (`types/protocol-config.ts:624-638`):

```text
OpenE2EE_X25519_SHA-256_ML-KEM-1024
```

The SDK sets both implementer-chosen parameters to name itself and the KEM it
runs. PQXDH §2.2 defines the info string as `info`, `curve`, `hash`, and `pqkem`
joined by `_`, with each representation implementer-chosen. PQXDH §2.1 defines
`info` as an application identifier of at least 8 bytes. X3DH §2.1 defines the
same `info` parameter, and §3.3 uses it as the HKDF info with nothing appended.

The SDK does not use `libsignal`'s labels, `WhisperText` and
`WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024` ([`pqxdh.rs:73-74`][pq]).
Inheriting them would be wrong on both parameters:

1. **`pqkem` would name a KEM the SDK does not run**, violating §2.2. That is
   worse than a labeling error. Two implementations feeding an identical label
   derive *different* shared secrets. The KEM underneath differs, and nothing at
   the KDF layer signals it. Domain separation is the one job the info string
   has.
2. **`info` would name someone else's application.** The specifications ask
   for an identifier of the application deriving the key. This SDK is not
   Signal Messenger.

The SDK's labels are incompatible with sessions established under
`libsignal`'s labels. Those sessions derive a different `SK`, and neither
side can continue them. Nothing else about the derivation changes.

An application that needs `libsignal`'s known-answer vectors can still get them
by setting `protocolStrategy.keyExchangeInfoString` to the old label
explicitly, which is what that option is for. Doing so re-adopts the §2.2
violation knowingly rather than by default.

### 2.2 Associated data binds identity commitments

X3DH §3.3 specifies `AD = Encode(IK_A) ‖ Encode(IK_B)`, and `libsignal`
implements exactly that with raw 33-byte serialized keys
([`protocol.rs:225-241`][proto]).

The SDK computes (`internal/session/identity-binding.ts:11-25`):

```text
HMAC-SHA256(mac_key,
    UTF8("signal-protocol-js composite identity message mac v1")
 || SHA-256 commitment to sender's composite identity
 || SHA-256 commitment to receiver's composite identity
 || version byte || protobuf bytes
)[0..8]
```

**Why.** With a two-key identity, an `AD` over the DH key alone would leave the
Ed25519 signing component unbound. That component authenticates every prekey the
peer will ever publish. Hashing the commitment covers both.

**Cost.** This is the single largest wire deviation in the message path. The
truncation to 8 bytes matches `libsignal`'s convention, and the construction is
sound and domain-separated. Even so, a Signal Messenger client and this SDK
cannot exchange a single message.

### 2.3 The SDK defers one-time prekey deletion

PQXDH §3.4 has Bob delete a used one-time prekey after successful decryption. The
SDK records a pending deletion (`internal/manager/manager.ts:940-952`) and
commits it only once a prekey message decrypts
(`internal/session/cipher.ts:1189-1200`). This is compliant in letter. It also
widens the window in which an attacker can replay the same first ciphertext
before commit. The SDK refuses auto-recovery for duplicate and missing-prekey
conditions (`internal/session/cipher.ts:1519-1527`).

### 2.4 Ratchet initialization details

Two differences at the boundary between key agreement and the ratchet:

**Alice reuses her key-agreement ephemeral as her first ratchet key**
(`internal/session/builder.ts:158-170`). By contrast, `libsignal` generates a
fresh sending ratchet key, distinct from the handshake ephemeral
([`ratchet.rs:77-81`][rat]). In `libsignal` the prekey message's base key and the
first message's ratchet key therefore differ. Here they are the same value. No
concrete attack follows, but the reuse weakens key separation and it is
wire-visible.

**Bob initializes without a sending chain** (`internal/session/builder.ts:318-356`),
deriving chains on the first DH ratchet, where `libsignal` seeds a sending chain
immediately ([`ratchet.rs:137-172`][rat]). A side effect is that bytes 32–64 of
the 96-byte derivation, the initial chain key, never produce a message key on
either side. The SDK keeps the 96-byte split for shape compatibility, but only
the root key and the SPQR key are load-bearing.

### 2.5 PQXDH is required

Every new session uses PQXDH. The SDK has no classical X3DH key agreement and
no setting that enables one. A peer bundle without an ML-KEM prekey fails with
`PQXDH_REQUIRED`, and any PQXDH failure raises rather than downgrading
(`internal/session/handshake.ts:156-408`). This matches `libsignal`, which
removed X3DH and rejects pre-Kyber prekey messages
([`session.rs:105-112`][sess]). A stored classical session continues as a
Double Ratchet session. [Protocol Policy](./PROTOCOL_POLICY.md) documents the
policy.

---

## 3. Double Ratchet and wire format

### 3.1 The ratchet core is faithful

These parts are byte-for-byte with `libsignal`:

- the `0x01`/`0x02` chain-key seeds (`internal/crypto/kdf/hkdf.ts:183-195` vs
  [`keys.rs:148-149`][rk])
- the `WhisperMessageKeys` expansion to 80 bytes split 32/32/16
  (`internal/crypto/kdf/hkdf.ts:215-243` vs [`keys.rs:100-118`][rk])
- the `WhisperRatchet` root-key step producing a 64-byte split
  (`internal/crypto/kdf/hkdf.ts:141-161` vs [`keys.rs:199-218`][rk])
- the DH ratchet half-step ordering
- `MAX_RECEIVER_CHAINS = 5`
- AES-256-CBC with PKCS#7
- the `0x44` version byte
- 8-byte MAC truncation

Message framing matches too: `[version byte] ‖ protobuf ‖ [8-byte HMAC]` for
messages and `[version byte] ‖ protobuf` for prekey messages
(`internal/encoding/proto/envelope.ts:104-168`). What goes *into* the MAC does
not. See §2.2.

Protobuf fields 1–8 match [`wire.proto`][wp] exactly, including `libsignal`'s
non-obvious ordering where `registrationId` is field 5 and `signedPreKeyId` is
field 6.

### 3.2 Added fields and address binding

**Extension.** The SDK adds fields in the 100+ range that `libsignal` does not
have: `recipientIdentityType` on both message types, and `kemOneTimePreKeyId` /
`kemOneTimeCiphertext` on prekey messages
(`internal/encoding/proto/signal-message.ts:80`, `:226-228`). High numbering
avoids collision with future upstream fields. A Signal Messenger client parses
the message and ignores the added fields, which loses the identity-type
binding.

**Deviation.** `libsignal` binds addresses as a 17-byte fixed-width ServiceId plus
a 1-byte device ID ([`protocol.rs:246-260`][proto]). The SDK binds a
format-version byte, a varint-length-prefixed UTF-8 user ID, and a 4-byte
big-endian device ID (`internal/encoding/proto/signal-message.ts:84-92`). The
encoding is unambiguous, but it authenticates an application-defined identifier
rather than a Signal Messenger ACI or PNI. That is the correct thing for this SDK
to bind, and an incompatible thing to put on the wire.

The SDK is also stricter than `libsignal` on decode. It requires fields that
`libsignal` treats as optional for backward compatibility, and it enforces exact
lengths (`internal/encoding/proto/signal-message.ts:332-340`, `:488-505`). This
is safer, and it is one more reason the formats cannot meet.

### 3.3 Skipped-key retention adds a 7-day expiry to libsignal's limits

The constants match: `MAX_MESSAGE_KEYS = 2000`, `MAX_FORWARD_JUMPS = 25000`, and
`MAX_RECEIVER_CHAINS = 5` (`internal/protocol/double-ratchet/ratchet.ts:194-207`
vs [`consts.rs:8-10`][consts]). The SDK applies the caps as `libsignal` does,
and it adds one limit that `libsignal` does not have.

**The cap is per chain.** `libsignal` applies 2000 to the key vector of each
chain ([`double_ratchet.rs:346-361`][dr]). The SDK does the same
(`internal/protocol/double-ratchet/chains.ts:425-447`). A store to one chain
never evicts a key of another chain. The worst case is 5 receiver chains of
2000 keys each, in the current session and in each of up to 40 archived
sessions (`types/session.ts:800`).

**A full chain evicts its lowest index.** `libsignal` inserts each key at the
front and drops the last entry, which is the oldest insertion. The keys of one
chain are stored in index order, so the two rules drop the same key. The SDK
does not read the clock to choose the key.

**Skipped keys expire after 7 days**
(`internal/protocol/double-ratchet/ratchet.ts:180`). `libsignal` has no
time-based expiry for message keys. Double Ratchet §8.4 recommends this policy:
a held skipped key decrypts its message for as long as it stays, so a
compromise of the device state exposes each message whose key is held. The
expiry bounds that window.

The consequence: **a message more than 7 days out of order is undecryptable in
this SDK, and `libsignal` decrypts it.** This occurs when the recipient is
offline for more than a week, or when the message stays in transit for more
than a week.

Two related extensions go with this. A `processedChains` map rejects messages
that bear a ratchet key from a retired chain
(`internal/protocol/double-ratchet/ratchet.ts:141-153`), which closes a replay gap
that `libsignal` handles only through its five-chain window. Self-sessions get a
finite 100,000-message skip limit (`internal/session/validation.ts:252-260`)
where `libsignal` uses `usize::MAX`.

### 3.4 Session archiving and serialization

The cap matches: 40 archived states, [`consts.rs:11`][consts]. The eviction
order matches: `libsignal` drops the oldest insertion from its ordered list
([`session.rs:814-826`][st]), and the SDK drops the oldest insertion from its
archive (`types/session.ts:844-879`). The structure differs. The SDK keeps a
map keyed by base key. Archiving a session whose base key is already archived
moves that entry to the newest end rather than adding a second one, so the
effective history can be shorter than 40.

The archive clears the unacknowledged prekey state, as `libsignal` does
([`session.rs:814-826`][st] calls `clear_unacknowledged_pre_key_message`,
[`session.rs:566-589`][st]). `SessionRecord.archiveCurrent` and
`promoteSession` archive a copy of the session without the pending flag, the
prekey identifiers, and the KEM ciphertexts (`types/session.ts:824-834`). A
promoted session sends a SignalMessage, not a PreKeyMessage.

**Session records serialize as JSON, not protobuf**
(`local/store/session-codec.ts:10-24`). The constraint is that no Signal client
reads or writes an SDK store, so the stored format has no interoperability
requirement. The SDK session also has fields that the `libsignal` record has no
place for, such as the KEM one-time prekey ciphertext next to the Kyber
ciphertext (`types/session.ts:255-256`). One consequence is worth naming. Key
material sits in immutable JavaScript strings that nothing can zero, where
`libsignal` can zero its byte vectors.

### 3.5 Padding

**Extension.** The SDK pads message plaintext to 160-byte buckets with ISO 7816-4
bit padding, which is a `0x80` terminator followed by zeros
(`internal/crypto/symmetric/padding.ts:19-60`). Unpadding scans backwards and
rejects malformed padding with a deliberately generic error, which avoids a
padding oracle.

`libsignal` does not bucket-pad at this layer. In Signal Messenger, that step
lives in the client applications. Padding in the library turns length hiding on
by default, instead of leaving it for each integrator to remember.

One imprecision follows. The padded plaintext is an exact multiple of 160, and
AES-CBC then applies PKCS#7, so every message gets a full extra block. A 5-byte
message produces 160 padded bytes and 176 ciphertext bytes. Length is still
quantized in 160-byte steps, so the hiding property holds. The ciphertext simply
sits 16 bytes past each boundary rather than on it.

---

## 4. SPQR and the ML-KEM Braid

This is the same protocol as the SparsePostQuantumRatchet v1 protocol, implemented
independently and pinned against commit `06959b4`, which upstream tags
`SparsePostQuantumRatchet v1.6.0`. The fidelity is high and specific:

- **KDF labels are byte-identical**, including the double space in
  `"Signal PQ Ratchet V1 Chain  Start"` (`internal/crypto/kdf/hkdf.ts:353-368`).
- **The authenticator construction matches**, including `PROTOCOL_INFO =
  "Signal_PQCKA_V1_MLKEM768"` and the `:ekheader` / `:ciphertext` MAC inputs
  (`internal/protocol/spqr/ml-kem-braid/kdf.ts:32-92`).
- **The Reed–Solomon erasure layer matches**: GF(2^16) with primitive polynomial
  `0x1100b`. Chunks are 32 bytes, with 16 polynomials and degree bound 35.
  Reed–Solomon comes from `libsignal`. It is not an SDK addition.
- **The production wire framing is byte-compatible**:
  `VERSION ‖ LEB128(epoch) ‖ LEB128(chain_index) ‖ MSG_TYPE ‖ [LEB128(chunk_index) ‖ CHUNK]`
  (`internal/encoding/proto/pq-ratchet-serialize.ts`), matching `libsignal`'s
  `serialize.rs`, with the same message-type values and the same epoch offset.
- **ML-KEM-768 with the same incremental split** (32-byte seed, 1152-byte vector,
  960/128-byte ciphertext parts).

Two delta reviews moved the pin forward from `f2589fef`.

The step to `fd32048` found one behavioral change upstream. Decoding a chain
epoch direction now rejects a `next` chain key whose length is neither zero nor
32 bytes. The internal next-key assertion checks that same exact length rather
than mere non-emptiness. Two upstream error strings now name the value they
reject. The rest of that delta is proof-assistant annotation and loop rewriting,
which leaves behavior unchanged.

The SDK refuses the same key at a different point. The internal SPQR state
loader requires every chain key, root key, and skipped-message key to be
canonical base64 for exactly 32 bytes (`internal/protocol/spqr/serialize.ts:44-72`).
The production session load does not run that loader, and it does not check the
chain-key length. A stored wrong-length chain key fails at its first chain step,
because the chain KDF refuses a key that is not 32 bytes
(`internal/crypto/kdf/hkdf.ts:438-445`). Upstream refuses the key when it loads
the state. The SDK has no state in which the key is absent.

The step to `06959b4` has two commits that change behavior. `cb8a727` ("Improve
handling of higher-than-1 SPQR versions") moves preamble parsing into
`src/lib.rs` (`msg_preamble`) and moves the epoch-0 index-0 case into
`Chain::recv_key` (`src/chain.rs:417-419`). `a395789` ("Disallow unsupported
versions from turning off PQ ratcheting") makes an unknown version after
negotiation a `VersionMismatch` error. It also removes `displaydoc`, moves
`curve25519-dalek` to the dev-dependencies, and adds one lint attribute to
`polynomial.rs`. The changed files are `src/lib.rs`, `src/chain.rs`,
`src/v1/chunked/states.rs`, `src/v1/chunked/states/serialize.rs`,
`src/encoding/polynomial.rs`, `Cargo.toml`, `Cargo.lock`, and one upstream
test module. `Version::MAX` stays `V1` (`src/lib.rs:239`). No KDF label,
framing byte, or Reed–Solomon parameter changes.

The SDK behavior does not change. Upstream now returns an epoch-0 key for a
higher-version message before negotiation, and it refuses an unknown version
after negotiation. The SDK refuses a version byte other than 1 before
negotiation and ignores it after negotiation. Neither path occurs between v1
peers. The SDK fixes the braid version at 1
(`internal/protocol/spqr/ml-kem-braid/serialize.ts:270-272`,
`internal/protocol/spqr/spqr.ts:597`) and maps a version byte other than 1 to
`v0` (`internal/protocol/version.ts:254`, `:183-197`).

### 4.1 The `hek` operand order diverges

One divergence breaks interoperability completely. The SDK computes
(`internal/protocol/spqr/ml-kem-braid/noble-pq/index.ts:841-843`):

```text
hek = SHA3-256(ek_seed || ek_vector)
```

`libsignal`, through libcrux, builds the encapsulation key as `t̂ ‖ ρ` before
hashing. That is the reverse order.

The SDK follows the **normative text of the published ML-KEM Braid
specification**, which states seed-first ordering. `libsignal` follows FIPS 203,
which serializes vector-first. The specification and the reference implementation
disagree, and the SDK chose the specification.

The value feeds the Fujisaki–Okamoto transform, so the consequences cascade:

- different header bytes, so `libsignal`'s header validation rejects the SDK's
  output
- a different ciphertext
- a different shared secret
- a different epoch secret
- a different authenticator ratchet

**A braid session between this SDK and Signal Messenger's implementation cannot
complete a single epoch.**

Two further consequences a reader should not have to infer:

- **In braid mode the KEM is not FIPS 203 ML-KEM-768.** It is ML-KEM-768 with a
  modified `hek` derivation. The change does not weaken the security argument,
  because the hash input permutes the same material. A FIPS conformance claim
  still does not hold for this path. Direct (non-braid) mode uses stock
  ML-KEM-768.
- Elsewhere the SDK resolves the same spec-versus-code conflict in the *opposite*
  direction. For `KDF_AUTH` it follows the `libsignal` Rust reference rather than
  the written specification. Each choice is defensible on its own. Together they
  are inconsistent about which artifact is authoritative.

The operand order is part of the public compatibility boundary stated in
[Protocol Policy](./PROTOCOL_POLICY.md). Changing it later would invalidate every
braid session persisted under the former ordering.

### 4.2 Direct mode and state format

**Extension.** An opt-in direct mode (`protocol.braid: 'disabled'`) uses stock
ML-KEM-768 and adds wire message types `0x80`–`0x82`
(`internal/encoding/proto/pq-ratchet-serialize.ts:40-45`). `libsignal`'s parser
rejects anything above `6`, so these types are visible only within the SDK. They
occupy a byte range `libsignal` has not claimed. This mode has no Signal Protocol
analogue.

**Independent design.** Persisted SPQR state uses a flat message with 20 fields
where `libsignal` uses an 11-variant `oneof` over nested structures. Serialized SPQR
state is not portable in either direction.

**Faithful.** The SPQR chain trims the held skipped keys of one epoch by
message index, as `libsignal`'s chain collects its key history. When an epoch
holds `max_ooo × 11/10 + 1` keys or more, 2201 by default, a receive drops each
key of that epoch whose index is below the receive counter minus `max_ooo`
(`internal/protocol/spqr/validate.ts:63-123`, called at
`internal/protocol/spqr/spqr.ts:1331`, vs `src/chain.rs:84-88` and `:146` at
`06959b4`). A jump past every held key clears the held keys of the epoch first
(`internal/protocol/spqr/spqr.ts:1273`, `:1320-1324` vs `src/chain.rs:266-270`). The
trim reads no clock. The horizon is equivalent: `libsignal` trims before it
steps its counter to the received index and so keeps one key that its refusal
rule (`src/chain.rs:192-194`) already refuses, and the SDK trims after the step
and keeps exactly the keys that the same rule accepts, so both decrypt the same
messages.

**Deviation.** The varint decoder is the stricter of the two. It rejects any
value above `uint64` (`internal/encoding/proto/pq-ratchet-serialize.ts:163-186`).
`libsignal` accumulates into a `u64` and shifts the tenth byte by 63 places
(`src/v1/chunked/states/serialize.rs:154-181`). It therefore drops every bit at
or above 2^64 without an error. The two decoders differ only on malformed input,
because no encoder produces such a varint.

**Deviation.** The erasure layer works in whole chunks. It counts 32-byte
chunks and zero-pads the final chunk
(`internal/protocol/spqr/ml-kem-braid/rs/codec.ts:261` and `:810`). `libsignal`
instead counts GF(2^16) elements, and spreads the remainder across the sixteen
polynomials (`src/encoding/polynomial.rs:794-802`). The two agree on any input
whose length is a multiple of 32 bytes. All four braid components have such a
length, from the 96-byte header with MAC to the 1152-byte encapsulation-key
vector (`internal/protocol/spqr/ml-kem-braid/state-machine.ts:91-97`). The
divergence therefore reaches no byte on the wire.

**Deviation.** The `PolynomialEncoder` state message differs from `libsignal`'s
in three ways (`internal/protocol/spqr/ml-kem-braid/serialize.ts:400`, `:671-682`).
The SDK sets `pts` and `polys` together. The reference sets exactly one of the
two, and its schema says so (`src/proto/pq_ratchet.proto:8-16`). The SDK's `pts`
holds one data chunk for each 32 bytes of the component, where the reference
holds sixteen point vectors. The SDK also adds a `messageSize` field at number 4,
which the reference message does not define. `libsignal` refuses all three
(`src/encoding/polynomial.rs:597-616`).

Nothing in the SDK calls this codec. It reaches only the internal `ml-kem-braid`
barrel (`internal/protocol/spqr/ml-kem-braid/index.ts:197-198`), and no braid
session persists through it. Correcting the shape would change a persisted
format, so this entry records the divergence rather than repairing it.

### 4.3 The Triple Ratchet is faithful

The post-quantum secret enters as the HKDF **salt** at message-key expansion. The
classical message key is the IKM, and the label is `WhisperMessageKeys`
(`internal/session/cipher.ts:453-510`). [`triple_ratchet.rs`][tr] uses the same
combination order and the same label. Neither implementation braids the root key.

`internal/protocol/triple-ratchet/` holds a second, unused hybrid KDF under the
label `'Signal Triple Ratchet V1'`. The barrel exports it, but the message path
never calls it, and it does not match what the SDK puts on the wire. The PR that
accompanied this file records it as cleanup work.

---

## 5. Sesame

Sesame has no reference implementation to compare against. `libsignal` does not
implement it. Device and session management lives in the Signal Messenger service
and its clients. This section therefore measures the SDK against the pinned
specification text (revision 2) alone.

These parts are faithful:

- the user-record and device-record structure (§3.1)
- the per-device session fan-out on send, including the sender's own other
  devices (§3.3)
- the bounded send loop (§3.3, §6.5)
- discarding all changes transactionally on error (§3.3, §3.4, §6.7)
- creating a session on receive only from an initiating message (§3.4)

The per-user identity model is one of the two models the specification permits
(§3.1).

### 5.1 The SDK marks a removed device and keeps it for MAXLATENCY

§3.1 and §3.3 require an implementation to mark a removed device's record stale
and keep it for MAXLATENCY. Messages already in flight from that device then
still decrypt. The SDK does this. A removal sets `removedAt` on the device
record, archives its current session, and keeps the record
(`internal/sesame/manager.ts:417-447`). A message that the device sent before
its removal therefore still decrypts against the archived session. Signal's
Android client also archives the session of a device that the server no longer
lists, in `SignalServiceMessageSender`. A send marks a device record in the
same way on two triggers:

- The relay no longer lists the device for the recipient (§5.5).
- On a relay that compares device sets, the send holds no message for the
  account of the device, and the relay has no prekey bundle for the device
  (`NOT_FOUND`). The Signal Protocol Relay gives that answer for an unregistered
  device, and for a registered device that has no uploaded prekeys. The relay
  can still list such a device.

A removed device gets no fan-out. One predicate, `isRemovedDevice`
(`internal/sesame/types.ts:347-355`), states the rule, and each device
enumeration of the send paths applies it. When the device list names the
device again, the marker clears, and the device returns to fan-out with no
current session. Its archived sessions stay
(`internal/sesame/manager.ts:449-483`).

The stale-record cleanup deletes a removed record when its removal is older
than `maxLatency`, 30 days by default (`internal/sesame/types.ts:357-369`,
`internal/sesame/manager.ts:2251-2261`). The receive queue runs the cleanup
once in each client run, after it resumes its stored receives. Nothing orders
the cleanup after a fetch of the whole mailbox, which §3.1 recommends.

The constraint is the message lifetime at the relay. The Signal Protocol Relay
caps the durable TTL of a message at 30 days (`MAX_DURABLE_TTL_SECONDS` in the
Relay mailbox contract). It enforces the cap when it parses a project and on
each request. The SDK fixes `maxLatency` at the same 30 days
(`internal/sesame/types.ts:114`), and no public client option sets it. The
removal clause is strict: the cleanup deletes the record only when
`now - removedAt > maxLatency`. A message that the Relay accepted before the
removal is therefore gone from the Relay before `maxLatency` passes after the
removal, and the record outlives it. The §3.1 guarantee for messages in flight
thus holds without a fetch of the whole mailbox. The Convex relay keeps a
message for 7 days (`remote/relay/convex/component/messages.ts:18`), so the
bound holds there too.

Two caveats limit the bound:

- **Clock skew.** The client measures the window on its own clock, and the
  Relay measures the TTL on its clock. A fixed offset between the two clocks
  cancels. If the client clock moves forward by e against the Relay clock
  between the removal and the cleanup, the record goes e early. A message that
  the Relay accepted up to e before the removal can then fail to decrypt.
- **Memory relay.** The in-process memory relay keeps a message with no TTL,
  so the bound does not hold there. A message from a removed device that waits
  there for longer than `maxLatency` after the removal can fail to decrypt.

Guarantee tests pin the default `maxLatency` at exactly 30 days, and assert
that no public client options type carries a `maxLatency` option.

The SDK also uses the word `stale` for a different concept: a device *list*
that needs refetching (`internal/sesame/types.ts:512-518`). The specification
uses the word for a deleted user or device, which the SDK calls removed.

### 5.2 Session expiry applies only to unacknowledged sessions

§4.2 is unconditional. At MAXSEND past its timestamp, a session may no longer
encrypt. The SDK applies that bound only to sessions that never received a reply
(`internal/sesame/types.ts:175-199`). A session that received one message on its
first day stays a valid encryption session indefinitely.

The configuration field carries the honest name `maxUnacknowledgedSessionAge`.
One gap follows. The §4.2 invariant check
(`internal/sesame/validation.ts:93-101`) still runs against that renamed
quantity. It therefore applies the specification's arithmetic to a value that no
longer carries the specification's meaning.

### 5.3 Device limit

The SDK caps a user at 5 devices (`internal/sesame/types.ts:45-50`).
The file `internal/sesame/manager.ts:285-290` enforces the cap. The
specification's §6.5 recommends *a* limit without fixing one, and `libsignal`
permits device IDs up to 127. The cap is a
product decision. A source comment credits it to the Signal Protocol, which is
inaccurate.

### 5.4 Extensions: transfer, device names

Sesame rev. 2 holds none of these. It says nothing about how a device comes to
exist, takes a name, or migrates.

**Device transfer** (`device/transfer.ts`). Copies the account identity key
pair, private key included, to a new device. The bundle holds no prekeys,
ratchet sessions, sender-key state, message state, or outbox state, and restore
rejects a bundle that holds one. The new device generates its own prekeys and
starts its own sessions, so each device keeps its own sessions as Sesame
requires. After a transfer, two physical devices hold the same identity private
key. That is the per-user identity model that the SDK selects.

**Encrypted device names** (`device/device-name-crypto.ts`). A three-field
protobuf carries a synthetic IV that HMAC derives, with AES-256-CTR. That is the
standard SIV pattern, correctly constructed. The specification has no
counterpart.

**Identity-change gating.** The SDK TOFU-pins an unseen identity. A changed
identity sets `pendingVerification` and blocks sending until the application
accepts the rotation (`internal/sesame/manager.ts:702-706`, `:1843`). Sesame
rev. 2 has no such concept. This is a genuine improvement.

**Not implemented:** proof of possession. Registration does not make the device
sign a server-issued nonce with its identity private key. Registration therefore
trusts the relay more than §6.3 assumes. A deployment that needs proof of
possession must add it at the application layer.

### 5.5 The relay compares the declared device set

Reviewed: 2026-10-18.

§3.3 steps 3 and 4 make the server the check. The server accepts a send only
when the sender's list of device IDs is current, and otherwise rejects it with
the old and new device IDs.

The Signal Protocol Relay and the memory relay make this check. Each post to
an account declares the device IDs that the sender holds records for. The
relay compares the declaration with its device list and with the registration
of each device:

- When a device is missing or extra, it refuses the post with
  `DEVICE_SET_MISMATCH` (409), and names the missing and the extra devices.
- When the registration of a device changed, it refuses the post with
  `STALE_DEVICE` (410), and names those devices.

The SDK then removes each extra device record, starts a new session with each
missing or stale device, and encrypts the message again only for those
devices. It posts again with the repaired declaration. §5.6 lists the details
that differ from Signal.

On these relays, a send to a recipient with a session reads no device list. A
recipient with no session gets one list read to start the sessions. A group
send declares the devices of the records that it holds, and reads the list of
a member only when it holds no record for that member. The SDK reads the own
device list only when a recipient receipt sets `needsSync` and the sender
holds no record of another own device. One exception holds in a live send and
in a replay. A repair that leaves an account with no device record reads the
list of that account once.

The Convex relay does not compare device sets. With it, the SDK declares
nothing. It reads the recipient's device list (`getActiveDevices`) before a
direct send or a sender key distribution, when the last read for that
recipient is more than 60 s old (`RECIPIENT_DEVICE_LIST_FRESH_MILLISECONDS` in
`client/signal-service-cipher.ts`). It makes a session for each listed device
that has none, marks each local device record that the relay does not list as
removed, and clears the mark of a removed record that the list names again
(§5.1). The time of the last read is kept in memory only, so a restarted client
reads the list on its first send to each recipient. Each send also reads the
own device list before it posts.

**Consequence on the Signal Protocol Relay and the memory relay.** A device
that is linked or removed before the relay accepts a post changes the answer
to that post. A linked device gets the message, and a removed device does not.
A phase of a send that does not match in 10 restarts fails the send with
`DeviceSetReconciliationError`.

**Consequence on the Convex relay.** A device linked less than 60 s before a
send can miss that send, and a device removed less than 60 s before a send can
still receive it.

The SESAME stale-device-list retry loop (`StaleDeviceListError`) stays in
`internal/sesame/manager.ts`, but no caller supplies a device-list version, so
it never runs.

### 5.6 Device-set reconciliation differs in detail

Reviewed: 2026-10-29.

The reconciliation of §5.5 follows Signal's server and Signal's Desktop
client in its rule: the server compares, the client repairs and posts again,
and a bound stops the loop. The bound of 10 restarts in each phase equals the
bound of Signal's Desktop client. It is stricter than the 4 attempts of
Signal's Android client. The following details differ.

| ID | Deviation | Constraint | Why Signal's form does not fit | Guarantee test |
|---|---|---|---|---|
| D1 | A stale registration is reported after missing and extra devices on every route, also for a direct post to one account | One answer order for every route | Signal's server reports stale devices first on its route for one account | Relay tests assert the order on each route |
| D2 | A direct send is one post for each device, and each post carries the full declaration of the account | The direct Relay route takes one destination for each body. A replay works for each device | One Signal request carries every device of the account. Here a race can accept some posts and refuse others | A restart posts the stored bytes to each accepted device, and each device gets the message once. A partly accepted pass posts every device again, and an accepted device replays |
| D3 | A group comparison reads the record of each account, up to 1,000, when the Relay accepts the post | The Relay keeps one record for each account | Signal's server reads accounts from one store in one process | Relay tests, and a cost measurement |
| D4 | The operation time is fixed. `OPERATION_EXPIRED` ends the reconciliation as acceptance-unknown. A new send refuses an application timestamp outside the delivery window with `InvalidSendTimestampError`. A manual resend carries its own stored operation time (row P8) | From the Relay release that follows v2026.10.25, the Relay admits a mailbox delivery epoch and a new group fan-out operation at most 5 minutes ahead of its clock and at most 24 hours behind it. Earlier Relay releases admit a new operation only within 5 minutes of its epoch. On an earlier Relay release, a time 5 minutes to 24 hours old passes the SDK check but gets `OPERATION_EXPIRED`. The SDK check uses the same bounds, so the SDK refuses an application-supplied time before any post | Signal has no admission window | A restart post that gets `OPERATION_EXPIRED` ends the phase as expired, and a recipient-phase end stores the outcome `acceptance-unknown`. A new send with a timestamp outside the window throws `InvalidSendTimestampError`, and stores and posts nothing |
| D5 | No fallback to one post for each recipient after the bound | The same bound covers every path | Signal's Desktop client falls back because its one-to-one path has no bound. Under the bound, a fallback only moves the churn | The 11th refusal of a phase ends the send with `DeviceSetReconciliationError` |
| D6 | A direct send also stops at 10 restarts | One bound for every send | Signal's Desktop client has no bound on missing or extra devices for a one-to-one send | The restart bound test of the direct send |
| D7 | No empty sync post. A `needsSync` mark on the recipient receipt and one read of the own list replace it | A Relay post needs at least one destination | Signal's server accepts an empty sync list, and Signal's Android client addresses its own device | A new own device repairs the sync phase and the recipient post is not sent again. The own list is read only on `needsSync` with no own record, and a failed read leaves the sync phase pending |
| D8 | A group post settles a not-found account as a refusal of each of its destinations, and the Relay accepts the rest | `NOT_FOUND` is a fan-out result code. A refusal of the whole post would use a restart | This is equivalent to the group-send-token path of Signal's server, which sends to the accounts it resolves and returns the others. Only the form differs: a refusal code for each destination | A removed account settles as refused and the send adds nothing. A lost response resumes as a duplicate with no not-found account |
| D9 | The receipt of a declared post carries a `deviceSetChecked` mark | The identified Relay route passes unknown keys, and a deployment lane can lag the SDK | Signal ships its client and server together | A receipt without the mark raises `DEVICE_SET_UNCHECKED` through `onRelayProtocolError` |
| D10 | The SDK seals a group body again only before the Relay accepts it, and only after a definite refusal | The Relay keys each delivery operation by message ID, class, destination device, generation and epoch, and keeps a fingerprint of it. It answers `RETRY_CONFLICT` to a changed body under the same operation. It also refuses a new operation whose message ID a row or journal entry of that mailbox holds. The message ID alone is not the operation key | Signal stores nothing on the server for a send attempt | A refused body is replaced in one write. A crash before the post of the replaced body posts it on resume. A `RETRY_CONFLICT` answer to a group shared post counts as acceptance and raises no `onRelayProtocolError` report |
| D11 | A group restart keeps the group ciphertext, seals the shared body again, and replaces it in one write. It does not encrypt the content again | One group pass posts the same ciphertext in the shared body and in the device posts. A new ciphertext would change a device post that the Relay already accepted. The Relay keys that post by its operation, so its replay would get `RETRY_CONFLICT`. The message-ID check of each mailbox also refuses a new operation under the same message ID | Signal's Desktop client encrypts again for each attempt | The group ciphertext is byte-equal before and after the replacement, the accepted device post replays to its stored receipt, and the new body names the repaired destinations. A repaired pre-message that gets `RETRY_CONFLICT` records no sender-key handoff |
| D12 | A declared post with no `recipientRegistrationId` skips the registration check | The field is optional on every Relay route | Signal's server compares the registration of each device of a post | A Relay test posts an unnamed registration |
| D13 | A declaration that names the sender device gets 400 | The Relay refuses a malformed declaration before it compares | Signal's server answers 409 and names the sender device as an extra device | Relay tests on the direct and the group routes. The SDK does not declare the sender device |
| D14 | The identified group route compares the declared device set, with the codes and the order of the direct route | The route serves Relay API customers | Signal has no identified group route | Relay tests. No SDK code calls the route |

### 5.7 Registration IDs of linked devices

Reviewed: 2026-10-21.

A managed device link gives the linked device a fresh registration ID that
differs from the ID of the active device. A held PNI record gets a separate
fresh ID. The link writes the IDs into the linked store before it registers,
and a restarted link sends the same IDs again. This follows Signal, where each
device has its own registration ID. Two cases keep an ID.

| ID | Deviation | Constraint | Why Signal's form does not fit | Guarantee test |
|---|---|---|---|---|
| R1 | A device that a 12.0.x release linked keeps a registration ID equal to that of its active device | The Relay and the peers hold the ID of the live device. A changed ID fails its next prekey sync or publication | Signal never gave two devices one ID, so it has no live device to migrate | Two devices of one account with an equal ID each keep their own handoff row. When the row of one device is removed, the next send gives the key to that device only, and both devices read the message |
| R2 | A link that a 12.0.x release began, and that stopped before it completed, keeps its stored ID | The operation ID of the link derives from the ID. A fresh ID gives a new operation ID, and the Relay could then reserve a second device | Signal has no link that a release before the change began | A resumed link with a stored registration and no link state keeps the stored ID and the operation ID. A refusal of that link leaves the ID unchanged |

### 5.8 Group keys of linked devices

Reviewed: 2026-10-21.

A managed device link copies the master key of each group that the active
device's group store lists into the linked device's group store. The copy runs
in the process that calls the link. A later client on the linked device fetches
each copied group with no application step. In Signal, a linked device restores
its groups from the storage service.

| ID | Deviation | Constraint | Why Signal's form does not fit | Guarantee test |
|---|---|---|---|---|
| G1 | The link copies group master keys in the calling process | No master key crosses the Relay, and the adapter gets no private key | The SDK has no storage service | Each listed group arrives on the linked device with the master key of the active device and initializes with no application step. A link stopped at any write of the copy and restarted, also in a new browser tab, ends with the group set of the active device. A Relay refusal removes each copied group |
| G2 | A group record that a release before 12.0.0 wrote, and that the active device has not read since, is not copied | The group store lists only migrated records. The link has no other source of the group IDs | Signal restores each group from the storage service | Such a group initializes on the linked device from its first group message. Read each group once on the active device before the link to copy it |

### 5.9 The posting deadline and send progress

Reviewed: 2026-10-30.

Signal's Android client gives a send job a lifespan of one day from its
creation, and Signal's Desktop client stops a send job one day after its
timestamp. A direct or group send of the SDK has a posting deadline in the same window.
At or after the deadline, the SDK starts no Relay request for the send. A
request that started before the deadline still counts when its answer arrives
later, and a device that the Relay accepted stays accepted, as in Signal. A
replay posts only the devices that the Relay did not accept, as Signal skips
the recipients that completed. The SDK replays open sends at start and on
reconnect, and the deadline ends the replay, as the Signal job runners do. On
a custom store without the optional listing method, the application replays.
A retry request has its own posting deadline, in row P9. The following details differ.

| ID | Deviation | Constraint | Why Signal's form does not fit | Guarantee test |
|---|---|---|---|---|
| P1 | The deadline is the earlier of 24 hours after the SDK first stores the send and 24 hours after its `clientTimestamp` | The epoch of each post is the send timestamp, and the Relay admits an epoch at most 24 hours behind its clock. A founder ruling sets this term | Signal has no caller timestamp and no admission window | A send backdated by 23 hours posts inside the remaining hour and posts nothing after it. A send backdated by 24 hours posts nothing and throws `SendNeverAcceptedByRelayError` |
| P2 | The deadline has no message-expiry term | The SDK has no message expiry. `SendOptions.expiresIn` is a future feature. The founder ruling "DA1 F1 posting window terms: the 24-hour terms only, no expiry term until a message expiry feature exists (2026-10-28, founder)" sets this term. When that feature ships, its timer starts after acceptance and controls local deletion only, and it never ends a pending post | Signal starts its expiry timer after the send | The stored deadline is 24 hours after the clock read that first stores the send, with no other term. At `deadlineAt` plus 1 ms, a replay of a declared or an undeclared send posts nothing and throws `SendAcceptanceUnknownError` |
| P3 | A replay, a restart or a repair never moves the deadline | The deadline bounds the age of the kept epoch, and the Relay refuses an older epoch. A founder ruling says that retries and restarts never reset it | Signal's Android client starts a new job for a pending send | The deadline after a replay, a restart and a repair equals the first stored value. The deadline read after a restart equals the stored value |
| P4 | A device whose Relay answer is lost, or whose answer follows an uncertain request, ends acceptance-unknown, not failed | The Relay can accept a post whose answer the SDK does not get, and a later post under the same ID can add one charged unit | Signal's Desktop client shows such a send as failed | An unanswered post and then an `OPERATION_EXPIRED` refusal end with `SendAcceptanceUnknownError`. A replay with no stored evidence for a device does not count that device as refused |
| P5 | An automatic retry posts the stored bytes and the stored epoch, also for a retry resend | The Relay keeps a fingerprint of each operation and answers `RETRY_CONFLICT` to other bytes under one ID. A fresh epoch makes a new charged operation | Signal encrypts the content again for each attempt | A replay after a restart posts the same bytes under the same ID and the first epoch, and a repair keeps that epoch. A stored retry resend that gets `OPERATION_EXPIRED` keeps its stored epoch and bytes, posts nothing more under its ID and encrypts nothing again |
| P6 | The SDK stores the progress of each destination device, for recipients and sync copies. Before each request, it marks the device as posted and counts the request. At the end, a device counts as refused only when its stored answer is a refusal or a pending answer and its `uncertain` flag is unset. A request with no answer, an uncertain answer, or a send that SDK 13.3 stored sets the flag for good. A replay skips a refused device, and counts it toward an end at once, only when no recovery in the call can change the refusal or its repair already ran | The Relay can store a post whose answer the SDK does not get, and a later post under the same ID can add one charged unit. The Relay gives a refusal or a pending answer before it stores the post | Signal has no charged operation, so it does not keep a durable mark of each request | A replay after a restart posts only the devices with no stored acceptance. A replay ends at once, and posts nothing, when each open device has a stored refusal that the SDK cannot recover, and throws an `Error` with the stored code of the first refused device that has one, in the order of the destinations. A stored `STALE_DEVICE` refusal with no spent repair gets a new post. A crash after a request, or a send that SDK 13.3 stored, ends with `SendAcceptanceUnknownError` when the replay gets `OPERATION_EXPIRED` |
| P7 | A repair of a stale device keeps the operation and its epoch. A `RETRY_CONFLICT` answer to the repaired post makes the device unknown, not accepted. The repair writes its mark to the stored progress, and the same call reads that mark | The repaired post has new bytes under the kept ID. The Relay answers `RETRY_CONFLICT` when it holds other bytes for that ID, so the SDK cannot tell which bytes it holds | Signal encrypts the content again for each attempt | A `RETRY_CONFLICT` answer to a repaired post throws a retryable `RETRY_CONFLICT` error, and the device is stored unknown with the `uncertain` flag. The answer never counts as an earlier acceptance, in the same call or on a replay |
| P8 | A manual resend with `resendMessage` after a send end is a new operation. It has a fresh stored operation time, the message ID `<clientMessageId>:manual:N` and its own posting deadline 24 hours after its creation. Its content keeps the original timestamp, and the receive queue of a recipient drops a copy with the same sender device, the same original timestamp and the same content digest. The drop needs the timestamp that the content adapter reads from the message, so raw string or byte content takes no drop key and a recipient that holds it receives the copy again. A resend of a group send posts the content of its send log entry, so each copy carries the group context of the original send, not the current one. The recipient records the message with the completion of its receive record. When a delivery receipt is due, it records the message right after the receipt-due write and again with the completion of the receipt. The record expires after 60 days. The caller-origin receive path gives every decrypted message to the caller, and a caller that keeps its own records removes a copy itself. Only a send younger than 30 days takes a new manual resend. The Relay can charge the resend as a new message, and the message might already have arrived | The Relay admits an operation time at most 24 hours behind its clock and charges each accepted operation. The founder ruling "DA1 F4 manual resend identity: a fresh operation epoch with the original timestamp in the content (2026-10-28, founder)" sets this identity. The SDK encrypts the content again for each device, as the retry-request resend does | Signal's clients resend the stored message with its original timestamp in a new job, and the receivers drop a copy by sender and timestamp alone. The SDK adds the SHA-256 digest of the content to the key, so an application that sends two messages in one millisecond keeps both. This rule holds in SDK 13.x and ends in the next major SDK version, which keys a received message by its sender and timestamp only. Signal's server keeps no operation time and charges no send | A resend posts under a fresh operation time and the manual message ID, with the original timestamp in the content. The Relay admits it after the original ended at its deadline. The entry stores its operation time, and a stored send without manual entries reads as an empty list. A recipient that holds the original drops the resend copy, and a recipient that never got the original receives it once. Two different messages of one sender device with one timestamp both deliver. When no receipt is owed, a stop before the completion of the receive record runs `onMessageDecrypted` again. When a receipt is owed, only a stop before the receipt-due write runs it again. A new resend at or after 30 days from the send throws and posts nothing |
| P9 | A retry request has a posting deadline 24 hours after the first failure of its message, and no post starts at or after it. A request whose post is due then ends as `posting-deadline`. After its posting deadline, a request whose post the Relay accepted posts nothing more and waits for its content until its 14-day deadline. `OPERATION_EXPIRED` before the posting deadline ends the request as `posting-deadline` with acceptance unknown. Each `posting-deadline` end resets the session, emits one `onRetryTerminal` event and posts no replacement attempt | The Relay admits an epoch at most 24 hours behind its clock. Its `OPERATION_EXPIRED` also answers an accepted operation that left its retained period, so it does not prove that the Relay holds nothing. The founder ruling "DA1 F3 OPERATION_EXPIRED before the posting deadline: end as acceptance-unknown now, resend on proof after DA1-Q3 (2026-10-28, founder)" sets this end. The version 2 code `DELIVERY_ALREADY_ACCEPTED` proves that the Relay holds the attempt, so a retry request reads it as `RETRY_CONFLICT` and posts no replacement | Signal's server refuses a send only for a wrong device set, before it stores anything, so a Signal client repairs and sends again at once. Signal's Android client gives its retry receipt job a lifespan of one day | A stored attempt that gets `OPERATION_EXPIRED` before the posting deadline posts no attempt 2, ends as `posting-deadline`, resets the session and emits one `onRetryTerminal` event. A fresh attempt and a stale-session repeat end the same way. No retry request posts at or after its first failure plus 24 hours, also after a restart. A request whose post the Relay accepted posts nothing after its posting deadline and ends as `expired-content` at its deadline. The next major SDK version renames this class to `request-expired`. A retry request that SDK 13.3 stored derives the posting deadline from its first failure, at most its deadline. A stored `posting-deadline` record reads back, and an unknown terminal class or a posting deadline that is not a number still reads as corrupt |
| P10 | With a store that implements `listMetadataKeys`, as every built-in store does, the SDK replays each open send at start and when the Relay connection returns, ends each send at its posting deadline, and reports each end once through `onSendOutcome`. An internal send of the SDK, such as a sender key distribution, never reaches `onSendOutcome`. The SDK keeps no content of a sender key distribution at rest, so it does not replay one: with the listing method, it ends an open distribution at its deadline and reports nothing, and a retry request of the receiver recovers a lost distribution, as in Signal. An open sender key distribution that an earlier SDK version stored carries no marker, so the SDK reports `content-required` for it once for each client run before its deadline, and reports its end through `onSendOutcome` once, at its deadline. When the stored plaintext of an open send is gone or does not match the send, the SDK reports `content-required` once for each client run, and the send stays open until its deadline. On a custom store without the optional listing method, the SDK does not replay open sends by itself, and the application replays with the same `clientMessageId` | The founder ruling "Managed-group receive follows Signal's complete workflow (DA13-L correction)" keeps custom stores supported through a documented contract and conformance tests, so the store contract does not require the listing method. The SDK keeps the plaintext of a send only when the store and the content recovery policy keep resendable content | Signal's clients keep each pending send as a job, with its content, in their own database, and run the job queue at start and when the network returns. The SDK runs on a store that the application provides, and that store can keep no content | An open send replays at start under its stored epoch and bytes, and again when the Relay connection returns. A send past its deadline at start ends with the class that its stored progress gives, posts nothing, and reports once, also across a restart before the report. A send whose plaintext is gone or does not match its digest reports `content-required` once for each client run. A store without the method starts no driver, logs one line, and still reports the end of an application send, and the conformance suite skips its listing cases on that store |

---

## 6. Sealed sender

### 6.1 The multi-recipient transport is faithful

These parts match `libsignal`:

- all four HKDF labels, byte for byte
- the KEM construction and its direction-swapped IKM orderings
- the authentication tag, which is the same 16-byte raw HKDF output
- AES-256-GCM-SIV with a zero nonce and no AAD
- the multi-recipient binary format ([`sealed_sender.rs:1023-1153`][ss],
  `:1306-1360`): version bytes `0x22`/`0x23`, the varint count, and 17-byte
  ServiceIds
- the packed device ID with its 14-bit registration ID and `0x3FFF` mask

The base trust-root loop also matches. It does not short-circuit and therefore
does not reveal which root validated. Required signed scope and issuer-validity
checks extend the upstream certificate semantics.

**`PLAINTEXT_CONTENT` (8) carries a sealed retry request, with an SDK payload.**
`libsignal` uses the type to carry a serialized `DecryptionErrorMessage` when
no session exists to encrypt one under ([`sealed_sender.rs:2055-2075`][ss]).
This SDK uses the same type for its own retry request (Sesame §4.1,
`client/retry-request-envelope.ts`). The sealed content is the small JSON
payload that the identified `retry_request` envelope carries, not a
`DecryptionErrorMessage`. The wire value matches. The payload does not.

A retry request follows the sealed sender delivery mode, as a delivery
receipt does. When the requester holds the access key of the target, it seals
the request, and the Relay does not see the requester. A group send
endorsement never seals a retry request. Without an access key, or when the
Relay refuses the access key, the request goes identified only in
`'preferred'` mode. In `'required'` mode the request never goes identified.
It stays pending, and the scheduler posts it again until its deadline. In
`'disabled'` mode it is always identified. An identified retry request shows
the Relay which device could not decrypt a message from which sender, so it
does not have the privacy of a sealed request.

The receive path accepts the type only for this route. The cipher unseals the
envelope, and a content type of 8 goes to the retry request handler, never to
a ratchet decrypt. The seal authenticates the requester: the authentication
tag binds the sealing key to the identity key of the sender certificate, and
the certificate must validate against the trust roots. `envelopeTypeForContent`
maps 8 to `retry_request`, so a new member without a route still fails loudly.

Note the cost when you debug interop. A `libsignal` peer that sends
`PLAINTEXT_CONTENT` with a `DecryptionErrorMessage` reaches the retry request
handler, which drops it as a malformed retry request. A shipped `11.0.x`
release of this SDK rejects the type at the parse. That receiver drops a
sealed retry request from a newer client, and the requester ends the request
as expired content. The parsers throw a single generic error for every
malformed envelope, `Sealed sender verification failed`, which is the same
string a MAC mismatch produces. The uniformity is deliberate, and the parse
runs after authentication, so nothing here is an oracle. Watch for one
pattern: sealed messages from one peer stack fail with that error while
messages from this SDK succeed. Check the leading content-type byte before you
treat that as a cryptographic failure.

### 6.2 The delivery token follows `libsignal`, not an SDK invention

Despite the module name, `deriveAccessKey`
(`internal/protocol/sealed-sender/delivery-token.ts:52-91`) is `libsignal`'s
`ProfileKey::derive_access_key`. It runs AES-256-GCM over 16 zero bytes with a
zero nonce and truncates to 16 bytes. It reproduces the values `libsignal`
publishes for that derivation.

The 16-byte value comes from the recipient's profile key. It proves to the relay
that the sender knows that profile key, which gates anonymous delivery to
contacts. It never enters the sealed-sender wire format. The sender presents it
out of band.

The SDK's own documentation once described a different, 12-byte HKDF
construction that no code implements. That description is wrong, and the PR that
accompanies this file corrects it.

Certificate signatures use Ed25519 rather than XEdDSA, per §1.2. The signed
Relay scope and issuer-validity interval are deployment extensions. Hosted and
self-hosted deployments use disjoint operator roots, issuers, scopes, and
revocation policy. Their certificates cannot validate against each other or a
Signal Messenger trust root.

---

## 7. Sender keys and groups

### 7.1 Sender key message format

These parts match:

- protobuf field numbers and types, against [`wire.proto`][wp] exactly
- the `[version byte] ‖ protobuf ‖ [64-byte signature]` framing
- the `0x01`/`0x02` chain seeds and the `WhisperGroup` info string
- AES-256-CBC with the derived IV
- the capacity constants

The following details differ:

**The signed frame version is `0x44`**. The format break in §7.2 separates
corrected message-key derivation from the former SDK derivation. Libsignal uses
`0x33`.

**`distributionUuid` carries a UTF-8 string, not 16 UUID bytes**. The SDK writes
the 36-character textual form of a random UUIDv4
(`internal/protocol/sender-keys/manager.ts:279`, `:932`). `libsignal` writes
exactly the 16 raw bytes and rejects anything else on parse. The value is the
same *kind* of thing `libsignal` uses, an opaque random identifier with no
relation to the group. The encoding still differs, so neither side can parse the
other's frames. One related point: `chain_id` is an FNV-1a hash of that string
rather than a random 31-bit value.

The SDK once wrote `groupId:userId:deviceId:timestamp` here. That was a metadata
leak rather than a format deviation, because `distributionUuid` sits outside the
ciphertext. Every relay on the path could read the plaintext group and sender off
each message. The current code fixes it, and the sender-keys specification now
requires an opaque identifier.

**Signatures are Ed25519, not XEdDSA**, per §1.2. `libsignal` also serializes the
signing key as 33 bytes where the SDK uses 32.

### 7.2 Message-key derivation matches the reference

Reviewed: 2026-10-11.

The SDK derives Sender Keys message material with HKDF-SHA256 Extract and
Expand. Its input is `HMAC-SHA256(chain_key, 0x01)`, its salt is 32 zero bytes,
and its info string is `WhisperGroup`. The 48-byte output contains a 16-byte
IV followed by a 32-byte cipher key. This matches
[`SenderMessageKey::new` in libsignal][sk].

The former implementation omitted Extract. The correction changes derived keys
and requires a format break. State and encrypted distribution messages now
require `senderKeyVersion: 'v2'`. Signed group frames require byte `0x44`.
The SDK rejects old state, unversioned distributions, and old frames.
Applications must reset group sender-key state and discard queued group sends
before they redistribute keys with upgraded peers.

For a chain key of 32 repeated `0x42` bytes, the current IV is
`890d51ea73e564722351dc0d5a09142c`. The former IV was
`2a56b9eb80b3c1ffebd97221b2175960`. An independent Node/OpenSSL oracle checks
ciphertext against the current derivation.

### 7.3 Groups are an independent design

The zero-knowledge primitives underneath are real and faithful (§7.4). The group
system built on them is not the Signal Private Group System.

These parts are faithful:

- role and access-control enum values, which match `libsignal`'s exactly
- group ID derivation from the master key
- the `open-e2ee:group:` identifier namespace, which the package owns
- authentication, which uses real zkgroup credentials
- member identifiers and profile keys, which the SDK encrypts into real
  `UidCiphertext` and `ProfileKeyCiphertext` values

What differs, and it is structural:

**The enforcement contract is this SDK's own**. The client submits change actions
that carry zero-knowledge presentations, as it does in the Signal Private Group
System. The **server** then validates every action against the group's access
control before it signs and persists the accepted result.

The enforcement rules are the SDK's own S1–S14 contract rather than Signal
Messenger's server implementation. The shipped enforcing server
(`internal/groups/server-engine.ts`, which the OpenE2EE Signal Protocol Relay runs)
implements that contract. On every applied change, clients verify the server's
signature, the group binding, the strict version sequence, and the pre-state
authorization.

**Profile-key credential issuance uses a package-owned blinded wire format**.
The client sends a fixed-width serialized request that contains an ephemeral
blinding public key and an ACI-bound blinded profile-key attribute. The issuer
sees the authenticated ACI and the public redemption time, but it does not
receive the raw 32-byte profile key or the client's blinding secret. The client
verifies and unblinds the signed response with the matching request context.
Fresh request randomness makes two requests for the same ACI and profile key
unlinkable from the blinded request bytes.

This preserves the Signal Private Group System's issuer-privacy property, but
the request and response encodings remain this SDK's own and are not
interchangeable with Signal Messenger or `libsignal` credentials.

**Serialization is JSON**, not protobuf, both for group state
(`internal/groups/manager.ts:1229-1236`) and for the blob payloads inside the
AES-256-GCM-SIV envelope (`internal/groups/encrypted-state.ts:70-81`). Signal
Messenger cannot decrypt an encrypted group title or description, even with the
correct master key.

**Invite links** use `https://join.open-e2ee.dev/#` with a 49-byte raw payload
(`internal/groups/invite-link.ts:36`, `:78-85`), where `libsignal` uses
`https://signal.group/#` with a protobuf. The source labels this accurately as
the package's own format.

### 7.4 The zero-knowledge layer is a faithful port

Stated directly, because "zk" in a codebase often means something weaker: this is
a genuine zero-knowledge credential system, not HMAC tokens, not signatures, not a
placeholder.

The directory `internal/protocol/zk/` implements the Sigma protocol over
Ristretto255 with Fiat–Shamir. It matches `poksho`'s protocol label
`POKSHO_Ristretto_SHOHMACSHA256` exactly. It also implements the
Chase–Perrin–Zaverucha algebraic MAC credential system, which matches
`zkcredential`'s five domain labels byte for byte. The Lizard encoding, the
`UidStruct` derivation, the `AuthCredentialWithPni` flow, and the redemption
window all match `libsignal`.

One test carries the strongest evidence. It asserts the 416-byte serialized
system parameters against a hex string taken from `libsignal`'s own Rust test,
and it passes.

One deviation remains. The SDK derives server secret parameters through four
separately labeled key derivations, where `libsignal` uses a single seeded
derivation (`internal/protocol/zk/groups/server-params.ts:43-54`). The same
randomness therefore yields different server keys.

That structural difference stands on its own. Separately, each deployment
generates its **own** random 32-byte seed, which puts the trust root with the
deploying operator rather than with Signal Messenger. No credential is
interchangeable with a Signal Messenger credential.

Credential serialization is also ad hoc and carries no version byte, where
`libsignal` uses a leading version byte. That is a forward-compatibility gap
rather than a security one.

### 7.5 Sender-key distribution tracking

Reviewed: 2026-10-20.

`libsignal` creates and processes sender-key distribution messages. It does
not record which devices hold a key. The Signal apps do that work.
Signal-Android keeps a shared-with set for each distribution
(`SenderKeySharedTable`). Signal-Desktop keeps the member devices with
each sender key. The SDK keeps a handoff
ledger for the same role. A row records that the Relay accepted a distribution
of the own key for one device of another member. A send gives the key to each
listed device with no matching row, and to each device with no session.

These parts follow Signal-Android:

- An inbound PreKey session deletes the rows of that device in every group.
  The SDK deletes them in the same write as the session. Signal-Android uses a
  separate write.
- A session archive deletes the rows of that device in every group.
- An identity change deletes the rows of the account.
- A retry request for a group message deletes the rows of that device in that
  group only.
- The session reset after an expired retry request deletes the rows of each
  device of the account in every group, as `AutomaticSessionResetJob` does.
  It does so for a group message and for a pairwise message. It archives the
  session with the device that sent the failed envelope only.
- A rotation deletes the rows of the group. The SDK deletes them in the same
  write as the key.
- Own devices get the sent transcript and no distribution.
- When the Relay refuses a sync copy because the registration of the own
  device changed, the SDK starts a new session and posts the transcript
  again. Signal-Android tries a send up to 4 times. The SDK repairs each
  refused copy once, as it does each other refused post. A second refusal
  archives the session and drops the copy.

The following details differ:

**1. The row match includes the key ID and the registration ID**.
Signal-Android keys a row by distribution and device. The registration-ID
match is faithful to Signal-Desktop, which compares the registration IDs of
the member devices. The key-ID match is an addition. A delete and then a
create of the own key start again at generation 1, so the SDK also matches the
key ID. A custom store can write the key and delete the rows in two writes,
and a crash between them leaves a row. With the key ID in the match, that row
never stops a device from getting the current key. A peer that holds the
earlier key installs the new key, because the receiver matches a sender key by
its ID and not by its generation.

**2. A new session from a prekey bundle deletes rows**. Signal-Android
replaces a session only after an archive. In the SDK, the commit of a new
session from a bundle archives the current session itself, so the same commit
deletes the rows of the device.

**3. The SDK reads the own device list only on `needsSync`**. Signal learns
of new and removed own devices from the 409 device-set mismatch answer of the
server to a sync post, and it posts to the recipients first. The SDK keeps
this order on the Signal Protocol Relay and the memory relay. The recipient
phase posts first. Then the sync phase declares the own devices that the
sender holds records for, and the relay compares them (§5.5). When a
recipient receipt sets `needsSync` and the sender holds no record of another
own device, the SDK reads the own list once (§5.6, D7). A failed read does
not fail the send. The result carries `syncPending`, and a call to `send()`
with the same `clientMessageId` reads the list again. The Convex relay does
not compare device sets, so each send with it reads the own list before it
posts. A failed read there stops the recipient post and fails the send or the
sync API call.

**4. A replay keeps the stored group ciphertext**. Signal encrypts again for
the devices of each attempt. The Relay refuses a second operation under the
same message ID, so the replay of a stored group send keeps its ciphertext. A
device that the replay adds cannot decrypt it. That device gets the content
only through its retry request and the resend of a `Resendable` send.

**5. A sweep at start deletes the rows of a replaced key**. Signal has no
sweep. The match already ignores these rows, so the sweep only frees storage.

**6. The Relay names each refused group destination**. Signal's server
names each stale device in a 410 answer. The Relay refuses a declared group
post with `DEVICE_SET_MISMATCH` or `STALE_DEVICE` before it accepts the post,
and the SDK repairs as §5.5 says. The receipt of an accepted post carries a
`refusals` list with a code for each refused destination. A `NOT_FOUND`
refusal settles a removed account (§5.6, D8). The SDK does not infer a stale
device from the count of refused destinations.

**7. Only a logged `Resendable` send can answer a retry request with its
content** (2026-10-15). Signal-Android logs sends in its message send log
through `MessageSendLogTables.insertIfPossible`. That method stores the
content of a send only when the `retryReceipts` remote config is on, the send
result is a success, and the result carries its content. For a group send, it
stores one entry for the recipients whose result meets the last two
conditions, and it stores no entry when no result does. The method does not
read the content hint. A group send calls it only when its send operation
returns true from `shouldIncludeInMessageLog`: a resendable data message or a
story, and never a typing or call message (`GroupSendUtil`). A retry
request for a group message with a log entry gets that content again. A
request with no entry gets the sender-key distribution alone
(`MessageContentProcessor`). Signal-Android keeps its own message
database, so each resendable data message that it sends can have an
entry. A data message sent through `sendUnresendableDataMessage`, such as
a profile-key or group-call update, has none.

The constraint is that the SDK does not own the message store of the
application. The SDK keeps a send log entry only for a group send whose
content hint is `Resendable`. The SDK sets the hint by default from the
content and the recovery policy. A group send of a `DataMessage` is
`Resendable` when content recovery is on, and `Default` when it is off. A
string or bytes send has no hint. The application can set another hint for a
send. When it sets `Resendable` and the SDK cannot answer, because recovery
is off or the content is a string or bytes, the send goes out as `Default`.
So a retry request for another send finds no entry. The SDK then answers with the current
distribution alone, as Signal-Android does for a missing entry. The device
gets the key for later messages, but it does not get that message. Item 4
makes this outcome more frequent, because a device that a replay adds can
decrypt the send only through its retry request.

Two guarantee tests assert the two outcomes. For a send that is not `Resendable`, the send log has no entry, and
the answer carries the current distribution and no message. For a
`Resendable` send, the answer carries the message and the distribution.

**8. A receipt or a retry request keeps the stale session until the new
session commits** (2026-10-16). Signal-Android archives the session of each
stale device first (`SignalServiceMessageSender.handleStaleDevices`).
The next pass of the send loop then fetches a bundle and starts a new
session. Signal-Desktop also archives each stale session first, and then
fetches the keys of the device (`handleMismatchedDevicesError`).
When the fetch fails, an application job sends again later, and that send
starts the session.

The constraint is that a receipt or a retry request has no application job
that retries it. If the SDK archived first and the fetch failed, the item
would have no session, and a lost session drops the item. So when the Relay
refuses a receipt or a retry request as a stale device, the SDK fetches the
bundle first. The session start then archives the stale session in the same
record write that stores the new one. A failure before that write keeps the
stale session, so the next post is refused again and refreshes again. A
failure after that write, in the SESAME registration, leaves the new session,
and the next post uses it. The `onSessionArchived` hook runs after the
session start succeeds. The refresh of a send keeps the order of Signal: it
archives the stale session first.

A guarantee test asserts the order. The
first session start fails, the stale session stays, and the hook does not
run. The retry refreshes the session, the hook runs once for the device, and
the device decrypts the receipt.

**9. A late copy of a previous sender key changes nothing** (2026-10-16).
Signal's published implementation keeps up to 5 sender-key states for each
sender. When a distribution matches a kept state, [`add_sender_key_state`][sk]
removes that state and puts it at the front of the record, so it becomes the
current state again. The SDK also keeps up to 5 states and matches a
distribution by its key ID. A distribution of the current key follows the
generation rules of the SDK: a lower or the same generation changes nothing,
and a higher generation replaces the current state in place. A distribution
of a kept previous key changes nothing, and that state stays in its place.
A distribution of another key becomes the current state, the earlier current
state moves to the front of the previous states, and when the record already
holds 5 states, the oldest state goes.
So a replay of an installed distribution changes nothing only while its key
is the current state or a kept previous state. When the key is neither, the
replay installs it again as the current state, and when the record already
holds 5 states, the oldest state goes.

The constraint is that the current state is the newest key that the sender
installed. The receiver matches the current state first, so a late copy of
an earlier key must not displace it. The cost is in the order of eviction.
When the record holds K5, K4, K3, K2, and K1, with K5 current, a late copy of
K1 and then K6 leave K6, K5, K4, K3, and K2 in the SDK. Signal keeps K1 and
evicts K2. A message in flight under K1 then fails in the SDK.

A guarantee test asserts the rule. The receiver holds the replaced key as a
previous state, and a late copy of its distribution arrives. The record keeps
the new key current and the replaced key previous, and a message under the
new key decrypts.

### 7.6 Group sends and session writes take a lock across tabs

Reviewed: 2026-10-20.

Signal runs one process for each device. Signal's Desktop client exits a
second instance and runs the sender-key jobs of one address one at a time.
Signal's Android client takes its session lock around each group encrypt.
`libsignal`'s `group_encrypt` loads the sender-key record and stores it with
no lock of its own, so the caller supplies the exclusion.

A browser application can open several tabs on one store. When
`navigator.locks.request` exists and the store sets `storeIdentity`, the SDK
takes a Web Lock for each group send and for each session write. A group send
takes `open-e2ee:group-send:<store identity>:<lock key>`
(`client/group-sender-key-operations.ts:41-57`). The session lock, the user
lock, and the device-list sync lock take
`open-e2ee:session:<store identity>:<lock key>`
(`internal/session/record-locks.ts:60-142`). The IndexedDB store and the web
SQLite store set `storeIdentity` to their database names. The tabs, workers,
and clients of one origin that share the store then run one operation of each
lock key at a time. Inside the group send lock, the sender-key manager reads
its state from the store again, so a rotation keeps the states that another
tab wrote. The session lock and the device-list sync lock keep their 5 s wait
timeout, so a lock-order fault or a hung holder shows as an error and not as a
receive or send that never ends. On the Web Lock path the wait rejects with
`ORIGIN_LOCK_TIMEOUT_MESSAGE` (`utils/origin-lock.ts:18`). On the in-process
path it rejects with the timeout message of the in-process lock. A Web Lock
queue has no bound on the number of waiting requests.

**Deviation.** Where `navigator.locks.request` does not exist, or the store
sets no identity, `originLockScope` gives no scope
(`utils/origin-lock.ts:25-32`), and each lock is an in-process lock keyed by
the store object. The constraint is that a Web Lock name needs a name for the
data that every tab gives alike, and such a runtime has no shared lock or no
such name.
The Node SQLite, key-value, and memory stores set no identity, and React
Native has no `navigator.locks`. Node has `navigator.locks`, but its locks
order one process only. Two processes, or two store objects, that share one
database are then not ordered. The application must give one of them
exclusive access, as Signal's Desktop client does with its single-instance
lock.

Guarantee tests assert both paths. Two browser tests open two tabs on one
IndexedDB store. In the first, both tabs send to one group at the same time:
the two ciphertexts carry distinct iterations, and the receiver decrypts each
message. In the second, both tabs encrypt on one direct session at the same
time: the two ciphertexts carry distinct counters, and the receiver decrypts
each message. Unit tests assert the lock names, the order of two store
objects with one identity, the in-process fallback with no Web Locks and with
no identity, the 5 s session lock timeout and its message on each path, the
stop of a wait, and two sender-key managers that rotate in turn and keep both
states in the archive.

### 7.7 The SDK posts group sends to the anonymous route only

Reviewed: 2026-10-18.

Signal's server accepts a multi-recipient send only with an access key or a
group send token, and it checks the device set of each recipient. The SDK
posts each group send with a group send token to the anonymous group route of
the Signal Protocol Relay (`client/hosted-anonymous-delivery.ts:269`, `:520`).
No SDK release posts to the identified group route.

**Deviation in the Relay.** The Relay still serves the identified group
route. It accepts a group post under the account credential of the sender,
and it checks no device set when the post declares none. The constraint is
that the Relay removes a served route forward only. The SDK does not depend on
the route, so its removal changes no SDK behavior.

---

## 8. Receive queue

Reviewed: 2026-10-20.

The receive queue keeps each decrypted receive in the local store until the
application hook accepts it and the receipt goes out (`client/receive-queue.ts`).
Signal's Android client keeps the same work in its message jobs, and Signal's
Desktop client keeps it in its table of unprocessed envelopes. This section
states where the queue follows them and where it differs.

### 8.1 The queue holds back one conversation

**Faithful.** A record that waits holds back the later records of its
conversation only (`client/receive-queue.ts:379-402`). Group content keys by
its group, a sent transcript keys by its destination, and other content keys
by its sender account, as Signal's Android client names its message job
queues. A record that
has not decrypted yet keys by its sender account, because its conversation is
not known. The commit order stays per sender device, because the ratchet of
one device must step in order.

Guarantee tests assert a record that fails before its restore and holds back
only its sender account, a group record that holds back its group from every
sender, pairwise content of a blocked group, and a second sender in a blocked
group whose direct message delivers.

### 8.2 A failed hook has an attempt cap, and the record stays

**Deviation.** After `RECEIVE_HOOK_ATTEMPT_CAP`, 10 failed
`onMessageDecrypted` attempts (`client/receive-queue.ts:285`), a record no
longer holds back its conversation. Signal's Desktop client has the same cap.
Desktop deletes such a record at startup and loses the message. The SDK keeps
it.
Each client start offers it to the hook once. After that offer, only
`processPendingReceives` runs it again before the next start.
`discardPendingReceive` removes it with no receipt, no hook call, and no
expiry report. `PendingReceive` shows `hookAttempts`.

The constraint is that the hook is application code. The SDK cannot tell a
lasting failure from a passing one. A drop loses content whose ratchet step is
spent, and an application update can repair the hook. **Consequence:** a hook
that ends the process on the record ends it once at each start, until the
record expires or the application discards it.

Guarantee tests assert the offer once at start and not again at the hook
registration, no second offer before the next start, and a discard with no
receipt, no hook call, and no expiry report.

### 8.3 A delivery receipt lives for 1 day

**Faithful.** A stored receipt is sent only within `RECEIPT_LIFESPAN_MS`, 1
day, after the receipt becomes owed (`client/receive-queue.ts:292`). Signal's
Android client gives its receipt job the same lifespan, and it creates the
job when the receipt becomes owed. The record keeps the receipt across a
restart, as Android stores its job. At the end of the lifespan the record
completes with no receipt and no report.

Guarantee tests assert a receipt 1 ms before the end of the lifespan, no
receipt at the end, the recovery report of a resend record at the end, and
the stop of the receipt retries of a running client.

### 8.4 Each awaited hook has a bound

**Deviation** in detail. A receive pass waits for each application hook for
at most `receiveHookTimeoutMs`, 2 minutes by default
(`client/receive-hook-bound.ts:36`). The value must be a positive integer no
longer than the longest timer delay (`client/storage-protection.ts:169-179`).
Signal's Desktop client bounds its receive dispatch at 2 minutes and its
long-running tasks at 30 minutes.

The constraint is a founder ruling that sets the bound at 2 minutes. The SDK
cannot tell a slow hook from a hung one, and one hung hook would otherwise
stop all receive. **Consequence:** a timeout of `onMessageDecrypted` counts as
one failed attempt, with the normal backoff and the attempt cap. A timeout of
another hook is logged, and the pass continues. A settle after the bound
writes nothing. A hook that needs longer than the bound fails each attempt.

Guarantee tests assert the 2-minute default, the refusal of an invalid bound,
a hung `onMessageDecrypted` hook that counts one attempt for each pass, a
late settle that writes nothing, and one timeout test for each other awaited
hook.

### 8.5 Admission bounds before a decrypt

**Extension.** Before a decrypt, the receive queue checks `maxItems`,
`maxBytes`, and the group share `blockedGroupShare`
(`client/receive-admission.ts:67-96`). The defaults are 3000 items, 750 MiB,
and 0.25. They are provisional until a measurement of real receive queues
replaces them (`client/constants.ts:36-43`). Signal's Desktop client decrypts
each envelope as it arrives and bounds stored content only by age and attempts.

The constraint is that the SDK shares a storage budget with the application
in a browser and on mobile. **Consequence:** a refused envelope is not
acknowledged. It stays at the Relay and expires there with no local hook. On
the WebSocket path, other conversations progress. An HTTP pull sends the Relay
cursor of the page before it, so a full page of refused envelopes does not stop
the pages behind it. A page without a Relay cursor clears the stored cursor,
and the next pull starts at the head. Two processes that share one store can
each pass the check and overshoot a bound.

Guarantee tests assert the global item and byte bounds, the group item and
byte shares, the progress of direct and other-group messages beside a full
group, and an HTTP pull past a full page of refused envelopes.
---

## Unverified and needs review

This review lists the following items rather than asserts them. It could not
confirm any of them in source.

- **Does a sealed-sender-wrapped prekey message decrypt end to end?** The unseal
  path rebuilds the envelope with a fixed message type
  (`client/sealed-sender.ts`). An adjacent comment suggests that the
  Sesame layer re-derives the initiation state from the ciphertext. This review
  traced neither that path nor the integration tests. First-contact sealed
  messages break if Sesame does not detect the state itself.
- **Does anything downstream enforce the session-identity-key check?** The
  sealed-sender note requires it. The decrypt path compares the certificate's
  identity key against the decrypted static key. It does not consult the session
  store. In `libsignal`, the identity store carries the equivalent guarantee
  later.
- **Is `@noble/post-quantum`'s ML-KEM-1024 byte-identical to libcrux's?** The
  repository claims pinned known-answer-test coverage. This review did not run
  those tests.
- **Does the Lizard encoding match `libsignal`'s vectors?** The forward and
  inverse Elligator maps are hand-implemented in TypeScript. The structure and
  the labels are correct, and unit tests exist. This review did not diff the
  outputs against `libsignal`'s. A subtle error here silently corrupts every
  `UidStruct`.
- **Do the SPQR state-machine transitions match?** State names, message types,
  and chunk counts match `libsignal`'s. This review did not diff the eleven-state
  transition table transition by transition.
- **Does the SPQR decoder bound the stored points?** `libsignal` caps stored
  points per polynomial. This review found no equivalent bound in the SDK's
  decoder.
- **Does SPQR state roll back on an authentication failure**? By contrast,
  `libsignal` commits the new state only after the MAC and the decryption
  succeed. The SDK's receive
  path mutates state during decode, and this review did not trace the caller's
  rollback behavior.
- **Does an equivalent of `libsignal`'s `promote_matching_session` exist?**
  `libsignal` matches archived sessions on `(version, base key)`. The SDK keys
  its map on the base key alone.

---

## Reporting an error in this document

Email security@open-e2ee.dev or open an issue when something here is wrong. Three
cases qualify:

- a citation that does not say what this document claims it says
- a deviation that the code already fixed
- a deviation that this document omits

A deviations document that drifts from the code is worse than no document at
all, because it invites exactly the assumption it exists to prevent.

[ik]: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/identity_key.rs
[fp]: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/fingerprint.rs
[sess]: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/session.rs
[pq]: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/pqxdh.rs
[rat]: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/ratchet.rs
[rk]: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/ratchet/keys.rs
[dr]: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/double_ratchet.rs
[proto]: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/protocol.rs
[wp]: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/proto/wire.proto
[consts]: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/consts.rs
[st]: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/state/session.rs
[ss]: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/sealed_sender.rs
[sk]: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/sender_keys.rs
[tr]: https://github.com/signalapp/libsignal/blob/main/rust/protocol/src/triple_ratchet.rs
[xeddsa]: https://signal.org/docs/specifications/xeddsa/
