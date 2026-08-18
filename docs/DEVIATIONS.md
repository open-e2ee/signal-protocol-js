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
specification closely. Such a row is here only to delimit what the neighbouring
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
| **Safety numbers** | `libsignal` `fingerprint.rs` | **Deviation.** Iteration and digit encoding are byte-identical, but the input is a composite-identity commitment under an SDK domain string, the QR version is `3`, and the two halves are ordered by user ID rather than by digit string | Follows from the composite identity; a single-key fingerprint cannot authenticate both components | **Safety numbers are not comparable to Signal Messenger's.** The ordering rule also differs from `libsignal` even on the single-key path |
| **X3DH / PQXDH** | X3DH rev. 1; PQXDH rev. 3 | **Faithful** on DH order, the `0xFF`×32 prefix, zero-salt HKDF, KEM-secret position, and PQXDH §2.2's info-string construction. **Deviation:** ML-KEM-1024 (FIPS 203) replaces round-3 Kyber1024 | Standardized ML-KEM preferred over round-3 Kyber. The info string names it, and names this application rather than `libsignal`'s, as §2.1 and §2.2 require | Wire-incompatible with `libsignal` by construction, and the label now says so. The info string is part of the derivation, so any peer that names a different one derives a different `SK` and cannot complete the handshake |
| **Associated data** | X3DH §3.3 | **Deviation.** `AD` is a domain-separated HMAC input over SHA-256 commitments to both composite identities, not `IK_A ‖ IK_B` | Binds the Ed25519 component, which a raw-key `AD` would leave uncovered | Stronger binding; wire-incompatible |
| **Double Ratchet** | Double Ratchet rev. 4 | **Faithful** on `WhisperRatchet`, `WhisperMessageKeys`, the `0x01`/`0x02` seeds, the 80-byte split, AES-256-CBC, the `0x44` version byte, and 8-byte MAC truncation | — | The ratchet core follows the Double Ratchet specification |
| **Message wire format** | `libsignal` `wire.proto` | **Faithful** field numbers 1–8. **Extension:** fields at 100+ carry identity type and ML-KEM one-time prekey material. **Deviation:** address binding uses variable-length UTF-8 user IDs and 4-byte device IDs instead of 17-byte ServiceIds and 1-byte device IDs | The SDK binds application-defined identifiers, not Signal Messenger ACIs | Wire-incompatible; a Signal Messenger client would silently ignore the added fields |
| **Skipped keys and archiving** | Double Ratchet §2.6; `libsignal` `consts.rs` | **Deviation.** The 2000-key cap is global rather than per-chain, eviction is by wall-clock timestamp, and skipped keys expire after 7 days. Session records serialize as JSON, not protobuf | Simpler storage accounting and bounded growth | **Legitimate messages can become undecryptable** where `libsignal` would still decrypt them: a 5× smaller effective cap, cross-chain eviction, and a hard 7-day limit for offline recipients |
| **Padding** | — | **Extension.** ISO 7816-4 bit padding to 160-byte buckets inside the library | Length hiding by default rather than left to the application | `libsignal` does not pad at this layer; Signal Messenger's apps do. PKCS#7 then adds a block, so ciphertext lands 16 bytes past each boundary |
| **SPQR / ML-KEM Braid** | ML-KEM Braid rev. 1 | **Deviation.** Same protocol, same KDF labels, same Reed–Solomon parameters, byte-identical message framing — except `hek = SHA3-256(ek_seed ‖ ek_vector)`, the operand order the specification states, which is the reverse of `libsignal`'s implementation | The normative text was followed over the executable reference | Wire-visible. Headers, ciphertexts, and shared secrets diverge; a braid session cannot complete a single epoch against `libsignal`'s implementation. Also means the KEM is not FIPS 203 in braid mode |
| **Triple Ratchet** | `libsignal` `triple_ratchet.rs` | **Faithful.** The PQ secret enters as the HKDF salt at message-key expansion, same label, same order | — | The braiding construction follows the ML-KEM Braid specification |
| **Sesame** | Sesame rev. 2 | **Deviation** on session expiry (§4.2 applies only to unacknowledged sessions) and on deleted devices (hard-removed rather than marked stale). **Extensions:** QR provisioning, device transfer, encrypted device names, identity-change gating, a 5-device cap | Product requirements the specification does not address | Hard deletion **drops the MAXLATENCY window, so in-flight messages from a just-removed device become permanently undecryptable**. Device transfer clones ratchet state, which weakens the forward-secrecy bound |
| **Sealed sender v1** | `libsignal` `sealed_sender.rs` | **Deviation.** Correct labels, cipher, and MAC length, but the 96-byte HKDF output is split `(cipher, mac, chain)` where `libsignal` splits `(chain, cipher, mac)`; keys in the salt omit the `0x05` type byte; the inner envelope is a hand-rolled varint format rather than the `UnidentifiedSenderMessage.Message` protobuf, though it now carries the same message-type values | The slice order and the missing prefix are unintentional; the framing is a deliberate simplification | Self-consistent and secure, but every v1 key sits in a different slot than `libsignal`'s |
| **Sealed sender v2** | `libsignal` `sealed_sender.rs` | **Faithful** on all four labels, the KEM, AES-256-GCM-SIV, the multi-recipient binary format, and the `0x3FFF` registration-ID mask | — | The v2 construction follows `libsignal` |
| **Delivery token** | `libsignal` `profile_key.rs` | **Faithful.** `deriveAccessKey` follows `libsignal`'s `ProfileKey::derive_access_key`, and reproduces `libsignal`'s published known-answer values | — | Not an SDK invention, despite what the module name suggests |
| **Sender keys** | `libsignal` `sender_keys.rs` | **Deviation.** Protobuf field numbers and `0x33` framing match, and the `0x01`/`0x02` seeds match, but message-key derivation **omits HKDF-Extract**, signatures are Ed25519 not XEdDSA, and `distributionUuid` carries a UTF-8 string rather than 16 UUID bytes | The Ed25519 choice follows the identity profile; the missing Extract appears unintentional | Group message keys differ from `libsignal`'s for the same chain key. Confirmed numerically, not merely by inspection |
| **Groups** | Signal Private Group System | **Independent design.** Real zkgroup primitives underneath; the server validates every change against zero-knowledge presentations and signs the accepted result, and clients verify those signatures. **Deviation:** profile-key credential issuance is not blinded — the issuing server sees the raw profile key at issuance time | Ships a validating group server with an enforcement contract (S1–S14) specified in-tree | Not wire-compatible with the Signal Private Group System; credentials are not interchangeable. The unblinded issuance path means a hostile issuance server learns profile keys, which the Signal Private Group System's blinded issuance prevents |
| **zkgroup / zkcredential** | `libsignal` `zkgroup`, `zkcredential`, `poksho` | **Faithful** port of the Ristretto255 KVAC and Sigma-protocol system, verified against `libsignal`'s known-answer vectors. **Deviation:** server parameter derivation is structured as four labelled derivations rather than one seeded derivation | Server keys are the deploying operator's own trust root (each deployment generates its own seed), not Signal Messenger's | The zero-knowledge properties are real. Credentials are not interchangeable with Signal Messenger's |
| **Registration IDs** | `libsignal` `sealed_sender.rs` | **Faithful.** Generated in `[1, 16383]`, strictly inside the 14 bits the wire format reserves | — | — |

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

Three independent reasons, any one of which is sufficient.

**The SDK computes the user-facing number over a composite commitment.**
The `client.verify()` method uses `generateCompositeSafetyNumber`
(`client/sessions.ts:326`, `:432-433`). Its per-party hash iterates over
`UTF8("signal-protocol-js composite safety number v1") ‖ type-tagged user ID ‖
SHA-256 identity commitment` (`safety/core.ts:48-50`, `:205-233`). None of that
input exists in `libsignal`'s construction ([`fingerprint.rs:161-192`][fp]).

**The identity material differs.** Even the raw input is a 67-byte two-key tuple
rather than a 33-byte `0x05 ‖ X25519` key.

**A different rule orders the two halves.** This one applies even on the
SDK's low-level single-key path, which is otherwise byte-identical to
`libsignal`. The SDK orders by user identifier,
`localId.localeCompare(remoteId)` (`safety/core.ts:177`). `libsignal` orders by
the encoded digit strings themselves ([`fingerprint.rs:32-40`][fp]). Both rules
are symmetric, so the two parties always agree with each other. They do not
agree with Signal Messenger, and roughly half the time the halves come out in
the opposite order.

`localeCompare` is also locale-sensitive. Two devices with different default
locales can in principle disagree on how to order the same pair of user IDs.

Other parts *are* faithful. The iteration is byte-for-byte `libsignal`'s: 5200
iterations of SHA-512 over `0x0000 ‖ key ‖ id`, then `hash ‖ key`
(`safety/core.ts:138-143` vs [`fingerprint.rs:170-189`][fp]). So is the digit
encoding (six 5-byte big-endian chunks mod 100000, 30 digits per party). So is
the scannable-fingerprint protobuf layout (`safety/protobuf.ts:94-109`). The
cross-verification swap and constant-time comparison match as well.

The QR format version is the SDK's own: `3` for the composite path
(`safety/core.ts:46`), where `libsignal` knows only versions 1 and 2 and returns
`VersionMismatch` for anything else. A distinct version in the same protobuf
namespace is the correct fail-closed choice. A Signal Messenger client rejects
the code rather than misreading it.

The SDK also offers an emoji fingerprint (`safety/core.ts:308-392`) and
verification deep links (`safety/url.ts`). Both are extensions with no
`libsignal` counterpart. The emoji form derives from one party's fingerprint
only. It therefore encodes roughly half of what the 60-digit number encodes.
Do not present it to users as an equal-strength alternative.

### 1.4 Registration ID range

The SDK generates registration IDs in the closed range `[1, 16383]`
(`keys/generation.ts:43-46`). The wire format reserves exactly 14 bits, and
`libsignal` rejects any ID where `id & 0x3FFF != id`
([`sealed_sender.rs:1508-1515`][ss]). Its own helper generates `[1, 16380]`.

The upper bound is load-bearing rather than cosmetic. The value `16384` is
`0x4000` and does not fit in 14 bits. The SDK's multi-recipient sealed-sender
encoder masks rather than rejects
(`internal/protocol/sealed-sender/v2-binary.ts:170-171`), so an ID one above
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

The info strings are the SDK's own (`types/protocol-config.ts:363-386`):

```text
OpenE2EE_X25519_SHA-256_ML-KEM-1024   (PQXDH)
OpenE2EE                              (X3DH)
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
   worse than a labelling error. Two implementations feeding an identical label
   derive *different* shared secrets. The KEM underneath differs, and nothing at
   the KDF layer signals it. Domain separation is the one job the info string
   has.
2. **`info` would name someone else's application.** The specifications ask
   for an identifier of the application deriving the key. This SDK is not
   Signal Messenger.

Choosing the SDK's own labels is a pre-1.0 format break against sessions
established under `libsignal`'s. Those sessions derive a different `SK`, and
neither side can continue them. Nothing else about the derivation changes.

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
(`internal/session/builder.ts:159-171`). By contrast, `libsignal` generates a
fresh sending ratchet key, distinct from the handshake ephemeral
([`ratchet.rs:77-81`][rat]). In `libsignal` the prekey message's base key and the
first message's ratchet key therefore differ. Here they are the same value. No
concrete attack follows, but the reuse weakens key separation and it is
wire-visible.

**Bob initializes without a sending chain** (`internal/session/builder.ts:326-364`),
deriving chains on the first DH ratchet, where `libsignal` seeds a sending chain
immediately ([`ratchet.rs:137-172`][rat]). A side effect is that bytes 32–64 of
the 96-byte derivation, the initial chain key, never produce a message key on
either side. The SDK keeps the 96-byte split for shape compatibility, but only
the root key and the SPQR key are load-bearing.

### 2.5 The SDK keeps a gated classical fallback

`libsignal` removed X3DH entirely and rejects pre-Kyber prekey messages
([`session.rs:105-112`][sess]). The SDK keeps the X3DH path reachable only via an
explicit opt-in. The default is fail-closed, and any PQXDH failure raises rather
than silently downgrading (`internal/session/handshake.ts:167-260`). This is a
downgrade surface that `libsignal` closed.
[Protocol Policy](./PROTOCOL_POLICY.md) documents it.

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

### 3.3 Skipped-key retention is much tighter than in libsignal

The constants match: `MAX_MESSAGE_KEYS = 2000` and `MAX_FORWARD_JUMPS = 25000`
(`internal/protocol/double-ratchet/ratchet.ts:194-227` vs
[`consts.rs:8-9`][consts]). The two implementations apply them differently, and
the difference is user-visible.

**The cap is global, not per-chain.** `libsignal` applies 2000 to each chain's key
vector ([`double_ratchet.rs:349-361`][dr]). Five receiver chains therefore give a
true system capacity of 10,000 skipped keys. The SDK counts across all chains and
evicts when the total reaches 2000
(`internal/protocol/double-ratchet/chains.ts:478-513`). The effective capacity is
5× smaller, and traffic on a newer chain can evict keys that belong to an older
one.

**Wall-clock timestamps drive eviction.** The SDK scans every chain for the
oldest entry (`internal/protocol/double-ratchet/chains.ts:414-463`). By contrast,
`libsignal` evicts strictly by insertion position. `Date.now()` is not monotonic,
so a clock adjustment makes the eviction order non-deterministic.

**Skipped keys expire after 7 days**
(`internal/protocol/double-ratchet/ratchet.ts:197`). `libsignal` has no
time-based expiry for message keys at all.

Taken together, these three differences create **message-delivery patterns where
this SDK reports an undecryptable message and `libsignal` decrypts it**. Two
recipients can lose messages that the specification's own limits keep. The first
is offline for more than a week. The second takes heavy traffic on a new chain
while older-chain messages are still in flight. The bounds are defensible as
storage hygiene. The consequence should not be a surprise.

Two related extensions go with this. A `processedChains` map rejects messages
that bear a ratchet key from a retired chain
(`internal/protocol/double-ratchet/ratchet.ts:141-153`), which closes a replay gap
that `libsignal` handles only through its five-chain window. Self-sessions get a
finite 100,000-message skip limit (`internal/session/validation.ts:453-461`)
where `libsignal` uses `usize::MAX`.

### 3.4 Session archiving and serialization

The cap matches: 40 archived states, [`consts.rs:11`][consts]. The structure
differs. `libsignal` keeps an ordered list with strict insertion-order eviction
([`session.rs:787-830`][st]). The SDK keeps a map keyed by base key and trims by
`lastUsedAt` (`types/session.ts:815-847`). Archiving a session whose base key
already exists overwrites rather than appends, so the effective history can be
shorter than 40.

`libsignal` clears unacknowledged prekey state before archiving a session. The
SDK does not. Retired sessions therefore keep pending prekey references alive in
storage.

**Session records serialize as JSON, not protobuf** (`types/session.ts:1002-1028`).
The source states this as a simplicity and debuggability choice. Two consequences
are worth naming. No Signal Messenger client can read or write these stored
sessions. Key material also sits in immutable JavaScript strings that nothing can
zero, where `libsignal` can zero its byte vectors.

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
independently and pinned against commit `fd32048`, which upstream tags
`SparsePostQuantumRatchet v1.5.3`. The fidelity is high and specific:

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

The delta review that moved the pin forward from `f2589fef` found one behavioural
change upstream. Decoding a chain epoch direction now rejects a `next` chain key
whose length is neither zero nor 32 bytes. The internal next-key assertion checks
that same exact length rather than mere non-emptiness.

The SDK is already at least as strict. Restoring SPQR state requires every chain
key, root key, and skipped-message key to be canonical base64 for exactly 32
bytes (`internal/protocol/spqr/serialize.ts:44-72`). The SDK has no state in
which the key is absent. Two upstream error strings now name the value they
reject. The rest of the delta is proof-assistant annotation and loop rewriting,
which leaves behaviour unchanged.

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

**Deviation.** Skipped-key eviction in the SPQR chain triggers at the cap and
evicts by wall-clock timestamp, where `libsignal` triggers at `max_ooo × 11/10 + 1` and
evicts by message index. `libsignal`'s rule is deterministic and index-anchored.
The SDK's rule puts a clock dependency into ratchet state.

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

### 5.1 The SDK removes deleted devices instead of marking them stale

§3.1 and §3.3 require an implementation to mark a removed device's record stale
and keep it for MAXLATENCY. Messages already in flight from that device then
still decrypt. The SDK removes the record immediately
(`internal/sesame/manager.ts:2098-2102`).

**State the consequence plainly. A message that a device sent moments before its
removal becomes permanently undecryptable.** The specification's staleness window
exists to prevent exactly that. No other part of the codebase contradicts the
Sesame text this directly.

The SDK also reuses the word `stale` for a different concept: a device *list*
that needs refetching (`internal/sesame/types.ts:476-483`). The specification uses
the word for a deleted user or device.

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

### 5.4 Extensions: provisioning, transfer, device names

Sesame rev. 2 holds none of these. It says nothing about how a device comes to
exist, takes a name, or migrates.

**QR device provisioning** (`device/provisioning.ts`). Ephemeral X25519 ECDH →
HKDF → AES-256-GCM, with a `signalprotocol://link-device` QR scheme, strict prefix
and key validation, a 5-minute TTL, and rollback on both server and local failure.
The construction is sound. One property is worth naming. Nothing binds the
provisioning key to the primary device's long-term identity. The only
authentication for the channel is the out-of-band display of the QR code.

**Device transfer** (`device/transfer.ts`). Clones the identity private key and
live ratchet state to a new device. This is useful, and it **breaks the invariant
that Sesame rests on**: one device record, one device, its own sessions. After a
transfer, two physical devices hold the same identity private key and the same
ratchet state for every peer.

A peer message that one device decrypts desynchronizes the other. The duplicated
ratchet state also weakens the
forward-secrecy guarantee that keeps the compromise of one endpoint within that
endpoint. Restore deliberately drops archived sessions, which discards the
convergence state that §3.4 needs.

**Encrypted device names** (`device/device-name-crypto.ts`). A three-field
protobuf carries a synthetic IV that HMAC derives, with AES-256-CTR. That is the
standard SIV pattern, correctly constructed. The specification has no
counterpart.

**Identity-change gating.** The SDK TOFU-pins an unseen identity. A changed
identity sets `pendingVerification` and blocks sending until the application
accepts the rotation (`internal/sesame/manager.ts:561-566`, `:1682-1714`). Sesame
rev. 2 has no such concept. This is a genuine improvement.

**Not implemented:** proof of possession. Registration does not make the device
sign a server-issued nonce with its identity private key. Registration therefore
trusts the relay more than §6.3 assumes. A deployment that needs proof of
possession must add it at the application layer.

---

## 6. Sealed sender

### 6.1 Version 2 is faithful

These parts match `libsignal`:

- all four HKDF labels, byte for byte
- the KEM construction and its direction-swapped IKM orderings
- the authentication tag, which is the same 16-byte raw HKDF output
- AES-256-GCM-SIV with a zero nonce and no AAD
- the multi-recipient binary format ([`sealed_sender.rs:1023-1153`][ss],
  `:1306-1360`): version bytes `0x22`/`0x23`, the varint count, and 17-byte
  ServiceIds
- the packed device ID with its 14-bit registration ID and `0x3FFF` mask

Certificate validation order and semantics match as well. That includes the
trust-root loop, which does not short-circuit and therefore does not reveal which
root validated.

### 6.2 Version 1 diverges in three places

**The SDK splits the 96-byte HKDF output in a different order.** `libsignal`
derives `(chain_key, cipher_key, mac_key)` ([`sealed_sender.rs:711-746`][ss]).
The SDK derives `(cipher, mac, chain)`
(`internal/protocol/sealed-sender/encryption.ts:164-166`). The construction is
self-consistent and secure, because the keys are independent HKDF output either
way. Every v1 key still sits in a different slot than `libsignal`'s. This is an
implementation divergence rather than a design decision. The SDK's own pinned
specification document records the same order, so the two agree with each other.

**Public keys in the v1 salt and in certificates omit the `0x05` type byte.**
`libsignal` uses the 33-byte serialized form. The SDK uses raw 32 bytes and
enforces that length
(`internal/protocol/sealed-sender/certificate.ts:306-309`). The SDK's own v2 path
*does* apply the `0x05` prefix, so the two sealed-sender versions disagree with
each other.

**The inner envelope is a hand-rolled varint format**
(`internal/protocol/sealed-sender/encryption.ts:46-86`) rather than the
`UnidentifiedSenderMessage.Message` protobuf. It still carries the message-type
field that `libsignal` dispatches on, which selects between prekey, regular,
sender-key, and plaintext payloads ([`sealed_sender.rs:2055-2075`][ss]). The
field is a leading byte holding `libsignal`'s enum values. The framing therefore
differs while the dispatch does not.

That field lets the unseal path restore the real message type. Without it the
path would rebuild the envelope with a fixed type, and a sealed group message
would not decrypt as a group message.

**`PLAINTEXT_CONTENT` (8) is a known wire value that this SDK rejects.**
`libsignal` uses it to carry a `DecryptionErrorMessage` when no session exists
to encrypt one under ([`sealed_sender.rs:2055-2075`][ss]). This SDK instead
delivers decryption-error signals over a dedicated relay channel. Sesame §4.1
defines that channel, and the SDK builds it from the `retryRequests` table and
`sendRetryRequest`. No send path produces the type, and no decrypt path consumes
it. The envelope parse therefore
rejects the value (`internal/protocol/sealed-sender/types.ts`) rather than map it
to an envelope type with no handler.

The enum keeps the member so the wire values stay a faithful record.
`envelopeTypeForContent` throws on it, so a new member without a route fails
loudly. A peer that sends one gets a clean parse failure, not a payload routed
into the pairwise ratchet.

Note the cost when you debug interop. The parsers throw a single generic error
for every malformed envelope. A peer implementation that legitimately sends
`PLAINTEXT_CONTENT` therefore fails with `Sealed sender verification failed`,
which is the same string a MAC mismatch produces. The uniformity is deliberate,
and the parse runs after authentication, so nothing here is an oracle. Watch for
one pattern: sealed messages from one peer stack fail with that error while
messages from this SDK succeed. Check the leading content-type byte before you
treat that as a cryptographic failure.

### 6.3 The delivery token follows `libsignal`, not an SDK invention

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

Certificate signatures use Ed25519 rather than XEdDSA, per §1.2, so SDK
certificates cannot validate against a Signal Messenger trust root or vice versa. The
revocation list is empty where `libsignal` revokes one key ID, which is
appropriate for a different trust root but worth noting.

---

## 7. Sender keys and groups

### 7.1 Sender key message format

These parts match:

- protobuf field numbers and types, against [`wire.proto`][wp] exactly
- the `[version byte] ‖ protobuf ‖ [64-byte signature]` framing with version
  `0x33`
- the `0x01`/`0x02` chain seeds and the `WhisperGroup` info string
- AES-256-CBC with the derived IV
- the capacity constants

Three things do not:

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

### 7.2 Message-key derivation omits HKDF-Extract

This one is worth stating precisely because the field numbers and labels above
make the format look compatible.

`libsignal` derives sender message keys with
`Hkdf::<Sha256>::new(None, &seed).expand(b"WhisperGroup", 48)`
([`sender_keys.rs:36-38`][sk]). `Hkdf::new` runs HKDF-**Extract** first, as
`PRK = HMAC-SHA256(salt = zeros[32], seed)`. Only then does it expand.

The SDK calls `hkdfExpand(seed, info, 48)` directly
(`internal/protocol/sender-keys/manager.ts:1062-1066`), where `hkdfExpand`
(`internal/crypto/kdf/hkdf.ts:86-116`) is pure RFC 5869 Expand using the seed
itself as the PRK. The SDK never runs the extract step.

The derived IV and cipher key therefore differ from `libsignal`'s for the same
chain key. A numeric check confirms it, rather than inspection alone. For a chain
key of 32 repeated `0x42` bytes, the SDK derives IV
`2a56b9eb80b3c1ffebd97221b2175960` where `libsignal` derives
`890d51ea73e564722351dc0d5a09142c`.

This appears unintentional. It is not a weakness, because dropping Extract from a
uniformly random HMAC output is cryptographically sound. The repository's own
sender-keys note still claims equivalence with `libsignal` at this step, and that
claim is incorrect. This entry flags it for correction.

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
(`internal/groups/server-engine.ts`, with an installable Convex component)
implements that contract. On every applied change, clients verify the server's
signature, the group binding, the strict version sequence, and the pre-state
authorization.

**Profile-key credential issuance is not blinded**. The issuance endpoint
receives the raw 32-byte profile key, so the issuing server sees every user's
profile key in plaintext at issuance time. The Signal Private Group System issues
profile-key credentials over a *blinded* commitment, so its server never learns
the key. The blinding primitives exist in this codebase
(`internal/protocol/zk/credentials/issuance.ts`), but nothing wires them into
this path. Section 12.1 of the in-tree group specification carries the same
caveat.

Until blinded issuance ships, a deployer must assume that the issuance server
learns profile keys, and therefore profile names and avatars.

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
separately labelled key derivations, where `libsignal` uses a single seeded
derivation (`internal/protocol/zk/groups/server-params.ts:43-54`). The same
randomness therefore yields different server keys.

That structural difference stands on its own. Separately, each deployment
generates its **own** random 32-byte seed, which puts the trust root with the
deploying operator rather than with Signal Messenger. No credential is
interchangeable with a Signal Messenger credential.

Credential serialization is also ad hoc and carries no version byte, where
`libsignal` uses a leading version byte. That is a forward-compatibility gap
rather than a security one.

---

## Unverified and needs review

This review lists the following items rather than asserts them. It could not
confirm any of them in source.

- **Does a sealed-sender-wrapped prekey message decrypt end to end?** The unseal
  path rebuilds the envelope with a fixed message type
  (`client/sealed-sender-ops.ts:263-265`). An adjacent comment suggests that the
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
  rollback behaviour.
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
