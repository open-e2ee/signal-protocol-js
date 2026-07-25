# Deviations from the Signal Protocol Specifications

> Navigation: [README](../README.md) | [ARCHITECTURE](../ARCHITECTURE.md) |
> [Security](./SECURITY.md) | [Protocol Policy](./PROTOCOL_POLICY.md) |
> **Deviations**

## What compatibility means here

This SDK implements the same cryptographic core as the published Signal Protocol
specifications — X3DH/PQXDH key agreement, the Double Ratchet, the ML-KEM Braid
post-quantum ratchet, Sesame multi-device session management, sealed sender, and
Signal's zero-knowledge group credential system. In many places it is faithful
down to the byte: the same KDF labels, the same chain-key constants, the same
protobuf field numbers, the same iteration counts.

It is **not wire-compatible with Signal Messenger or with `libsignal`**, and it
is not intended to be. Messages produced by this SDK cannot be decrypted by a
Signal client, identities cannot be exchanged, safety numbers computed here
cannot be compared against safety numbers shown in Signal, and sessions cannot be
migrated in either direction. This is a distinct wire profile —
`IndependentProfileV1` — that shares Signal's cryptographic design and
deliberately does not share its encoding.

That distinction matters in a specific way. Reading "implements X3DH and the
Double Ratchet" reasonably leads someone to expect interoperability. There is
none. Reading "Signal-compatible safety numbers" would reasonably lead someone to
expect that a user could verify a contact by comparing a number shown in this SDK
against the same contact's number in Signal. They cannot; the numbers are
computed over different inputs and will never match.

This document is the complete, honest account of where and why the profile
differs. Each entry names the implementing file, the specification section or
`libsignal` source it departs from, the engineering reason, and the cost. Where a
deviation weakens an assurance that a reader of the specification would
reasonably assume, that is stated plainly rather than framed as a feature.

Deviations fall into three kinds:

- **Deviation** — does something different from the specification or from
  `libsignal`, deliberately.
- **Extension** — adds a mechanism the specification does not describe.
- **Independent design** — shares a name and a goal with a Signal system, but is
  the SDK's own construction rather than a port of Signal's.

A fourth label, **faithful**, appears in the table where an area follows the
specification closely enough that its presence in this document is only to
delimit what the neighbouring deviations do and do not touch.

Companion documents: [Protocol Policy](./PROTOCOL_POLICY.md) states which
protocol modes run and which fail closed; this document states how the profile
differs from the specifications. [Security](./SECURITY.md) states the threat
model and what is out of scope.

---

## Summary

| Area | Specification followed | Deviation or extension | Why | Consequence |
|---|---|---|---|---|
| **Identity keys** | X3DH §2.2; `libsignal` `identity_key.rs` | **Deviation.** A 67-byte composite of separate X25519 and Ed25519 keys replaces the single 33-byte Curve25519 identity key | Avoids XEdDSA, a non-standard signature scheme with no vetted JavaScript implementation; standard Ed25519 is independently verifiable | Two keys to store and rotate; larger identity; **no wire compatibility for any identity-bearing material** |
| **Prekey signatures** | X3DH §2.2, §4.5 | **Deviation.** RFC 8032 Ed25519 over a domain-separated context binding the identity commitment, algorithm tag, and key ID — not XEdDSA over the bare key | Defeats cross-algorithm and cross-key-ID substitution that a bare-key signature does not cover | Strictly stronger binding; signatures are unverifiable by Signal clients and vice versa |
| **Safety numbers** | `libsignal` `fingerprint.rs` | **Deviation.** Iteration and digit encoding are byte-identical, but the input is a composite-identity commitment under an SDK domain string, the QR version is `3`, and the two halves are ordered by user ID rather than by digit string | Follows from the composite identity; a single-key fingerprint cannot authenticate both components | **Safety numbers are not comparable to Signal's.** The ordering rule also differs from `libsignal` even on the single-key path |
| **X3DH / PQXDH** | X3DH rev. 1; PQXDH rev. 3 | **Faithful** on DH order, the `0xFF`×32 prefix, zero-salt HKDF, and KEM-secret position. **Deviation:** ML-KEM-1024 (FIPS 203) runs under an info string naming `CRYSTALS-KYBER-1024` | Standardized ML-KEM preferred over round-3 Kyber; the label was inherited from `libsignal` and not updated | Identical label with a different KEM means the same transcript derives a **different** shared secret, with no domain separation signalling it. Violates PQXDH §2.2 |
| **Associated data** | X3DH §3.3 | **Deviation.** `AD` is a domain-separated HMAC input over SHA-256 commitments to both composite identities, not `IK_A ‖ IK_B` | Binds the Ed25519 component, which a raw-key `AD` would leave uncovered | Stronger binding; wire-incompatible |
| **Double Ratchet** | Double Ratchet rev. 4 | **Faithful** on `WhisperRatchet`, `WhisperMessageKeys`, the `0x01`/`0x02` seeds, the 80-byte split, AES-256-CBC, the `0x44` version byte, and 8-byte MAC truncation | — | The ratchet core is Signal's |
| **Message wire format** | `libsignal` `wire.proto` | **Faithful** field numbers 1–8. **Extension:** fields at 100+ carry identity type and ML-KEM one-time prekey material. **Deviation:** address binding uses variable-length UTF-8 user IDs and 4-byte device IDs instead of 17-byte ServiceIds and 1-byte device IDs | The SDK binds application-defined identifiers, not Signal ACIs | Wire-incompatible; a Signal client would silently ignore the added fields |
| **Skipped keys and archiving** | Double Ratchet §2.6; `libsignal` `consts.rs` | **Deviation.** The 2000-key cap is global rather than per-chain, eviction is by wall-clock timestamp, and skipped keys expire after 7 days. Session records serialize as JSON, not protobuf | Simpler storage accounting and bounded growth | **Legitimate messages can become undecryptable** where `libsignal` would still decrypt them: a 5× smaller effective cap, cross-chain eviction, and a hard 7-day limit for offline recipients |
| **Padding** | — | **Extension.** ISO 7816-4 bit padding to 160-byte buckets inside the library | Length hiding by default rather than left to the application | `libsignal` does not pad at this layer; Signal's apps do. PKCS#7 then adds a block, so ciphertext lands 16 bytes past each boundary |
| **SPQR / ML-KEM Braid** | ML-KEM Braid rev. 1 | **Deviation.** Same protocol, same KDF labels, same Reed–Solomon parameters, byte-identical message framing — except `hek = SHA3-256(ek_seed ‖ ek_vector)`, the operand order the specification states, which is the reverse of Signal's implementation | The normative text was followed over the executable reference | Wire-visible. Headers, ciphertexts, and shared secrets diverge; a braid session cannot complete a single epoch against Signal's implementation. Also means the KEM is not FIPS 203 in braid mode |
| **Triple Ratchet** | `libsignal` `triple_ratchet.rs` | **Faithful.** The PQ secret enters as the HKDF salt at message-key expansion, same label, same order | — | The braiding construction is Signal's |
| **Sesame** | Sesame rev. 2 | **Deviation** on session expiry (§4.2 applies only to unacknowledged sessions) and on deleted devices (hard-removed rather than marked stale). **Extensions:** QR provisioning, device transfer, encrypted device names, identity-change gating, a 5-device cap | Product requirements the specification does not address | Hard deletion **drops the MAXLATENCY window, so in-flight messages from a just-removed device become permanently undecryptable**. Device transfer clones ratchet state, which weakens the forward-secrecy bound |
| **Sealed sender v1** | `libsignal` `sealed_sender.rs` | **Deviation.** Correct labels, cipher, and MAC length, but the 96-byte HKDF output is split `(cipher, mac, chain)` where `libsignal` splits `(chain, cipher, mac)`; keys in the salt omit the `0x05` type byte; the inner envelope is a hand-rolled varint format rather than the `UnidentifiedSenderMessage.Message` protobuf | The slice order and the missing prefix are unintentional; the envelope is a deliberate simplification | Self-consistent and secure, but every v1 key sits in a different slot than `libsignal`'s. The envelope also drops the message-type field |
| **Sealed sender v2** | `libsignal` `sealed_sender.rs` | **Faithful** on all four labels, the KEM, AES-256-GCM-SIV, the multi-recipient binary format, and the `0x3FFF` registration-ID mask | — | The v2 construction is Signal's |
| **Delivery token** | `libsignal` `profile_key.rs` | **Faithful.** `deriveAccessKey` is Signal's `ProfileKey::derive_access_key`, and reproduces `libsignal`'s published known-answer values | — | Not an SDK invention, despite what the module name suggests |
| **Sender keys** | `libsignal` `sender_keys.rs` | **Deviation.** Protobuf field numbers and `0x33` framing match, and the `0x01`/`0x02` seeds match, but message-key derivation **omits HKDF-Extract**, signatures are Ed25519 not XEdDSA, and `distributionUuid` carries a UTF-8 string rather than 16 UUID bytes | The Ed25519 choice follows the identity profile; the missing Extract appears unintentional | Group message keys differ from `libsignal`'s for the same chain key. Confirmed numerically, not merely by inspection |
| **Groups v2** | Signal Private Group System | **Independent design.** Real zkgroup primitives underneath, but the client is the state authority: it re-encrypts and uploads whole group state, and server signatures are not verified | Ships a working group system without a validating server | The relay **cannot validate group changes**, so it cannot enforce roles or membership. This is a materially weaker trust model than Signal's, where the server validates every change against zero-knowledge presentations |
| **zkgroup / zkcredential** | `libsignal` `zkgroup`, `zkcredential`, `poksho` | **Faithful** port of the Ristretto255 KVAC and Sigma-protocol system, verified against `libsignal`'s known-answer vectors. **Deviation:** server parameter derivation uses SDK-specific labels | Server keys are the SDK's own trust root, not Signal's | The zero-knowledge properties are real. Credentials are not interchangeable with Signal's |
| **Registration IDs** | `libsignal` `sealed_sender.rs` | **Faithful** as of 0.1.0-alpha.4. Generated in `[1, 16383]`, strictly inside the 14 bits the wire format reserves | — | Through alpha.3 the range ran to 16384, which masked to `0` on the wire in multi-recipient sealed sender for roughly 1 install in 16,384 |

---

## 1. Identity keys and signatures

### 1.1 Composite identity replaces the single Curve25519 key

`libsignal` represents an identity as one Curve25519 public key serialized as
`0x05 ‖ key` — 33 bytes ([`identity_key.rs:23-49`][ik]). The same private key is
used both for Diffie-Hellman and, via XEdDSA, for signing.

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
converting a Montgomery point to an Edwards point at signing time. It is
elegant, and it is also non-standard: no vetted JavaScript implementation exists,
the conversion has sign-bit handling that is easy to get subtly wrong, and the
resulting signatures cannot be checked by any general-purpose Ed25519 verifier.
Carrying an explicit Ed25519 key costs 32 bytes and one more key to manage, and
buys signatures that any RFC 8032 implementation can verify and that auditors can
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

A commitment received from a relay, cache, or caller is never trusted; it is
recomputed and compared in constant time (`keys/identity.ts:103-111`), and every
producer of stored identity bytes is forced through a decode/re-encode round trip
so that two encodings of the same key cannot forge an identity-change event
(`keys/identity.ts:154-161`). `libsignal` has no commitment concept, because a
single-key format has nothing to bind together.

**Not ported.** `libsignal`'s ACI↔PNI alternate-identity signature
([`identity_key.rs:61-70`][ik]) has no SDK equivalent. ACI and PNI are fully
independent identities here with independent trust histories; neither certifies
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

**Why.** A bare-key signature says only "the identity holder signed these 32
bytes." It does not say which algorithm the key is for, which key ID it occupies,
or which identity it belongs to. Binding all three defeats cross-algorithm
substitution (presenting an X25519 signature as an ML-KEM one) and cross-key-ID
substitution. This is strictly stronger than the specification requires.

**Cost.** Wire incompatibility, and a signature format that no Signal
implementation can verify.

The same Ed25519-instead-of-XEdDSA choice applies to sealed sender certificates
(`internal/protocol/sealed-sender/certificate.ts:59`, `:106`) and to sender key
messages (§7.2).

XEdDSA and VXEdDSA are not implemented, not stubbed, and not claimed anywhere in
this codebase. Where the frozen upstream specification snapshots mention them,
that is upstream text; the SDK's own documentation consistently states that
ordinary Ed25519 is used instead.

### 1.3 Safety numbers are not comparable to Signal's

State this without hedging: **a safety number produced by this SDK will never
match the safety number Signal shows for the same two users.** A user cannot
verify a contact by reading a number out of one application and comparing it
against the other.

Three independent reasons, any one of which is sufficient.

**The user-facing number is computed over a composite commitment.**
`client.verify()` uses `generateCompositeSafetyNumber`
(`client/sessions.ts:326`, `:432-433`), whose per-party hash iterates over
`UTF8("signal-protocol-js composite safety number v1") ‖ type-tagged user ID ‖
SHA-256 identity commitment` (`safety/core.ts:48-50`, `:205-233`). None of that
input exists in `libsignal`'s construction ([`fingerprint.rs:161-192`][fp]).

**The identity material differs.** Even the raw input is a 67-byte two-key tuple
rather than a 33-byte `0x05 ‖ X25519` key.

**The two halves are ordered by a different rule.** This one applies even on the
SDK's low-level single-key path, which is otherwise byte-identical to
`libsignal`. The SDK orders by user identifier — `localId.localeCompare(remoteId)`
(`safety/core.ts:177`) — where `libsignal` orders by the encoded digit strings
themselves ([`fingerprint.rs:32-40`][fp]). Both rules are symmetric, so the two
parties always agree with each other; they simply do not agree with Signal, and
roughly half the time the halves come out in the opposite order. `localeCompare`
is additionally locale-sensitive, so two devices with different default locales
can in principle disagree with each other on the ordering of the same pair of
user IDs.

What *is* faithful: the iteration is byte-for-byte `libsignal`'s — 5200
iterations of SHA-512 over `0x0000 ‖ key ‖ id`, then `hash ‖ key`
(`safety/core.ts:138-143` vs [`fingerprint.rs:170-189`][fp]) — as is the digit
encoding (six 5-byte big-endian chunks mod 100000, 30 digits per party) and the
scannable-fingerprint protobuf layout (`safety/protobuf.ts:94-109`). The
cross-verification swap and constant-time comparison match as well.

The QR format version is the SDK's own: `3` for the composite path
(`safety/core.ts:46`), where `libsignal` knows only versions 1 and 2 and returns
`VersionMismatch` for anything else. Using a distinct version in the same
protobuf namespace is the correct fail-closed choice — a Signal client rejects
the code rather than misreading it.

The SDK also offers an emoji fingerprint (`safety/core.ts:308-392`) and
verification deep links (`safety/url.ts`). Both are extensions with no
`libsignal` counterpart. Note that the emoji form is derived from one party's
fingerprint only, so it carries roughly half the information of the 60-digit
number and should not be presented to users as an equal-strength alternative.

### 1.4 Registration ID range

Registration IDs are generated in the closed range `[1, 16383]`
(`keys/generation.ts:43-46`). The wire format reserves exactly 14 bits, and
`libsignal` rejects any ID where `id & 0x3FFF != id`
([`sealed_sender.rs:1508-1515`][ss]); Signal's own helper generates `[1, 16380]`.

Through 0.1.0-alpha.3 the range was `[1, 16384]`, an off-by-one: 16384 is
`0x4000` and does not fit in 14 bits, and the SDK's multi-recipient sealed sender
encoder masks rather than rejects
(`internal/protocol/sealed-sender/v2-binary.ts:170-171`), so a generated `16384`
was written to the wire as `0` — roughly 1 install in 16,384. This is corrected
as of 0.1.0-alpha.4; the generated range is now strictly narrower than
`libsignal`'s accepted range, and a regression test asserts every generated ID
survives the mask unchanged.

---

## 2. X3DH and PQXDH

The key agreement is the most faithful area in the codebase. The DH computation
order, the 32-byte `0xFF` discontinuity prefix, the zero-filled HKDF salt, the
single-step derivation over the full concatenation, the position of the KEM
shared secret (appended last), and the 96-byte output split all match
`libsignal` exactly.

- Initiator DH order `DH(IK_A,SPK_B)`, `DH(EK_A,IK_B)`, `DH(EK_A,SPK_B)`,
  `DH(EK_A,OPK_B)`: `internal/protocol/pqxdh/pqxdh.ts:243-264` vs
  [`pqxdh.rs:202-224`][pq]. Spec X3DH §3.3.
- `F = 0xFF × 32` prefix: `internal/protocol/pqxdh/pqxdh.ts:267-271` vs
  [`pqxdh.rs:200`][pq]. Spec X3DH §2.2.
- KEM secret appended after all DH outputs, then one HKDF:
  `internal/protocol/pqxdh/pqxdh.ts:365-374` vs [`pqxdh.rs:226-230`][pq]. Spec
  PQXDH §3.3.

Two hardening extensions go beyond the specification at no interop cost: every
remote X25519 point is validated before any DH is computed
(`internal/protocol/pqxdh/pqxdh.ts:219-227`), and prekey bundles are validated
far more strictly than `libsignal` requires
(`internal/session/handshake.ts:107-138`).

### 2.1 ML-KEM-1024 runs under an info string naming Kyber

The SDK uses ML-KEM-1024 (FIPS 203) where `libsignal` uses round-3 Kyber1024,
tagged `0x0A` rather than `0x08` (`internal/crypto/pq/kyber.ts:79`). That much is
deliberate: the standardized algorithm is preferred over the round-3 draft, and a
single unambiguous tag is preferred over carrying a legacy fallback.

The info string was not updated to match (`types/protocol-config.ts:365`):

```text
WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024
```

This is byte-identical to `libsignal`'s label ([`pqxdh.rs:73-74`][pq]) while
naming a KEM the SDK does not use. Two consequences:

1. **It violates the SDK's own pinned specification.** PQXDH §2.2 requires the
   info string to be the concatenation of the four PQXDH parameters *including
   the actual `pqkem`*. The running `pqkem` is ML-KEM-1024; the string says
   CRYSTALS-KYBER-1024.
2. **It removes the domain separation that would make the incompatibility
   self-evident.** Two implementations feeding the identical label derive
   different shared secrets, because the KEM underneath differs. A label naming
   ML-KEM-1024 would make the non-interoperability explicit at the KDF layer.

Changing the label to name ML-KEM-1024 would satisfy §2.2 and improve the
situation. It is a pre-1.0 format break, and is flagged rather than fixed here.

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
Ed25519 signing component unbound — the component that authenticates every prekey
the peer will ever publish. Hashing the commitment covers both.

**Cost.** This is the single largest wire deviation in the message path. The
truncation to 8 bytes matches Signal's convention, and the construction is sound
and domain-separated, but a Signal client and this SDK cannot exchange a single
message.

### 2.3 One-time prekey deletion is deferred

PQXDH §3.4 has Bob delete a used one-time prekey after successful decryption. The
SDK records a pending deletion (`internal/manager/manager.ts:940-952`) and
commits it only once a prekey message decrypts
(`internal/session/cipher.ts:1189-1200`). This is compliant in letter and widens
the window in which the same first ciphertext can be replayed before commit;
duplicate and missing-prekey conditions are refused auto-recovery
(`internal/session/cipher.ts:1519-1527`).

### 2.4 Ratchet initialization details

Two differences at the boundary between key agreement and the ratchet:

**Alice reuses her key-agreement ephemeral as her first ratchet key**
(`internal/session/builder.ts:159-171`). `libsignal` generates a fresh sending
ratchet key distinct from the handshake ephemeral ([`ratchet.rs:77-81`][rat]), so
the prekey message's base key and the first message's ratchet key differ. Here
they are the same value. No concrete attack follows, but it is a reduction in key
separation and it is wire-visible.

**Bob initializes without a sending chain** (`internal/session/builder.ts:326-364`),
deriving chains on the first DH ratchet, where `libsignal` seeds a sending chain
immediately ([`ratchet.rs:137-172`][rat]). A side effect is that bytes 32–64 of
the 96-byte derivation — the initial chain key — never produce a message key on
either side. The 96-byte split is retained for shape compatibility, but only the
root key and the SPQR key are load-bearing.

### 2.5 Classical fallback is retained but gated

`libsignal` has removed X3DH entirely and rejects pre-Kyber prekey messages
([`session.rs:105-112`][sess]). The SDK keeps the X3DH path reachable only via an
explicit opt-in; the default is fail-closed, and any PQXDH failure raises rather
than silently downgrading (`internal/session/handshake.ts:167-260`). This is a
downgrade surface that `libsignal` has closed, and it is documented in
[Protocol Policy](./PROTOCOL_POLICY.md).

---

## 3. Double Ratchet and wire format

### 3.1 The ratchet core is faithful

Byte-for-byte with `libsignal`: the `0x01`/`0x02` chain-key seeds
(`internal/crypto/kdf/hkdf.ts:183-195` vs [`keys.rs:148-149`][rk]), the
`WhisperMessageKeys` expansion to 80 bytes split 32/32/16
(`internal/crypto/kdf/hkdf.ts:215-243` vs [`keys.rs:100-118`][rk]), the
`WhisperRatchet` root-key step producing a 64-byte split
(`internal/crypto/kdf/hkdf.ts:141-161` vs [`keys.rs:199-218`][rk]), the DH ratchet
half-step ordering, `MAX_RECEIVER_CHAINS = 5`, AES-256-CBC with PKCS#7, the
`0x44` version byte, and 8-byte MAC truncation.

Message framing matches too: `[version byte] ‖ protobuf ‖ [8-byte HMAC]` for
messages and `[version byte] ‖ protobuf` for prekey messages
(`internal/encoding/proto/envelope.ts:104-168`). What goes *into* the MAC does
not — see §2.2.

Protobuf fields 1–8 match [`wire.proto`][wp] exactly, including `libsignal`'s
non-obvious ordering where `registrationId` is field 5 and `signedPreKeyId` is
field 6.

### 3.2 Added fields and address binding

**Extension.** The SDK adds fields in the 100+ range that `libsignal` does not
have: `recipientIdentityType` on both message types, and `kemOneTimePreKeyId` /
`kemOneTimeCiphertext` on prekey messages
(`internal/encoding/proto/signal-message.ts:80`, `:226-228`). High numbering
avoids collision with future upstream fields. A Signal client would parse the
message and silently ignore them, losing the identity-type binding.

**Deviation.** `libsignal` binds addresses as a 17-byte fixed-width ServiceId plus
a 1-byte device ID ([`protocol.rs:246-260`][proto]). The SDK binds a
format-version byte, a varint-length-prefixed UTF-8 user ID, and a 4-byte
big-endian device ID (`internal/encoding/proto/signal-message.ts:84-92`). The
encoding is unambiguous, but it authenticates an application-defined identifier
rather than a Signal ACI or PNI — which is the correct thing for this SDK to bind
and an incompatible thing to put on the wire.

The SDK is also stricter than `libsignal` on decode, requiring fields that
`libsignal` treats as optional for backward compatibility and enforcing exact
lengths (`internal/encoding/proto/signal-message.ts:332-340`, `:488-505`). Safer,
and one more reason the formats cannot meet.

### 3.3 Skipped-key retention is materially tighter than libsignal's

The constants match — `MAX_MESSAGE_KEYS = 2000`, `MAX_FORWARD_JUMPS = 25000`
(`internal/protocol/double-ratchet/ratchet.ts:194-227` vs [`consts.rs:8-9`][consts])
— but they are applied differently, and the difference is user-visible.

**The cap is global, not per-chain.** `libsignal` applies 2000 to each chain's key
vector ([`double_ratchet.rs:349-361`][dr]), so with five receiver chains the true
system capacity is 10,000 skipped keys. The SDK counts across all chains and
evicts when the total reaches 2000
(`internal/protocol/double-ratchet/chains.ts:478-513`). The effective capacity is
5× smaller, and traffic on a newer chain can evict keys belonging to an older one.

**Eviction is by wall-clock timestamp**, scanning every chain for the oldest
entry (`internal/protocol/double-ratchet/chains.ts:414-463`), where `libsignal`
evicts strictly by insertion position. `Date.now()` is not monotonic, so eviction
order is not deterministic across clock adjustments.

**Skipped keys expire after 7 days**
(`internal/protocol/double-ratchet/ratchet.ts:197`). `libsignal` has no
time-based expiry for message keys at all.

Taken together: **there are message-delivery patterns where this SDK reports an
undecryptable message and `libsignal` would have decrypted it.** A recipient
offline for more than a week, or one receiving heavy traffic on a new chain while
older-chain messages are still in flight, can lose messages that the
specification's own limits would have preserved. The bounds are defensible as
storage hygiene; the consequence should not be a surprise.

Two related extensions: a `processedChains` map rejects messages bearing a ratchet
key from an already-retired chain (`internal/protocol/double-ratchet/ratchet.ts:141-153`),
closing a replay gap that `libsignal` handles only via its five-chain window; and
self-sessions get a finite 100,000-message skip limit
(`internal/session/validation.ts:453-461`) where `libsignal` uses `usize::MAX`.

### 3.4 Session archiving and serialization

The cap matches (40 archived states, [`consts.rs:11`][consts]), but the structure
differs. `libsignal` keeps an ordered list with strict insertion-order eviction
([`session.rs:787-830`][st]); the SDK keeps a map keyed by base key and trims by
`lastUsedAt` (`types/session.ts:815-847`). Archiving a session whose base key
already exists overwrites rather than appends, so the effective history can be
shorter than 40.

`libsignal` clears unacknowledged prekey state before archiving a session; the SDK
does not. Retired sessions therefore keep pending prekey references alive in
storage.

**Session records serialize as JSON, not protobuf** (`types/session.ts:1002-1028`).
This is acknowledged in the source as a simplicity and debuggability choice.
Consequences worth naming: stored sessions are not portable to or from any Signal
client, and key material sits in immutable JavaScript strings that cannot be
zeroed, where `libsignal`'s byte vectors can be.

### 3.5 Padding

**Extension.** Message plaintext is padded to 160-byte buckets with ISO 7816-4 bit
padding — a `0x80` terminator followed by zeros
(`internal/crypto/symmetric/padding.ts:19-60`). Unpadding scans backwards and
rejects malformed padding with a deliberately generic error to avoid a padding
oracle.

`libsignal` does not bucket-pad at this layer; in Signal, that lives in the client
applications. Doing it in the library means length hiding is on by default rather
than a thing each integrator must remember.

One imprecision: because the padded plaintext is an exact multiple of 160 and
AES-CBC then applies PKCS#7, a full block is always appended. A 5-byte message
produces 160 padded bytes and 176 ciphertext bytes. Length is still quantized in
160-byte steps, so the hiding property holds; the ciphertext simply sits 16 bytes
past each boundary rather than on it.

---

## 4. SPQR and the ML-KEM Braid

This is the same protocol as Signal's SparsePostQuantumRatchet v1, implemented
independently and pinned against `SparsePostQuantumRatchet v1.5.1` (commit
`f2589fef`). The fidelity is high and specific:

- **KDF labels are byte-identical**, including the double space in
  `"Signal PQ Ratchet V1 Chain  Start"` (`internal/crypto/kdf/hkdf.ts:353-368`).
- **The authenticator construction matches**, including `PROTOCOL_INFO =
  "Signal_PQCKA_V1_MLKEM768"` and the `:ekheader` / `:ciphertext` MAC inputs
  (`internal/protocol/spqr/ml-kem-braid/kdf.ts:32-92`).
- **The Reed–Solomon erasure layer matches**: GF(2^16) with primitive polynomial
  `0x1100b`, 32-byte chunks, 16 polynomials, degree bound 35. Reed–Solomon is
  present in Signal's implementation; it is not an SDK addition.
- **The production wire framing is byte-compatible**:
  `VERSION ‖ LEB128(epoch) ‖ LEB128(chain_index) ‖ MSG_TYPE ‖ [LEB128(chunk_index) ‖ CHUNK]`
  (`internal/encoding/proto/pq-ratchet-serialize.ts`), matching Signal's
  `serialize.rs`, with the same message-type values and the same epoch offset.
- **ML-KEM-768 with the same incremental split** (32-byte seed, 1152-byte vector,
  960/128-byte ciphertext parts).

### 4.1 The `hek` operand order diverges

One divergence breaks interoperability completely. The SDK computes
(`internal/protocol/spqr/ml-kem-braid/noble-pq/index.ts:841-843`):

```text
hek = SHA3-256(ek_seed || ek_vector)
```

Signal's implementation, via libcrux, builds the encapsulation key as
`t̂ ‖ ρ` before hashing — the reverse order.

The SDK follows the **normative text of the published ML-KEM Braid
specification**, which states seed-first ordering. Signal's code follows FIPS 203,
which serializes vector-first. The specification and the reference implementation
disagree, and the SDK chose the specification.

The value feeds the Fujisaki–Okamoto transform, so the consequences cascade:
different header bytes, so Signal's header validation rejects the SDK's output;
different ciphertext; different shared secret; different epoch secret; different
authenticator ratchet. **A braid session between this SDK and Signal's
implementation cannot complete a single epoch.**

Two further consequences a reader should not have to infer:

- **In braid mode the KEM is not FIPS 203 ML-KEM-768.** It is ML-KEM-768 with a
  modified `hek` derivation. The security argument is unaffected — the hash input
  is a permutation of the same material — but a FIPS conformance claim would not
  hold for this path. Direct (non-braid) mode uses stock ML-KEM-768.
- The SDK resolves the same spec-versus-code conflict in the *opposite* direction
  elsewhere: for `KDF_AUTH`, it follows Signal's Rust reference rather than the
  written specification. The two choices are individually defensible and
  collectively inconsistent about which artifact is authoritative.

The operand order is part of the public compatibility boundary stated in
[Protocol Policy](./PROTOCOL_POLICY.md). Changing it later would invalidate every
braid session persisted under the former ordering.

### 4.2 Direct mode and state format

**Extension.** An opt-in direct mode (`protocol.braid: 'disabled'`) uses stock
ML-KEM-768 and adds wire message types `0x80`–`0x82`
(`internal/encoding/proto/pq-ratchet-serialize.ts:38-45`). Signal's parser rejects
anything above `6`, so these are visible only within the SDK; they occupy a byte
range Signal has not claimed. This mode has no Signal analogue.

**Independent design.** Persisted SPQR state uses a flat message with 20 fields
where Signal uses an 11-variant `oneof` over nested structures. Serialized SPQR
state is not portable in either direction.

**Deviation.** Skipped-key eviction in the SPQR chain triggers at the cap and
evicts by wall-clock timestamp, where Signal triggers at `max_ooo × 11/10 + 1` and
evicts by message index. Signal's rule is deterministic and index-anchored; the
SDK's introduces a clock dependency into ratchet state.

### 4.3 The Triple Ratchet is faithful

The post-quantum secret enters as the HKDF **salt** at message-key expansion, with
the classical message key as IKM and the `WhisperMessageKeys` label
(`internal/session/cipher.ts:453-510`) — the same combination order and the same
label as [`triple_ratchet.rs`][tr]. There is no root-key braiding in either
implementation.

Note that `internal/protocol/triple-ratchet/` contains a second, unused hybrid KDF
using the label `'Signal Triple Ratchet V1'`. It is exported but not called from
the message path, and it is incompatible with what the SDK actually puts on the
wire. It is documented in the PR that accompanied this file as cleanup work.

---

## 5. Sesame

Sesame has no reference implementation to compare against — `libsignal` does not
implement it; device and session management lives in the Signal service and its
clients. Everything below is measured against the pinned specification text
(revision 2) alone.

Faithful: the user-record and device-record structure (§3.1), the per-device
session fan-out on send including the sender's own other devices (§3.3), the
bounded send loop (§3.3, §6.5), discard-all-changes-on-error handled
transactionally (§3.3, §3.4, §6.7), and creating a session on receive only from an
initiating message (§3.4). The per-user identity model is one of the two the
specification explicitly permits (§3.1).

### 5.1 Deleted devices are removed rather than marked stale

§3.1 and §3.3 require a removed device's record to be marked stale and retained
for MAXLATENCY, so that messages already in flight from that device still
decrypt. The SDK removes the record immediately
(`internal/sesame/manager.ts:2098-2102`).

**Consequence, stated plainly: a message sent by a device that was removed moments
earlier becomes permanently undecryptable.** The specification's staleness window
exists precisely to prevent this. This is the most substantive contradiction of
the Sesame text in the codebase.

Relatedly, the SDK reuses the word `stale` for a different concept — a device
*list* that needs refetching (`internal/sesame/types.ts:476-483`) — rather than
the specification's meaning of a deleted user or device.

### 5.2 Session expiry applies only to unacknowledged sessions

§4.2 is unconditional: at MAXSEND past its timestamp, a session must no longer be
used for encryption. The SDK applies that bound only to sessions that have never
received a reply (`internal/sesame/types.ts:175-199`). A session that received one
message on its first day remains a valid encryption session indefinitely.

The configuration field is honestly renamed to `maxUnacknowledgedSessionAge` to
reflect this. The gap worth naming is that the §4.2 invariant check
(`internal/sesame/validation.ts:93-101`) is still validated against that renamed
quantity, so it is enforcing the specification's arithmetic over a value that no
longer carries the specification's meaning.

### 5.3 Device limit

A hard cap of 5 devices per user (`internal/sesame/types.ts:45-50`, enforced at
`internal/sesame/manager.ts:285-290`). §6.5 recommends *a* limit without fixing
one; `libsignal` permits device IDs up to 127. This is a product decision, and a
source comment attributing it to the Signal Protocol is inaccurate.

### 5.4 Extensions: provisioning, transfer, device names

None of these exist in Sesame rev. 2, which says nothing about how devices come to
exist, are named, or migrate.

**QR device provisioning** (`device/provisioning.ts`). Ephemeral X25519 ECDH →
HKDF → AES-256-GCM, with a `signalprotocol://link-device` QR scheme, strict prefix
and key validation, a 5-minute TTL, and rollback on both server and local failure.
The construction is sound. The property worth naming: the provisioning key is not
bound to the primary device's long-term identity, so the channel is authenticated
only by out-of-band display of the QR code.

**Device transfer** (`device/transfer.ts`). Clones the identity private key and
live ratchet state to a new device. This is useful and it **violates the
invariant Sesame is built on** — one device record, one device, its own sessions.
After a transfer, two physical devices hold the same identity private key and the
same ratchet state for every peer. Peer messages decrypted by one desynchronize
the other, and duplicating ratchet state weakens the forward-secrecy guarantee
that compromise of one endpoint is bounded to that endpoint. Archived sessions are
deliberately dropped on restore, which also discards the convergence state §3.4
depends on.

**Encrypted device names** (`device/device-name-crypto.ts`). A three-field
protobuf with a synthetic IV derived by HMAC and AES-256-CTR — the standard SIV
pattern, correctly constructed. No specification counterpart.

**Identity-change gating.** Unseen identities are TOFU-pinned; a changed identity
sets `pendingVerification` and blocks sending until the application accepts the
rotation (`internal/sesame/manager.ts:561-566`, `:1682-1714`). Sesame rev. 2 has
no such concept. This is a genuine improvement.

**Not implemented:** proof of possession. Device registration does not require the
device to sign a server-issued nonce with the identity private key, so
registration places more trust in the relay than §6.3's discussion assumes. A
deployment that needs this must add it at the application layer.

---

## 6. Sealed sender

### 6.1 Version 2 is faithful

All four HKDF labels are byte-identical, the KEM construction and its
direction-swapped IKM orderings match, the authentication tag is the same 16-byte
raw HKDF output, AES-256-GCM-SIV is used with a zero nonce and no AAD as
`libsignal` does, and the multi-recipient binary format — version bytes
`0x22`/`0x23`, varint count, 17-byte ServiceIds, the packed device ID and 14-bit
registration ID, the `0x3FFF` mask — matches ([`sealed_sender.rs:1023-1153`][ss],
`:1306-1360`). Certificate validation order and semantics match as well, including
the non-short-circuiting trust-root loop that avoids revealing which root
validated.

### 6.2 Version 1 diverges in three places

**The 96-byte HKDF output is split in a different order.** `libsignal` derives
`(chain_key, cipher_key, mac_key)` ([`sealed_sender.rs:711-746`][ss]); the SDK
derives `(cipher, mac, chain)`
(`internal/protocol/sealed-sender/encryption.ts:164-166`). The construction is
self-consistent and secure — the keys are independent HKDF output either way — but
every v1 key sits in a different slot than `libsignal`'s. This is an
implementation divergence rather than a design decision, and the SDK's own pinned
specification document records the same order, so the two are at least consistent
with each other.

**Public keys in the v1 salt and in certificates omit the `0x05` type byte.**
`libsignal` uses the 33-byte serialized form; the SDK uses raw 32 bytes and
enforces that length
(`internal/protocol/sealed-sender/certificate.ts:306-309`). Notably the SDK's own
v2 path *does* apply the `0x05` prefix, so the two sealed-sender versions are
internally inconsistent about this.

**The inner envelope is a hand-rolled varint format**
(`internal/protocol/sealed-sender/encryption.ts:46-86`) rather than the
`UnidentifiedSenderMessage.Message` protobuf. It omits the message-type field that
`libsignal` uses to dispatch between prekey and regular messages
([`sealed_sender.rs:2055-2075`][ss]); the unseal path reconstructs the envelope
with a fixed type instead.

### 6.3 The delivery token is Signal's, not the SDK's

Despite the module name, `deriveAccessKey`
(`internal/protocol/sealed-sender/delivery-token.ts:52-91`) is `libsignal`'s
`ProfileKey::derive_access_key` — AES-256-GCM over 16 zero bytes with a zero
nonce, truncated to 16 bytes — and it reproduces `libsignal`'s published test
vectors exactly. It is a 16-byte value derived from the recipient's profile key
that proves to the relay that the sender knows that profile key, gating anonymous
delivery to contacts. It never enters the sealed-sender wire format; it is
presented out of band.

The SDK's own documentation previously described a different, 12-byte HKDF
construction that no code implements. That description is wrong and is corrected
in the PR accompanying this file.

Certificate signatures use Ed25519 rather than XEdDSA, per §1.2, so SDK
certificates cannot validate against a Signal trust root or vice versa. The
revocation list is empty where `libsignal` revokes one key ID, which is
appropriate for a different trust root but worth noting.

---

## 7. Sender keys and groups

### 7.1 Sender key message format

Protobuf field numbers and types match [`wire.proto`][wp] exactly, the
`[version byte] ‖ protobuf ‖ [64-byte signature]` framing with version `0x33`
matches, the `0x01`/`0x02` chain seeds and the `WhisperGroup` info string match,
AES-256-CBC with the derived IV matches, and the capacity constants match.

Three things do not:

**`distributionUuid` carries a UTF-8 string, not 16 UUID bytes.** The SDK writes
`groupId:userId:deviceId:timestamp`
(`internal/protocol/sender-keys/manager.ts:266`, `:493`); `libsignal` writes
exactly 16 raw bytes and rejects anything else on parse. Related: `chain_id` is
an FNV-1a hash of that string rather than a random 31-bit value.

**Signatures are Ed25519, not XEdDSA**, per §1.2 — and `libsignal` serializes the
signing key as 33 bytes where the SDK uses 32.

### 7.2 Message-key derivation omits HKDF-Extract

This one is worth stating precisely because the field numbers and labels above
make the format look compatible.

`libsignal` derives sender message keys with
`Hkdf::<Sha256>::new(None, &seed).expand(b"WhisperGroup", 48)`
([`sender_keys.rs:36-38`][sk]). `Hkdf::new` performs HKDF-**Extract** first:
`PRK = HMAC-SHA256(salt = zeros[32], seed)`. Only then does it expand.

The SDK calls `hkdfExpand(seed, info, 48)` directly
(`internal/protocol/sender-keys/manager.ts:1062-1066`), where `hkdfExpand`
(`internal/crypto/kdf/hkdf.ts:86-116`) is pure RFC 5869 Expand using the seed
itself as the PRK. The extract step is missing.

The derived IV and cipher key therefore differ from `libsignal`'s for the same
chain key. This was confirmed numerically, not merely by inspection: for a chain
key of 32 repeated `0x42` bytes, the SDK derives IV
`2a56b9eb80b3c1ffebd97221b2175960` where `libsignal` derives
`890d51ea73e564722351dc0d5a09142c`.

This appears unintentional. It is not a weakness — omitting Extract from a
uniformly random HMAC output is cryptographically fine — but the repository's own
sender-keys note claims equivalence with `libsignal` at this step, and that claim
is incorrect. Flagged for correction.

### 7.3 Groups v2 is an independent design

The zero-knowledge primitives underneath are real and faithful (§7.4). The group
system built on them is not Signal's.

What is faithful: role and access-control enum values match Signal's exactly,
group ID derivation from the master key is correct, the `__signal_group__v2__!`
identifier encoding is Signal's, authentication genuinely uses zkgroup
credentials, and member identifiers and profile keys are encrypted with real
`UidCiphertext` and `ProfileKeyCiphertext`.

What differs, and it is structural:

**The client is the state authority.** The SDK's client applies a change,
re-encrypts the entire group state, and uploads it
(`internal/groups-v2/manager.ts:1176-1193`). Signal's client submits only a set of
change actions, each carrying zero-knowledge presentations, and the **server**
validates every action and signs the result.

**Consequence, stated plainly: the relay cannot validate group changes.** It can
compare an expected version number and nothing else. It cannot verify that the
member making a change was permitted to make it, because the change actions carry
no zero-knowledge presentations for it to check. Any authenticated member can
rewrite roles, membership, and the ban list. Server signatures are returned but
never verified on receipt.

This is a materially weaker trust model than Signal's Private Group System, and
anyone deploying group messaging on this SDK needs to know it: group membership
and roles are enforced by cooperating clients, not by the server, and not
cryptographically against a malicious member. It is a reasonable position for an
SDK that ships without a validating server component, and it is not what a reader
of Signal's group documentation would assume.

**Serialization is JSON**, not protobuf, both for group state
(`internal/groups-v2/manager.ts:1229-1236`) and for the blob payloads inside the
AES-256-GCM-SIV envelope (`internal/groups-v2/encrypted-state.ts:70-81`). Every
encrypted group title and description is undecryptable by Signal even with the
correct master key.

**Invite links** use `https://join.open-e2ee.dev/#` with a 49-byte raw payload
(`internal/groups-v2/invite-link.ts:36`, `:78-85`), where Signal uses
`https://signal.group/#` with a protobuf. This is labelled accurately in source as
the package's own format.

### 7.4 The zero-knowledge layer is a faithful port

Stated directly, because "zk" in a codebase often means something weaker: this is
a genuine zero-knowledge credential system, not HMAC tokens, not signatures, not a
placeholder.

`internal/protocol/zk/` implements the Sigma protocol over Ristretto255 with
Fiat–Shamir, matching `poksho`'s protocol label
`POKSHO_Ristretto_SHOHMACSHA256` exactly, and the Chase–Perrin–Zaverucha algebraic
MAC credential system matching `zkcredential`'s five domain labels byte for byte.
The Lizard encoding, `UidStruct` derivation, `AuthCredentialWithPni` flow, and
redemption window all match `libsignal`. The strongest evidence is a test that
asserts the 416-byte serialized system parameters against a hex string taken from
`libsignal`'s own Rust test, and passes.

One deviation: server secret parameters are derived under four SDK-specific labels
rather than `libsignal`'s single seeded derivation
(`internal/protocol/zk/groups/server-params.ts:43-54`). The same randomness
therefore yields different server keys, and credentials are not interchangeable
with Signal's. That follows from the SDK being its own trust root.

Credential serialization is also ad hoc and carries no version byte, where
`libsignal` uses a leading version byte. That is a forward-compatibility gap
rather than a security one.

---

## Unverified and needs review

Listed rather than asserted, because these could not be confirmed in source
within this review.

- **Whether a sealed-sender-wrapped prekey message decrypts end to end.** The
  unseal path reconstructs the envelope with a fixed message type
  (`client/sealed-sender-ops.ts:263-265`), and an adjacent comment suggests the
  Sesame layer re-derives the initiation state from the ciphertext. That path was
  not traced and the integration tests were not executed. If Sesame does not
  self-detect, first-contact sealed messages would be affected.
- **Whether the session-identity-key check the sealed-sender note requires is
  enforced downstream.** The decrypt path compares the certificate's identity key
  against the decrypted static key but does not consult the session store. In
  `libsignal` the equivalent guarantee arrives later via the identity store.
- **Whether `@noble/post-quantum`'s ML-KEM-1024 is byte-identical to libcrux's.**
  The repository claims pinned known-answer-test coverage; those tests were not
  executed as part of this review.
- **Lizard encoding correctness against `libsignal`'s vectors.** The forward and
  inverse Elligator maps are hand-implemented in TypeScript. Structure and labels
  are correct and unit tests exist, but the outputs were not diffed against
  `libsignal`'s. A subtle error here would silently corrupt every `UidStruct`.
- **SPQR state-machine transition equivalence.** State names, message types, and
  chunk counts match Signal's; the eleven-state transition table was not diffed
  transition by transition.
- **Whether the SPQR decoder enforces a bound on stored points.** Signal caps
  stored points per polynomial; no equivalent bound was located in the SDK's
  decoder.
- **Whether SPQR state mutations are rolled back when message authentication
  fails.** `libsignal` commits the new state only after the MAC and decryption
  succeed; the SDK's receive path mutates state during decode, and the caller's
  rollback behaviour was not traced.
- **Whether an equivalent of `libsignal`'s `promote_matching_session` exists.**
  `libsignal` matches archived sessions on `(version, base key)`; the SDK's map is
  keyed on base key alone.

---

## Reporting an error in this document

If something here is wrong — a citation that does not say what it is claimed to
say, a deviation that has since been fixed, or a deviation that is missing —
email security@open-e2ee.dev or open an issue. A deviations document that has
drifted from the code is worse than none, because it invites exactly the
assumption it exists to prevent.

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
