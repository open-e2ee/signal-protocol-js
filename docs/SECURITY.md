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

- Required post-quantum session establishment is the default.
- PQXDH uses standardized FIPS 203 ML-KEM-1024 behavior.
- Public keys and ciphertexts require exactly `0x0A || raw ML-KEM-1024 bytes`.
  Untagged values, the deployed Kyber1024 `0x08` tag, unknown tags, and wrong
  lengths fail before secret derivation or state commit.
- Prekey signatures cover a domain-separated context. That context contains the
  locally derived composite identity commitment, algorithm tag, key ID, and
  complete tagged public key.
- `protocol.postQuantum: 'compatible'` is an explicit opt-in. It permits a
  classical session only when a peer advertises no PQ material. Malformed or
  failed PQ processing does not trigger fallback.

The `0x0A` encoding is distinct from Signal Messenger deployments that use
round-3 Kyber1024 tagged `0x08`.

### SPQR and ML-KEM Braid

- PQXDH sessions keep SPQR mandatory.
- The default SCKA mode is the specification-defined ML-KEM Braid profile
  using ML-KEM-768 and bounded Reed-Solomon decoding.
- HEK follows the ML-KEM Braid specification:
  `SHA3-256(ek_seed || ek_vector)`.
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

Local adapters own identity keys, contact trust metadata, prekeys, session
records, retry records, and group state. The package requires:

- atomic composite-identity writes and explicit rotation acceptance.
- current session-record format version 4.
- that an adapter reject stale-format writes before it replaces current state.
- that an adapter remove or reject stale persisted session records on read.
- no authoritative cached identity commitment.
- authenticated encryption for adapters that persist encrypted records.

Adapter encryption does not compensate for:

- XSS, malicious dependencies, or compromised application code.
- a stolen unlocked device.
- an attacker who also holds the adapter encryption key.

Browser IndexedDB and caller-provided React Native storage inherit their host
application's security boundary.

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
