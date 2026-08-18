# Keys module

The keys module defines the identity, prekey, and bundle types used by the SDK's
independently versioned, Signal Protocol-based profile. See
[`docs/SECURITY.md`](../docs/SECURITY.md) for the public compatibility boundary
and security assumptions.

## Why it exists

Identity trust, prekey authentication, and session establishment share exact
byte encodings and lifecycle rules. Keeping those contracts in one module
prevents storage and relay adapters from inventing incompatible key shapes.

## Usage

```ts
import {
  createCompositeIdentityV1,
  generateEcSignedPreKey,
  generateIdentityKeyPair,
  type CompositeIdentityV1,
} from "@open-e2ee/signal-protocol-sdk/keys";

const identity = await generateIdentityKeyPair();
const publicIdentity: CompositeIdentityV1 =
  createCompositeIdentityV1(identity);
const signedPreKey = await generateEcSignedPreKey(identity);
```

Ordinary application code usually lets `SignalProtocolClient` generate and
persist this material. Direct key APIs serve adapter, provisioning, and
advanced lifecycle integrations.

## Composite identity

`CompositeIdentityV1` is the canonical public trust object:

```ts
interface CompositeIdentityV1 {
  readonly version: 1;
  readonly x25519PublicKey: PublicKey;
  readonly ed25519PublicKey: PublicKey;
}
```

The SDK provisions one tuple per `(userId, identityType)` across linked devices.
ACI and PNI are independent identity types. Device registration IDs, prekeys,
and sessions remain device-specific.

The tuple encodes to exactly 67 bytes:

```text
0x01 || 0x01 || X25519 public key || 0x02 || Ed25519 public key
```

The SDK derives its SHA-256 commitment locally with the
`signal-protocol-js composite identity v1` domain. Stores persist the tuple and
trust metadata, not an authoritative supplied commitment.

The signing component uses ordinary RFC 8032 Ed25519. It is not XEdDSA and does
not make this profile interoperable with XEdDSA identity signatures.

## Prekeys

- `EcSignedPreKey` is an X25519 prekey authenticated by the composite identity's
  Ed25519 component.
- `EcOneTimePreKey` is an optional single-use X25519 contribution.
- `KyberPreKey` is the historical API name for the reusable standardized
  ML-KEM-1024 last-resort prekey.
- `KemOneTimePreKey` is a signed single-use ML-KEM-1024 prekey.

ML-KEM-1024 public keys use the mandatory `0x0A || raw` representation: one tag
byte plus 1,568 raw bytes. The corresponding serialized ciphertext has the same
1,569-byte size. A value with the deployed round-3 Kyber1024 `0x08` tag is a
different profile, and the SDK rejects it.

Prekey signatures cover a domain-separated context, not only the raw key:

```text
"signal-protocol-js prekey signature v1"
|| composite identity commitment
|| algorithm tag
|| uint32be(prekey id)
|| serialized public key
```

For ML-KEM-1024, `serialized public key` includes the `0x0A` tag.

## Prekey bundle

`PreKeyBundle` carries one composite identity and the device-specific material
needed for X3DH/PQXDH session establishment:

- registration ID and device ID.
- composite identity tuple.
- required signed EC prekey.
- optional EC one-time prekey.
- either a one-time or last-resort signed ML-KEM-1024 prekey when the session
  uses PQXDH.

Relay and storage adapters carry the same canonical tuple. Consumers must reject
an identity mismatch before consuming a one-time prekey or committing a session.

## Secret ownership

Private keys are Base64 strings in the current public types and therefore cannot
be reliably erased by the SDK. Generation and crypto functions overwrite their
temporary mutable byte arrays after use, where practical. JavaScript still does
not guarantee physical zeroization, freedom from copies, or hard constant-time
execution. The strongest platform-backed storage available to the application
should hold long-lived keys.

## Module boundaries

- `identity.ts`: tuple codec, commitment derivation, and trust transitions.
- `prekey-signature.ts`: domain-separated signature context.
- `generation.ts`: identity and prekey generation.
- `types.ts`: canonical public data contracts.

These boundaries keep encoding, trust transitions, signatures, and key
generation independently inspectable without exposing storage or relay
internals.
