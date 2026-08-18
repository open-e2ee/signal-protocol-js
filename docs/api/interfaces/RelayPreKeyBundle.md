[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RelayPreKeyBundle

# Interface: RelayPreKeyBundle

PreKey Bundle - Public keys for establishing an encrypted session

Contains all public information needed for X3DH/PQXDH key exchange.
Fetched from the server when initiating a session with a new device.

## Key Exchange Flow (PQXDH)

Alice fetches Bob's PreKeyBundle and computes:
```
DH1 = DH(Alice_IK, Bob_SPK)      // Identity to Signed PreKey
DH2 = DH(Alice_EK, Bob_IK)       // Ephemeral to Identity
DH3 = DH(Alice_EK, Bob_SPK)      // Ephemeral to Signed PreKey
DH4 = DH(Alice_EK, Bob_OPK)      // Ephemeral to One-Time PreKey (if available)
KEM = Encaps(Bob_MLKEM1024_PK)   // Standardized ML-KEM-1024

SK = KDF(DH1 || DH2 || DH3 || DH4 || KEM_SS)
```

## Bundle Contents

| Field              | Type        | Purpose                              | Lifetime       |
|--------------------|-------------|--------------------------------------|----------------|
| registrationId     | number      | Detect app reinstalls                | Per install    |
| deviceId           | number      | Identify device (1=primary, 2-5)     | Per device     |
| identity           | CompositeV1 | Per-user DH + signing trust object   | Permanent      |
| ecSignedPreKey     | X25519+sig  | Medium-term DH key (SPK)             | Rotates weekly |
| ecOneTimePreKey    | X25519      | Single-use forward secrecy (OPK)     | Consumed once  |
| kemLastResortPreKey| ML-KEM-1024 | Post-quantum protection (PQSPK)      | Rotates weekly |

## Security Properties

These inputs support the profile's conditional hybrid-security and
one-time-prekey properties. See `docs/SECURITY.md` for their assumptions and
limits. This data shape alone is not a security proof.

## See

 - https://signal.org/docs/specifications/pqxdh/
 - https://signal.org/docs/specifications/x3dh/

## Properties

### deviceId

> **deviceId**: `number`

Device ID within this user's device set.

- Primary device: 1
- Linked devices: 2-5 (max 5 devices per user)

Used for multi-device fanout. The client encrypts messages separately
for each of the recipient's devices.

***

### ecOneTimePreKey?

> `optional` **ecOneTimePreKey?**: \{ `keyId`: `number`; `publicKey`: [`PublicKey`](../type-aliases/PublicKey.md); \} \| `null`

EC One-Time PreKey (X25519, optional).

Single-use key consumed atomically on fetch. Provides additional
forward secrecy - if compromised, only affects one session.

May be null/undefined if the server exhausted the prekey pool.
Session establishment still works without it (degraded to 3-DH).

#### Union Members

##### Type Literal

\{ `keyId`: `number`; `publicKey`: [`PublicKey`](../type-aliases/PublicKey.md); \}

##### keyId

> **keyId**: `number`

Key ID for tracking which key the session consumed

##### publicKey

> **publicKey**: [`PublicKey`](../type-aliases/PublicKey.md)

X25519 public key (32 bytes, base64)

***

`null`

***

### ecSignedPreKey

> **ecSignedPreKey**: `object`

EC Signed PreKey (X25519 + Ed25519 signature).

Medium-term key that rotates weekly. Signed by identitySigningKey
to prove authenticity. Used for DH1 and DH3 in X3DH.

The signature covers the composite identity commitment, algorithm tag, key
ID, and public key in the profile's domain-separated context.

#### keyId

> **keyId**: `number`

Key ID for tracking which key the session used

#### publicKey

> **publicKey**: [`PublicKey`](../type-aliases/PublicKey.md)

X25519 public key (32 bytes, base64)

#### signature

> **signature**: [`Signature`](../type-aliases/Signature.md)

Ed25519 signature over publicKey bytes (64 bytes, base64)

***

### identity

> **identity**: [`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

Versioned per-user identity trust object. ACI and PNI are independent.
Linked devices expose the same tuple. Registration IDs and prekeys remain
device-specific. Consumers derive commitments locally.

***

### kemLastResortPreKey?

> `optional` **kemLastResortPreKey?**: \{ `keyId`: `number`; `publicKey`: [`PublicKey`](../type-aliases/PublicKey.md); `signature`: [`Signature`](../type-aliases/Signature.md); \} \| `null`

Last-resort KEM PreKey for PQXDH (ML-KEM-1024 + Ed25519 signature, optional).

Post-quantum key encapsulation mechanism. Provides protection against
"harvest now, decrypt later" attacks from quantum computers.

Reusable KEM prekey used when the server exhausted the one-time KEM pool.
Server and relay adapters must not place one-time KEM material in this field.
Use `kemOneTimePreKey` for consumed one-time KEM material.

- Public key: 1569 bytes (`0x0A` plus 1568 raw bytes, base64 encoded)
- Ciphertext: 1569 bytes (`0x0A` plus 1568 raw bytes)
- Shared secret: 32 bytes

The signature covers the complete tagged public key plus identity
commitment, algorithm tag, and key ID in a domain-separated context.

#### Union Members

##### Type Literal

\{ `keyId`: `number`; `publicKey`: [`PublicKey`](../type-aliases/PublicKey.md); `signature`: [`Signature`](../type-aliases/Signature.md); \}

##### keyId

> **keyId**: `number`

Key ID

##### publicKey

> **publicKey**: [`PublicKey`](../type-aliases/PublicKey.md)

Tagged ML-KEM-1024 public key (1569 bytes, base64)

##### signature

> **signature**: [`Signature`](../type-aliases/Signature.md)

Ed25519 signature over the profile's complete prekey context

***

`null`

#### See

https://signal.org/docs/specifications/pqxdh/

***

### kemOneTimePreKey?

> `optional` **kemOneTimePreKey?**: \{ `keyId`: `number`; `publicKey`: [`PublicKey`](../type-aliases/PublicKey.md); `signature`: [`Signature`](../type-aliases/Signature.md); \} \| `null`

KEM One-Time PreKey (ML-KEM-1024 + Ed25519 signature, optional).

Per PQXDH spec Section 3.2, the identity key signs these one-time pqkem prekeys
that provide per-session post-quantum forward secrecy.

Server prefers these over the last-resort KEM prekey. Consumed atomically on
fetch (like EC one-time prekeys). A bundle should contain either this field
or `kemLastResortPreKey` as the selected KEM material for PQXDH.

May be null/undefined if the server exhausted the prekey pool.
Session establishment still works without it (falls back to last-resort).

#### Union Members

##### Type Literal

\{ `keyId`: `number`; `publicKey`: [`PublicKey`](../type-aliases/PublicKey.md); `signature`: [`Signature`](../type-aliases/Signature.md); \}

##### keyId

> **keyId**: `number`

Key ID for tracking which key the session consumed

##### publicKey

> **publicKey**: [`PublicKey`](../type-aliases/PublicKey.md)

Tagged ML-KEM-1024 public key (1569 bytes, base64)

##### signature

> **signature**: [`Signature`](../type-aliases/Signature.md)

Ed25519 signature over the profile's complete prekey context

***

`null`

#### See

https://signal.org/docs/specifications/pqxdh/#sending-the-initial-message

***

### registrationId

> **registrationId**: `number`

Registration ID - Random 16-bit integer generated on app install.

Changes when user reinstalls app, allowing peers to detect stale sessions
and re-establish encryption. Prevents replay of messages from old installs.
