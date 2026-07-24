[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / IdentityKeyPair

# Interface: IdentityKeyPair

Identity key pair (long-lived, per-user)

The SDK's independent composite profile deliberately uses separate standard
keys for DH and signatures:
- dhKey: Used for X3DH key exchange (DH1 operation)
- signingKey: Used for signing prekeys
- registrationId: Random ID generated once per app install

## Properties

### dhKey

> **dhKey**: [`KeyPair`](KeyPair.md)

X25519 key pair for Diffie-Hellman

***

### registrationId

> **registrationId**: `number`

Registration ID - Random 16-bit integer generated once per app install.

Used to detect session resets when a device reinstalls the app.
Changes on reinstall to invalidate old sessions and prevent replay attacks.

From Signal Protocol:
"Registration IDs help detect stale sessions from previous installations"

#### See

https://signal.org/docs/specifications/x3dh/#registration-id

***

### signingKey

> **signingKey**: [`KeyPair`](KeyPair.md)

Ed25519 signing key pair for signatures
