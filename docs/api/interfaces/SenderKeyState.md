[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SenderKeyState

# Interface: SenderKeyState

## Properties

### chainId

> **chainId**: `number`

Chain identifier serialized as uint32 field 2.

Derived deterministically from senderKeyId via FNV-1a hash.
Included in protobuf-encoded messages for wire compatibility.

***

### chainIndex

> **chainIndex**: `number`

***

### chainKey

> **chainKey**: `string`

***

### createdAt

> **createdAt**: `number`

Creation timestamp (ms since epoch) for time-based rotation.

The manager checks only locally created encryption keys for expiry. Received
decryption keys remain usable for delayed messages.

***

### generation

> **generation**: `number`

***

### publicSignatureKey

> **publicSignatureKey**: `string`

***

### senderKeyId

> **senderKeyId**: `string`

Opaque random UUID identifying this sender key.

Written to the wire as the SenderKeyMessage `distribution_uuid`, which
sits in the *unencrypted* frame. A relay reads it off every group
message. It therefore carries no derivable content: no group, no sender,
no device, no timestamp. Matching the reference, which likewise uses a
random UUID distinct from the group identifier.

Randomness also makes rotation unambiguous. Receivers detect a rotation by
comparing this value against their stored state. An identifier built from a
millisecond clock would collide for two rotations inside the same
millisecond, and hide the second one.

***

### senderKeyVersion

> **senderKeyVersion**: `string`

Sender key wire format version for protocol evolution.

Format 'v1' (current): Ed25519 signatures, AES-256-CBC encryption
Future versions may support format changes or algorithm upgrades.

***

### signatureKey

> **signatureKey**: `string`
