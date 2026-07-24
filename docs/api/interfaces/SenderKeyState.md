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

Only locally created encryption keys are checked for expiration. Received
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

***

### senderKeyVersion

> **senderKeyVersion**: `string`

Sender key wire format version for protocol evolution.

Format 'v1' (current): Ed25519 signatures, AES-256-CBC encryption
Future versions may support format changes or algorithm upgrades.

***

### signatureKey

> **signatureKey**: `string`
