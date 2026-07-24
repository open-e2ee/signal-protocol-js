[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / PreKeyMessage

# Interface: PreKeyMessage

PreKey message for initial session establishment.

The first message from Alice to Bob contains additional information needed
for Bob to establish his session as the responder. This follows the
Signal Protocol specification for asynchronous messaging.

Per X3DH spec: "Alice sends Bob an initial message containing:
- Alice's identity key IKA
- Alice's ephemeral key EKA
- Ciphertext encrypted with shared secret SK"

This allows Bob to:
1. Extract Alice's keys from the message
2. Perform X3DH as responder using Alice's ephemeral key
3. Derive the same shared secret SK
4. Decrypt the message and establish his session

## Properties

### ciphertext

> **ciphertext**: [`Base64`](../type-aliases/Base64.md)

AES-CBC encrypted message body

***

### counter

> **counter**: `number`

Message counter in current sending chain (proto: counter, field 2)

***

### kemOneTimePreKeyCiphertext?

> `optional` **kemOneTimePreKeyCiphertext?**: [`Base64`](../type-aliases/Base64.md)

***

### kyberCiphertext?

> `optional` **kyberCiphertext?**: [`Base64`](../type-aliases/Base64.md)

***

### mac

> **mac**: [`Base64`](../type-aliases/Base64.md)

HMAC-SHA256 truncated to 8 bytes (identity-bound: includes sender/receiver identity keys)

***

### messageVersion

> **messageVersion**: `string`

Wire format version for protocol evolution.

Format 'v1' (current): JSON serialization, plaintext headers + identity-bound MAC

Allows backward/forward compatibility - recipients can gracefully handle
different versions or reject unsupported versions during decryption.

***

### previousCounter

> **previousCounter**: `number`

Number of messages in previous sending chain (proto: previous_counter, field 3)

***

### ratchetKey

> **ratchetKey**: [`PublicKey`](../type-aliases/PublicKey.md)

Sender's current ratchet public key (proto: ratchet_key, field 1)

***

### recipientIdentityType

> **recipientIdentityType**: [`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

Explicit recipient account identity namespace, authenticated by the inner message MAC.

***

### senderDeviceId

> **senderDeviceId**: `number`

***

### senderEphemeralKey

> **senderEphemeralKey**: [`PublicKey`](../type-aliases/PublicKey.md)

***

### senderId

> **senderId**: `string`

***

### senderIdentity

> **senderIdentity**: [`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

***

### senderRegistrationId

> **senderRegistrationId**: `number`

***

### type

> **type**: [`PREKEY`](../enumerations/MessageType.md#prekey)

Message type discriminator - enables exhaustive type checking

***

### usedKemOneTimePreKeyId?

> `optional` **usedKemOneTimePreKeyId?**: `number`

***

### usedKyberPreKeyId?

> `optional` **usedKyberPreKeyId?**: `number`

***

### usedOneTimePreKeyId?

> `optional` **usedOneTimePreKeyId?**: `number`

***

### usedSignedPreKeyId?

> `optional` **usedSignedPreKeyId?**: `number`
