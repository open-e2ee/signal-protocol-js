[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SessionState

# Interface: SessionState

Signal Protocol session state (Full Double Ratchet)

Implements the complete Double Ratchet algorithm with:
- DH ratchet (periodic Diffie-Hellman key exchange)
- Symmetric ratchet (chain key updates)
- Out-of-order message handling
- Break-in recovery and future secrecy

State variable names follow Signal Protocol specification exactly:
- DHs, DHr: DH ratchet keys
- RK: Root Key
- CKs, CKr: Chain Keys (sending/receiving)
- Ns, Nr, PN: Message counters
- receiverChains: Skipped message keys (protobuf-compatible format)

Note: This uses Section 3 variant (plaintext headers + MAC) not Section 4
(header encryption). Header keys (HKs, HKr, NHKs, NHKr) are not used.

## Properties

### baseKey

> **baseKey**: [`Base64`](../type-aliases/Base64.md)

Session state identifier - initiator's ephemeral public key (EKA).

The initiator's ephemeral public key is the unique identifier for this
session state. It is named "baseKey" because:
- "ephemeral" describes the key's LIFECYCLE (temporary, single-use)
- "base" describes the key's ROLE (foundation for SK derivation in X3DH/PQXDH)

For initiator (Alice): Set to ephemeralKeyPair.publicKey from X3DH/PQXDH
For responder (Bob): Set to senderEphemeralKey from PreKeyMessage

CRITICAL: This is different from sessionId/ProtocolAddress lookup.
Sessions are LOOKED UP by ProtocolAddress (userId:deviceId), but
session STATES are IDENTIFIED by baseKey (ephemeral public key).

***

### CKr

> **CKr**: [`Base64`](../type-aliases/Base64.md) \| `undefined`

***

### CKs

> **CKs**: [`Base64`](../type-aliases/Base64.md) \| `undefined`

***

### createdAt

> **createdAt**: `number`

***

### DHr

> **DHr**: [`PublicKey`](../type-aliases/PublicKey.md) \| `undefined`

***

### DHs

> **DHs**: \{ `privateKey`: [`PrivateKey`](../type-aliases/PrivateKey.md); `publicKey`: [`PublicKey`](../type-aliases/PublicKey.md); \} \| `null`

***

### hasReceivedMessage?

> `optional` **hasReceivedMessage?**: `boolean`

Whether we've received at least one message in this session.

Unacknowledged PreKey sessions (where the initiator has not received a
reply) expire after 30 days (MAX_UNACKNOWLEDGED_SESSION_AGE).

#### Default

```ts
false for initiator sessions, true for responder sessions
```

***

### identityKeyPair

> **identityKeyPair**: [`IdentityKeyPair`](IdentityKeyPair.md)

***

### isInitiator?

> `optional` **isInitiator?**: `boolean`

***

### kemOneTimePreKeyCiphertext?

> `optional` **kemOneTimePreKeyCiphertext?**: [`Base64`](../type-aliases/Base64.md)

***

### kyberCiphertext?

> `optional` **kyberCiphertext?**: [`Base64`](../type-aliases/Base64.md)

***

### kyberKeys?

> `optional` **kyberKeys?**: \{ `lastRefreshNs`: `number`; `publicKey`: [`Base64`](../type-aliases/Base64.md); \} \| `null`

***

### kyberSecretKey?

> `optional` **kyberSecretKey?**: [`Base64`](../type-aliases/Base64.md)

***

### lastKyberUpdate?

> `optional` **lastKyberUpdate?**: `number` \| `null`

***

### lastUsedAt

> **lastUsedAt**: `number`

***

### localAddress

> **localAddress**: [`ProtocolAddress`](ProtocolAddress.md)

***

### localDeviceId

> **localDeviceId**: `number`

***

### localIdentity

> **localIdentity**: [`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

Canonical identities bound into transcript and message authentication.

***

### localIdentityType

> **localIdentityType**: [`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

Identity namespaces are part of the session trust binding.

***

### localRegistrationId

> **localRegistrationId**: `number`

Our registration ID (from our IdentityKeyPair).

Generated once per app install. Used to detect if we've reinstalled.

***

### Nr

> **Nr**: `number`

***

### Ns

> **Ns**: `number`

***

### pendingPreKeyDeletion?

> `optional` **pendingPreKeyDeletion?**: `object`

Prekey IDs pending deletion after first successful decryption.

One-time prekeys are deleted after decryption succeeds, not after session
establishment. This prevents
irrecoverable failure if the inner message is corrupted (the sender can
retry with the same prekey).

Set during performX3DHResponder() and cleared after the first successful
decrypt in SessionCipher.

#### identityType

> **identityType**: `"aci"` \| `"pni"`

Identity type the prekeys belong to (for correct scoped deletion)

#### kemOneTimePreKeyId?

> `optional` **kemOneTimePreKeyId?**: `number`

#### oneTimePreKeyId?

> `optional` **oneTimePreKeyId?**: `number`

***

### PN

> **PN**: `number`

***

### processedChains?

> `optional` **processedChains?**: `Record`\<`string`, \{ `lastNr`: `number`; `timestamp`: `number`; \}\>

Processed receiving chains for replay detection.

When a DH ratchet occurs, we store the old DHr and its final Nr value
to detect replay attacks. If a message arrives with an old DHr:
- If in receiverChains: decrypt (out-of-order message)
- If in processedChains but not receiverChains: replay attack (already processed)
- If not in either: new chain (perform DH ratchet)

Key: DHr (Base64 DH public key)
Value: { lastNr: number, timestamp: number }

***

### receiverChains

> **receiverChains**: [`ReceiverChain`](ReceiverChain.md)[]

Receiver chains with skipped message keys (v3 format).

This implements the spec's MKSKIPPED dictionary:
> "MKSKIPPED: Dictionary of skipped-over message keys, indexed by ratchet
> public key and message number. Raises an exception if too many elements
> are stored."

Signal Protocol Section 3.5: Store skipped message keys indexed by
(ratchetKey, counter) for out-of-order message decryption.

This nested structure provides bounded skipped-key storage:
- Up to MAX_RECEIVER_CHAINS (5) chains stored
- Each chain indexed by sender's ratchet public key
- Each chain contains up to MAX_MESSAGE_KEYS (2000 total) message keys

#### See

Signal Protocol Double Ratchet Section 3.1 (state.MKSKIPPED)

***

### recipientIdentityType?

> `optional` **recipientIdentityType?**: [`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

Explicit remote identity namespace included in authenticated PreKeyMessages.

***

### remoteAddress

> **remoteAddress**: [`ProtocolAddress`](ProtocolAddress.md)

***

### remoteDeviceId

> **remoteDeviceId**: `number`

***

### remoteIdentity

> **remoteIdentity**: [`CompositeIdentityV1`](../namespaces/keys/interfaces/CompositeIdentityV1.md)

***

### remoteIdentityType

> **remoteIdentityType**: [`IdentityType`](../namespaces/keys/type-aliases/IdentityType.md)

***

### remoteRegistrationId

> **remoteRegistrationId**: `number`

Remote party's registration ID (from their PreKeyBundle).

If this changes, they've reinstalled their app and we should
archive the old session and establish a new one.

***

### RK

> **RK**: [`Base64`](../type-aliases/Base64.md)

***

### tripleRatchet?

> `optional` **tripleRatchet?**: [`TripleRatchetState`](TripleRatchetState.md) \| `null`

***

### unacknowledgedPreKeyMessage?

> `optional` **unacknowledgedPreKeyMessage?**: `boolean`

Whether this session still needs to send PreKeyMessages.

Set to true when the session is created as initiator. Remains true until
the first message is received from the responder, which proves the
responder successfully processed the PreKeyMessage.

This ensures that if the first PreKeyMessage is lost, subsequent messages
are still sent as PreKeyMessages so the responder can establish the session.

#### Default

```ts
undefined (treated as false for responder sessions)
```

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
