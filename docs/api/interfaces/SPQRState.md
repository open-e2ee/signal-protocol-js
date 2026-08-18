[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SPQRState

# Interface: SPQRState

Sparse Post-Quantum Ratchet state (Section 5).

Signal Protocol Section 5:
"The sparse post-quantum ratchet provides ~90% post-quantum protection
by periodically refreshing Kyber keys (not every message)."

When combined with the EC Double Ratchet, this state supplies the profile's
post-quantum contribution to hybrid message-key derivation.

State Structure:
- Root Key (RK): Derives new KDF chain keys when epoch changes
- Epoch: Current epoch number (increments with DH ratchet)
- KDF Chains: Per-epoch chains for deriving message keys
- MKSKIPPED: Skipped message keys for out-of-order delivery
- Direction: Communication direction (A2B or B2A)
- SCKA State: ML-KEM Braid state for continuous key agreement

## Properties

### braidState?

> `optional` **braidState?**: [`MLKEMBraidAgentState`](MLKEMBraidAgentState.md)

ML-KEM Braid agent state.

Only present when mode is `braid`.

***

### direction

> **direction**: `"A2B"` \| `"B2A"`

Communication direction

***

### epoch

> **epoch**: `number`

Current epoch number (synchronized with DH ratchet)

***

### infoStrings?

> `optional` **infoStrings?**: [`ResolvedSPQRInfoStrings`](ResolvedSPQRInfoStrings.md)

Resolved HKDF info strings for SPQR key derivation.

***

### kdfChains

> **kdfChains**: `Record`\<`number`, \{ `receive`: [`KDFChain`](KDFChain.md); `send`: [`KDFChain`](KDFChain.md); \}\>

KDF chains per epoch.

Map structure: epoch -> { send: KDFChain, receive: KDFChain }

Each epoch has two chains:
- send: For encrypting outgoing messages
- receive: For decrypting incoming messages

Note: Using Record instead of Map for JSON serialization compatibility.
Convert to/from Map in memory for better performance if needed.

***

### limits?

> `optional` **limits?**: [`ResolvedSPQRLimits`](ResolvedSPQRLimits.md)

Resolved security limits for SPQR DoS and skipped-key handling.

***

### MKSKIPPED

> **MKSKIPPED**: `Record`\<`string`, \{ `key`: [`Base64`](../type-aliases/Base64.md); `timestamp`: `number`; \}\>

Skipped message keys for out-of-order delivery.

Map structure: epoch -> (index -> messageKey)

Signal Protocol Section 4.6:
"Messages may arrive out of order. Store skipped message keys
to decrypt them later."

Signal Protocol Section 8.4:
"A recommended policy is to delete message keys more than one week old"

Note: Using Record for JSON serialization. The map holds keys as strings
in format "epoch:index" -> { key: Base64, timestamp: number }

***

### mode

> **mode**: [`SCKAMode`](../type-aliases/SCKAMode.md)

SCKA mode used for this session.

- `'braid'` (default): specification-defined ML-KEM Braid profile
- `'direct'`: Explicit direct ML-KEM-768 encapsulation mode

Once set during session establishment, the mode stays fixed for the
lifetime of the session, which keeps the protocol consistent.

#### Default

```ts
'braid'
```

***

### needsSendRatchet?

> `optional` **needsSendRatchet?**: `boolean`

Flag: next spqrSend() should do full KEM ratchet.

Set to true by spqrRecv() after decapsulating kyber ciphertext,
and during bootstrap. Cleared by spqrSend() after performing the
encapsulation/keypair generation.

`send()` decides whether to run a KEM exchange from this state. Callers
do not trigger the exchange separately.

***

### pendingOutgoingChunks?

> `optional` **pendingOutgoingChunks?**: [`MLKEMBraidMessage`](MLKEMBraidMessage.md)[]

Pending outgoing Braid chunks.

Only present when mode is `braid` and the state machine holds queued chunks
for future message headers.

***

### RK

> **RK**: [`Base64`](../type-aliases/Base64.md)

Root Key for deriving new KDF chain keys

***

### sckaState

> **sckaState**: [`SCKAState`](SCKAState.md)

ML-KEM Braid state for continuous key agreement

***

### sendEpoch?

> `optional` **sendEpoch?**: `number`

Latest epoch used for sending.

Tracks send-epoch cleanup for SPQR forward secrecy while retaining receive
chains needed for in-flight messages.

***

### versionNegotiation?

> `optional` **versionNegotiation?**: [`VersionNegotiationState`](VersionNegotiationState.md)

Version negotiation state for this session.

Tracks the negotiation process with the peer to agree on a protocol version.
Once negotiation completes, the version stays locked for the session lifetime.

#### See

VersionNegotiationState
