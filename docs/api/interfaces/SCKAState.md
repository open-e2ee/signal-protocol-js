[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SCKAState

# Interface: SCKAState

ML-KEM Braid state for continuous key agreement.

Signal Protocol Section 5 (ML-KEM Braid):
The ML-KEM Braid provides continuous post-quantum key agreement by
maintaining alternating send/receive Kyber key pairs across epochs.

Intended properties are conditional on authenticated establishment, correct
state handling, uncompromised refresh entropy, and the underlying primitive
assumptions. See docs/SECURITY.md.

## Properties

### direction

> **direction**: `"A2B"` \| `"B2A"`

Which way messages flow ('A2B' = Alice to Bob, 'B2A' = Bob to Alice)

***

### epoch

> **epoch**: `number`

Current epoch number (increments with each DH ratchet)

***

### lastRefreshMessageCount

> **lastRefreshMessageCount**: `number`

Message counter at last Kyber refresh (for message-count-based rotation)

***

### lastRefreshTimestamp

> **lastRefreshTimestamp**: `number`

Timestamp of last Kyber key refresh (for time-based rotation)

***

### ourKyberPrivateKey

> **ourKyberPrivateKey**: [`Base64`](../type-aliases/Base64.md) \| `null`

Our current Kyber private key (for receiving)

***

### theirKyberPublicKey

> **theirKyberPublicKey**: [`Base64`](../type-aliases/Base64.md) \| `null`

Remote party's current Kyber public key (for sending)
