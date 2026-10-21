[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolConfig

# Interface: SignalProtocolConfig

Public Signal Protocol configuration.

This keeps application code in product/security terms. Internal protocol
strategy details remain below the SignalProtocolClient seam.

## Properties

### braid?

> `optional` **braid?**: [`BraidPolicy`](../type-aliases/BraidPolicy.md)

ML-KEM Braid policy for the ongoing post-quantum ratchet.

- `required`: use the specification-defined ML-KEM Braid SPQR profile.
- `disabled`: explicitly use the direct ML-KEM SPQR mode instead.

Direct mode remains post-quantum, but it is a separate SDK SPQR mode.
Prefer `required` unless a product-reviewed constraint needs direct mode.

#### Default

```ts
'required'
```

***

### contentRecovery?

> `optional` **contentRecovery?**: [`ContentRecoveryPolicy`](ContentRecoveryPolicy.md)

Policy for the content that a sender keeps to answer a retry request.

A device that cannot decrypt a message asks the sender for it again. To
answer, the sender keeps the plaintext of each resendable message in its
local store until the recipient device confirms it or the retention
ends. This policy decides whether the local store may hold that
plaintext. The client reads it at creation and shows the decision in
`contentRecoveryStatus`.

#### Default

```ts
{ mode: 'require-protected' }
```

***

### postQuantum?

> `optional` **postQuantum?**: `"required"`

Post-quantum policy for session establishment.

`required` is the only value. Every new session uses PQXDH, and a peer
without ML-KEM prekeys fails closed with `PQXDH_REQUIRED`.

#### Default

```ts
'required'
```

***

### receiveQueue?

> `optional` **receiveQueue?**: [`ReceiveQueuePolicy`](ReceiveQueuePolicy.md)

Policy for received content that waits on this device.

The client stores decrypted content before it acknowledges the Relay
message, then processes it. Content waits when its group state is not
current, when its delivery receipt is due, or until the application
completes a helper receive. This policy bounds the queue. Content that
waits 30 days from its first durable admission on this device expires,
and the client runs `onReceiveExpired` and drops it. Content whose
delivery receipt is due completes with no receipt and no
`onReceiveExpired` report at that age, or 1 day after the receipt
became due if that is earlier. The age uses the wall clock: a forward
clock jump can expire content early. Retention cannot recover content
whose keys or sender content are gone. No setting changes this age.

#### Default

```ts
{ maxItems: 3000, maxBytes: 786432000, blockedGroupShare: 0.25 }
```
