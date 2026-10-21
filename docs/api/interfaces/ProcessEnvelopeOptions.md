[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ProcessEnvelopeOptions

# Interface: ProcessEnvelopeOptions

Options for processing incoming message envelopes.

Used when SignalProtocolClient does not have a relay (e.g., background tasks).
Provides callbacks for sending retry requests and marking messages delivered.

## Properties

### forcePreKeyRotation?

> `optional` **forcePreKeyRotation?**: () => `Promise`\<`void`\>

Force prekey rotation when the client detects a stale prekey.

Generate new keys, clear stale KEM prekeys, and upload fresh bundle.

Required for background processing where there is no relay.
Called before sending retry request when PREKEY_NOT_FOUND or MAC_FAILED
on PreKeyMessage indicates stale/corrupted keys.

#### Returns

`Promise`\<`void`\>

***

### markDelivered?

> `optional` **markDelivered?**: (`messageId`) => `Promise`\<`void`\>

Callback that acknowledges an envelope when no relay is available.

The client calls it after it sends a retry request for a failed
envelope, and after it discards an envelope that it does not process
again, so the envelope is not fetched again.

#### Parameters

##### messageId

`string`

#### Returns

`Promise`\<`void`\>

***

### onPersist?

> `optional` **onPersist?**: (`outcome`) => `Promise`\<`void`\>

Save content that `processIncomingEnvelope` gives. The client calls it
with the `processed` outcome before the method returns. When it
resolves, the client completes the receive record, so you do not call
`completeReceive`. When it rejects, the method still returns the
`processed` outcome, and the record waits for `completeReceive` or for
its expiry. A redelivery of the envelope calls it again.

#### Parameters

##### outcome

[`ProcessedReceive`](ProcessedReceive.md)

#### Returns

`Promise`\<`void`\>

***

### sendRetryRequest?

> `optional` **sendRetryRequest?**: (`envelope`) => `Promise`\<`void`\>

Callback to send retry requests when no relay is available.

Required for background processing where there is no WebSocket relay.
The callback receives a `retry_request` envelope for the device that sent
the failed message. Deliver it to that device as any other envelope.
The envelope is identified, and without a relay the client cannot seal
it. The client calls the callback only when the sealed sender delivery
mode permits identified delivery, so `'required'` never calls it.

#### Parameters

##### envelope

[`Envelope`](Envelope.md)

#### Returns

`Promise`\<`void`\>
