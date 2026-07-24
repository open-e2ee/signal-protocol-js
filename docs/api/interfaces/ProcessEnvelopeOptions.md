[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / ProcessEnvelopeOptions

# Interface: ProcessEnvelopeOptions

Options for processing incoming message envelopes.

Used when SignalProtocolClient doesn't have a relay (e.g., background tasks).
Provides callbacks for sending retry requests and marking messages delivered.

## Properties

### forcePreKeyRotation?

> `optional` **forcePreKeyRotation?**: () => `Promise`\<`void`\>

Force prekey rotation when stale prekey is detected.

Generate new keys, clear stale KEM prekeys, and upload fresh bundle.

Required for background processing where there's no relay.
Called before sending retry request when PREKEY_NOT_FOUND or MAC_FAILED
on PreKeyMessage indicates stale/corrupted keys.

#### Returns

`Promise`\<`void`\>

***

### markDelivered?

> `optional` **markDelivered?**: (`messageId`) => `Promise`\<`void`\>

Callback to mark message as delivered when no relay is available.

Called after retry request is sent to prevent the failed message
from being re-fetched indefinitely.

#### Parameters

##### messageId

`string`

#### Returns

`Promise`\<`void`\>

***

### sendRetryRequest?

> `optional` **sendRetryRequest?**: (`request`) => `Promise`\<`void`\>

Callback to send retry requests when no relay is available.

Required for background processing where there's no WebSocket relay.
The callback receives a fully-formed RetryRequest created by SesameManager.

#### Parameters

##### request

[`RetryRequest`](RetryRequest.md)

#### Returns

`Promise`\<`void`\>
