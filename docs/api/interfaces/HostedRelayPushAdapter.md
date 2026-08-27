[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayPushAdapter

# Interface: HostedRelayPushAdapter

Authenticated hosted transport for wake registration and durable mailbox pull.

The adapter owns the device credential. These request shapes do not accept an
account, device, scope, or generation because the Relay derives those fields
from that credential.

## Methods

### acknowledgeMailbox()

> **acknowledgeMailbox**(`request`): `Promise`\<`void`\>

#### Parameters

##### request

[`HostedRelayMailboxAcknowledgmentRequest`](HostedRelayMailboxAcknowledgmentRequest.md)

#### Returns

`Promise`\<`void`\>

***

### pullMailbox()

> **pullMailbox**(`request`): `Promise`\<readonly [`IncomingEnvelope`](IncomingEnvelope.md)[]\>

#### Parameters

##### request

[`HostedRelayMailboxPullRequest`](HostedRelayMailboxPullRequest.md)

#### Returns

`Promise`\<readonly [`IncomingEnvelope`](IncomingEnvelope.md)[]\>

***

### registerPush()

> **registerPush**(`request`): `Promise`\<`void`\>

#### Parameters

##### request

[`HostedRelayPushRegistrationRequest`](HostedRelayPushRegistrationRequest.md)

#### Returns

`Promise`\<`void`\>

***

### removePush()

> **removePush**(`request`): `Promise`\<`void`\>

#### Parameters

##### request

[`HostedRelayPushRemovalRequest`](HostedRelayPushRemovalRequest.md)

#### Returns

`Promise`\<`void`\>
