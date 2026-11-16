[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayFirstSyncCallback

# Type Alias: HostedSignalProtocolRelayFirstSyncCallback

> **HostedSignalProtocolRelayFirstSyncCallback** = (`bundle`, `details`) => `void` \| `Promise`\<`void`\>

Called on a newly linked device with each new first-sync bundle from
device 1. The device writes the apply-once record of the bundle after the
callback resolves. When the callback throws or rejects, the device writes
no record, and the durable local receive queue gives the bundle again,
also after a restart. The Relay acknowledgment follows the local commit of
the message, before the callback, so the Relay does not deliver the bundle
again. A crash after the callback and before the record write also gives
one more call with the same bundle, so apply each part as a full replace.

## Parameters

### bundle

[`HostedSignalProtocolRelayFirstSyncBundle`](../interfaces/HostedSignalProtocolRelayFirstSyncBundle.md)

### details

#### bundleId

`string`

#### createdAt

`Date`

#### senderDeviceId

`number`

## Returns

`void` \| `Promise`\<`void`\>
