[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayJoinResult

# Interface: HostedSignalProtocolRelayJoinResult

The result of a join.

## Properties

### applicationData?

> `readonly` `optional` **applicationData?**: `Uint8Array`\<`ArrayBufferLike`\>

The `applicationData` of the approval, when the primary device sent it.

***

### client

> `readonly` **client**: [`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)

The started client of the new device.

***

### deviceId

> `readonly` **deviceId**: `number`

The device ID of the new device.
