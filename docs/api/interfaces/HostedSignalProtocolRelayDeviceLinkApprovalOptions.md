[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayDeviceLinkApprovalOptions

# Interface: HostedSignalProtocolRelayDeviceLinkApprovalOptions

## Properties

### applicationData?

> `readonly` `optional` **applicationData?**: `Uint8Array`\<`ArrayBufferLike`\>

Application bytes for the new device, 16,384 bytes or less. The join
returns them in `applicationData`.

***

### ~~deviceName?~~

> `readonly` `optional` **deviceName?**: `string`

#### Deprecated

This option does nothing. The new device names itself with
`hosted.deviceName` of `joinHostedSignalProtocolRelayAccount`. A later
major version removes this option.

***

### signal?

> `readonly` `optional` **signal?**: `AbortSignal`

Stops the approval with `CANCELLED`.
