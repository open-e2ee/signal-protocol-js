[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayFirstSyncContact

# Interface: HostedSignalProtocolRelayFirstSyncContact

A contact of a first-sync bundle.

## Properties

### applicationData?

> `readonly` `optional` **applicationData?**: `Uint8Array`\<`ArrayBufferLike`\>

Opaque to the SDK.

***

### profileKey?

> `readonly` `optional` **profileKey?**: `Uint8Array`\<`ArrayBufferLike`\>

The profile key of the contact. 32 bytes.

***

### userId

> `readonly` **userId**: `string`

Not empty. Unique in one bundle.
