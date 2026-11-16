[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayFirstSyncBundle

# Interface: HostedSignalProtocolRelayFirstSyncBundle

The snapshot that device 1 gives a newly linked own device.

The bundle has at least one part. Each part is a full snapshot of its
kind: a part that is present replaces that kind on the new device, and an
empty array clears it. A part that is absent keeps that kind unchanged.
The SDK reads no part from its own stores.

## Extended by

- [`FirstSyncInput`](FirstSyncInput.md)

## Properties

### applicationData?

> `readonly` `optional` **applicationData?**: `Uint8Array`\<`ArrayBufferLike`\>

Opaque to the SDK.

***

### blocked?

> `readonly` `optional` **blocked?**: readonly `object`[]

***

### contacts?

> `readonly` `optional` **contacts?**: readonly [`HostedSignalProtocolRelayFirstSyncContact`](HostedSignalProtocolRelayFirstSyncContact.md)[]

***

### profileKey?

> `readonly` `optional` **profileKey?**: `Uint8Array`\<`ArrayBufferLike`\>

The own profile key. 32 bytes.

***

### settings?

> `readonly` `optional` **settings?**: `object`

#### readReceipts

> `readonly` **readReceipts**: `boolean`

#### typingIndicators

> `readonly` **typingIndicators**: `boolean`
