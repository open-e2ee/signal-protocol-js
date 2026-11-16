[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / FirstSyncInput

# Interface: FirstSyncInput

The first-sync bundle with the fields that the SDK adds: the version, the
bundle ID, and the creation time on device 1.

## Extends

- [`HostedSignalProtocolRelayFirstSyncBundle`](HostedSignalProtocolRelayFirstSyncBundle.md)

## Properties

### applicationData?

> `readonly` `optional` **applicationData?**: `Uint8Array`\<`ArrayBufferLike`\>

Opaque to the SDK.

#### Inherited from

[`HostedSignalProtocolRelayFirstSyncBundle`](HostedSignalProtocolRelayFirstSyncBundle.md).[`applicationData`](HostedSignalProtocolRelayFirstSyncBundle.md#applicationdata)

***

### blocked?

> `readonly` `optional` **blocked?**: readonly `object`[]

#### Inherited from

[`HostedSignalProtocolRelayFirstSyncBundle`](HostedSignalProtocolRelayFirstSyncBundle.md).[`blocked`](HostedSignalProtocolRelayFirstSyncBundle.md#blocked)

***

### bundleId

> `readonly` **bundleId**: `string`

16 random bytes, as base64url with no padding: 22 characters.

***

### contacts?

> `readonly` `optional` **contacts?**: readonly [`HostedSignalProtocolRelayFirstSyncContact`](HostedSignalProtocolRelayFirstSyncContact.md)[]

#### Inherited from

[`HostedSignalProtocolRelayFirstSyncBundle`](HostedSignalProtocolRelayFirstSyncBundle.md).[`contacts`](HostedSignalProtocolRelayFirstSyncBundle.md#contacts)

***

### createdAt

> `readonly` **createdAt**: `number`

Milliseconds since the Unix epoch, by the clock of device 1.

***

### profileKey?

> `readonly` `optional` **profileKey?**: `Uint8Array`\<`ArrayBufferLike`\>

The own profile key. 32 bytes.

#### Inherited from

[`HostedSignalProtocolRelayFirstSyncBundle`](HostedSignalProtocolRelayFirstSyncBundle.md).[`profileKey`](HostedSignalProtocolRelayFirstSyncBundle.md#profilekey)

***

### settings?

> `readonly` `optional` **settings?**: `object`

#### readReceipts

> `readonly` **readReceipts**: `boolean`

#### typingIndicators

> `readonly` **typingIndicators**: `boolean`

#### Inherited from

[`HostedSignalProtocolRelayFirstSyncBundle`](HostedSignalProtocolRelayFirstSyncBundle.md).[`settings`](HostedSignalProtocolRelayFirstSyncBundle.md#settings)

***

### version

> `readonly` **version**: `1`
