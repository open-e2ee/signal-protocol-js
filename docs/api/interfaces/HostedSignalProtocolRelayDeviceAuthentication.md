[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayDeviceAuthentication

# Interface: HostedSignalProtocolRelayDeviceAuthentication

A device proof signer whose private key never leaves the SDK-owned local store.

Each Relay protocol version signs its own label. A call without
`protocolVersion` signs the label of version 1, which the Relay verifies
on versions 1 and 2 and on a request without a version.

## Properties

### publicKey

> `readonly` **publicKey**: `Uint8Array`

## Methods

### signCertificateRequest()

> **signCertificateRequest**(`tokenId`, `nonce`, `protocolVersion?`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Sign the canonical certificate request with the SDK-owned device key.
`protocolVersion` selects the label, as for `signChallenge`.

#### Parameters

##### tokenId

`string`

##### nonce

`string`

##### protocolVersion?

`number`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

***

### signChallenge()

> **signChallenge**(`challenge`, `protocolVersion?`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Sign a Relay challenge with domain separation and publishable-key binding.
The adapter verifies `label || publishableKey || 0x00 || challenge`.
`protocolVersion` is the Relay protocol version of the request that
carries the proof, and it selects the label.

#### Parameters

##### challenge

`Uint8Array`

##### protocolVersion?

`number`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>
