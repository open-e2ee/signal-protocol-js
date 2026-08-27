[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayDeviceAuthentication

# Interface: HostedRelayDeviceAuthentication

A device proof signer whose private key never leaves the SDK-owned local store.

## Properties

### publicKey

> `readonly` **publicKey**: `Uint8Array`

## Methods

### signChallenge()

> **signChallenge**(`challenge`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Sign a Relay challenge with domain separation and publishable-key binding.
The adapter verifies `label || publishableKey || 0x00 || challenge`.

#### Parameters

##### challenge

`Uint8Array`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>
