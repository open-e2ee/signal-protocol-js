[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SealedSenderConfig

# Interface: SealedSenderConfig

Sealed Sender configuration.

## See

https://signal.org/blog/sealed-sender/

## Properties

### accessMode?

> `optional` **accessMode?**: `SealedSenderAccessMode`

Who may send sealed sender messages to this user.

#### Default

```ts
'unrestricted'
```

***

### certificateProvider?

> `optional` **certificateProvider?**: () => `Promise`\<`string`\>

Provider function that returns a serialized SenderCertificate (base64).

The client calls this lazily when it sends a sealed sender message and the
cached certificate expired. The client caches the returned certificate for
its validity period (typically 24 hours).

#### Returns

`Promise`\<`string`\>

Base64-encoded serialized SenderCertificate

***

### contactStateStore?

> `optional` **contactStateStore?**: `ContactProfileStateStore`

Optional host-provided contact profile state store.

When present, the Signal Protocol client can use per-contact profile keys
and unidentified-access mode for direct-message sealed sender sends. It
does not import the host app's persistence layer.

***

### trustRoots

> **trustRoots**: `Uint8Array`\<`ArrayBufferLike`\>[]

Ed25519 trust root public keys for certificate validation.

Clients use these to validate the certificate chain:
trust_root signs ServerCertificate -> ServerCertificate signs SenderCertificate

Multiple roots work for key rotation scenarios.
