[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSealedSenderConfig

# Interface: HostedSealedSenderConfig

Signal Protocol Relay sealed-sender trust is bound to one project environment.

## Extends

- `SealedSenderConfigBase`

## Properties

### accessMode?

> `optional` **accessMode?**: `SealedSenderAccessMode`

Who may send sealed sender messages to this user.

#### Default

```ts
'unrestricted'
```

#### Inherited from

`SealedSenderConfigBase.accessMode`

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

#### Inherited from

`SealedSenderConfigBase.certificateProvider`

***

### contactStateStore?

> `optional` **contactStateStore?**: `ContactProfileStateStore`

Optional host-provided contact profile state store.

When present, the Signal Protocol client can use per-contact profile keys
and unidentified-access mode for direct-message sealed sender sends. It
does not import the host app's persistence layer.

#### Inherited from

`SealedSenderConfigBase.contactStateStore`

***

### deliveryMode?

> `optional` **deliveryMode?**: `SealedSenderDeliveryMode`

Outbound delivery policy. It covers each message and resend, each
delivery receipt, and each retry request that this client sends to a
device of another account. A message can use a group send endorsement or
the access key of the recipient. A delivery receipt and a retry request
use only the access key. A typing indicator, and a sync message to
another device of the local account, always go identified.

- `preferred`: seal each covered envelope. Use identified delivery only
  when anonymous capability or the credential of the recipient is absent
  before send, or the relay rejects anonymous authorization.
- `required`: never send a covered envelope identified. A send that
  cannot be sealed, or whose anonymous authorization the relay rejects,
  fails closed. A retry request that fails this way stays pending, and
  the scheduler posts it again until its deadline.
- `disabled`: always use identified delivery and do not fetch a certificate.

#### Default

```ts
'preferred'
```

#### Inherited from

`SealedSenderConfigBase.deliveryMode`

***

### onIdentifiedFallback?

> `optional` **onIdentifiedFallback?**: (`event`) => `void` \| `Promise`\<`void`\>

Reports a message or a resend that `preferred` sends identified after
the relay rejects its anonymous authorization. A delivery receipt and a retry
request that fall back the same way are not reported.

#### Parameters

##### event

`SealedSenderIdentifiedFallbackEvent`

#### Returns

`void` \| `Promise`\<`void`\>

#### Inherited from

`SealedSenderConfigBase.onIdentifiedFallback`

***

### relayScopeId

> **relayScopeId**: `Uint8Array`

Opaque 16-byte Relay project-environment scope pinned by the application.

#### Inherited from

`SealedSenderConfigBase.relayScopeId`

***

### revokedIssuerKeyIds

> **revokedIssuerKeyIds**: readonly `number`[]

Issuer key IDs revoked by this deployment's operator.

#### Inherited from

`SealedSenderConfigBase.revokedIssuerKeyIds`

***

### trustModel

> **trustModel**: `"hosted"`

Selects the OpenE2EE hosted trust system.

***

### trustRoots

> **trustRoots**: `Uint8Array`\<`ArrayBufferLike`\>[]

Ed25519 trust root public keys for certificate validation.

Clients use these to validate the certificate chain:
trust_root signs ServerCertificate -> ServerCertificate signs SenderCertificate

Multiple roots work for key rotation scenarios.

#### Inherited from

`SealedSenderConfigBase.trustRoots`
