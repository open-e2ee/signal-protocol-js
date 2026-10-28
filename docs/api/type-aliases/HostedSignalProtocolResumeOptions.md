[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolResumeOptions

# Type Alias: HostedSignalProtocolResumeOptions

> **HostedSignalProtocolResumeOptions** = `Omit`\<[`HostedSignalProtocolClientOptions`](../interfaces/HostedSignalProtocolClientOptions.md), `"adapters"` \| `"hosted"`\> & `object`

Existing hosted options without any registration/assertion authority.

## Type Declaration

### adapters

> `readonly` **adapters**: `Omit`\<[`HostedSignalProtocolClientOptions`](../interfaces/HostedSignalProtocolClientOptions.md)\[`"adapters"`\], `"protocolManager"`\> & `object`

#### Type Declaration

##### protocolManager?

> `readonly` `optional` **protocolManager?**: `never`

### hosted

> `readonly` **hosted**: `Omit`\<[`HostedSignalProtocolClientOptions`](../interfaces/HostedSignalProtocolClientOptions.md)\[`"hosted"`\], `"getIdentityAssertion"` \| `"assertionPurpose"` \| `"assurance"` \| `"onProgress"`\> & `object`

#### Type Declaration

##### assertionPurpose?

> `readonly` `optional` **assertionPurpose?**: `never`

##### assurance?

> `readonly` `optional` **assurance?**: `never`

##### getIdentityAssertion?

> `readonly` `optional` **getIdentityAssertion?**: `never`

##### onProgress?

> `readonly` `optional` **onProgress?**: [`HostedRelayResumeProgressCallback`](HostedRelayResumeProgressCallback.md)
