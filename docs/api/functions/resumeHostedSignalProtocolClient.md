[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / resumeHostedSignalProtocolClient

# Function: resumeHostedSignalProtocolClient()

> **resumeHostedSignalProtocolClient**(`options`): `Promise`\<[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)\>

Require the existing permanent identities, device key and scoped hosted session.
Renews the token and starts the ordinary client, including prekey maintenance and
automatic subscription. Never requests assertions or registers a replacement.
The caller owns the already-open store and must not use it concurrently.
On an unresolved stop, the thrown HostedRelayResumeError owns retryCleanup().

## Parameters

### options

[`HostedSignalProtocolResumeOptions`](../type-aliases/HostedSignalProtocolResumeOptions.md)

## Returns

`Promise`\<[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)\>
