[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / pullHostedRelayAfterWake

# Function: pullHostedRelayAfterWake()

> **pullHostedRelayAfterWake**(`options`): `Promise`\<[`HostedRelayWakeResult`](../interfaces/HostedRelayWakeResult.md)\>

Authenticate, pull the durable mailbox, process each envelope, and acknowledge
only successful decryptions. This operation is safe to call after repeated
wake hints and can also be called when push is unavailable.

## Parameters

### options

[`HostedRelayWakeOptions`](../interfaces/HostedRelayWakeOptions.md)

## Returns

`Promise`\<[`HostedRelayWakeResult`](../interfaces/HostedRelayWakeResult.md)\>
