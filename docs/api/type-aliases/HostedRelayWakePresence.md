[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayWakePresence

# Type Alias: HostedRelayWakePresence

> **HostedRelayWakePresence** = `Omit`\<[`HostedRelayPresence`](../interfaces/HostedRelayPresence.md), `"watch"`\>

The presence of a wake client: a hosted client in a push handler, a
notification service extension, or a background task, which pulls its
mailbox without a subscription. Each request is one authenticated HTTP
request. A wake client has no `watch()`.
