[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayIdentityProgress

# Type Alias: HostedRelayIdentityProgress

> **HostedRelayIdentityProgress** = \{ `operation`: `"bootstrap"` \| `"recovery"`; `phase`: `"preparing-local-state"` \| `"requesting-assertion"` \| `"submitting"` \| `"complete"`; \} \| \{ `action`: [`HostedRelayIdentityMigrationAction`](HostedRelayIdentityMigrationAction.md); `operation`: `"migration"`; `phase`: `"requesting-assertion"` \| `"submitting"` \| `"complete"`; `providerRole?`: [`IdentityAssertionProviderRole`](IdentityAssertionProviderRole.md); `state?`: [`HostedRelayIdentityMigrationState`](HostedRelayIdentityMigrationState.md); \} \| \{ `deviceId?`: `number`; `operation`: `"device-link"`; `phase`: `"preparing-linked-device"` \| `"submitting"` \| `"complete"`; \}

Hosted identity operation progress suitable for application UI.
