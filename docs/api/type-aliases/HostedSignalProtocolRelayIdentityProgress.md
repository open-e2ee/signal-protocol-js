[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayIdentityProgress

# Type Alias: HostedSignalProtocolRelayIdentityProgress

> **HostedSignalProtocolRelayIdentityProgress** = \{ `operation`: `"bootstrap"` \| `"recovery"`; `phase`: `"preparing-local-state"` \| `"requesting-assertion"` \| `"submitting"` \| `"complete"`; \} \| \{ `action`: [`HostedSignalProtocolRelayIdentityMigrationAction`](HostedSignalProtocolRelayIdentityMigrationAction.md); `operation`: `"migration"`; `phase`: `"requesting-assertion"` \| `"submitting"` \| `"complete"`; `providerRole?`: [`IdentityAssertionProviderRole`](IdentityAssertionProviderRole.md); `state?`: [`HostedSignalProtocolRelayIdentityMigrationState`](HostedSignalProtocolRelayIdentityMigrationState.md); \} \| \{ `deviceId?`: `number`; `operation`: `"device-link"`; `phase`: `"preparing-linked-device"` \| `"copying"` \| `"submitting"` \| `"complete"`; \}

Hosted identity operation progress suitable for application UI.
