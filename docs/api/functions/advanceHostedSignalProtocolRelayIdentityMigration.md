[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / advanceHostedSignalProtocolRelayIdentityMigration

# Function: advanceHostedSignalProtocolRelayIdentityMigration()

> **advanceHostedSignalProtocolRelayIdentityMigration**(`options`): `Promise`\<[`HostedSignalProtocolRelayIdentityMigrationSnapshot`](../interfaces/HostedSignalProtocolRelayIdentityMigrationSnapshot.md)\>

Advance one hosted provider-migration transition without accepting an account ID.

The application supplies provider assertions through the same purpose-aware
callback used by hosted bootstrap. The transport owns device-token storage
and the HTTP representation.

## Parameters

### options

[`HostedSignalProtocolRelayIdentityMigrationOptions`](../interfaces/HostedSignalProtocolRelayIdentityMigrationOptions.md)

## Returns

`Promise`\<[`HostedSignalProtocolRelayIdentityMigrationSnapshot`](../interfaces/HostedSignalProtocolRelayIdentityMigrationSnapshot.md)\>
