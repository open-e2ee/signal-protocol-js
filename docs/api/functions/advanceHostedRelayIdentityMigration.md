[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / advanceHostedRelayIdentityMigration

# Function: advanceHostedRelayIdentityMigration()

> **advanceHostedRelayIdentityMigration**(`options`): `Promise`\<[`HostedRelayIdentityMigrationSnapshot`](../interfaces/HostedRelayIdentityMigrationSnapshot.md)\>

Advance one hosted provider-migration transition without accepting an account ID.

The application supplies provider assertions through the same purpose-aware
callback used by hosted bootstrap. The transport owns device-token storage
and the HTTP representation.

## Parameters

### options

[`HostedRelayIdentityMigrationOptions`](../interfaces/HostedRelayIdentityMigrationOptions.md)

## Returns

`Promise`\<[`HostedRelayIdentityMigrationSnapshot`](../interfaces/HostedRelayIdentityMigrationSnapshot.md)\>
