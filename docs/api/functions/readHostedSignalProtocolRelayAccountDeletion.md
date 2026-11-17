[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / readHostedSignalProtocolRelayAccountDeletion

# Function: readHostedSignalProtocolRelayAccountDeletion()

> **readHostedSignalProtocolRelayAccountDeletion**(`options`): `Promise`\<[`HostedSignalProtocolRelayAccountDeletionReceipt`](../interfaces/HostedSignalProtocolRelayAccountDeletionReceipt.md)\>

Read deletion status with the retained secret capability, without a device token.
The store and `relayUrl` must match the deletion request.
This call reads status once. Failed and unknown reads preserve the intent.
Keep the store until the Relay confirms the required release and purge state.

## Parameters

### options

[`HostedSignalProtocolRelayAccountDeletionOptions`](../interfaces/HostedSignalProtocolRelayAccountDeletionOptions.md)

## Returns

`Promise`\<[`HostedSignalProtocolRelayAccountDeletionReceipt`](../interfaces/HostedSignalProtocolRelayAccountDeletionReceipt.md)\>

## Throws

HostedSignalProtocolRelayAccountDeletionError `DELETION_INTENT_UNAVAILABLE` when the
store has no deletion intent, `DELETION_UNSUPPORTED` when the Relay has no versioned deletion
receipt route, and `DELETION_STATE_INVALID` when the stored intent or a Relay receipt is invalid.

## Throws

HostedSignalProtocolRelayHttpError `404` with code `NOT_FOUND` when the Relay has no
status for the operation, for example before the deletion request reaches it.
Each other Relay refusal also keeps its own error.
