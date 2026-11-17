[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / deleteHostedSignalProtocolRelayAccount

# Function: deleteHostedSignalProtocolRelayAccount()

> **deleteHostedSignalProtocolRelayAccount**(`options`): `Promise`\<[`HostedSignalProtocolRelayAccountDeletionReceipt`](../interfaces/HostedSignalProtocolRelayAccountDeletionReceipt.md)\>

Request deletion with the retained device authority. This call never registers an account.
A store without the retained device authentication or session of the hosted account
gets a `HostedSignalProtocolRelayResumeError`, and the call writes nothing and sends nothing.
Otherwise the SDK saves one operation and a secret status capability before the first status request.
Each attempt reads versioned status before submission, including after a lost response or process restart.

The saved operation binds the store to the hosted account, also when the first attempt fails
before it submits the request. Before submission, `createHostedSignalProtocolClient` runs the
strict resume of `resumeHostedSignalProtocolClient` for that account, and it reports the
`bootstrap` progress of an ordinary resume. A recovery, a re-registration, and a custom
protocol manager refuse with `DELETION_PREFLIGHT_PENDING`. After submission,
`createHostedSignalProtocolClient` and `resumeHostedSignalProtocolClient` refuse with
`DELETION_ALREADY_REQUESTED`.
A later call continues the same operation. Only `storage.clearAllKeys()` discards the binding,
and then the SDK keeps no record of a deletion that the Relay may have received.

Acknowledgment and `capacityRelease: 'pending'` do not confirm a free slot.
Only `capacityRelease: 'released'` confirms release. No timer infers release.
The call preserves identities, protocol state, and failed deletion intents.

## Parameters

### options

[`HostedSignalProtocolRelayAccountDeletionOptions`](../interfaces/HostedSignalProtocolRelayAccountDeletionOptions.md)

## Returns

`Promise`\<[`HostedSignalProtocolRelayAccountDeletionReceipt`](../interfaces/HostedSignalProtocolRelayAccountDeletionReceipt.md)\>

## Throws

HostedSignalProtocolRelayResumeError `RETAINED_DEVICE_AUTHENTICATION_UNAVAILABLE` or
`RETAINED_SESSION_UNAVAILABLE` when the store does not retain the hosted account.

## Throws

HostedSignalProtocolRelayAccountDeletionError `DELETION_UNSUPPORTED` when the Relay
has no versioned deletion receipt route, and `DELETION_STATE_INVALID` when the stored intent
or a Relay receipt is invalid.

## Throws

HostedSignalProtocolRelayHttpError `404` with code `NOT_FOUND` when the Relay refuses
the deletion request, or has no status for a submitted operation. The intent stays, and a later
call reads its status again. Each other Relay refusal also keeps its own error.
