[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / pullHostedRelayAfterWake

# Function: pullHostedRelayAfterWake()

> **pullHostedRelayAfterWake**(`options`): `Promise`\<[`HostedRelayWakeResult`](../interfaces/HostedRelayWakeResult.md)\>

Authenticate, pull the durable mailbox, commit each envelope to the local
store, hand off each Relay receipt after the envelopes, acknowledge the
committed envelopes and the receipts, then process the stored receives
until `deadlineMs`. Register onMessageDecrypted to persist application
content before calling this function. Push is not required.

Group content that waits for its group state is committed and
acknowledged, and waits in the local store. Three kinds of envelope stay
unacknowledged: an envelope that the receive bounds refuse, a decrypt
failure that no retry request owns, and a retry request that waits for
the next group fetch. A full page of such envelopes does not stall the
pull: the next wake pulls the page after it with the Relay cursor. A
wake whose page past the cursor is empty clears the cursor, so the wake
after it pulls from the head and offers those envelopes again. A failed
wake also clears the cursor.

One call makes one pull. The result copies `retainedWork` from the Relay
page. When it is true, the caller runs the next pass.

## Parameters

### options

[`HostedRelayWakeOptions`](../interfaces/HostedRelayWakeOptions.md)

## Returns

`Promise`\<[`HostedRelayWakeResult`](../interfaces/HostedRelayWakeResult.md)\>
