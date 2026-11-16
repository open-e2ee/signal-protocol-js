[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / joinHostedSignalProtocolRelayAccount

# Function: joinHostedSignalProtocolRelayAccount()

> **joinHostedSignalProtocolRelayAccount**(`options`): `Promise`\<[`HostedSignalProtocolRelayJoinResult`](../interfaces/HostedSignalProtocolRelayJoinResult.md)\>

Join this device to the account of a primary device.

The call shows a link code through `hosted.onLinkCode`. The user approves
the code on the primary device with
`approveHostedSignalProtocolRelayDeviceLink`. The call then receives the
account identity and the groups through the provisioning channel, which
the Relay cannot read, and registers this device with its own device ID,
registration ID, prekeys, and device key.

The store keeps the state of the join. After a failure, call again with
the same store: a join that received its envelope continues with the same
link token and opens no new channel. A redeem that gets no answer, a 5xx
answer, or another retryable answer than 429 is sent again with the same
body, two times at most. Then the call throws and keeps the join state.
A refusal of the redeem that the same request gets again
(`ENVELOPE_INVALID` or `LINK_TOKEN_REJECTED`) removes the join state, so
the next call shows a new link code.

The Relay can make the device and then lose its answer. A later call that
repeats the redeem gets the same answer until the token cleanup, 24 hours
after the link token expires. When the device token of that answer has
expired, the call gets a new device token with the device proof. After the
cleanup, the call gives `LINK_TOKEN_REJECTED`, and the device that the
Relay made has no owner. The primary device lists it with
`listHostedSignalProtocolRelayDevices` and removes it with
`removeHostedSignalProtocolRelayDevice`.

## Parameters

### options

[`HostedSignalProtocolRelayJoinOptions`](../interfaces/HostedSignalProtocolRelayJoinOptions.md)

## Returns

`Promise`\<[`HostedSignalProtocolRelayJoinResult`](../interfaces/HostedSignalProtocolRelayJoinResult.md)\>

## Throws

HostedSignalProtocolRelayDeviceProvisioningError for a refusal of
the link (wire contract section 11.1).

## Throws

HostedSignalProtocolRelayHttpError for another Relay refusal. The
join state stays.
