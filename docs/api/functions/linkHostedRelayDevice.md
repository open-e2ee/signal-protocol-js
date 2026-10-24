[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / linkHostedRelayDevice

# Function: linkHostedRelayDevice()

> **linkHostedRelayDevice**(`options`): `Promise`\<[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)\>

Bind a linked-device store to the Relay-authoritative account.

The linked store must already contain the account identity. The application
puts it there by device transfer or by a channel that the application owns.
Omit `hosted.adapter` to use the authenticated Signal Protocol Relay transport.
An explicit adapter retains application-owned transport composition.

The call reads both stores in the calling process. It signs the link
challenge with the device-authentication private key from
`activeDeviceStorage` and with the one from the linked store. Thus the
process that calls it must hold the active device's store. The adapter gets
the public identity, fresh linked-device prekey material, and two challenge
signers. It gets no private key.

The call copies the master key of each group that `activeGroupStore` lists
into the linked device's group store: `groups.store`, or the SDK group store
on the linked store. The copy runs in the calling process, so no master key
crosses the Relay. It runs with no `groups` option too, and a later client
with `groups` fetches each copied group. A group record that an earlier
release wrote, and that the active device has not read since, is not listed
and is not copied. Read each group once on the active device before the
link to copy it. A linked group store that lists a group that the link did
not write is refused with `HostedRelayDeviceLinkError` before any write.
The copied keys live in the linked device's group store. The SDK does not
move them again. A later move of that store is the application's store move.

The linked device gets its own registration ID. The call writes it into the
linked store's identity records before it registers, and a held PNI record
gets a separate one. A link that an earlier release began keeps its stored
registration ID. A linked store that holds a device-authentication key with
no registration of this link is refused with `HostedRelayDeviceLinkError`
before any write.

The linked store keeps the state of the link. Call again with the same
stores after any failure: the call sends the same registration, so the
Relay answers with the same device. The call stops the client and rejects
when the client's first sync fails, and the next call resumes the link.

When the Relay refuses the link with `KEY_PROOF_INVALID` or `CONFLICT`, and
the refusal is not retryable, no device holds the link. The call then
removes the link state and the copied groups, and rethrows. It keeps the
identity records and the registration, so the next call sends the same
registration ID. Every other error keeps the link state and the copied
groups. A completed link is never rolled back. A custom
adapter throws `HostedRelayHttpError` with the Relay's `code` and
`retryable` when the Relay refuses the link, so that the call can roll the
link back.

## Parameters

### options

[`HostedRelayManagedDeviceLinkOptions`](../interfaces/HostedRelayManagedDeviceLinkOptions.md)

## Returns

`Promise`\<[`DefaultSignalProtocolClient`](../classes/DefaultSignalProtocolClient.md)\>
