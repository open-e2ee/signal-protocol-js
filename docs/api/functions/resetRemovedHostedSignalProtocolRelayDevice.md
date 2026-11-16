[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / resetRemovedHostedSignalProtocolRelayDevice

# Function: resetRemovedHostedSignalProtocolRelayDevice()

> **resetRemovedHostedSignalProtocolRelayDevice**(`options`): `Promise`\<`void`\>

Deletes the local account state of a removed device, so that the same
store can join the account again with `joinHostedSignalProtocolRelayAccount`.

The reset renews the device token of the stored device session. It deletes
the state only when the Relay refuses the renewal with
`HostedSignalProtocolRelayDeviceRevokedError`, as it does after
`removeHostedSignalProtocolRelayDevice` or an account recovery. It deletes
the identities, the sessions, the prekeys, the message records, the device
key, the device session, the join marker, and the groups. It sends nothing
to the Relay after the renewal, and it does not store the renewed token.

- When the Relay still serves the device, the reset throws
  `HostedSignalProtocolRelayDeviceProvisioningError` with the code
  `DEVICE_NOT_REMOVED`. It deletes nothing.
- The reset throws each other failure unchanged and deletes nothing.
  Examples are a store with no device session and a network failure.

A reset that stops before `storage.clearAllKeys()` starts keeps the device
session, so call it again. A reset that stops during
`storage.clearAllKeys()` can delete the device key. A second call then
fails with `HostedSignalProtocolRelayResumeError` before it sends a
request. After that failure, call `storage.clearAllKeys()` to delete the
remaining state.

## Parameters

### options

[`HostedSignalProtocolRelayDeviceResetOptions`](../interfaces/HostedSignalProtocolRelayDeviceResetOptions.md)

## Returns

`Promise`\<`void`\>
