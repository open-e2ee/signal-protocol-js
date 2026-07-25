[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / compareDeviceIdentityKeys

# Function: compareDeviceIdentityKeys()

> **compareDeviceIdentityKeys**(`pinned`, `incoming`): `"unpinned"` \| `"same"` \| `"changed"`

Compare two `DeviceRecord.identityKey` values.

Returns `'unpinned'` when no identity has been observed for the device yet,
which is first contact (a TOFU pin) and not a change.

## Parameters

### pinned

`Uint8Array`

### incoming

`Uint8Array`

## Returns

`"unpinned"` \| `"same"` \| `"changed"`
