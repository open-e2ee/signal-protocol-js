[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / compareDeviceIdentityKeys

# Function: compareDeviceIdentityKeys()

> **compareDeviceIdentityKeys**(`pinned`, `incoming`): `"unpinned"` \| `"same"` \| `"changed"`

Compare two `DeviceRecord.identityKey` values.

Returns `'unpinned'` when the device has no observed identity yet,
which is first contact (a TOFU pin) and not a change.

## Parameters

### pinned

`Uint8Array`

### incoming

`Uint8Array`

## Returns

`"unpinned"` \| `"same"` \| `"changed"`
