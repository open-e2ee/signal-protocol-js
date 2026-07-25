[**@open-e2ee/signal-protocol-sdk**](../../../README.md)

***

[@open-e2ee/signal-protocol-sdk](../../../README.md) / [keys](../README.md) / canonicalizeDeviceIdentityKey

# Function: canonicalizeDeviceIdentityKey()

> **canonicalizeDeviceIdentityKey**(`bytes`, `label`): `Uint8Array`

Reduce `DeviceRecord.identityKey` bytes to their canonical form, rejecting
any other encoding at the storage boundary.

Every producer of device identity bytes goes through here so that a single
encoding reaches storage and comparison. Without it, two producers using two
encodings of the same key compare unequal and forge an identity-change event.

## Parameters

### bytes

`Uint8Array`

### label

`string`

## Returns

`Uint8Array`
