[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeviceSetLastRefusal

# Interface: DeviceSetLastRefusal

The last refusal of a phase. `DEVICE_SET_MISMATCH` and `STALE_DEVICE` are
the Relay's answers. `BUNDLE_NOT_FOUND` is a listed device that had no
prekey bundle when the send repaired it.

## Properties

### accounts

> `readonly` **accounts**: readonly [`DeviceSetRefusalAccount`](DeviceSetRefusalAccount.md)[]

***

### code

> `readonly` **code**: `"DEVICE_SET_MISMATCH"` \| `"STALE_DEVICE"` \| `"BUNDLE_NOT_FOUND"`
