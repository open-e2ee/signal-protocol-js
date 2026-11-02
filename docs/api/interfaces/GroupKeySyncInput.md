[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / GroupKeySyncInput

# Interface: GroupKeySyncInput

The key of one managed group that a device gives to the other devices of
its account, so each own device can fetch the group with no group traffic.

## Properties

### masterKey

> **masterKey**: `Uint8Array`

The group master key. It is 32 bytes.

***

### revision

> **revision**: `number`

The revision of the sender's group state at the send, or 0 with no state.
