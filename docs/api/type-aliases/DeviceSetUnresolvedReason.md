[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / DeviceSetUnresolvedReason

# Type Alias: DeviceSetUnresolvedReason

> **DeviceSetUnresolvedReason** = `"exhausted"` \| `"expired"`

Why a phase of a declared send ended without the acceptance of every
device. `exhausted`: the Relay refused the declaration after the 10th
restart. `expired`: the Relay refused a restart post with
`OPERATION_EXPIRED`, because the operation epoch of the send is outside
its admission window.
