[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolClientIdentityConfig

# Interface: SignalProtocolClientIdentityConfig

Stable identity inputs for one Signal Protocol client instance.

A client represents one app install for one account and one device.

## Properties

### deviceId?

> `optional` **deviceId?**: `number`

Signal Protocol device identifier. Defaults to primary device 1.

***

### enablePniKeys?

> `optional` **enablePniKeys?**: `boolean`

Generate and sync both ACI and PNI key material when true.

***

### userId

> **userId**: `string`

Canonical account/user identifier.
