[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedSignalProtocolRelayDeviceLinkRequiredError

# Class: HostedSignalProtocolRelayDeviceLinkRequiredError

The Relay refused a registration, because the account already has a
device. A second device joins the account through a device link: call
`joinHostedSignalProtocolRelayAccount` on the new device, and approve its
link code with `approveHostedSignalProtocolRelayDeviceLink` on the primary
device. Without the primary device, recover the account.

`status` is 409. `retryable` is false: the same registration is refused
again.

## Extends

- [`HostedSignalProtocolRelayHttpError`](HostedSignalProtocolRelayHttpError.md)

## Constructors

### Constructor

> **new HostedSignalProtocolRelayDeviceLinkRequiredError**(`status`, `message`): `HostedSignalProtocolRelayDeviceLinkRequiredError`

#### Parameters

##### status

`number`

##### message

`string`

#### Returns

`HostedSignalProtocolRelayDeviceLinkRequiredError`

#### Overrides

[`HostedSignalProtocolRelayHttpError`](HostedSignalProtocolRelayHttpError.md).[`constructor`](HostedSignalProtocolRelayHttpError.md#constructor)

## Properties

### code

> `readonly` **code**: `string`

The Relay's error code, for example `KEY_PROOF_INVALID`.

#### Inherited from

[`HostedSignalProtocolRelayHttpError`](HostedSignalProtocolRelayHttpError.md).[`code`](HostedSignalProtocolRelayHttpError.md#code)

***

### data?

> `readonly` `optional` **data?**: `Readonly`\<`Record`\<`string`, `unknown`\>\>

More values of the refusal. A refused declared post keeps the Relay's `details` here.

#### Inherited from

[`HostedSignalProtocolRelayHttpError`](HostedSignalProtocolRelayHttpError.md).[`data`](HostedSignalProtocolRelayHttpError.md#data)

***

### retryable

> `readonly` **retryable**: `boolean`

The Relay's own hint that the same operation can be sent again. On an
error that `send()` throws before its posting deadline, the SDK sets
`retryable` to true and keeps this hint in `relayRetryable`.

#### Inherited from

[`HostedSignalProtocolRelayHttpError`](HostedSignalProtocolRelayHttpError.md).[`retryable`](HostedSignalProtocolRelayHttpError.md#retryable)

***

### status

> `readonly` **status**: `number`

The HTTP status of the response.

#### Inherited from

[`HostedSignalProtocolRelayHttpError`](HostedSignalProtocolRelayHttpError.md).[`status`](HostedSignalProtocolRelayHttpError.md#status)
