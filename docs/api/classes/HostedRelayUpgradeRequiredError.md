[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayUpgradeRequiredError

# Class: HostedRelayUpgradeRequiredError

The Relay no longer serves the protocol version of this SDK. The same
request fails again until the application ships a newer SDK, so the SDK
does not retry it. The mailbox subscription stops with the reason
`upgrade-required` for the same refusal on its socket.

## Extends

- `Error`

## Constructors

### Constructor

> **new HostedRelayUpgradeRequiredError**(`status`): `HostedRelayUpgradeRequiredError`

#### Parameters

##### status

`number`

#### Returns

`HostedRelayUpgradeRequiredError`

#### Overrides

`Error.constructor`

## Properties

### code

> `readonly` **code**: `"UPGRADE_REQUIRED"` = `"UPGRADE_REQUIRED"`

***

### retryable

> `readonly` **retryable**: `false` = `false`

Always false: only a newer SDK can send the request again.

***

### status

> `readonly` **status**: `number`

The HTTP status of the refusal, 426 from a current Relay.
