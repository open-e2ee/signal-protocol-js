[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / RelayLifecycleAppState

# Interface: RelayLifecycleAppState

The part of an app state source that `bindRelayLifecycle` reads.

React Native's `AppState` satisfies it. The client entry does not import
react-native, so any source with this shape can drive the binding.

## Properties

### currentState

> `readonly` **currentState**: `string`

The state at bind time, for example `active` or `background`.

## Methods

### addEventListener()

> **addEventListener**(`type`, `listener`): \{ `remove`: `void`; \} \| (() => `void`)

Returns a subscription with `remove()`, or a function that removes the listener.

#### Parameters

##### type

`"change"`

##### listener

(`state`) => `void`

#### Returns

\{ `remove`: `void`; \} \| (() => `void`)
