[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / bindSignalProtocolRelayLifecycle

# Function: bindSignalProtocolRelayLifecycle()

> **bindSignalProtocolRelayLifecycle**(`signal`, `appState`, `options?`): [`Unsubscribe`](../type-aliases/Unsubscribe.md)

Stops the relay subscription when the app goes to the background and starts
it again when the app becomes active.

- `background` calls `stopSignalProtocolRelaySubscription()`, which closes the socket with
  code 1000. The Relay records a client close.
- `active` calls `startSignalProtocolRelaySubscription()`, but only after a stop that this
  binding made. The Relay replays retained messages over the new socket.
- `inactive` and other states change nothing. There is no grace delay.
- A subscription that is `stopped` stays stopped, so an app stop is kept.

If the app is in the background at bind time, the binding stops at once.
Call the returned function before `stop()` on the client. It removes the
listener and does not start or stop the subscription.

An object that has only the deprecated member names, such as
`stopRelaySubscription()`, also drives the binding. The binding reads each
new name first.

## Parameters

### signal

`Pick`\<[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md), `"signalProtocolRelayConnectionState"` \| `"startSignalProtocolRelaySubscription"` \| `"stopSignalProtocolRelaySubscription"`\> \| `Pick`\<[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md), `"relayConnectionState"` \| `"startRelaySubscription"` \| `"stopRelaySubscription"`\>

The Signal Protocol client

### appState

[`SignalProtocolRelayLifecycleAppState`](../interfaces/SignalProtocolRelayLifecycleAppState.md)

React Native's `AppState`, or an object of the same shape

### options?

[`SignalProtocolRelayLifecycleOptions`](../interfaces/SignalProtocolRelayLifecycleOptions.md) = `{}`

Binding options

## Returns

[`Unsubscribe`](../type-aliases/Unsubscribe.md)

A function that removes the binding

## Example

```typescript
import { AppState } from 'react-native';
import { bindSignalProtocolRelayLifecycle } from '@open-e2ee/signal-protocol-sdk/client';

const unbind = bindSignalProtocolRelayLifecycle(signal, AppState);
// At sign-out:
unbind();
await signal.stop();
```
