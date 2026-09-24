[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / bindRelayLifecycle

# Function: bindRelayLifecycle()

> **bindRelayLifecycle**(`signal`, `appState`, `options?`): [`Unsubscribe`](../type-aliases/Unsubscribe.md)

Stops the relay subscription when the app goes to the background and starts
it again when the app becomes active.

- `background` calls `stopRelaySubscription()`, which closes the socket with
  code 1000. The Relay records a client close.
- `active` calls `startRelaySubscription()`, but only after a stop that this
  binding made. The Relay replays retained messages over the new socket.
- `inactive` and other states change nothing. There is no grace delay.
- A subscription that is `stopped` stays stopped, so an app stop is kept.

If the app is in the background at bind time, the binding stops at once.
Call the returned function before `stop()` on the client. It removes the
listener and does not start or stop the subscription.

## Parameters

### signal

`Pick`\<[`SignalProtocolClient`](../interfaces/SignalProtocolClient.md), `"relayConnectionState"` \| `"startRelaySubscription"` \| `"stopRelaySubscription"`\>

The Signal Protocol client

### appState

[`RelayLifecycleAppState`](../interfaces/RelayLifecycleAppState.md)

React Native's `AppState`, or an object of the same shape

### options?

[`RelayLifecycleOptions`](../interfaces/RelayLifecycleOptions.md) = `{}`

Binding options

## Returns

[`Unsubscribe`](../type-aliases/Unsubscribe.md)

A function that removes the binding

## Example

```typescript
import { AppState } from 'react-native';
import { bindRelayLifecycle } from '@open-e2ee/signal-protocol-sdk/client';

const unbind = bindRelayLifecycle(signal, AppState);
// At sign-out:
unbind();
await signal.stop();
```
