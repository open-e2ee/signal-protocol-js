# React Hooks

The hooks module adapts client lifecycle operations to React components. It
includes key rotation, group membership, session health, relay connection
state, relay lifecycle, and single-flight helpers.

## Why it exists

The core SDK is framework-neutral. React hooks live on a separate package
subpath. Non-React consumers therefore do not load React, and UI code can
subscribe to SDK state without duplicating effect cleanup.

## Usage

```tsx
import {
  useRelayConnectionState,
  useRelayLifecycle,
  useSessionHealth,
} from "@open-e2ee/signal-protocol-sdk/hooks";

function SignalLifecycle({ signal }) {
  useRelayLifecycle({ signal });
  return null;
}

function OwnConnectionDot({ signal }) {
  const { state } = useRelayConnectionState({ signal });
  return <Dot online={state === "connected"} />;
}

function ConversationStatus({ signal, userId }) {
  const { health, isLoading } = useSessionHealth({ signal, userId });
  if (isLoading) return <p>Checking…</p>;
  return <p>{health?.status === "healthy" ? "Ready" : "Check the session"}</p>;
}
```

## Relay connection state

`useRelayConnectionState({ signal })` returns the `RelayConnectionState` of
the relay subscription on this device. The component renders again on each
transition, and the hook unsubscribes when the component unmounts. The state
is `stopped`, `connecting`, `connected`, or `reconnecting`. A `reason` tells
which site caused the last transition. The state is local to this device. It
is not presence and does not tell you about other users.

## Relay lifecycle

`useRelayLifecycle({ signal })` stops the relay subscription when a React
Native app goes to the background and starts it again when the app becomes
active. The stop closes the socket with code 1000, so the Relay records a
client close. The Relay replays retained messages when the app becomes active.
The hook ignores `inactive` and has no grace delay. On web it does nothing:
a hidden desktop tab keeps its socket open by itself.

Set `keepOpenInBackground: true` to keep the socket open in the background,
for example while an Android foreground service runs. Outside React, call
`bindRelayLifecycle(signal, AppState)` from
`@open-e2ee/signal-protocol-sdk/client`.

Install a compatible React version when importing this subpath. Do not call
these hooks outside React components or custom hooks. Event callbacks from
`SignalProtocolClient.registerHook()` are a separate, framework-neutral API.

See the [client guide](../client/README.md) and
[API reference](../docs/api/README.md).
