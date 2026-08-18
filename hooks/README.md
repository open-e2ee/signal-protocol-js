# React Hooks

The hooks module adapts client lifecycle operations to React components. It
includes connection presence, key rotation, group membership, session health,
and single-flight helpers.

## Why it exists

The core SDK is framework-neutral. React hooks live on a separate package
subpath. Non-React consumers therefore do not load React, and UI code can
subscribe to SDK state without duplicating effect cleanup.

## Usage

```tsx
import {
  useConnectionPresence,
  useSessionHealth,
} from "@open-e2ee/signal-protocol-sdk/hooks";

function ConversationStatus({ client, address }) {
  const connection = useConnectionPresence({ client });
  const session = useSessionHealth({ client, address });

  return (
    <p>
      {connection.isConnected && session.isHealthy
        ? "Ready"
        : "Reconnecting…"}
    </p>
  );
}
```

Install a compatible React version when importing this subpath. Do not call
these hooks outside React components or custom hooks. Event callbacks from
`SignalProtocolClient.registerHook()` are a separate, framework-neutral API.

See the [client guide](../client/README.md) and
[API reference](../docs/api/README.md).
