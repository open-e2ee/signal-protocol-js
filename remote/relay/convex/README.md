# Convex Relay Adapter

The Convex relay adapter maps an application-owned generated Convex API module
to `ISignalRelayServer`.

## Why it exists

Convex generated references retain precise query and mutation types but do not
implement the SDK relay contract directly. The adapter performs that client-side
mapping while leaving backend registration and policy in the application.

## Ownership boundary

The SDK supplies the client adapter and exact function-reference types. The
application owns its Convex deployment, schema, authentication, authorization,
functions, retention policy, and operational controls.

## Usage

Organize the application functions under one generated module namespace, then
pass that namespace directly:

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import {
  convexRelay,
  type ConvexSignalRelayApi,
} from "@open-e2ee/signal-protocol-sdk/remote/relay/convex";
import { api } from "../convex/_generated/api";

const signalApi = api.signal satisfies ConvexSignalRelayApi;

const relay = convexRelay({
  convex,
  api: signalApi,
  currentUserId: userId,
});

const client = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
});
```

The generated `api.signal` namespace must expose the nested functions described
by `ConvexSignalRelayApi`. Use `satisfies` to get a compile-time diagnostic
without widening the generated references.

Public-key reads may be available to authenticated peers, but every write must
derive ownership from server-side authentication rather than trusting a
client-supplied user ID.

See the [relay guide](../README.md) and
[API reference](../../../docs/api/README.md).
