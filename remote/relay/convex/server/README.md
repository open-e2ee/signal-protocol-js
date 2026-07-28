# Convex group server

This server-only subpath provides the production group-server implementation
for Convex. It owns canonical encrypted group state, immutable signed changes,
per-version signed snapshots, anonymous group authorization, credential
issuance, and group-send endorsements.

Import it from:

```ts
import {
  convexGroupServerTables,
  defineConvexGroupServer,
} from "@open-e2ee/signal-protocol-sdk/remote/relay/convex/server";
```

## Schema

The component owns three package-scoped tables. Add them to the app schema:

```ts
// convex/schema.ts
import { defineSchema } from "convex/server";
import {
  convexGroupServerTables,
} from "@open-e2ee/signal-protocol-sdk/remote/relay/convex/server";

export default defineSchema({
  ...convexGroupServerTables,
  // App-owned tables...
});
```

The tables store the latest canonical encrypted state, the exact accepted and
signed action bytes, and every historical encrypted snapshot with its cached
S14 baseline signature. They never store the group master key, group secret
parameters, plaintext group attributes, or the server secret.

Storage grows with one full encrypted snapshot per accepted version and is
never pruned. Old snapshots are load-bearing: `getGroupChanges` serves signed
history from them, so deleting rows breaks catch-up for clients behind that
version. A snapshot-compaction protocol is future work; budget storage as
O(versions × state size) per group.

## Functions

The relay reads these functions through the same generated namespace as the
rest of the protocol API — `api.signal` in the
[Convex relay adapter](../README.md). The modules therefore must live inside
that namespace: `convex/signal/groups.ts` and `convex/signal/zkAuth.ts`, not
at the top of `convex/`. Both `groups` and `zkAuth` are optional on
`ConvexSignalProtocolRelayApi`, so a wrong location still compiles; the relay
then reports the missing `groupServer` capability on the first group call.

Create the handlers with the application's one authentication hook:

```ts
// convex/signal/groups.ts
import {
  defineConvexGroupServer,
} from "@open-e2ee/signal-protocol-sdk/remote/relay/convex/server";
import { resolveProtocolIdentity } from "../auth";

const server = defineConvexGroupServer({
  identify: async (ctx) => {
    const identity = await resolveProtocolIdentity(ctx);
    return {
      aciBytes: identity.aciBytes,
      pniBytes: identity.pniBytes,
    };
  },
});

export const {
  createGroup,
  getGroup,
  getGroupJoinInfo,
  getGroupChanges,
  submitGroupChange,
  refreshGroupSendEndorsements,
} = server;
```

Credential functions can be mounted from a second module so the generated API
matches `ConvexSignalProtocolRelayApi`:

```ts
// convex/signal/zkAuth.ts
import {
  defineConvexGroupServer,
} from "@open-e2ee/signal-protocol-sdk/remote/relay/convex/server";
import { resolveProtocolIdentity } from "../auth";

const server = defineConvexGroupServer({
  identify: async (ctx) => {
    const identity = await resolveProtocolIdentity(ctx);
    return {
      aciBytes: identity.aciBytes,
      pniBytes: identity.pniBytes,
    };
  },
});

export const {
  issueAuthCredentialMutation,
  issueProfileKeyCredentialMutation,
} = server;
```

The `identify` hook drives issuance only. Group reads and writes never trust the
app session for membership; they verify the supplied zero-knowledge
presentation and enforce S1–S14 over ciphertext.

`identify` must return the authenticated account's real ACI, and its real PNI
or **no PNI at all**. Never substitute a shared placeholder value for accounts
without a PNI: credentials are matched by ACI-or-PNI alias, so a constant PNI
issued to every account would let any authenticated user act on any
PNI-addressed pending membership. An absent PNI must be absent.

## Secret initialization and pinned trust root

From the Convex app directory, run:

```sh
npx oe-groups trust-root
```

Add `--prod` for the default production deployment or
`--deployment <name-or-reference>` for another deployment. The command checks
`OE_GROUPS_SERVER_SECRET`, generates a cryptographically random 32-byte seed
only when it is absent, writes it to the selected Convex deployment through
stdin, and prints the base64 serialized trust root. Pin that printed value in
the client build. Never fetch and trust it at runtime.

The seed remains in the Convex environment and deterministically derives all
four server keypairs. It is never written to a Convex table or log. Back up the
deployment secret: deleting or replacing it rotates the trust root and strands
clients pinned to the previous deployment.

## Profile-key issuance threat model

`issueProfileKeyCredentialMutation` receives the raw 32-byte profile key. The
group server therefore sees the plaintext profile key at issuance time. The
credential proof hides it in later group presentations, but issuance in this
credential layer is not blinded. Blinded issuance is a future credential-layer
candidate and is explicitly outside this component's scope.
