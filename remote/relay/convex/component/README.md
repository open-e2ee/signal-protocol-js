# Convex Signal Protocol component

This installable Convex component owns the complete relay backend:

- account and device registration
- identity and prekey storage
- message queues, sealed-sender delivery, and retry requests
- provisioning and sender certificates
- canonical encrypted group state and anonymous group authorization
- credential issuance and group-send endorsements

The app owns only its authentication-to-protocol-identity mapping and thin
public wrappers.

## Install the component

Mount the component in the app's Convex configuration:

```ts
// convex/convex.config.ts
import { defineApp } from 'convex/server';
import { v } from 'convex/values';
import signalProtocol from '@open-e2ee/signal-protocol-sdk/convex.config';

const app = defineApp({
  env: { OE_GROUPS_SERVER_SECRET: v.optional(v.string()) },
});
app.use(signalProtocol, {
  env: { OE_GROUPS_SERVER_SECRET: app.env.OE_GROUPS_SERVER_SECRET },
});
export default app;
```

The `env` forwarding is load-bearing. Convex isolates each component from the
app's environment variables. Without the forwarding, the component cannot see
the deployment's `OE_GROUPS_SERVER_SECRET`, and every group,
credential-issuance, and sender-certificate call fails at runtime. The
messaging, device, key, and provisioning namespaces work without the secret.

The component owns these isolated tables. They do not appear in the app schema
and need no package-specific prefixes:

- `accounts`: reverse lookup from application account IDs to protocol service
  identifiers and sealed-sender access keys.
- `devices` and `deviceHeartbeats`: device lifecycle and presence state.
- `identityKeys` and `identityRegistrations`: account-scoped composite
  identities and device-scoped registration IDs.
- `ecPreKeys`, `ecSignedPreKeys`, `kemOneTimePreKeys`, and
  `kemLastResortPreKeys`: the four prekey kinds, including durable one-time-key
  consumption tombstones.
- `messages` and `retryRequests`: device delivery and retry queues.
- `provisioningSessions`: the linked-device provisioning state machine.
- `senderCertificates`: cached account/device certificate material.
- `groups`, `groupChanges`, and `groupSnapshots`: canonical encrypted group
  state, immutable signed changes, and per-version signed snapshots.

The component derives **no** membership map from group state. Zero-knowledge
presentations authorize every group read and write. Therefore `groups`,
`groupChanges`, and `groupSnapshots` never name an account, and the relay
surface has no `getGroupMembers` endpoint. Membership is local-first. Each
client resolves fan-out recipients from its own decrypted group state and
passes their user IDs with the send (`SendOptions.groupMemberUserIds`). The
relay expands users to devices through `getActiveDevices`.

See [Group metadata privacy](#group-metadata-privacy) for what the relay can
still infer from delivery traffic. The absence of a membership endpoint is not
by itself a metadata-privacy guarantee.

The mounted `@convex-dev/rate-limiter` child component separately owns its
isolated `rateLimits` table.

The tables store:

- the latest canonical encrypted state
- the exact accepted and signed action bytes
- every historical encrypted snapshot with its cached S14 baseline signature

They never store the group master key, group secret parameters, plaintext group
attributes, or the server secret.

Storage grows with one full encrypted snapshot per accepted version and is
never pruned. Old snapshots are load-bearing: `getGroupChanges` serves signed
history from them, so deleting rows breaks catch-up for clients behind that
version. A snapshot-compaction protocol is future work. Budget storage as
O(versions × state size) per group.

## Mount the public wrappers

Create the wrapper once with the mounted component reference and the app's
authentication hook:

```ts
// convex/relayBackend.ts
import { components } from './_generated/api';
import { defineConvexSignalProtocolBackend } from '@open-e2ee/signal-protocol-sdk/remote/relay/convex';
import { resolveProtocolIdentity } from './auth';

export const signalRelay = defineConvexSignalProtocolBackend(
  components.signalProtocol,
  {
    identify: async (ctx) => {
      const identity = await resolveProtocolIdentity(ctx);
      return {
        userId: identity.userId,
        aciBytes: identity.aciBytes,
        pniBytes: identity.pniBytes,
      };
    },
  }
);
```

The relay reads these functions through `api.signal`, so the modules must live
inside that namespace rather than at the top of `convex/`:

```ts
// convex/signal/groups.ts
import { signalRelay } from '../relayBackend';

export const {
  createGroup,
  getGroup,
  getGroupJoinInfo,
  getGroupChanges,
  submitGroupChange,
  refreshGroupSendEndorsements,
} = signalRelay.groups;
```

```ts
// convex/signal/zkAuth.ts
import { signalRelay } from '../relayBackend';

export const {
  issueAuthCredentialMutation,
  issueProfileKeyCredentialMutation,
} = signalRelay.zkAuth;
```

Mount the remaining relay namespaces alongside those group modules:

```ts
// convex/signal/messages.ts
import { signalRelay } from '../relayBackend';
export const {
  send,
  getPendingMessages,
  markDelivered,
  getActiveDevices,
  sendUnidentified,
  sendMultiRecipientUnidentified,
  sendRetryRequest,
  getPendingRetryRequests,
  markRetryRequestHandled,
} = signalRelay.messages;
```

```ts
// convex/signal/devices.ts
import { signalRelay } from '../relayBackend';
export const {
  getDevices,
  registerDevice,
  removeDevice,
  markDeviceConnected,
  markDeviceDisconnected,
  presenceHeartbeat,
} = signalRelay.devices;
```

```ts
// convex/signal/keys.ts
import { signalRelay } from '../relayBackend';
export const {
  uploadIdentityKey,
  getIdentityKey,
  uploadPreKeys,
  fetchPreKeyBundle,
  getPreKeyCount,
  clearStaleKemPreKeys,
  uploadEcSignedPreKey,
  uploadKemLastResortPreKey,
  getEcSignedPreKeyMetadata,
  getKemLastResortPreKeyMetadata,
} = signalRelay.keys;
```

```ts
// convex/signal/certificates.ts
import { signalRelay } from '../relayBackend';
export const { issueSenderCertificate } = signalRelay.certificates;
```

```ts
// convex/signal/provisioning.ts
import { signalRelay } from '../relayBackend';
export const {
  createProvisioningSession,
  connectNewDevice,
  sendProvisioningMessage,
  getProvisioningMessage,
  completeProvisioning,
  acknowledgeProvisioning,
  rollbackProvisioning,
  deleteProvisioningSession,
} = signalRelay.provisioning;
```

- `messages` owns identified and sealed delivery, multi-recipient fan-out,
  retry queues, and message/device lookup reads.
- `devices` owns registration, removal, connection state, and presence.
- `keys` owns identity provisioning and compare-and-swap rotation, prekey
  upload, atomic one-time-key consumption, and key metadata.
- `certificates` issues sender certificates for registered account/device
  identities.
- `provisioning` owns the linked-device session state machine through
  acknowledgment or rollback.

The account-scoped wrappers resolve the caller identity on the server and
inject the application `userId`, raw ACI, and optional PNI bytes into the
isolated component. Client-supplied owner IDs are never trusted. Credential
issuance also resolves identity. Group wrappers pass client arguments through
untouched because group reads and writes authenticate membership solely through
the supplied zero-knowledge presentation.

`sendUnidentified` and `sendMultiRecipientUnidentified` are the deliberate
exception: those sealed-sender paths do **not** call `identify`. They authorize
the bearer request with the target's unidentified-access key or verified group
send material, which keeps delivery available without an authenticated
application session. Rejections carry structured `ConvexError` data. The relay
adapter reads `data.code === 'UNAUTHORIZED'` to decide the fallback to
identified delivery, and never matches on the message text. A deployment that
wraps or re-throws component rejections must preserve `code`. If it drops
`code`, a sealed send that must retry on the identified path surfaces as a hard
failure instead.

The zero-knowledge profile-key credential flow
(`issueProfileKeyCredentialMutation`) registers a recipient's
unidentified-access key as a side effect. Until a recipient completes that flow,
the component rejects access-key-authorized sealed sends to them, and the client
falls back to identified delivery. Messages still arrive, but without sender
anonymity. Deployments that want sealed sender for 1:1 messaging must drive
the profile-key credential flow during account setup, not lazily.

`identify` must return the authenticated account's real ACI, and its real PNI
or **no PNI at all**, plus the application-owned `userId` used for relay
routing. Never substitute a shared placeholder value for accounts without a
PNI. The credential layer matches by ACI-or-PNI alias. A constant PNI issued to
every account would therefore let any authenticated user act on any
PNI-addressed pending membership. An absent PNI must be absent.

## Retention and rate limiting

Component-owned interval jobs delete expired seven-day messages hourly,
expired seven-day retry requests hourly, expired provisioning sessions every
minute, and stale KEM prekeys daily. Cleanup mutations delete bounded batches
and schedule immediate continuations until the indexed range is empty.

Completing a provisioning session grants the acknowledgment its own full
session TTL. The cron rolls back a link that nobody acknowledges within that
window. It deletes the device the link created, together with all of its key
material, queued messages, and heartbeats. Teardown matches the device's
`linkedAt` stamp recorded at completion. A stale session therefore never reaps
a device that a legitimate re-registration put into the freed slot.

Prekey-bundle fetches use the mounted `@convex-dev/rate-limiter` child
component. Each authenticated fetcher/target-account pair receives ten fetches
per fixed one-minute window. The eleventh request fails with structured
`RATE_LIMITED` data and HTTP-equivalent status 429.

## Upgrading: clear `messages` before deploying this version

This version drops two shapes from the `messages` table: the optional
`groupId` field, and `plaintext_content` from the `messageType` union.

Convex validates every existing document against the new schema **during the
push**, before any of your code runs. A stored row carrying a `groupId`, or one
whose `messageType` is `plaintext_content`, therefore fails the deploy. No
migration mutation can fix it, because the deploy that would ship the mutation
is the deploy that fails. The order has to be: clear first, deploy second.

Messages are transient by design. The table has a seven-day TTL and an hourly
cleanup cron. Clients re-request undelivered messages through the retry path,
so clearing the table is a normal operation rather than data loss.

Check whether the deployment has anything to clear. Run the check while the
deployment is still on the previous version, because the table lives inside the
component rather than the app:

```sh
npx convex data messages --component signalProtocol
```

Add `--prod` or `--deployment <name-or-reference>` to target a deployment other
than your dev one. A deployment that never relayed a group message, and never
had a caller pass `plaintext_content`, has no affected rows and needs no
action. No send path in this SDK ever produced the latter.

If there are rows, either wait or clear:

- **Wait**. Stop sending, and the hourly cleanup cron drains the table as the
  seven-day retention window expires. No manual step, but it takes a week.
- **Clear**. In the Convex dashboard, select the `signalProtocol` component,
  open the `messages` table, and clear it. Undelivered messages are lost.
  Clients re-request them over the retry path.

Deploy once the table is empty.

## Secret initialization and pinned trust root

From the Convex app directory, run:

```sh
npx oe-groups trust-root
```

Add `--prod` for the default production deployment or
`--deployment <name-or-reference>` for another deployment. The command:

- checks `OE_GROUPS_SERVER_SECRET`
- generates a cryptographically random 32-byte seed only when the secret is
  absent
- writes the seed to the selected Convex deployment through stdin
- prints two labelled base64 roots: the serialized group trust root and the
  Ed25519 sender-certificate root

Pin both in the client build. See
[Sender certificate trust root](#sender-certificate-trust-root) for where each
one goes. Never fetch and trust either at runtime.

The seed remains in the Convex environment and deterministically derives all
four server keypairs. It is never written to a Convex table or log. Back up the
deployment secret: deleting or replacing it rotates the trust root and strands
clients pinned to the previous deployment.

## Sender certificate trust root

`certificates.issueSenderCertificate` signs sender certificates with an Ed25519
key pair deterministically derived from the deployment secret, domain-separated
from the group signing key by distinct KDF labels
(`open-e2ee:sealed-sender:root:v1` / `:server:v1`). Clients verify inbound
sealed-sender certificates against the matching Ed25519 **root** public key.

`oe-groups trust-root` prints both roots, labelled:

```
group trust root: <base64>
sealed sender trust root: <base64>
```

The two roots go in different places and are not interchangeable. The group
trust root goes into the group configuration, and the sealed-sender root into
`sealedSender.trustRoots` in the client build. Pin both at build time. Never
fetch either from a relay at runtime, because a relay that chooses its own
validation root can mint certificates for any sender.

The component derives both from the same deployment secret, so rotating
`OE_GROUPS_SERVER_SECRET` rotates both and strands clients pinned to either
previous value.

With `trustRoots` left empty, inbound sealed-sender validation stays disabled,
and sends fall back to identified delivery. Messages still arrive, but they
disclose the sender to the relay.

## Group metadata privacy

The relay cannot read message contents and cannot derive membership from group
state. It also no longer sees a group identifier on the two channels that used
to carry one.

**Closed: the distribution identifier in the frame**. The identified send path
stores the framed `SenderKeyMessage` as its `ciphertext`, and that frame's
`distributionUuid` is **not** encrypted. It used to embed
`groupId:senderUserId:senderDeviceId:timestamp`. The group and the sender's
device were therefore readable straight out of the ciphertext column. Worse
than a column, they were readable off every message in flight to any relay on
the path.

Sealed sender did not help. It hides the frame from the relay, but not from the
rest of the path. The component also keeps sealed sender disabled until you
export the trust root (see above), so group traffic takes the identified path
anyway. Distribution identifiers are now opaque random UUIDs carrying no group,
sender, device, or clock, as the reference implementation uses, as the
sender-keys specification now requires.

**Closed: the `groupId` column**. Every `messages` row used to store a plaintext
`groupId` next to `targetUserId` for the seven-day retention window. The column
is gone, and a `sender_key` message type replaces it. The type tells the
receiver to decrypt the payload as a framed `SenderKeyMessage` and nothing
more. The receiver reads the opaque distribution identifier out of the frame
and resolves the group against its own sender key store. No group identifier
travels on an envelope, sealed or not.

**Open: the group partition itself**. Removing the identifier removed the
group's *name*, not the ability to group rows. Be precise about what is left,
because the difference matters and it is easy to overstate:

- The frame leaves `distributionUuid` unencrypted, and the row stores it
  verbatim inside `messages.ciphertext`. The paragraph above says as much. It
  is opaque, but stable for the life of a sender key. Nothing rotates keys on a
  timer. Grouping rows by it recovers the recipient set for a sender's group
  traffic.
- Sender keys encrypt once and fan out, so every recipient row of one send
  carries a byte-identical `ciphertext`. Grouping by that recovers the
  recipient set of a single send, which is sharper than the old column.
- The fan-out stamps one `timestamp` across every recipient row, and passes
  through one `clientMessageId` when the application supplies one.
- `sendMultiRecipientUnidentified` hands the relay the roster explicitly, in
  one call. The sealed-sender path names the recipient set outright.

So the relay cannot learn *which* group, or its name, membership list, or
attributes. It can still partition delivery pairs into unlabeled groups, and
any one of those channels suffices. That is a real improvement on a plaintext
`groupId`, which handed over a stable, meaningful, cross-send label. It is not
anonymity of the partition. The `sender_key` type is also a single-column
filter that isolates group traffic from pairwise traffic. The old design did
not offer that filter, because group messages used to hide among `ciphertext`
rows.

**Still visible**. Delivery metadata itself: who sent to whom, when, and how
much. Every relay sees this. Sealed sender removes the sender from the
identified half of it.

## Authorization is account-scoped, not device-scoped

`identify` maps an authenticated session to an account (`userId`), with no
device. Every account-scoped endpoint therefore authorizes at account
granularity, and the caller chooses each `deviceId` argument as a route
selector rather than an authenticated claim. Concretely, any session for an
account can:

- read and delete **any** of that account's device queues
  (`getPendingMessages`, `markDelivered`)
- send as any of its device IDs (`send.senderDeviceId`)
- upload or rotate key material for any of its devices (`keys`)

This is the intended model, because a compromised session already holds the
account. It does mean that the component provides no isolation *between* an
account's own devices. Deployments that need device isolation must issue
device-scoped sessions and enforce the binding in their own `identify` wrapper.
The component cannot do it while its identity has no device field.

## Profile-key issuance threat model

`issueProfileKeyCredentialMutation` receives the raw 32-byte profile key. The
group server therefore sees the plaintext profile key at issuance time. The
credential proof hides it in later group presentations, but issuance in this
credential layer is not blinded. Blinded issuance is a future credential-layer
candidate and is explicitly outside this component's scope.
