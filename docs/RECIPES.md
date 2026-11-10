# Recipes

> Navigation: [README](../README.md) | [Getting Started](./GETTING_STARTED.md) |
> [Package Surface](./PACKAGE_SURFACE.md) |
> [Client Composition](./CLIENT_COMPOSITION.md) |
> [Protocol Policy](./PROTOCOL_POLICY.md)

Working shapes for the tasks applications do most often. Each example
uses public exports only.

## Hosted Client Setup

The recipes require a configured OpenE2EE Signal Protocol Relay project, an
identity-assertion callback, and device-local storage. Use a Sandbox
environment for development, where
`hostedSignalProtocolRelaySandboxIdentity(storage)` supplies the callback. The
[getting-started guide](./GETTING_STARTED.md) describes these inputs.

## Application-bound identity callback

Your backend verifies the current application session and member eligibility.
It signs the Relay-specific ES256 assertion. The browser callback only requests
that assertion. Keep provider credentials and signing keys on the backend.

<!-- doc-snippet:skip requires-external-context -->
```ts
import type { GetIdentityAssertion } from "@open-e2ee/signal-protocol-sdk";

const getIdentityAssertion: GetIdentityAssertion = async (request) => {
  const response = await fetch("https://application.example/api/signal-relay-identity", {
    method: "POST",
    credentials: "include",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
    cache: "no-store",
  });
  if (!response.ok) throw new Error("Application authentication is required.");
  const result: unknown = await response.json();
  if (!result || typeof result !== "object" || !("assertion" in result) ||
      typeof result.assertion !== "string") {
    throw new Error("Identity assertion missing.");
  }
  return result.assertion;
};

void getIdentityAssertion;
```

Replace the example application origin with your authenticated backend.
Configure its CSRF controls and cookie policy. Do not send a member ID or
provider token from this callback as proof of membership.

The browser callback above uses cookies. Native apps (React Native and Expo)
use the bearer-credential callback in
[native apps](https://docs.open-e2ee.dev/signal-relay/custom-token#native-apps-react-native-and-expo).

The [Better Auth recipe](https://docs.open-e2ee.dev/signal-relay/better-auth) uses a
real server session with the cookie cache disabled. The
[backend contract](https://docs.open-e2ee.dev/signal-relay/backend-identity) lists
other provider paths and their evidence levels. Those backend paths issue
custom-token assertions. The [native provider profiles](#native-provider-profiles)
use the provider token instead.

Application logout and assertion refusal do not revoke existing device proofs.
To stop identified access on existing devices, follow the
[suspension procedure](https://docs.open-e2ee.dev/signal-relay/backend-identity#suspend-an-identified-account).
Anonymous capabilities retain their separate limits.

## Native provider profiles

A native provider profile lets the OpenE2EE Signal Protocol Relay verify the
token of the identity provider itself. The browser callback returns that
token. No application backend signs a Relay-specific assertion.

The Signal Protocol Relay accepts Clerk and Firebase sign-in as native
identity providers in Sandbox and Production. Select Clerk or Firebase as the
identity source of the environment in the Console before the first device
registers. The recipes below give the callback and the Relay verifier contract
for each profile.

Relay applies these checks to both providers:

- The token is a JWT signed with RS256. Its header has a `kid`. It has no
  `crit`, `jku`, `jwk`, `x5c`, or `x5u` parameter.
- The `iss` claim matches the configured issuer. The `sub` claim is the user
  ID of the provider. The issuer and the subject together select one Relay
  account.
- The `iat` and `exp` claims are integers. The token is not expired, and its
  `nbf` claim, when present, is not in the future.
- Relay records an identifier for each accepted token. With a `jti` claim,
  the identifier is that claim, and the same token in a second SDK operation
  fails with `ASSERTION_REPLAY`. Without `jti`, Relay derives the identifier
  from the token, the purpose, and the SDK operation.

The SDK calls the callback to register a device, to recover the account, and
to advance an identity migration. Each callback in these recipes asks the
provider for a new token on each call. It refuses a migration request, because
one provider session cannot serve as both the source and the target of a
migration.

### Clerk session token callback

The profile names the issuer of the Clerk instance and its authorized
parties. Relay checks these claims of the Clerk session token:

| Claim | Relay rule |
|---|---|
| `iss` | The public HTTPS origin of the Clerk instance, with no path or port. |
| `azp` | One of the 1 to 16 configured authorized parties. A profile accepts a token without `azp` only when it also requires an audience. |
| `aud` | Absent, unless the profile sets an audience. Then it must match. |
| `sid`, `v`, `nbf` | Required. `v` is `2`. The `sts` claim, when present, is `active`. |
| `jti` | Optional. |
| `exp` | At most 10 minutes after `iat`. |

Return the session token itself. A token from a JWT template without the
session claims fails verification.

<!-- doc-snippet:run recipes-clerk-identity-callback expect="clerk register=clerk-session-token migration=This callback does not serve identity migration." -->
```ts
// Real protocol and cryptography; simulated in-memory infrastructure.
import type {
  GetIdentityAssertion,
  IdentityAssertionRequest,
} from "@open-e2ee/signal-protocol-sdk";

// The part of a loaded Clerk instance that the callback reads.
interface ClerkSessionSource {
  readonly session?: {
    readonly user: { readonly id: string } | null;
    getToken(options: { skipCache: boolean }): Promise<string | null>;
  } | null;
}

function clerkIdentityAssertion(
  clerk: ClerkSessionSource,
  userId: string,
): GetIdentityAssertion {
  return async (request: IdentityAssertionRequest) => {
    if (request.migration || request.purpose === "refresh") {
      throw new Error("This callback does not serve identity migration.");
    }
    const session = clerk.session;
    if (!session || session.user?.id !== userId) {
      throw new Error("Sign in as the user of this device store.");
    }
    // Relay refuses an expired or reused token, so ask for a new one.
    const token = await session.getToken({ skipCache: true });
    if (clerk.session?.user?.id !== userId) {
      throw new Error("The signed-in user changed.");
    }
    if (!token) throw new Error("Clerk returned no session token.");
    return token;
  };
}

// In-memory stand-in for a signed-in Clerk instance.
const clerk: ClerkSessionSource = {
  session: {
    user: { id: "user_example" },
    getToken: async ({ skipCache }) => (skipCache ? "clerk-session-token" : null),
  },
};
const getIdentityAssertion = clerkIdentityAssertion(clerk, "user_example");
const context = { environment: "sandbox", publishableKey: "example" } as const;
const token = await getIdentityAssertion({ ...context, purpose: "register" });
const migration = await getIdentityAssertion({
  ...context,
  purpose: "refresh",
  migration: { action: "prepare", providerRole: "target" },
}).catch((error: Error) => error.message);
console.log(`clerk register=${token} migration=${migration}`);
```

Pass the Clerk instance after it loads, and the user ID of the device store.
For recovery, Relay reads the factor verification ages in the `fva` claim.
By default, recovery needs a first-factor verification in the last 5 minutes.
A profile that requires step-up needs a second-factor verification in the
last 5 minutes. Otherwise, Relay refuses recovery with `AUTHORITY_DENIED`. Ask
the user to verify again before you start recovery.

### Firebase ID token callback

The profile names the Firebase project. Relay checks these claims of the
Firebase ID token:

| Claim | Relay rule |
|---|---|
| `iss` | `https://securetoken.google.com/<project id>` |
| `aud` | The project ID. |
| `auth_time` | An integer sign-in time, not later than `iat`. |
| `firebase.sign_in_provider` | Required. |
| `firebase.tenant` | Absent. Relay refuses a tenant token. |
| `exp` | At most 1 hour after `iat`. |

Relay accepts project-level tokens only. Sign users in to the project itself,
not to a tenant.

<!-- doc-snippet:run recipes-firebase-identity-callback expect="firebase register=firebase-id-token migration=This callback does not serve identity migration." -->
```ts
// Real protocol and cryptography; simulated in-memory infrastructure.
import type {
  GetIdentityAssertion,
  IdentityAssertionRequest,
} from "@open-e2ee/signal-protocol-sdk";

// The part of a Firebase Auth instance that the callback reads.
interface FirebaseUserSource {
  readonly currentUser: {
    readonly uid: string;
    getIdToken(forceRefresh?: boolean): Promise<string>;
  } | null;
}

function firebaseIdentityAssertion(
  auth: FirebaseUserSource,
  uid: string,
): GetIdentityAssertion {
  return async (request: IdentityAssertionRequest) => {
    if (request.migration || request.purpose === "refresh") {
      throw new Error("This callback does not serve identity migration.");
    }
    const user = auth.currentUser;
    if (!user || user.uid !== uid) {
      throw new Error("Sign in as the user of this device store.");
    }
    // Relay refuses an expired or reused token, so ask for a new one.
    const token = await user.getIdToken(true);
    if (auth.currentUser?.uid !== uid) {
      throw new Error("The signed-in user changed.");
    }
    return token;
  };
}

// In-memory stand-in for a signed-in Firebase Auth instance.
const auth: FirebaseUserSource = {
  currentUser: {
    uid: "uid-example",
    getIdToken: async (forceRefresh) =>
      forceRefresh ? "firebase-id-token" : "cached-id-token",
  },
};
const getIdentityAssertion = firebaseIdentityAssertion(auth, "uid-example");
const context = { environment: "sandbox", publishableKey: "example" } as const;
const token = await getIdentityAssertion({ ...context, purpose: "register" });
const migration = await getIdentityAssertion({
  ...context,
  purpose: "refresh",
  migration: { action: "prepare", providerRole: "target" },
}).catch((error: Error) => error.message);
console.log(`firebase register=${token} migration=${migration}`);
```

Pass the Auth instance and the user ID of the device store. For recovery,
Relay reads the sign-in time in `auth_time`. By default, recovery needs a
sign-in in the last 5 minutes. A profile that requires step-up also needs the
`firebase.sign_in_second_factor` claim. Otherwise, Relay refuses recovery
with `AUTHORITY_DENIED`. Ask the user to sign in again before you start
recovery.

### Native provider lifecycle

Open one device store for each provider user, and stop the client at sign-out:

<!-- doc-snippet:skip requires-external-context -->
```ts
import { createHostedSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { webSqliteStore } from "@open-e2ee/signal-protocol-sdk/local/store/web-sqlite";

// An application-chosen name for this provider user, within the store name rules.
const storage = await webSqliteStore({ name: storeName });
const signalRelayUrl = process.env.OPEN_E2EE_SIGNAL_RELAY_URL!;
const signal = await createHostedSignalProtocolClient({
  adapters: { storage },
  hosted: {
    relayUrl: signalRelayUrl,
    getIdentityAssertion: firebaseIdentityAssertion(auth, uid),
  },
});

// At provider sign-out, stop the client before another user signs in.
await signal.stop();
```

These rules apply to Clerk and Firebase profiles:

- **Token refresh.** A registered device resumes its session with its device
  key. The SDK does not call the callback for a resume. A provider token
  refresh or expiry does not change a registered device.
- **Sign-out.** Provider sign-out does not revoke the device. The store
  resumes its account without the callback. A shared store would give the
  next user the account of the previous user. To stop access on existing
  devices, follow the
  [suspension procedure](https://docs.open-e2ee.dev/signal-relay/backend-identity#suspend-an-identified-account).
- **Reinstall or lost store.** A new store registers a new device of the same
  account. It has a new Signal identity key, no earlier sessions, and no
  message history. Peers must verify and accept the new key. The earlier
  devices stay active with the old key. Until the earlier devices are removed,
  or until recovery, peers cannot send to all devices of the account. A peer
  that accepted the new key gets `UNTRUSTED_IDENTITY` when it sends to an
  earlier device. A peer that has not accepted it cannot decrypt messages from
  the new device. To keep the account identity, use device linking. Each
  registration reserves one of the five device IDs of the account for good.
  See [Signal Protocol Relay device errors](./ERROR_HANDLING.md#signal-protocol-relay-device-errors).
- **Device linking.** To keep the account identity on a new device, move the
  identity from an existing device and call `linkHostedSignalProtocolRelayDevice`. Your
  application owns that transfer.
- **Recovery.** Create the client with `assertionPurpose: "recover"` when no
  device of the account remains. Recovery revokes all earlier devices of the
  account and returns device ID 1. The device ID reservation applies to
  registrations, so recovery starts again at device 1. Recovery does not
  restore message plaintext or sessions. Your application decides when to
  start it. Recovery needs a recent provider sign-in. Sign the user in again
  before you start recovery. Relay refuses a sign-in older than the recovery
  window with HTTP 401 `AUTHORITY_DENIED`. See
  [device lifecycle and recovery](https://docs.open-e2ee.dev/signal-relay/device-lifecycle-and-recovery).
- **Provider change.** A different provider, Clerk instance, or Firebase
  project gives a different issuer or subject. Relay treats it as a different
  account. An environment keeps its identity profile after its first
  registration. To use another provider, start a new project. See
  [in-use environments](https://docs.open-e2ee.dev/signal-relay/identity#in-use-environments).

## Production composition with Expo on the Signal Protocol Relay

<!-- doc-snippet:skip requires-external-context -->
```ts
import { createHostedSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { expoStore } from "@open-e2ee/signal-protocol-sdk/local/store/expo";

const signal = await createHostedSignalProtocolClient({
  adapters: {
    // Expo storage owns this device's private keys and session state.
    storage: await expoStore(),
  },
  hosted: {
    // The environment-scoped connection URL from the OpenE2EE console.
    relayUrl: process.env.EXPO_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL ?? process.env.EXPO_PUBLIC_OPEN_E2EE_RELAY_URL!,
    // The native app callback: https://docs.open-e2ee.dev/signal-relay/custom-token#native-apps-react-native-and-expo
    getIdentityAssertion,
  },
});
```

The hosted factory authenticates and registers the current device. Expo apps
must complete the [database setup](../local/store/expo/README.md) first.

## App message flow

<!-- doc-snippet:skip requires-external-context -->
```ts
const signal = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
});

// Upload public prekeys before other devices need to message this device.
await signal.syncToServer();

signal.registerHook("onMessageDecrypted", async (message) => {
  // Decrypted content belongs in your app database, not in the relay.
  await appMessages.insert({
    conversationId: message.conversationId,
    senderId: message.senderId,
    body: message.content,
    receivedAt: message.receivedAt,
  });
});

// Subscribing starts encrypted envelope delivery and local decryption.
signal.startRelaySubscription();

await signal.send(recipientUserId, "hello");
```

The relay only handles encrypted envelopes. Your application owns decrypted
message storage through hooks.

## Protocol policy

<!-- doc-snippet:skip requires-external-context -->
```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: {
    postQuantum: "required",
    braid: "required",
  },
});
```

`postQuantum: 'required'` and `braid: 'required'` are the defaults. Peers
without post-quantum material fail closed, and PQ sessions use the SDK's
ML-KEM Braid SPQR profile. See the [protocol policy](./PROTOCOL_POLICY.md) for
supported choices.

`'required'` is the only `postQuantum` value. The SDK has no classical key
agreement, so a peer that advertises no post-quantum material fails with
`PQXDH_REQUIRED`.

<!-- doc-snippet:skip requires-external-context -->
```ts
await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  protocol: {
    postQuantum: "required",
    braid: "disabled",
  },
});
```

`braid: 'disabled'` is an explicit direct-SPQR escape hatch for
product-reviewed constraints. It is not downgrade recovery and does not relax
PQXDH strictness.

## Multi-device send

<!-- doc-snippet:skip requires-external-context -->
```ts
const result = await signal.send(recipientUserId, "hello");
await appMessages.insertOutgoing({
  messageId: result.messageId,
  conversationId,
  body: "hello",
  sentAt: result.clientTimestamp ?? result.timestamp,
  recipientDeviceCount: result.recipientDeviceCount,
});
```

## Direct device session

<!-- doc-snippet:skip requires-external-context -->
```ts
import { ProtocolAddress } from "@open-e2ee/signal-protocol-sdk";

const bob = ProtocolAddress.create("bob", 2);
await signal.establishSession(bob, bundle);
await signal.encryptMessage(bob, "linked-device hello");
```

## Username and ZK helpers

<!-- doc-snippet:skip requires-external-context -->
```ts
import {
  hashUsername,
  parseUsername,
} from "@open-e2ee/signal-protocol-sdk/username";
import { computeProfileKeyVersion } from "@open-e2ee/signal-protocol-sdk/zk/groups";

const parsed = parseUsername("alice.42");
const usernameHash = hashUsername(parsed.nickname, parsed.discriminator);
const version = computeProfileKeyVersion(profileKeyBytes, userIdBytes);
```

## Encrypted attachments

<!-- doc-snippet:skip requires-external-context -->
```ts
import { media } from "@open-e2ee/signal-protocol-sdk";

await signal.send(recipientUserId, photoBytes, {
  isBinary: true,
  mimeType: "image/jpeg",
  width: 1200,
  height: 800,
  thumbnail: thumbnailBase64,
  attachment: {
    transfer: media.createTusMediaAttachmentTransfer({
      chunkSizeBytes: 1024 * 1024,
    }),
    policy: media.MEDIA_ATTACHMENT_POLICY_PRESETS.Image,
    onProgress: (event) => {
      console.log(
        event.operation,
        event.phase,
        event.bytesTransferred,
        event.totalBytes,
      );
    },
  },
});

const attachment = await signal.uploadAttachment(photoBytes, {
  mimeType: "image/jpeg",
  fileName: "photo.jpg",
  width: 1200,
  height: 800,
  thumbnail: thumbnailBase64,
  attachment: {
    transfer: media.createTusMediaAttachmentTransfer({
      chunkSizeBytes: 1024 * 1024,
    }),
    policy: media.MEDIA_ATTACHMENT_POLICY_PRESETS.Image,
  },
});

const mediaWork = media.planMediaAttachmentProcessing({
  attachment,
  senderUserId,
  timestamp: messageTimestamp,
  processedDeliveryIds: await appMessages.processedMediaDeliveryIds(),
  cachedAttachmentIds: await appMediaCache.attachmentIds(),
  openedViewOnceDeliveryIds: await appMediaCache.openedViewOnceDeliveryIds(),
});

if (mediaWork.downloadJob) {
  await signal.media.download(
    {
      attachment,
      senderUserId,
      timestamp: messageTimestamp,
      processedDeliveryIds: await appMessages.processedMediaDeliveryIds(),
      cachedAttachmentIds: await appMediaCache.attachmentIds(),
      openedViewOnceDeliveryIds:
        await appMediaCache.openedViewOnceDeliveryIds(),
    },
    {
      transfer: appMediaTransferAdapter,
      onCheckpoint: appMediaTransfers.save,
    },
  );
}

const downloaded = await signal.downloadAttachment(attachment, {
  transfer: media.createByteRangeMediaAttachmentTransfer({
    chunkSizeBytes: 1024 * 1024,
    partialStore: appMediaTransfers.partialStore(),
  }),
  resume: await appMediaTransfers.resumeState(mediaWork.attachmentId),
  onCheckpoint: (checkpoint) => appMediaTransfers.save(checkpoint),
});

const opened = media.planMediaAttachmentOpen({
  attachment,
  senderUserId,
  timestamp: messageTimestamp,
});

if (opened.viewOnceOpenSync) {
  await signal.syncViewOnceOpenToLinkedDevices(opened.viewOnceOpenSync);
}

if (opened.cleanup?.deleteLocalCache) {
  await appMediaCache.delete(opened.cleanup.storageId);
}

const deleteSync = media.planMediaAttachmentDeleteSync({
  attachment,
  reason: media.MediaAttachmentCleanupReason.MessageDeleted,
  deletedAt: Date.now(),
});

await appMediaCache.delete(deleteSync.storageId);
await signal.syncMediaAttachmentDeleteToLinkedDevices(deleteSync);

await signal.media.cleanup(
  {
    cleanup: media.planMediaAttachmentCleanup(
      attachment,
      media.MediaAttachmentCleanupReason.MessageExpired,
    ),
    includeLocal: true,
    includeRemote: true,
    includeSync: true,
  },
  {
    transfer: appMediaTransferAdapter,
  },
);
```

See the [encrypted media guide](../media/README.md) and
[remote object store](../remote/README.md) for the transfer and object-store
contracts these examples compose.
