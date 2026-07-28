[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / SignalProtocolClientConfig

# Interface: SignalProtocolClientConfig

Low-level SignalProtocolClient configuration options.

Application code should usually prefer `createSignalProtocolClient()`, which groups
account identity, adapters, and protocol policy into a friendlier shape. Use
this config directly when lower-level integration code already has flattened
client options.

## Example

```typescript
import {
  createSignalProtocolClient,
  SignalProtocolClient,
} from '@open-e2ee/signal-protocol-sdk';
import {
  convexRelay,
  type ConvexSignalProtocolRelayApi,
} from '@open-e2ee/signal-protocol-sdk/remote/relay/convex';
import { api } from '../convex/_generated/api';

const signalApi = api.signal satisfies ConvexSignalProtocolRelayApi;
const relay = convexRelay({ convex, api: signalApi, currentUserId: userId });

// Preferred app-facing composition.
const signal = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
});

// Low-level factory with the same underlying options.
const advancedSignalProtocol = await SignalProtocolClient.create(userId, {
  storage,
  relay,
  onProgress,
  ratchetConfig: {
    maxSkip: 2000,
    keyExpirationMs: 14 * 24 * 60 * 60 * 1000 // 14 days
  },
  enableDebugLogging: true
});
```

## Properties

### aci?

> `optional` **aci?**: [`ServiceId`](ServiceId.md)

This account's ACI for Group System credential presentation.

Required when `groups` is configured.

***

### contentAdapter?

> `optional` **contentAdapter?**: [`SignalProtocolContentAdapter`](SignalProtocolContentAdapter.md)

Application-provided content adapter.

This is the boundary between the protocol layer and app-specific content,
notification batching, and privacy preference policy.

***

### deviceId?

> `optional` **deviceId?**: `number`

Device identifier for multi-device support

- 1 = Primary device (default)
- 2-5 = Linked devices

Device 1 bootstraps identity locally. Devices 2-5 must already have a
provisioned identity imported into the provided storage before
`SignalProtocolClient.create()` is called.

Prekeys and sessions remain device-specific; account identity is shared.
Maximum 5 devices per user (1 primary + 4 linked).

#### Default

```ts
1 (primary device)
```

#### Example

```typescript
// Primary device
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  deviceId: 1
});

// Linked device (from QR code provisioning)
const signal = await SignalProtocolClient.create(userId, {
  storage: provisionedLinkedDeviceStorage,
  deviceId: 2
});
```

***

### enableDebugLogging?

> `optional` **enableDebugLogging?**: `boolean`

Enable debug logging
Default: false
Recommended: Enable in development, disable in production

***

### enablePniKeys?

> `optional` **enablePniKeys?**: `boolean`

Enable PNI (Phone Number Identity) cryptographic key generation

When `true`, generates and syncs both ACI and PNI identity keys, prekeys,
and Kyber prekeys for applications that maintain both account identifiers.

When `false` (default), only ACI keys are generated and synchronized. Use
this for applications whose account model does not require PNI keys.

The PNI UUID on the users table is unaffected — it can still exist for ZK
group credentials without generating cryptographic keys.

#### Default

```ts
false
```

***

### groups?

> `optional` **groups?**: `object`

Group System configuration.
Required for group state management (create, sync, membership changes).

#### allowUnauthenticatedGroupHistory?

> `optional` **allowUnauthenticatedGroupHistory?**: `boolean`

Explicitly accept group history without server signatures.

This selects the documented non-conforming deployment mode and emits a
visible configuration warning.

#### endorsementManager?

> `optional` **endorsementManager?**: [`EndorsementManager`](../classes/EndorsementManager.md)

Pre-constructed EndorsementManager for group send endorsement-based auth.

#### issueCredential?

> `optional` **issueCredential?**: () => `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Override the relay's auth-credential issuance transport.

##### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

#### issueProfileKeyCredential?

> `optional` **issueProfileKeyCredential?**: () => `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Override the relay's profile-key credential issuance transport.

##### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

#### onConfigurationWarning?

> `optional` **onConfigurationWarning?**: (`warning`) => `void`

Receive the §12.3 non-conforming deployment warning.

##### Parameters

###### warning

`GroupConfigurationWarning`

##### Returns

`void`

#### profileKey

> **profileKey**: `Uint8Array`

This account's 32-byte profile key.

#### resolveAciBytesByUserIds?

> `optional` **resolveAciBytesByUserIds?**: (`userIds`) => `Promise`\<`Map`\<`string`, `Uint8Array`\<`ArrayBufferLike`\>\>\>

Resolve member ACIs without importing app content models into the client.

##### Parameters

###### userIds

`string`[]

##### Returns

`Promise`\<`Map`\<`string`, `Uint8Array`\<`ArrayBufferLike`\>\>\>

#### server?

> `optional` **server?**: [`IGroupServer`](IGroupServer.md)

Override `relay.groupServer.server` for a custom deployment.

#### store?

> `optional` **store?**: [`IGroupStateStore`](IGroupStateStore.md)

Override the SDK local storage adapter for group state.

#### trustRoot

> **trustRoot**: `Uint8Array`

Versioned serialized trust root pinned by the application at build time.

This value is never fetched from the relay and trusted at runtime.

#### Example

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  relay,
  aci,
  pni,
  groups: {
    trustRoot: GROUP_TRUST_ROOT,
    profileKey,
  }
});
```

***

### hooks?

> `optional` **hooks?**: [`SignalProtocolClientHooks`](SignalProtocolClientHooks.md)

Event hooks for Signal Protocol lifecycle events

Provides integration points for applications to react to:
- Session establishment/deletion
- Key rotation
- Message encryption/decryption
- Errors and cleanup operations

All hooks are optional and support both sync and async implementations.
Hook errors are caught internally and won't affect core functionality.

Common use cases:
- Cache invalidation (ContentManager, React Query)
- Analytics and monitoring (Sentry, DataDog)
- State management integration (Redux, Zustand)
- User notifications

#### Examples

**Basic usage**

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  hooks: {
    onSessionEstablished: (sessionId) => {
      ContentManager.invalidateSession(sessionId);
    },
    onKeyRotated: (keyType) => {
      analytics.track('Key Rotated', { keyType });
    }
  }
});
```

**Error tracking**

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  hooks: {
    onDecryptionError: (sessionId, error) => {
      Sentry.captureException(error, {
        tags: { sessionId }
      });
    }
  }
});
```

***

### keyRefreshIntervalMs?

> `optional` **keyRefreshIntervalMs?**: `number`

Key refresh interval in milliseconds.

Controls how often signed prekeys and Kyber (last-resort) prekeys are rotated.
Per PQXDH specification Section 3.2, both key types use the same rotation
schedule for synchronized post-quantum security.

#### Default

```ts
172800000 (2 days)
```

#### Examples

**Default rotation interval**

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  keyRefreshIntervalMs: 2 * 24 * 60 * 60 * 1000 // 2 days
});
```

**Weekly rotation (lower bandwidth)**

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  keyRefreshIntervalMs: 7 * 24 * 60 * 60 * 1000 // 7 days
});
```

#### See

https://signal.org/docs/specifications/pqxdh/#publishing-keys

***

### logger?

> `optional` **logger?**: [`ILogger`](ILogger.md)

Custom logger implementation

Default: Environment-aware console logging
- Development: verbose (debug, info, warn, error, breadcrumb)
- Production: minimal (warn, error only)

#### Examples

**Using custom logger**

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  logger: {
    info: (msg, data) => myLogger.log('info', msg, data),
    error: (msg, err) => myLogger.log('error', msg, err),
    warn: (msg, data) => myLogger.log('warn', msg, data)
  }
});
```

**Using console directly**

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  logger: console // Works directly!
});
```

**Using pino**

```typescript
import pino from 'pino';
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  logger: pino({ level: 'info' })
});
```

**Silent mode**

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  logger: {} // All methods optional
});
```

***

### maxPreKeyAgeMs?

> `optional` **maxPreKeyAgeMs?**: `number`

Maximum allowed prekey age in milliseconds.

If prekeys exceed this age, message sending should be blocked to force
key rotation. Provides a safety buffer above keyRefreshIntervalMs.

With the default two-day refresh interval, the default maximum age leaves
a twelve-day recovery window.

#### Default

```ts
1209600000 (14 days)
```

#### Example

**Default maximum age**

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  maxPreKeyAgeMs: 14 * 24 * 60 * 60 * 1000 // 14 days
});
```

#### See

https://signal.org/docs/specifications/pqxdh/#publishing-keys

***

### media?

> `optional` **media?**: [`SignalProtocolClientMediaConfig`](SignalProtocolClientMediaConfig.md)

App-owned media lifecycle callbacks for the SignalProtocolClient media queue.

The queue itself is persisted through the existing Signal Protocol local storage
adapter. These callbacks keep local bytes, plaintext caches, and product
state in the app layer where they can share file permissions, UI state, and
app database ownership.

#### Example

```typescript
const signal = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay, remoteObjectStore },
  media: {
    loadLocalAttachment: async ({ localMediaId }) => appDrafts.readBytes(localMediaId),
    saveUploadedAttachment: async ({ localMediaId, attachment }) =>
      appPointers.save(localMediaId, attachment),
    saveDownloadedAttachment: async ({ attachmentId, downloaded }) =>
      appMediaCache.save(attachmentId, downloaded.data),
    deleteLocalAttachment: async ({ attachmentId }) => appMediaCache.delete(attachmentId),
  },
});
```

***

### onGroupSenderKeyRotated?

> `optional` **onGroupSenderKeyRotated?**: (`groupId`, `newGeneration`) => `void`

Called when a group sender key is rotated.

Useful for logging, analytics, or triggering UI updates when
sender keys are rotated due to membership changes.

#### Parameters

##### groupId

`string`

The group whose sender key was rotated

##### newGeneration

`number`

The new generation number of the sender key

#### Returns

`void`

#### Example

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  onGroupSenderKeyRotated: (groupId, newGeneration) => {
    console.log(`Group ${groupId} sender key rotated to gen ${newGeneration}`);
    analytics.track('sender_key_rotated', { groupId, newGeneration });
  }
});
```

***

### onPreKeyLow?

> `optional` **onPreKeyLow?**: (`remaining`) => `void`

Callback when one-time prekeys are running low

Called when prekey count drops below the threshold (default: 50).
Use this to trigger prekey replenishment to prevent session
establishment failures.

#### Parameters

##### remaining

`number`

#### Returns

`void`

#### Example

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  onPreKeyLow: (remaining) => {
    console.warn(`Only ${remaining} prekeys remaining, replenishment needed`);
    // Trigger server-side prekey generation
    backend.replenishPrekeys(userId);
  }
});
```

***

### onProgress?

> `optional` **onProgress?**: [`ProgressCallback`](../type-aliases/ProgressCallback.md)

Progress callback for initialization and relay sync operations.

Receives updates during:
- Key generation
- Prekey bundle generation
- Relay upload

#### Example

```typescript
const signal = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
  onProgress: ({ stage, percent, message }) => {
    console.log(`${stage}: ${percent}% - ${message}`);
  }
});
```

***

### pni?

> `optional` **pni?**: [`ServiceId`](ServiceId.md)

This account's optional PNI for Group System credential presentation.

***

### preKeyCheckThrottleMs?

> `optional` **preKeyCheckThrottleMs?**: `number`

Prekey check throttle interval in milliseconds.

Controls how often prekey count checks are performed on app activation.
Prevents unnecessary server queries when the app is repeatedly foregrounded.

#### Default

```ts
43200000 (12 hours)
```

#### See

https://signal.org/docs/specifications/pqxdh/#publishing-keys

***

### preKeyLowThreshold?

> `optional` **preKeyLowThreshold?**: `number`

Threshold for prekey low warning
Default: 50 (warn when fewer than 50 one-time prekeys remain)

***

### preKeyMaintenance?

> `optional` **preKeyMaintenance?**: [`PreKeyMaintenanceStore`](PreKeyMaintenanceStore.md)

App-provided prekey bookkeeping store.

Needed for SQLite-backed adapters that track replaced prekeys separately
from the protocol-facing local store interface.

***

### protocol?

> `optional` **protocol?**: [`SignalProtocolConfig`](SignalProtocolConfig.md)

Developer-facing protocol policy.

The default is strict post-quantum behavior with the specification-defined
ML-KEM Braid SPQR mode. Use `compatible` only when the product deliberately
supports genuinely non-PQ peers. Use `braid: 'disabled'` only when a
product-reviewed constraint requires the local direct SPQR mode.

#### Default

```ts
{ postQuantum: 'required', braid: 'required' }
```

#### Examples

**Strict post-quantum mode**

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  protocol: {
    postQuantum: 'required',
    braid: 'required'
  }
});
```

**Compatibility with non-PQ peers**

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  protocol: {
    postQuantum: 'compatible',
    braid: 'required'
  }
});
```

**Explicit direct SPQR mode**

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  protocol: {
    postQuantum: 'required',
    braid: 'disabled'
  }
});
```

***

### protocolManager?

> `optional` **protocolManager?**: [`ISignalProtocolManager`](ISignalProtocolManager.md)

Signal Protocol Manager implementation (for advanced use cases)
Default: Creates new SignalProtocolManager instance

***

### protocolStrategy?

> `optional` **protocolStrategy?**: [`ProtocolStrategyConfig`](ProtocolStrategyConfig.md)

Advanced protocol strategy configuration.

Most application code should use `protocol.postQuantum` instead. This seam
exists for diagnostics, telemetry callbacks, and advanced tuning.

#### Example

**Track protocol usage**

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  protocolStrategy: {
    onProtocolSelected: (event) => {
      analytics.track('Protocol Selected', {
        pq: event.usedPQXDH,
        tripleRatchet: event.usedTripleRatchet,
        compatibilityFallback: event.usedClassicalFallback,
        fallbackReason: event.classicalFallbackReason
      });
    }
  }
});
```

***

### ratchetConfig?

> `optional` **ratchetConfig?**: [`DoubleRatchetConfig`](DoubleRatchetConfig.md)

Double Ratchet algorithm configuration

***

### relay?

> `optional` **relay?**: [`ISignalProtocolRelayServer`](ISignalProtocolRelayServer.md)

Relay adapter for server synchronization.

If provided, the client will automatically:
1. Generate prekey bundle
2. Upload public keys to the relay server
3. Provide progress updates via onProgress callback

If omitted, client operates in local-only mode.

#### Example

```typescript
import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
import {
  convexRelay,
  type ConvexSignalProtocolRelayApi,
} from '@open-e2ee/signal-protocol-sdk/remote/relay/convex';
import { api } from '../convex/_generated/api';

const signalApi = api.signal satisfies ConvexSignalProtocolRelayApi;
const relay = convexRelay({ convex, api: signalApi, currentUserId: userId });

const signal = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
});
```

***

### remoteObjectStore?

> `optional` **remoteObjectStore?**: [`SignalProtocolRemoteObjectStore`](SignalProtocolRemoteObjectStore.md)

Remote object storage adapter for encrypted file uploads (two-layer encryption)

If provided, enables encrypted file upload (two-layer encryption):
1. Generate AES-256-GCM key
2. Encrypt file bytes with AES
3. Upload encrypted bytes to object storage
4. Send storage ID + key via Signal Protocol

If omitted, file upload operations will throw an error.

#### Example

```typescript
import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
import { convexR2ObjectStore } from '@open-e2ee/signal-protocol-sdk/remote/object-store/convex-r2';
import { api } from '../convex/_generated/api';

const remoteObjectStore = convexR2ObjectStore({
  convex,
  api: api.signalObjectStore,
});

const signal = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay, remoteObjectStore },
});

// Send file bytes
const fileBytes = new Uint8Array(await file.arrayBuffer());
await signal.send('bob', fileBytes, { mimeType: 'image/jpeg' });
```

***

### sealedSender?

> `optional` **sealedSender?**: [`SealedSenderConfig`](SealedSenderConfig.md)

Sealed Sender configuration for anonymous message delivery.

When configured, messages are wrapped with sealed sender encryption
that hides the sender's identity from the server. The recipient can
still verify the sender via the embedded certificate.

Requires:
- A relay deployment secret (`OE_GROUPS_SERVER_SECRET`), from which the
  certificate signing keys are derived — there is no separate signing-key
  variable.
- The deployment's Ed25519 sender-certificate root public key pinned in
  `trustRoots` at build time. Print it with `npx oe-groups trust-root`,
  which reports it as `sealed sender trust root` alongside the group trust
  root. Never fetch it from a relay at runtime: a relay that can choose the
  root it is validated against can mint certificates for any sender.

With `trustRoots` empty, inbound sealed-sender validation stays disabled
and sends fall back to identified delivery, which deanonymizes the sender
to the relay.

#### See

https://signal.org/blog/sealed-sender/

#### Example

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  sealedSender: {
    trustRoots: [trustRootPublicKeyBytes],
    certificateProvider: async () => {
      return await convex.mutation(api.signal.certificates.issueSenderCertificate, { deviceId: 1 });
    },
    accessMode: 'unrestricted',
  }
});
```

***

### senderKeys?

> `optional` **senderKeys?**: [`SenderKeysConfig`](SenderKeysConfig.md)

Sender Keys (group messaging) configuration.

Controls HKDF info strings, DoS protection limits, and out-of-order
message handling for group encryption.

#### Examples

**Custom protocol branding**

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  senderKeys: {
    hkdfInfoString: 'MyApp Group V1'
  }
});
```

**Production-recommended limits (these are the defaults)**

```typescript
const signal = await SignalProtocolClient.create(userId, {
  storage: customStorage,
  senderKeys: {
    maxChainAdvance: 2000,      // DoS protection
    maxSkippedKeys: 2000        // Memory limit
  }
});
```

***

### storage

> **storage**: [`ISignalProtocolLocalStore`](ISignalProtocolLocalStore.md)

Local store implementation for the current runtime.
Required by SignalProtocolClient.create().

***

### throwDetailedErrors?

> `optional` **throwDetailedErrors?**: `boolean`

Throw detailed errors instead of generic messages
Default: false (generic error messages for security)
Recommended: Enable in development for debugging
