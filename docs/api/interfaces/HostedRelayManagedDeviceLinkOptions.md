[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / HostedRelayManagedDeviceLinkOptions

# Interface: HostedRelayManagedDeviceLinkOptions

## Extends

- `Omit`\<[`SignalProtocolClientCompositionOptions`](SignalProtocolClientCompositionOptions.md), `"adapters"` \| `"identity"` \| `"sealedSender"`\>

## Properties

### activeDeviceStorage

> `readonly` **activeDeviceStorage**: [`ISignalProtocolLocalStore`](ISignalProtocolLocalStore.md)

***

### adapters

> `readonly` **adapters**: `Omit`\<[`SignalProtocolClientCompositionOptions`](SignalProtocolClientCompositionOptions.md)\[`"adapters"`\], `"relay"`\>

***

### contentAdapter?

> `optional` **contentAdapter?**: [`SignalProtocolContentAdapter`](SignalProtocolContentAdapter.md)

Application-provided content adapter.

This is the boundary between the protocol layer and app-specific content,
notification batching, and privacy preference policy.

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`contentAdapter`](SignalProtocolClientConfig.md#contentadapter)

***

### enableDebugLogging?

> `optional` **enableDebugLogging?**: `boolean`

Enable debug logging
Default: false
Recommended: Enable in development, disable in production

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`enableDebugLogging`](SignalProtocolClientConfig.md#enabledebuglogging)

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

> `optional` **issueProfileKeyCredential?**: (`request`) => `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Override the relay's blinded profile-key credential issuance transport.

##### Parameters

###### request

`Uint8Array`

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

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`groups`](SignalProtocolClientConfig.md#groups)

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
Hook errors are caught internally and will not affect core functionality.

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

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`hooks`](SignalProtocolClientConfig.md#hooks)

***

### hosted

> `readonly` **hosted**: `object`

#### adapter

> `readonly` **adapter**: [`HostedRelayManagedDeviceLinkAdapter`](HostedRelayManagedDeviceLinkAdapter.md)

#### onProgress?

> `readonly` `optional` **onProgress?**: [`HostedRelayIdentityProgressCallback`](../type-aliases/HostedRelayIdentityProgressCallback.md)

#### publishableKey

> `readonly` **publishableKey**: `string`

#### sealedSenderAccessMode?

> `readonly` `optional` **sealedSenderAccessMode?**: `SealedSenderAccessMode`

***

### keyRefreshIntervalMs?

> `optional` **keyRefreshIntervalMs?**: `number`

Key refresh interval in milliseconds.

Controls how often the client rotates signed prekeys and Kyber (last-resort) prekeys.
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

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`keyRefreshIntervalMs`](SignalProtocolClientConfig.md#keyrefreshintervalms)

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

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`logger`](SignalProtocolClientConfig.md#logger)

***

### maxPreKeyAgeMs?

> `optional` **maxPreKeyAgeMs?**: `number`

Maximum allowed prekey age in milliseconds.

If prekeys exceed this age, the app should block message sending to force
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

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`maxPreKeyAgeMs`](SignalProtocolClientConfig.md#maxprekeyagems)

***

### media?

> `optional` **media?**: [`SignalProtocolClientMediaConfig`](SignalProtocolClientMediaConfig.md)

App-owned media lifecycle callbacks for the SignalProtocolClient media queue.

The existing Signal Protocol local storage adapter persists the queue
itself. These callbacks keep local bytes, plaintext caches, and product
state in the app layer. There they can share file permissions, UI state,
and app database ownership.

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

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`media`](SignalProtocolClientConfig.md#media)

***

### onGroupSenderKeyRotated?

> `optional` **onGroupSenderKeyRotated?**: (`groupId`, `newGeneration`) => `void`

Runs after the client rotates a group sender key.

Useful for logging, analytics, or triggering UI updates when
the client rotates sender keys after membership changes.

#### Parameters

##### groupId

`string`

The group whose sender key changed

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

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`onGroupSenderKeyRotated`](SignalProtocolClientConfig.md#ongroupsenderkeyrotated)

***

### onPreKeyLow?

> `optional` **onPreKeyLow?**: (`remaining`) => `void`

Callback for the moment one-time prekeys run low

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

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`onPreKeyLow`](SignalProtocolClientConfig.md#onprekeylow)

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

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`onProgress`](SignalProtocolClientConfig.md#onprogress)

***

### preKeyCheckThrottleMs?

> `optional` **preKeyCheckThrottleMs?**: `number`

Prekey check throttle interval in milliseconds.

Controls how often the client checks the prekey count on app activation.
Prevents unnecessary server queries when the app is repeatedly foregrounded.

#### Default

```ts
43200000 (12 hours)
```

#### See

https://signal.org/docs/specifications/pqxdh/#publishing-keys

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`preKeyCheckThrottleMs`](SignalProtocolClientConfig.md#prekeycheckthrottlems)

***

### preKeyLowThreshold?

> `optional` **preKeyLowThreshold?**: `number`

Threshold for prekey low warning
Default: 50 (warn when fewer than 50 one-time prekeys remain)

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`preKeyLowThreshold`](SignalProtocolClientConfig.md#prekeylowthreshold)

***

### preKeyMaintenance?

> `optional` **preKeyMaintenance?**: [`PreKeyMaintenanceStore`](PreKeyMaintenanceStore.md)

App-provided prekey bookkeeping store.

Needed for SQLite-backed adapters that track replaced prekeys separately
from the protocol-facing local store interface.

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`preKeyMaintenance`](SignalProtocolClientConfig.md#prekeymaintenance)

***

### protocol?

> `optional` **protocol?**: [`SignalProtocolConfig`](SignalProtocolConfig.md)

#### Inherited from

[`SignalProtocolClientCompositionOptions`](SignalProtocolClientCompositionOptions.md).[`protocol`](SignalProtocolClientCompositionOptions.md#protocol)

***

### ratchetConfig?

> `optional` **ratchetConfig?**: [`DoubleRatchetConfig`](DoubleRatchetConfig.md)

Double Ratchet algorithm configuration

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`ratchetConfig`](SignalProtocolClientConfig.md#ratchetconfig)

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

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`senderKeys`](SignalProtocolClientConfig.md#senderkeys)

***

### throwDetailedErrors?

> `optional` **throwDetailedErrors?**: `boolean`

Throw detailed errors instead of generic messages
Default: false (generic error messages for security)
Recommended: Enable in development for debugging

#### Inherited from

[`SignalProtocolClientConfig`](SignalProtocolClientConfig.md).[`throwDetailedErrors`](SignalProtocolClientConfig.md#throwdetailederrors)
