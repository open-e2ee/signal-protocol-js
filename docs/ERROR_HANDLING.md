# Error Handling Guide

How to handle the errors that the `@open-e2ee/signal-protocol-sdk` library throws.

## Overview

The library uses a structured error system with stable programmatic codes:

- **EncryptionError**: Base error class with error codes and context
- **Specialized Error Classes**: For specific error types requiring special handling
- **Error Codes**: Enumerated codes for programmatic error handling

## Error Classes

### EncryptionError (Base Class)

Every error in the `EncryptionErrorCode` family extends `EncryptionError`:

<!-- doc-snippet:skip requires-existing-client-and-session -->
```typescript
import { EncryptionError, EncryptionErrorCode } from '@open-e2ee/signal-protocol-sdk';

try {
  await signal.encryptMessage(remoteAddress, plaintext);
} catch (error) {
  if (error instanceof EncryptionError) {
    console.log('Error code:', error.code);
    console.log('Context:', error.context);
    console.log('Original error:', error.originalError);
  }
}
```

### Specialized Error Classes

#### UntrustedIdentityError

Thrown when an identity key is not trusted. Requires user intervention (safety number verification).

<!-- doc-snippet:skip requires-untrusted-identity-fixture -->
```typescript
import { isUntrustedIdentityError } from '@open-e2ee/signal-protocol-sdk';

try {
  await signal.establishSession(remoteAddress, bundle);
} catch (error) {
  if (isUntrustedIdentityError(error)) {
    // Show safety number verification UI
    const safetyNumber = await signal.verify(remoteUserId);
    // Ask user to verify safety number
    showVerificationDialog(safetyNumber);
    // Pass back the exact immutable evidence that was displayed.
    await signal.confirmSafetyNumber(safetyNumber.confirmation);
  }
}
```

## Error Codes

The SDK throws every code below. An error-surface check parses the SDK for the
construction sites that decide that. It fails the build if a code or a subclass
survives that nothing produces. A code documented here is therefore one an
application can branch on. The check runs on every change, with the rest of the
checks that [ASSURANCE.md](./ASSURANCE.md) describes.

The tables list the complete `EncryptionErrorCode` enum. The error-surface check
holds each member to a production construction site.

### Session Errors

| Code | Cause | Application response |
|---|---|---|
| `SESSION_NOT_FOUND` | No session exists for the address. | Establish a new session. |
| `SESSION_CORRUPTED` | Stored session data is invalid. | Delete the damaged session, then establish one. |
| `RECIPIENT_NOT_REGISTERED` | The recipient has no published prekey bundle. | Wait for recipient registration, then retry. |
| `PREKEY_FETCH_RATE_LIMITED` | The relay refused another prekey fetch. | Wait for the relay limit, then retry. |
| `SESSION_ESTABLISHMENT_FAILED` | Session setup failed after retries. | Inspect `originalError`, then retry after its cause is fixed. |

### Message Errors

| Code | Cause | Application response |
|---|---|---|
| `INVALID_CIPHERTEXT` | The ciphertext format is invalid. | Reject the message. |
| `DECRYPTION_FAILED` | Available session state could not decrypt the message. | Let the retry flow recover, or inspect the session state. |
| `ENCRYPTION_FAILED` | The SDK could not encrypt the message. | Inspect the session state and `originalError`. |
| `MESSAGE_DUPLICATE` | The session processed this message before. | Discard the duplicate. |
| `TOO_MANY_SKIPPED_MESSAGES` | The message exceeded the skipped-key bound. | Reset the affected session. |
| `REPLAY_DETECTED` | Envelope and encrypted-content timestamps differ. | Reject the message as a replay. |
| `SENDER_KEY_EXPIRED` | The sender key exceeded its rotation period. | Rotate and redistribute the sender key. |

### Identity and Trust Errors

| Code | Cause | Application response |
|---|---|---|
| `UNTRUSTED_IDENTITY` | The peer identity is unverified or changed. | Verify the safety number before acceptance. |
| `IDENTITY_MISMATCH` | The message identity does not match the expected sender. | Reject the message and inspect the identity state. |
| `SIGNATURE_VERIFICATION_FAILED` | A signature is invalid. | Reject the signed value. |

### Prekey and Session Establishment Errors

| Code | Cause | Application response |
|---|---|---|
| `INVALID_PREKEY_BUNDLE` | A prekey bundle is malformed or inconsistent. | Reject it and fetch a current bundle. |
| `PREKEY_NOT_FOUND` | The required prekey is unavailable. | Fetch current peer keys or rotate local keys, as the operation requires. |
| `PREKEY_ROTATION_REQUIRED` | A local signed or Kyber prekey is too old. | Rotate prekeys before another send. |

### Ratchet Errors

| Code | Cause | Application response |
|---|---|---|
| `COUNTER_OVERFLOW` | A message counter reached its safe bound. | Rotate the session or ratchet epoch. |
| `INVALID_DH_KEY` | A DH public key is malformed or invalid. | Reject the key and its message. |

### Storage Errors

| Code | Cause | Application response |
|---|---|---|
| `KEY_STORAGE_ERROR` | A key-storage operation failed. | Inspect `originalError`, then retry or reinitialize storage. |
| `STORAGE_QUOTA_EXCEEDED` | The storage origin ran out of space. | Free storage space, then retry the rejected write or open. |
| `SECRET_VAULT_REQUIRED` | An operation that keeps a local secret ran without a `SignalProtocolLocalSecretVault`. | Pass a vault, such as `ExpoSecureStoreSignalProtocolSecretVault`, or the application's own. |
| `LOCAL_STORE_KEY_LOST` | A local store holds data, but its secret vault holds no key for that data. | Restore the vault entry, or reset the store. A reset deletes the local data. |
| `SQLITE_ENGINE_UNAVAILABLE` | The SQLite Wasm engine did not load in its web worker. Usually the worker's Content Security Policy does not allow `'wasm-unsafe-eval'`. | Allow `'wasm-unsafe-eval'` in `script-src` on the worker script response, and serve the Wasm file as `application/wasm`. |
| `OPFS_UNAVAILABLE` | The browser cannot keep a SQLite database in the origin private file system, for example in a private or ephemeral context. | Use the IndexedDB store in this runtime. |
| `OPFS_FILE_BUSY` | The web SQLite store could not open its database file this time, usually because another tab of the origin still holds the file. The file is unchanged. | Retry later. Do not change to another store: the data stays in this one. |

### Initialization and Protocol Policy Errors

| Code | Cause | Application response |
|---|---|---|
| `INITIALIZATION_FAILED` | Client or group initialization failed. | Inspect `originalError` and the configuration. |
| `SECURE_RANDOM_UNAVAILABLE` | The runtime has no global `crypto.getRandomValues`. The SDK throws `SecureRandomUnavailableError` from `@open-e2ee/signal-protocol-sdk/types`. | On React Native and Expo, install `react-native-get-random-values` 2.x or `react-native-quick-crypto` and load it before the first SDK call. |
| `PQXDH_REQUIRED` | Every new session requires PQXDH, and the peer bundle has no ML-KEM prekey. No classical key agreement exists. | Wait for new peer keys or queue the message. |
| `PQXDH_FAILED` | The PQXDH exchange failed. | Abort setup and inspect `originalError`. |
| `TRIPLE_RATCHET_REQUIRED` | Triple Ratchet applies, but the session has no PQXDH result. | Establish a PQXDH session first. |

### SPQR Errors

| Code | Cause | Application response |
|---|---|---|
| `SPQR_EPOCH_OUT_OF_RANGE` | The requested epoch is too old or not established. | Reject the message and synchronize session state. |
| `SPQR_MESSAGE_JUMP_TOO_LARGE` | The message jump exceeds the configured bound. | Reject the message. |
| `SPQR_COUNTER_OVERFLOW` | The SPQR message counter reached its bound. | Rotate the SPQR epoch. |
| `SPQR_INVALID_CIPHERTEXT` | An SPQR ML-KEM ciphertext has an invalid form. | Reject the message. |
| `SPQR_VERSION_MISMATCH` | Peer and local SPQR version ranges do not overlap. | Update the peer or the required protocol policy. |

### Sealed Sender and State Errors

| Code | Cause | Application response |
|---|---|---|
| `SEALED_SENDER_AUTH_FAILED` | The relay rejected sealed-sender authorization. | Reauthorize or use identified delivery when policy permits it. |
| `INVALID_STATE` | The requested operation is invalid for current state. | Correct the call order or synchronize state. |

## Relay Protocol Errors

The Relay serves a set of Relay protocol versions. This SDK speaks
protocol version 1. Two errors come from that set. Neither is an `EncryptionError`.

| Error | Cause | Application response |
|---|---|---|
| `HostedRelayUpgradeRequiredError` | The Relay no longer serves version 1. `code` is `UPGRADE_REQUIRED`, `status` is the HTTP status (426), and `retryable` is false. | Ship a newer SDK. The same request fails again, so do not retry it. |
| `PROTOCOL_UNSUPPORTED` | The Relay does not serve version 1. The request fails with status 400, the `code` `PROTOCOL_UNSUPPORTED`, and `retryable` true. | Retry later. The Relay never rolls back below a version that a published SDK sends, so this is a transient fault, not a planned state. |

The SDK does not retry an HTTP request that `UPGRADE_REQUIRED` refuses. Each
Relay route that answers with a JSON body throws
`HostedRelayUpgradeRequiredError`. An attachment download does not read the
response body, so it reports the 426 as a
[`MediaAttachmentError`](./api/namespaces/media/classes/MediaAttachmentError.md)
with the code `download-failed` and the `status` 426.

The mailbox subscription stops for the same refusal on its socket, with the
state `stopped` and the reason `upgrade-required`. It does not reconnect and
does not pull. For `PROTOCOL_UNSUPPORTED` on its socket, the subscription
reconnects with its usual backoff. See [`RelayConnectionReason`](./api/type-aliases/RelayConnectionReason.md).

The subscription also stops when the Relay refuses its socket token request or
a pull conclusively. The refusal has `retryable` false and the code
`AUTHORITY_DENIED`, `NOT_FOUND`, or `OPERATION_EXPIRED`. The state is `stopped`
and the reason is `authority-refused`. A refusal with `retryable` true, for
example a missing Relay binding, goes to the retry schedule. A `NOT_FOUND` on
the socket token request is a refusal of this device instead, as
[Relay Device Errors](#relay-device-errors) describes. See
[`RelayConnectionState`](./api/interfaces/RelayConnectionState.md).

A client call can wrap the error in an `EncryptionError`. It is then the
`originalError`.

<!-- doc-snippet:skip requires-existing-client -->
```typescript
import {
  EncryptionError,
  HostedRelayUpgradeRequiredError,
} from '@open-e2ee/signal-protocol-sdk';

function upgradeRequired(error: unknown): boolean {
  return (
    error instanceof HostedRelayUpgradeRequiredError ||
    (error instanceof EncryptionError &&
      error.originalError instanceof HostedRelayUpgradeRequiredError)
  );
}

try {
  await signal.send(remoteUserId, plaintext);
} catch (error) {
  // Only a newer SDK can send again. Ask the user to update the app.
  if (upgradeRequired(error)) showUpdateRequired();
  else throw error;
}
```

### Stale Devices

A direct message, a sync copy, a sender-key distribution, a group device
message, a receipt, and a retry request go to one device. Each of these
posts names the registration ID of the recipient session. A shared group
message names the registration of each destination device. The identified
route and both sealed routes send the registration. A sealed post sends no
sender identity. A post to a device with no session names none.

The Relay compares this value with the current registration of the device.
A device that was reinstalled with the same device ID has a new
registration. The Relay then refuses the post:

- The identified route and the sealed direct route answer HTTP 410 with
  the code `STALE_DEVICE`. The sealed direct route takes an access key or
  the group endorsement of the one recipient account.
- The sealed group route refuses only that destination. Its receipt names
  each refused destination with the code `STALE_DEVICE`. The refused count
  alone names no device, so the SDK infers no code from it. A one-device post
  goes on this route only after a fallback from the direct route. See
  [Sealed Route Rejections](#sealed-route-rejections).

The SDK handles this refusal for each of these post kinds. It refreshes
the session of the device once and posts again. A direct message, a sync
copy, a sender-key distribution, a group device message, and a receipt are
encrypted again under the new session and get a new transport ID. A retry
request is not encrypted, so it keeps its envelope: the second post has the
same transport ID and names the registration of the new session. The
application does not have to act. A retry request ends with the terminal
class `missing-sender` only when the Relay has no bundle for the device, or
when the device refuses the request again after the refresh. When the
refresh of a receipt or a retry request fails for another reason, the SDK
keeps the stale session and posts the item again later. A device that a
shared group message names gets the same repair when the receipt refuses it.

The registration field never identifies the sender. A sealed post that
names an old registration tells the Relay only that some sender still has
a session from before the reinstall. The post carries no sender identity,
so it does not tell the Relay which sender that is.

### Sealed Route Rejections

A post to one device can use the group endorsement on the sealed direct
route. The Relay answers a rejection in one of two ways:

| Answer | Meaning | SDK behavior |
|---|---|---|
| 401 `ANONYMOUS_AUTH_REJECTED` | The direct route does not take the endorsement. The post did not start. | The SDK posts the message once on the sealed group route for that device, and writes one `info` log line with the behavior `GROUP_ROUTE_FALLBACK`. The post stays sealed. |
| 401 `GROUP_CREDENTIAL_REJECTED` | The Relay rejected the endorsement. | No route fallback. In `required` mode, the send fails with `SEALED_SENDER_AUTH_FAILED` and makes no identified post. In `preferred` mode, the SDK posts identified and calls `onIdentifiedFallback`. |

A resend that answers a retry request uses the same authorization as its
original send. A resend of a group send to a member with no access key is
sealed with the group endorsement. A resend in `required` mode that has no
sealed authorization fails with `SEALED_SENDER_REQUIRED` and makes no
identified post.

### Device Sets

A Relay that compares device sets checks each declared post. Each post to an
account declares the device IDs that the sender holds records for. The Relay
refuses a declaration that does not match its device list:

- HTTP 409 with the code `DEVICE_SET_MISMATCH` names the missing and the extra
  devices of each account.
- HTTP 410 with the code `STALE_DEVICE` names each declared device whose
  registration changed.

The SDK repairs the set and posts again. It removes each extra device record,
starts a new session with each missing or stale device, and encrypts the
message again only for those devices. A device that the Relay accepted keeps
its stored post. The application does not have to act.

A send has two phases: the recipient phase, and then the sync phase for the
own devices. Each phase can restart 10 times. When the Relay refuses the
declaration of the recipient phase after the 10th restart, or refuses a
restart post with `OPERATION_EXPIRED`, the send throws
[`DeviceSetReconciliationError`](./api/classes/DeviceSetReconciliationError.md).
`isOutgoingMessageError` is true for it. Its fields:

| Field | Meaning |
|---|---|
| `reason` | `exhausted` after the 10th restart, or `expired` after `OPERATION_EXPIRED` |
| `phase` | `recipient` or `sync` |
| `restarts` | The restarts of the phase |
| `lastRefusal` | The code and the devices of the last refusal. `BUNDLE_NOT_FOUND` is a listed device with no prekey bundle |
| `acceptedDevices` | The devices that the Relay accepted. They stay accepted |
| `unresolvedDevices` | The devices that did not get the message |
| `clientMessageId` | The ID of the send |

The outbox keeps the send as terminal and does not post it again. A call of
`send()` with the same `clientMessageId` starts a new run at 0 restarts.

The sync phase does not fail the send. The recipient result is stored first.
When the sync phase does not complete, or the own device list cannot be read,
the result carries `syncPending: true`. Call `send()` again with the same
`clientMessageId` to post the pending copies.

The Relay marks each accepted declared post with `deviceSetChecked`. When an
accepted post has no mark, the Relay did not compare its device set. The send
is delivered and its result does not change. The client reports a
[`RelayProtocolError`](./api/classes/RelayProtocolError.md) with the code
`DEVICE_SET_UNCHECKED` once for the send through the `onRelayProtocolError`
hook. Its `route` names the post route. A sync copy to another own device is
an `identified-direct` post. A sync payload of a method such as
`syncReadToLinkedDevices` reports the error once, with no `clientMessageId`.
Report it to the Relay operator.

A relay that does not compare device sets gets no declaration. The Convex
relay is one. With it, the SDK reads the device lists as before, and none of
these errors occur.

## Relay Device Errors

The Relay can refuse this device. Two errors name that refusal. Neither is an
`EncryptionError`, and the SDK retries neither one.

| Error | Cause | Application response |
|---|---|---|
| [`HostedRelayDeviceRevokedError`](./api/classes/HostedRelayDeviceRevokedError.md) | An account recovery revoked this device. `code` is `DEVICE_REVOKED`, `status` is 403, and `retryable` is false. | Sign the user out of this device. The Relay refuses a registration with the revoked key, so a re-registration fails too. |
| [`HostedRelayDeviceUnknownError`](./api/classes/HostedRelayDeviceUnknownError.md) | The Relay has no device for the stored session. `code` is `NOT_FOUND`, `status` is 404, and `retryable` is false. The message is the Relay's own message. | Ask the user to confirm a re-registration of this device. Do not re-register without that confirmation. |

`createHostedSignalProtocolClient` throws either error when the stored session
cannot get a device token. It does not register a new device in their place. A
running client throws them from its Relay calls. A client call can wrap them
in an `EncryptionError`, as the `originalError`. The mailbox subscription
stops with the reason `device-revoked` or `device-unknown`. See
[`RelayConnectionReason`](./api/type-aliases/RelayConnectionReason.md).

To re-register, create the client again with `assertionPurpose: 'reregister'`.
It keeps the stored identity and device key, and it asks for a `register`
assertion. It throws before any assertion when the store holds no identity or
no device key. A retry after a failed call sends the same registration again.

A re-registration has these effects:

- The Relay can give this device a new device ID. The messages queued for the
  old device are lost.
- Each re-registration reserves a device ID for good. An account has five
  device IDs, so a registration fails when all five are reserved.
- When the account itself was deleted, the re-registration makes a new account
  address. Contacts of the old address do not reach the new one.
- A device that a recovery revoked before the Relay recorded revoked keys reads
  as unknown. A re-registration can then restore it. So always ask the user
  first.

<!-- doc-snippet:skip requires-existing-client -->
```typescript
import {
  HostedRelayDeviceRevokedError,
  HostedRelayDeviceUnknownError,
  createHostedSignalProtocolClient,
} from '@open-e2ee/signal-protocol-sdk';

try {
  signal = await createHostedSignalProtocolClient(options);
} catch (error) {
  if (error instanceof HostedRelayDeviceRevokedError) {
    signOutThisDevice();
  } else if (
    error instanceof HostedRelayDeviceUnknownError &&
    (await confirmReregistration())
  ) {
    signal = await createHostedSignalProtocolClient({
      ...options,
      hosted: { ...options.hosted, assertionPurpose: 'reregister' },
    });
  } else {
    throw error;
  }
}
```

## Group Receive Errors

A managed group receive can end in three errors. None of them is an
`EncryptionError`. Each one tells the caller what to do with the message.

| Error | Cause | Keep rule |
|---|---|---|
| [`GroupReceiveUnavailableError`](./api/classes/GroupReceiveUnavailableError.md) | The group state is not current. `reason` names the wait, and `retryAfterMs` gives the time to the next try. The client stored the content in a receive record under `messageId`. | Call again later with the same message. The later call decides the stored content with no second decrypt. |
| [`GroupReceiveRefusedError`](./api/classes/GroupReceiveRefusedError.md) | The client refused the content. `reason` names the refusal, for example `sender-not-member` or `sync-from-other-account`. The client asked for no resend. | Drop the message. A redelivery is dropped as a processed duplicate. |
| [`GroupResendDeferredError`](./api/classes/GroupResendDeferredError.md) | A resend to a group member waits for the group state. The client neither sent nor refused the resend. | The Relay keeps the retry request. Do not acknowledge it. A later delivery decides again. |

The deprecated `decryptGroupMessage` throws the first two errors. It also
throws `EncryptionError` with `STORAGE_QUOTA_EXCEEDED` when the receive queue
has no room, and with `MESSAGE_DUPLICATE` for a message that this client
processed or that gives no content, such as a null message. A decrypt failure
throws its error with no retry request and no report.
`decryptEnvelope` throws `GroupReceiveRefusedError` for a group context that
is malformed or names another group. `processIncomingEnvelope` throws none
of them. It returns a receive outcome: `pending` for content that waits for
its group state, and `denied` for refused content. Acknowledge the envelope
for both. The receive queue keeps pending content on the device and decides
it when its group updates. Do not acknowledge an envelope whose outcome is
`refused`: the receive queue had no room, and the client stored nothing.

Content from another account that carries a sync message is refused as
`sync-from-other-account` on the Relay subscription, in
`receiveIncomingEnvelopes`, in `decryptEnvelope` and `decryptGroupMessage`,
and in `processIncomingEnvelope` as a `denied` outcome. The raw decrypt
methods `receive`, `decryptMessage`, and `decryptMessages` return the
plaintext with no group classification and do not refuse it.

The Relay subscription applies the rule itself. It acknowledges an envelope
after its content is committed, also when the content waits for its group
or is denied. An envelope that the receive queue refuses for lack of room
stays unacknowledged. `receiveIncomingEnvelopes` commits each envelope and sends
no acknowledgment. It reports the committed envelopes in
`processedMessageIds`, ready for the transport acknowledgment. It reports a
deferred retry request and an envelope that the receive queue had no room
for in `failedMessageIds`.

<!-- doc-snippet:skip requires-existing-client -->
```typescript
const outcome = await signal.processIncomingEnvelope(envelope, {
  onPersist: (processed) => saveMessage(processed.messageId, processed.plaintext),
});
if (outcome.kind === 'refused') {
  keepForLater(envelope);
} else {
  acknowledge(envelope);
}
```

## Error Handling Patterns

### One Handler for Every Error

<!-- doc-snippet:skip application-handler-fragment -->
```typescript
import {
  EncryptionError,
  EncryptionErrorCode,
  isUntrustedIdentityError,
  isSealedSenderAuthError,
} from '@open-e2ee/signal-protocol-sdk';

async function handleEncryptionError(error: unknown): Promise<void> {
  if (!(error instanceof EncryptionError)) {
    // Not a signal error, re-throw
    throw error;
  }

  // Handle specialized errors first
  if (isUntrustedIdentityError(error)) {
    await handleUntrustedIdentity(error);
    return;
  }

  if (isSealedSenderAuthError(error)) {
    await reauthorizeSealedSender(error);
    return;
  }

  // Handle by error code
  switch (error.code) {
    case EncryptionErrorCode.SESSION_NOT_FOUND:
      await establishNewSession(error.address);
      break;

    case EncryptionErrorCode.TOO_MANY_SKIPPED_MESSAGES:
      // Message is unrecoverable, notify user
      notifyMessageLost(error.context?.operation);
      break;

    case EncryptionErrorCode.DECRYPTION_FAILED:
      // Possible tampering or corruption
      logSecurityEvent(error);
      break;

    case EncryptionErrorCode.KEY_STORAGE_ERROR:
      // Storage issue, retry with backoff
      await retryWithBackoff(() => reinitializeStorage());
      break;

    default:
      // Unknown error, log and notify
      logError(error);
      notifyUnexpectedError(error.message);
  }
}
```

### Retry with Exponential Backoff

The library provides a built-in retry utility:

<!-- doc-snippet:skip requires-existing-client -->
```typescript
import { withRetry } from '@open-e2ee/signal-protocol-sdk/utils/retry';

await withRetry(
  async () => {
    await signal.rotatePreKeys();
  },
  {
    operationName: 'rotatePreKeys',
    maxRetries: 2,
    baseDelay: 2000,
    maxDelay: 30000,
  }
);
```

### Session Recovery Pattern

<!-- doc-snippet:skip application-session-recovery-fragment -->
```typescript
import {
  EncryptionError,
  EncryptionErrorCode,
  ProtocolAddress,
  type SignalProtocolClient,
} from '@open-e2ee/signal-protocol-sdk';

async function ensureSession(
  signal: SignalProtocolClient,
  userId: string,
  deviceId: number
): Promise<void> {
  const remoteAddress = ProtocolAddress.create(userId, deviceId);

  try {
    const hasSession = await signal.hasSession(remoteAddress);
    if (!hasSession) {
      // Fetch prekey bundle and establish session
      const bundle = await fetchPreKeyBundle(userId, deviceId);
      await signal.establishSession(remoteAddress, bundle);
    }
  } catch (error) {
    if (error instanceof EncryptionError) {
      switch (error.code) {
        case EncryptionErrorCode.SESSION_CORRUPTED:
          // Delete corrupted session and retry
          await signal.deleteSession(remoteAddress);
          const bundle = await fetchPreKeyBundle(userId, deviceId);
          await signal.establishSession(remoteAddress, bundle);
          break;

        case EncryptionErrorCode.INVALID_PREKEY_BUNDLE:
          // Bundle was invalid, try fetching again
          const newBundle = await fetchPreKeyBundle(userId, deviceId);
          await signal.establishSession(remoteAddress, newBundle);
          break;

        default:
          throw error;
      }
    } else {
      throw error;
    }
  }
}
```

## Logging Errors

The library includes structured logging for errors:

<!-- doc-snippet:skip requires-platform-adapters -->
```typescript
import { DefaultSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';

const signal = await DefaultSignalProtocolClient.create(userId, {
  storage,
  relay,
  logger: {
    debug: console.debug,
    info: console.info,
    warn: console.warn,
    error: console.error,
    breadcrumb: console.debug,
  },
});

// Errors are automatically logged with context through the client logger.
void signal;
```

## Best Practices

### 1. Always Use Type Guards

<!-- doc-snippet:skip type-guard-comparison-fragment -->
```typescript
// Prefer the exported guard so narrowing stays behind one public function.
if (isUntrustedIdentityError(error)) {
  // Handle untrusted identity
}

// Current guards delegate to instanceof. Bundle one copy of the SDK.
```

### 2. Preserve Error Context

<!-- doc-snippet:skip error-wrapping-comparison-fragment -->
```typescript
// Good: Wrap errors with context
throw new EncryptionError('Failed to establish session', EncryptionErrorCode.SESSION_NOT_FOUND, {
  address: remoteAddress,
  operation: 'establishSession',
  originalError: error,
});

// Bad: Lose original error
throw new Error('Session error');
```

### 3. Handle Security-Critical Errors Prominently

<!-- doc-snippet:skip requires-identity-change-fixture -->
```typescript
// Identity changes require prominent user warning
if (isUntrustedIdentityError(error)) {
  // Don't silently accept - show security dialog
  const accepted = await showSecurityWarningDialog(error);
  if (accepted) {
    // acceptIdentityRotation() takes the peer's new composite identity tuple and
    // resets the sessions bound to the retired identity. Read that tuple from the
    // relay rather than from `error.identity`: the error carries whichever tuple
    // failed the trust check, which on the three session-bound throw sites is the
    // pinned one being rejected, not the one the peer now publishes.
    const userId = error.untrustedAddress.userId;
    const identity = await relay.getIdentityKey(userId);
    if (identity) {
      await signal.acceptIdentityRotation(userId, identity);
    }
  }
}
```

## See Also

- [SECURITY.md](./SECURITY.md) - Security guidelines
- [ARCHITECTURE.md](../ARCHITECTURE.md) - System architecture
- [Signal Protocol Specification](https://signal.org/docs/) - Official spec
