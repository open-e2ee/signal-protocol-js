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
| `STORAGE_QUOTA_EXCEEDED` | The storage origin ran out of space. | Free storage space, then retry the rejected write. |

### Initialization and Protocol Policy Errors

| Code | Cause | Application response |
|---|---|---|
| `INITIALIZATION_FAILED` | Client or group initialization failed. | Inspect `originalError` and the configuration. |
| `PQXDH_REQUIRED` | Policy requires PQXDH, but the peer lacks required keys. | Wait for new peer keys or queue the message. |
| `PQXDH_FAILED` | The PQXDH exchange failed. | Abort setup and inspect `originalError`. |
| `TRIPLE_RATCHET_REQUIRED` | Triple Ratchet policy lacks a PQXDH session. | Establish the required PQXDH session first. |

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
    await signal.rotateEcSignedPreKey();
  },
  {
    operationName: 'rotateEcSignedPreKey',
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
import { SignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';

const signal = await SignalProtocolClient.create(userId, {
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
