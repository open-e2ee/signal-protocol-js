# Error Handling Guide

Comprehensive guide to error handling in the `@open-e2ee/signal-protocol-sdk` library.

## Overview

The library uses a structured error system with stable programmatic codes:

- **EncryptionError**: Base error class with error codes and context
- **Specialized Error Classes**: For specific error types requiring special handling
- **Error Codes**: Enumerated codes for programmatic error handling

## Error Classes

### EncryptionError (Base Class)

All signal protocol errors extend `EncryptionError`:

```typescript
import { EncryptionError, EncryptionErrorCode } from '@open-e2ee/signal-protocol-sdk';

try {
  await signal.encryptMessage(sessionId, plaintext);
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

```typescript
import { isUntrustedIdentityError } from '@open-e2ee/signal-protocol-sdk';

try {
  await signal.establishSession(sessionId, remoteAddress, bundle);
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

#### IdentityKeyChangedError

Thrown when a remote party's identity key has changed. Could indicate:

- Legitimate: Device reinstall, new device, backup restoration
- Attack: Man-in-the-middle attack

```typescript
import { isIdentityKeyChangedError } from '@open-e2ee/signal-protocol-sdk';

try {
  await signal.decryptMessage(sessionId, ciphertext);
} catch (error) {
  if (isIdentityKeyChangedError(error)) {
    // Show prominent security warning
    showIdentityChangedWarning({
      userId: error.changedAddress.userId,
      deviceId: error.changedAddress.deviceId,
      oldKey: error.oldIdentityKey,
      newKey: error.newIdentityKey,
    });
  }
}
```

#### SessionConflictError

Thrown when both parties try to establish sessions simultaneously.

```typescript
import { isSessionConflictError } from '@open-e2ee/signal-protocol-sdk';

try {
  await signal.establishSession(sessionId, remoteAddress, bundle);
} catch (error) {
  if (isSessionConflictError(error)) {
    // Archive old session and retry with Sesame convergence
    await signal.archiveSession(sessionId);
    await signal.establishSession(sessionId, remoteAddress, bundle);
  }
}
```

#### RegistrationIdChangedError

Thrown when a remote party's registration ID has changed (app reinstall detected).

```typescript
import { isRegistrationIdChangedError } from '@open-e2ee/signal-protocol-sdk';

try {
  await signal.decryptMessage(sessionId, ciphertext);
} catch (error) {
  if (isRegistrationIdChangedError(error)) {
    // Archive old session, re-establish new one
    await signal.archiveSession(sessionId);
    // Notify user of reset
    showSessionResetNotification(error.resetAddress.userId);
  }
}
```

## Error Codes

### Session Errors

| Code                | Description                       | Recovery                |
| ------------------- | --------------------------------- | ----------------------- |
| `SESSION_NOT_FOUND` | No session exists for the address | Establish new session   |
| `SESSION_CORRUPTED` | Session data is invalid           | Delete and re-establish |
| `SESSION_CONFLICT`  | Multiple active sessions detected | Use Sesame convergence  |

### Message Errors

| Code                        | Description                 | Recovery                   |
| --------------------------- | --------------------------- | -------------------------- |
| `INVALID_CIPHERTEXT`        | Message format is malformed | Request retransmission     |
| `DECRYPTION_FAILED`         | Could not decrypt message   | Check session state        |
| `ENCRYPTION_FAILED`         | Could not encrypt message   | Check session state        |
| `MESSAGE_DUPLICATE`         | Message already processed   | Ignore (replay protection) |
| `MESSAGE_TOO_OLD`           | Message keys expired        | Request retransmission     |
| `TOO_MANY_SKIPPED_MESSAGES` | DoS protection triggered    | Reset session              |
| `INVALID_MESSAGE_VERSION`   | Protocol version mismatch   | Update client              |

### Identity & Trust Errors

| Code                            | Description           | Recovery                 |
| ------------------------------- | --------------------- | ------------------------ |
| `UNTRUSTED_IDENTITY`            | Identity not verified | Verify safety number     |
| `IDENTITY_KEY_CHANGED`          | Identity key changed  | Verify and accept/reject |
| `SIGNATURE_VERIFICATION_FAILED` | Signature is invalid  | Reject message           |

### PreKey & Session Establishment Errors

| Code                      | Description             | Recovery             |
| ------------------------- | ----------------------- | -------------------- |
| `INVALID_PREKEY_BUNDLE`   | Bundle is malformed     | Fetch new bundle     |
| `PREKEY_NOT_FOUND`        | PreKey not available    | Rotate prekeys       |
| `INVALID_REGISTRATION_ID` | Invalid registration ID | Re-register          |
| `REGISTRATION_ID_CHANGED` | App was reinstalled     | Re-establish session |

### Ratchet Errors

| Code             | Description       | Recovery       |
| ---------------- | ----------------- | -------------- |
| `RATCHET_ERROR`  | DH ratchet failed | Reset session  |
| `INVALID_DH_KEY` | DH key is invalid | Reject message |

### Storage Errors

| Code                | Description               | Recovery              |
| ------------------- | ------------------------- | --------------------- |
| `KEY_STORAGE_ERROR` | Storage operation failed  | Retry or reinitialize |
| `DATABASE_ERROR`    | Database operation failed | Check DB connection   |
| `DATABASE_LOCKED`   | Database is inaccessible  | Check encryption key  |

### Cryptographic Errors

| Code                       | Description                   | Recovery         |
| -------------------------- | ----------------------------- | ---------------- |
| `KYBER_ERROR`              | Post-quantum operation failed | Check Kyber keys |
| `KDF_ERROR`                | Key derivation failed         | Check input keys |
| `HMAC_VERIFICATION_FAILED` | Message tampered              | Reject message   |

## Error Handling Patterns

### Comprehensive Error Handler

```typescript
import {
  EncryptionError,
  EncryptionErrorCode,
  isUntrustedIdentityError,
  isIdentityKeyChangedError,
  isSessionConflictError,
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

  if (isIdentityKeyChangedError(error)) {
    await handleIdentityKeyChanged(error);
    return;
  }

  if (isSessionConflictError(error)) {
    await handleSessionConflict(error);
    return;
  }

  // Handle by error code
  switch (error.code) {
    case EncryptionErrorCode.SESSION_NOT_FOUND:
      await establishNewSession(error.address);
      break;

    case EncryptionErrorCode.MESSAGE_TOO_OLD:
    case EncryptionErrorCode.TOO_MANY_SKIPPED_MESSAGES:
      // Message is unrecoverable, notify user
      notifyMessageLost(error.context?.operation);
      break;

    case EncryptionErrorCode.DECRYPTION_FAILED:
    case EncryptionErrorCode.HMAC_VERIFICATION_FAILED:
      // Possible tampering or corruption
      logSecurityEvent(error);
      break;

    case EncryptionErrorCode.DATABASE_ERROR:
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

```typescript
async function ensureSession(
  signal: SignalProtocolClient,
  userId: string,
  deviceId: number
): Promise<void> {
  const sessionId = `${userId}_${deviceId}`;

  try {
    const hasSession = await signal.hasSession(sessionId);
    if (!hasSession) {
      // Fetch prekey bundle and establish session
      const bundle = await fetchPreKeyBundle(userId, deviceId);
      await signal.establishSession(sessionId, `${userId}_${deviceId}`, bundle);
    }
  } catch (error) {
    if (error instanceof EncryptionError) {
      switch (error.code) {
        case EncryptionErrorCode.SESSION_CORRUPTED:
          // Delete corrupted session and retry
          await signal.deleteSession(sessionId);
          const bundle = await fetchPreKeyBundle(userId, deviceId);
          await signal.establishSession(sessionId, `${userId}_${deviceId}`, bundle);
          break;

        case EncryptionErrorCode.INVALID_PREKEY_BUNDLE:
          // Bundle was invalid, try fetching again
          const newBundle = await fetchPreKeyBundle(userId, deviceId);
          await signal.establishSession(sessionId, `${userId}_${deviceId}`, newBundle);
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

```typescript
// Good: Use type guards for specialized errors
if (isUntrustedIdentityError(error)) {
  // Handle untrusted identity
}

// Bad: instanceof check without import
if (error instanceof UntrustedIdentityError) {
  // This might fail if bundled differently
}
```

### 2. Preserve Error Context

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

```typescript
// Identity changes require prominent user warning
if (isIdentityKeyChangedError(error)) {
  // Don't silently accept - show security dialog
  const accepted = await showSecurityWarningDialog(error);
  if (accepted) {
    await signal.trustIdentity(error.changedAddress, error.newIdentityKey);
  }
}
```

### 4. Clean Up on Errors

```typescript
let session = null;
try {
  session = await signal.establishSession(sessionId, remoteAddress, bundle);
  // Use session...
} catch (error) {
  // Clean up partial state
  if (session) {
    await signal.deleteSession(sessionId);
  }
  throw error;
}
```

## See Also

- [SECURITY.md](./SECURITY.md) - Security guidelines
- [ARCHITECTURE.md](../ARCHITECTURE.md) - System architecture
- [Signal Protocol Specification](https://signal.org/docs/) - Official spec
