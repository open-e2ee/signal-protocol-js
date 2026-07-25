/**
 * Session management operations for SignalProtocolClient
 *
 * Extracted from SignalProtocolClient class to reduce file size.
 * Handles session establishment, deletion, and archiving.
 */

import type {
  CompositeIdentityV1,
  ContactIdentityRecord,
  IdentityType,
  PreKeyBundle,
} from '../keys';
import {
  compositeIdentitiesEqual,
  createCompositeIdentityV1,
  deriveIdentityCommitment,
} from '../keys/identity';
import { EncryptionError, EncryptionErrorCode } from '../types';
import { ProtocolAddress } from '../types/address';
import { callHook } from './event-hooks';
import type { SafetyNumberConfirmation, SignalProtocolClientContext, SafetyNumber } from './types';
import type { SessionHealthResult, SessionHealthIssue, SessionHealthStatus } from './types';
import type { ISesameManager } from '../internal/sesame/types';
import * as CryptoUtils from '../internal/crypto';

/**
 * Establish a new session with a partner
 *
 * Performs X3DH key exchange using partner's prekey bundle to establish
 * a Double Ratchet session for end-to-end encrypted communication.
 *
 * @param ctx - Client context with dependencies
 * @param sesameManager - Sesame manager for multi-device support
 * @param remoteAddress - Partner's protocol address (userId + deviceId)
 * @param prekeyBundle - Partner's prekey bundle (fetched from server)
 */
export {};
export async function establishSession(
  ctx: SignalProtocolClientContext,
  sesameManager: ISesameManager,
  remoteAddress: ProtocolAddress,
  prekeyBundle: PreKeyBundle,
  recipientIdentityType: IdentityType = 'aci'
): Promise<void> {
  const { withRetry } = await import('../utils/retry');
  const sessionId = ProtocolAddress.toString(remoteAddress);

  try {
    await withRetry(
      async () => {
        await ctx.manager.startSession(remoteAddress, prekeyBundle, recipientIdentityType);
      },
      {
        operationName: 'establishSession',
        maxRetries: 2,
        baseDelay: 1000,
      }
    );

    // Register session with SESAME for multi-device support
    // ProtocolAddress already has userId and deviceId - no parsing needed
    //
    const sessionRecord = await ctx.storage.getSessionRecord(remoteAddress);
    if (sessionRecord?.currentSession) {
      await sesameManager.registerSession(
        remoteAddress.userId,
        remoteAddress.deviceId,
        sessionRecord.currentSession,
        true // We are the initiator (we called establishSession)
      );
    }

    ctx.logger.debug('Session established', {
      category: 'E2EE',
      data: { sessionId, remoteAddress: ProtocolAddress.toString(remoteAddress) },
    });

    // Call hook: session established
    await callHook(ctx.hooks, 'onSessionEstablished', sessionId, remoteAddress.userId);
  } catch (error) {
    if (error instanceof EncryptionError) {
      throw error;
    }
    throw new EncryptionError(
      `Failed to establish session for ${ProtocolAddress.toString(remoteAddress)}`,
      EncryptionErrorCode.SESSION_CORRUPTED,
      { originalError: error as Error }
    );
  }
}

/**
 * Check if a session exists
 *
 * @param ctx - Client context with dependencies
 * @param remoteAddress - Remote device's protocol address
 * @returns True if session exists
 */
export async function hasSession(
  ctx: SignalProtocolClientContext,
  remoteAddress: ProtocolAddress
): Promise<boolean> {
  const record = await ctx.storage.getSessionRecord(remoteAddress);
  return record?.currentSession !== null && record?.currentSession !== undefined;
}

/**
 * Delete a session
 *
 * Use this to reset encryption for a session (e.g., after a security incident).
 * You'll need to establish a new session before sending/receiving messages.
 *
 * @param ctx - Client context with dependencies
 * @param remoteAddress - Remote device's protocol address
 */
export async function deleteSession(
  ctx: SignalProtocolClientContext,
  remoteAddress: ProtocolAddress
): Promise<void> {
  const sessionId = ProtocolAddress.toString(remoteAddress);
  try {
    await ctx.storage.deleteSessionRecord(remoteAddress);
    ctx.logger.debug('Session deleted', {
      category: 'E2EE',
      data: { sessionId },
    });

    // Call hook: session deleted
    await callHook(ctx.hooks, 'onSessionDeleted', sessionId);
  } catch (error) {
    throw new EncryptionError(
      `Failed to delete session for ${sessionId}`,
      EncryptionErrorCode.SESSION_CORRUPTED,
      { originalError: error as Error }
    );
  }
}

/**
 * Explicitly accept a changed per-user composite identity and discard every
 * local session bound to the superseded tuple. Detection alone never mutates
 * trust; callers must authenticate the replacement out of band first.
 */
export async function acceptIdentityRotation(
  ctx: SignalProtocolClientContext,
  userId: string,
  identity: CompositeIdentityV1,
  identityType: IdentityType = 'aci'
): Promise<ContactIdentityRecord> {
  const trustAddress = ProtocolAddress.create(userId, 1);
  const current = await ctx.storage.getContactIdentity(trustAddress, identityType);
  if (current && compositeIdentitiesEqual(current.identity, identity)) {
    throw new Error('The supplied identity is already the trusted identity');
  }
  return await ctx.storage.acceptContactIdentityRotationAndDeleteSessions(
    trustAddress,
    identity,
    identityType
  );
}

/**
 * Archive a session after a stale-device response.
 *
 * Moves current session to inactive list, preserving it for delayed message decryption.
 * Per SESAME §3.2: "previously active session is moved to the head of the inactive sessions list"
 *
 * Use this when handling stale device errors (410) - the old session may still be needed
 * to decrypt messages that were in-flight during the session refresh.
 *
 * @param ctx - Client context with dependencies
 * @param remoteAddress - Remote device's protocol address
 */
export async function archiveSession(
  ctx: SignalProtocolClientContext,
  remoteAddress: ProtocolAddress
): Promise<void> {
  const sessionId = ProtocolAddress.toString(remoteAddress);
  try {
    await ctx.storage.archiveCurrentSession(remoteAddress, null);
    ctx.logger.debug('Session archived', {
      category: 'E2EE',
      data: { sessionId },
    });

    // Call hook: session archived
    await callHook(ctx.hooks, 'onSessionArchived', sessionId);
  } catch (error) {
    throw new EncryptionError(
      `Failed to archive session for ${sessionId}`,
      EncryptionErrorCode.SESSION_CORRUPTED,
      { originalError: error as Error }
    );
  }
}

/**
 * Get session health and diagnostic information
 *
 * Provides detailed health status for encryption with a specific user,
 * including key status, session state, and actionable recommendations.
 *
 * @param ctx - Client context with dependencies
 * @param userId - The user ID to check session health for
 * @returns SessionHealthResult with status and detailed diagnostics
 */
export async function getSessionHealth(
  ctx: SignalProtocolClientContext,
  userId: string
): Promise<SessionHealthResult> {
  const now = Date.now();
  const issues: SessionHealthIssue[] = [];

  // Check our own key status
  const [hasIdentityKey, signedPreKey, kyberPreKey] = await Promise.all([
    ctx.storage.hasIdentityKey(),
    ctx.storage.getEcSignedPreKey(),
    ctx.storage.getKyberPreKey(),
  ]);

  const hasSignedPreKey = !!signedPreKey;
  const hasKyberPreKey = !!kyberPreKey;

  // Calculate key ages in days
  const signedPreKeyAgeDays = signedPreKey
    ? Math.floor((now - signedPreKey.timestamp) / (24 * 60 * 60 * 1000))
    : 0;
  const kyberPreKeyAgeDays = kyberPreKey
    ? Math.floor((now - kyberPreKey.timestamp) / (24 * 60 * 60 * 1000))
    : 0;

  const ROTATION_THRESHOLD_DAYS = 7;
  const needsRotation =
    signedPreKeyAgeDays >= ROTATION_THRESHOLD_DAYS || kyberPreKeyAgeDays >= ROTATION_THRESHOLD_DAYS;

  // Check if we have sessions with this user
  const sessions = await ctx.storage.getSessionsForUser(userId);
  const sessionExists = sessions.length > 0;

  // Add issues based on checks
  if (!hasIdentityKey) {
    issues.push({
      code: 'NO_IDENTITY_KEY',
      severity: 'error',
      message: 'Identity key not configured',
    });
  }

  if (!hasSignedPreKey) {
    issues.push({
      code: 'NO_SIGNED_PREKEY',
      severity: 'error',
      message: 'Signed prekey not configured',
    });
  }

  if (needsRotation) {
    issues.push({
      code: 'KEY_ROTATION_NEEDED',
      severity: 'warning',
      message: 'Key rotation recommended',
      details: { signedPreKeyAgeDays, kyberPreKeyAgeDays },
    });
  }

  if (!sessionExists) {
    issues.push({
      code: 'NO_SESSION',
      severity: 'warning',
      message: 'No active session with this user',
    });
  }

  // Determine overall status
  const hasErrors = issues.some((i) => i.severity === 'error');
  const hasWarnings = issues.some((i) => i.severity === 'warning');

  let status: SessionHealthStatus;
  if (hasErrors) {
    status = 'error';
  } else if (hasWarnings) {
    status = 'warning';
  } else {
    status = 'healthy';
  }

  // Generate summary message
  let message = 'Session is active';
  if (status === 'error') {
    message = issues.find((i) => i.severity === 'error')?.message || 'Session error';
  } else if (status === 'warning') {
    message = issues.find((i) => i.severity === 'warning')?.message || 'Session needs attention';
  }

  return {
    status,
    sessionExists,
    issues,
    keyStatus: {
      hasIdentityKey,
      hasSignedPreKey,
      hasKyberPreKey,
      signedPreKeyAgeDays,
      kyberPreKeyAgeDays,
      needsRotation,
    },
    checkedAt: now,
    message,
  };
}

/**
 * Verify identity with another user via Safety Number
 *
 * Generates a safety number that can be compared out-of-band to verify
 * the identity of a conversation partner.
 *
 * @param ctx - Client context with dependencies
 * @param userId - User ID to verify
 * @returns SafetyNumber for verification
 */
export async function verify(
  ctx: SignalProtocolClientContext,
  userId: string,
  identityType: IdentityType = 'aci'
): Promise<SafetyNumber> {
  // Import safety module
  const { generateCompositeSafetyNumber } = await import('../safety');

  // Get our identity key
  const myIdentityKey = await ctx.storage.getIdentityKey(identityType);
  if (!myIdentityKey) {
    throw new EncryptionError(
      'Identity key not found - client not initialized',
      EncryptionErrorCode.INITIALIZATION_FAILED
    );
  }

  const trustAddress = ProtocolAddress.create(userId, 1);
  const trustRecord = await ctx.storage.getContactIdentity(trustAddress, identityType);
  if (!trustRecord) {
    throw new EncryptionError(
      `No pinned identity exists for user ${userId}`,
      EncryptionErrorCode.UNTRUSTED_IDENTITY
    );
  }

  // The pinned tuple is the trust object. The relay is checked for consistency,
  // but is never allowed to select which tuple the user sees.
  if (!ctx.relay) {
    throw new EncryptionError(
      'Relay server required to verify identity',
      EncryptionErrorCode.INITIALIZATION_FAILED
    );
  }

  const relayIdentity = await ctx.relay.getIdentityKey(userId, identityType);
  if (!relayIdentity) {
    throw new EncryptionError(
      `Identity key not found for user ${userId}`,
      EncryptionErrorCode.SESSION_NOT_FOUND
    );
  }
  if (!compositeIdentitiesEqual(relayIdentity, trustRecord.identity)) {
    throw new EncryptionError(
      `Relay identity does not match the pinned identity for user ${userId}`,
      EncryptionErrorCode.IDENTITY_MISMATCH
    );
  }

  // Generate safety number
  const safetyNum = generateCompositeSafetyNumber(
    createCompositeIdentityV1(myIdentityKey),
    trustRecord.identity,
    ctx.userId,
    userId,
    identityType
  );

  const fingerprint = CryptoUtils.hexToBytes(safetyNum.hex);

  return {
    numeric: safetyNum.numeric,
    fingerprint,
    userId,
    identityType,
    trustState: trustRecord.trustState,
    confirmation: {
      version: 1,
      userId,
      identityType,
      fingerprint: CryptoUtils.bytesToBase64(fingerprint),
      remoteIdentityCommitment: CryptoUtils.bytesToBase64(
        deriveIdentityCommitment(trustRecord.identity)
      ),
    },
  };
}

/** Promote only the exact tuple after the application completes authenticated comparison. */
export async function confirmSafetyNumber(
  ctx: SignalProtocolClientContext,
  confirmation: SafetyNumberConfirmation
): Promise<void> {
  if (confirmation.version !== 1) {
    throw new Error(`Unsupported safety-number confirmation version: ${String(confirmation.version)}`);
  }
  const { userId, identityType } = confirmation;
  const trustAddress = ProtocolAddress.create(userId, 1);
  const trustRecord = await ctx.storage.getContactIdentity(trustAddress, identityType);
  if (!trustRecord) {
    throw new EncryptionError(
      `No pinned identity exists for user ${userId}`,
      EncryptionErrorCode.UNTRUSTED_IDENTITY
    );
  }

  const expectedCommitment = deriveIdentityCommitment(trustRecord.identity);
  const suppliedCommitment = CryptoUtils.base64ToBytes(confirmation.remoteIdentityCommitment);
  if (!CryptoUtils.constantTimeEqual(expectedCommitment, suppliedCommitment)) {
    throw new EncryptionError(
      `Safety-number confirmation does not match the pinned identity for user ${userId}`,
      EncryptionErrorCode.IDENTITY_MISMATCH
    );
  }

  const myIdentityKey = await ctx.storage.getIdentityKey(identityType);
  if (!myIdentityKey) {
    throw new EncryptionError(
      'Identity key not found - client not initialized',
      EncryptionErrorCode.INITIALIZATION_FAILED
    );
  }
  const { generateCompositeSafetyNumber } = await import('../safety');
  const recomputed = generateCompositeSafetyNumber(
    createCompositeIdentityV1(myIdentityKey),
    trustRecord.identity,
    ctx.userId,
    userId,
    identityType
  );
  const suppliedFingerprint = CryptoUtils.base64ToBytes(confirmation.fingerprint);
  if (!CryptoUtils.constantTimeEqual(CryptoUtils.hexToBytes(recomputed.hex), suppliedFingerprint)) {
    throw new EncryptionError(
      `Safety-number confirmation does not match the displayed value for user ${userId}`,
      EncryptionErrorCode.IDENTITY_MISMATCH
    );
  }

  if (!ctx.relay) {
    throw new EncryptionError(
      'Relay server required to confirm identity',
      EncryptionErrorCode.INITIALIZATION_FAILED
    );
  }
  const relayIdentity = await ctx.relay.getIdentityKey(userId, identityType);
  if (!relayIdentity) {
    throw new EncryptionError(
      `Identity key not found for user ${userId}`,
      EncryptionErrorCode.SESSION_NOT_FOUND
    );
  }
  if (!compositeIdentitiesEqual(relayIdentity, trustRecord.identity)) {
    throw new EncryptionError(
      `Relay identity changed after safety-number display for user ${userId}`,
      EncryptionErrorCode.IDENTITY_MISMATCH
    );
  }
  await ctx.storage.verifyContactIdentity(
    trustAddress,
    trustRecord.identity,
    identityType,
    expectedCommitment
  );
}

/**
 * Clean up expired message keys for a session
 *
 * Signal Protocol Section 8.4 recommends deleting message keys older than
 * one week to avoid excessive storage. This method explicitly triggers cleanup.
 *
 * @param ctx - Client context with dependencies
 * @param remoteAddress - Remote party's protocol address (userId:deviceId)
 * @returns true if cleanup succeeded, false otherwise
 */
export async function cleanupExpiredKeys(
  ctx: SignalProtocolClientContext,
  remoteAddress: ProtocolAddress
): Promise<boolean> {
  const sessionId = ProtocolAddress.toString(remoteAddress);
  try {
    // Count stored keys before cleanup.
    const recordBefore = await ctx.storage.getSessionRecord(remoteAddress);
    const keyCountBefore =
      recordBefore?.currentSession?.receiverChains?.reduce(
        (sum, chain) => sum + chain.messageKeys.length,
        0
      ) ?? 0;

    await ctx.manager.cleanupExpiredKeys(remoteAddress);

    // Count stored keys after cleanup.
    const recordAfter = await ctx.storage.getSessionRecord(remoteAddress);
    const keyCountAfter =
      recordAfter?.currentSession?.receiverChains?.reduce(
        (sum, chain) => sum + chain.messageKeys.length,
        0
      ) ?? 0;
    const removedCount = keyCountBefore - keyCountAfter;

    ctx.logger.debug('Expired message keys cleaned up', {
      category: 'E2EE',
      data: { sessionId, removedCount },
    });

    // Call hook: keys cleaned up
    if (removedCount > 0) {
      await callHook(ctx.hooks, 'onKeysCleanedUp', sessionId, removedCount);
    }

    return true;
  } catch (error) {
    if (ctx.config?.enableDebugLogging) {
      ctx.logger.error('Failed to cleanup expired keys', {
        category: 'E2EE',
        error: error as Error,
      });
    }
    return false;
  }
}

/**
 * Get encryption statistics
 *
 * @param ctx - Client context with dependencies
 * @returns Statistics about sessions, keys, and usage
 */
export async function getStats(ctx: SignalProtocolClientContext): Promise<{
  hasIdentityKey: boolean;
  sessionCount: number;
  oneTimePreKeysCount: number;
}> {
  const [hasIdentityKey, oneTimePreKeys, sessionCount] = await Promise.all([
    ctx.storage.hasIdentityKey(),
    ctx.storage.getEcOneTimePreKeys(),
    ctx.storage.getSessionCount(),
  ]);

  return {
    hasIdentityKey,
    sessionCount,
    oneTimePreKeysCount: oneTimePreKeys.length,
  };
}
