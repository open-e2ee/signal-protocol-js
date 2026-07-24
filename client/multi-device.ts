/**
 * Multi-device (SESAME) operations for SignalProtocolClient
 *
 * Extracted from SignalProtocolClient class to reduce file size.
 * Implements the SESAME protocol for multi-device session management.
 *
 * @see https://signal.org/docs/specifications/sesame/
 */

import type { SesameMessage, SesameStats, OutgoingMessageBatch } from '../internal/sesame/types';
import { EncryptionError, EncryptionErrorCode } from '../types';
import type { SignalProtocolClientContext } from './types';

/**
 * Send message to all devices of a user (multi-device support)
 *
 * Implements the 3-phase sending process from SESAME spec:
 *   Phase 1: Identify devices with non-stale active sessions
 *   Phase 2: Encrypt message for each device using Double Ratchet
 *   Phase 3: Validate device list is current before sending
 *
 * Returns an OutgoingMessageBatch that separates:
 * - deviceMessages: Messages for recipient's devices
 * - syncMessages: Messages for our own other devices (multi-device sync)
 *
 * Device-targeted messages remain separate from linked-device sync
 * transcripts.
 *
 * Note: This method does NOT upload messages to the server automatically.
 * You must call the backend API to upload the returned messages.
 *
 * @param ctx - Client context with dependencies
 * @param recipientUserId - The user ID to send to (all their active devices)
 * @param plaintext - The message to encrypt
 * @param includeSyncMessages - Whether to include sync messages for our own devices (default: true)
 * @returns OutgoingMessageBatch with separated device and sync messages
 *
 * @throws {EncryptionError} If encryption fails or user has no devices
 */
export {};
export async function send(
  ctx: SignalProtocolClientContext,
  recipientUserId: string,
  plaintext: string,
  includeSyncMessages: boolean = true
): Promise<OutgoingMessageBatch> {
  try {
    // Convert plaintext to Uint8Array
    const plaintextBytes = new TextEncoder().encode(plaintext);

    // Delegate to Sesame manager (encrypts for all devices)
    const batch = await ctx.sesameManager.send(recipientUserId, plaintextBytes, {
      includeSyncMessages,
    });

    ctx.logger.debug('Message encrypted for user devices', {
      category: 'E2EE',
      data: {
        recipientUserId,
        deviceCount: batch.deviceMessages.length,
        syncCount: batch.syncMessages.length,
      },
    });

    return batch;
  } catch (error) {
    // Preserve EncryptionError codes
    if (error instanceof EncryptionError) {
      throw error;
    }
    throw new EncryptionError(
      'Failed to encrypt message for user',
      EncryptionErrorCode.ENCRYPTION_FAILED,
      { originalError: error as Error, recipientUserId }
    );
  }
}

/**
 * Receive and decrypt message from another device (multi-device support)
 *
 * Implements session convergence per SESAME spec:
 * - Try to decrypt with active session first
 * - If that fails, try inactive sessions
 * - If decryption succeeds on inactive session, that session becomes active
 *
 * @param ctx - Client context with dependencies
 * @param message - The encrypted Sesame message envelope
 * @returns Decrypted plaintext
 *
 * @throws {EncryptionError} If decryption fails
 */
export async function receive(
  ctx: SignalProtocolClientContext,
  message: SesameMessage
): Promise<string> {
  try {
    // Delegate to Sesame manager (handles session convergence)
    const plaintextBytes = await ctx.sesameManager.receive(message);
    const plaintext = new TextDecoder().decode(plaintextBytes);

    ctx.logger.debug('Message received and decrypted', {
      category: 'E2EE',
      data: {
        senderUserId: message.senderUserId,
        senderDeviceId: message.senderDeviceId,
      },
    });

    return plaintext;
  } catch (error) {
    // Preserve EncryptionError for client-layer handling
    // (e.g., PREKEY_NOT_FOUND triggers key rotation).
    if (error instanceof EncryptionError) {
      throw error;
    }
    throw new EncryptionError('Failed to decrypt message', EncryptionErrorCode.DECRYPTION_FAILED, {
      originalError: error as Error,
      senderUserId: message.senderUserId,
    });
  }
}

/**
 * Get Sesame session statistics (for debugging)
 *
 * Returns information about users, devices, and sessions.
 *
 * @param ctx - Client context with dependencies
 * @returns Session statistics
 */
export async function getSesameStats(ctx: SignalProtocolClientContext): Promise<SesameStats> {
  return ctx.sesameManager.getStats();
}

/**
 * Cleanup expired Sesame sessions
 *
 * Removes inactive sessions that are older than the configured TTL.
 * Should be called periodically (e.g., daily) to prevent database bloat.
 *
 * @param ctx - Client context with dependencies
 * @returns Number of sessions cleaned up
 */
export async function cleanupExpiredSesameSessions(
  ctx: SignalProtocolClientContext
): Promise<number> {
  const cleaned = await ctx.sesameManager.cleanupExpiredSessions();
  ctx.logger.debug('Expired Sesame sessions cleaned up', {
    category: 'E2EE',
    data: { count: cleaned },
  });
  return cleaned;
}
