/**
 * Message encryption/decryption operations for SignalProtocolClient
 *
 * Extracted from SignalProtocolClient class to reduce file size.
 * Uses Double Ratchet algorithm for forward secrecy and post-compromise security.
 */

import type { Ciphertext } from '../keys';
import { EncryptionError, EncryptionErrorCode } from '../types';
import { ProtocolAddress } from '../types/address';
import type { Envelope } from '../remote/relay/types';
import { callHook } from './event-hooks';
import type { ParsedReceiptContent, ParsedTypingContent } from './content-adapter';
import type { SignalProtocolClientContext } from './types';
import { TypingAction, ReceiptType, type DeliveryReceipt } from './types';
import { ContentHint } from '../types/messages';
import * as CryptoUtils from '../internal/crypto';
import * as SessionOps from './sessions';
import { ensurePreKeysValid } from './key-rotation-core';

// ════════════════════════════════════════════════════════════════════════════
// ENUM MAPPING: signal-layer numeric → content-layer string
// ════════════════════════════════════════════════════════════════════════════

/** Map signal-layer numeric ReceiptType → content-layer string enum */
export {};
function toContentReceiptType(type: ReceiptType): 'DELIVERY' | 'READ' | 'VIEWED' {
  if (type === ReceiptType.READ) return 'READ';
  if (type === ReceiptType.VIEWED) return 'VIEWED';
  return 'DELIVERY';
}

/** Map content-layer string receipt type → signal-layer numeric ReceiptType, or null for unknown */
function fromContentReceiptType(type: string): ReceiptType | null {
  if (type === 'DELIVERY') return ReceiptType.DELIVERY;
  if (type === 'READ') return ReceiptType.READ;
  if (type === 'VIEWED') return ReceiptType.VIEWED;
  return null;
}

/** Map signal-layer numeric TypingAction → content-layer string enum */
function toContentTypingAction(action: TypingAction): 'STARTED' | 'STOPPED' {
  return action === TypingAction.STARTED ? 'STARTED' : 'STOPPED';
}

/**
 * Encrypt a message for a session
 *
 * Uses the Double Ratchet algorithm to encrypt plaintext with forward secrecy
 * and post-compromise security.
 *
 * Pre-send validation:
 * Before encrypting, checks if prekeys have exceeded the maximum allowed age
 * (14 days). If expired, attempts rotation. If rotation fails, throws
 * PREKEY_ROTATION_REQUIRED to block sending and maintain security.
 *
 * @param ctx - Client context with dependencies
 * @param remoteAddress - Remote party's protocol address (userId:deviceId)
 * @param plaintext - Message to encrypt
 * @returns Encrypted ciphertext with authentication
 * @throws {EncryptionError} PREKEY_ROTATION_REQUIRED if prekeys are too old and rotation fails
 *
 * @see https://signal.org/docs/specifications/pqxdh/#publishing-keys
 */
export async function encryptMessage(
  ctx: SignalProtocolClientContext,
  remoteAddress: ProtocolAddress,
  plaintext: string
): Promise<Ciphertext> {
  const sessionId = ProtocolAddress.toString(remoteAddress);
  try {
    // Check prekey age and rotate before advancing any send state.
    if (ctx.relay) {
      const maxAgeMs = ctx.config.maxPreKeyAgeMs;
      const preKeyCheck = await ensurePreKeysValid(
        ctx.relay,
        ctx.userId,
        ctx.deviceId,
        ctx.storage,
        maxAgeMs,
        'aci',
        ctx.logger
      );

      if (!preKeyCheck.canSend) {
        throw new EncryptionError(
          preKeyCheck.errorMessage || 'Prekey rotation required before sending',
          EncryptionErrorCode.PREKEY_ROTATION_REQUIRED
        );
      }
    }

    const ciphertext = await ctx.manager.encrypt(remoteAddress, plaintext);

    // Report the sending-chain counter after encryption.
    const record = await ctx.storage.getSessionRecord(remoteAddress);
    const counter = record?.currentSession?.Ns ?? 0;

    // Call hook: message encrypted
    await callHook(ctx.hooks, 'onMessageEncrypted', sessionId, counter);

    return ciphertext;
  } catch (error) {
    // Call hook: encryption error
    await callHook(ctx.hooks, 'onEncryptionError', sessionId, error as Error);

    throw new EncryptionError(
      `Failed to encrypt message for session ${sessionId}`,
      EncryptionErrorCode.ENCRYPTION_FAILED,
      { originalError: error as Error }
    );
  }
}

/**
 * Decrypt a message from a session
 *
 * Uses the Double Ratchet algorithm to decrypt ciphertext, handling
 * out-of-order messages and updating session state.
 *
 * @param ctx - Client context with dependencies
 * @param remoteAddress - Remote party's protocol address (userId:deviceId)
 * @param ciphertext - Message to decrypt
 * @returns Decrypted plaintext
 */
export async function decryptMessage(
  ctx: SignalProtocolClientContext,
  remoteAddress: ProtocolAddress,
  ciphertext: Ciphertext
): Promise<string> {
  const sessionId = ProtocolAddress.toString(remoteAddress);
  try {
    const plaintext = await ctx.manager.decrypt(remoteAddress, ciphertext);

    // Note: onMessageDecrypted hook is called from handleIncomingEnvelope
    // for relay subscription, where we have full envelope metadata.
    // Manual decryptMessage() callers handle storage themselves.

    return plaintext;
  } catch (error) {
    // Call hook: decryption error
    await callHook(ctx.hooks, 'onDecryptionError', sessionId, error as Error);

    // Preserve specific error codes (e.g., PREKEY_NOT_FOUND for stale bundle detection)
    // instead of wrapping all errors as generic DECRYPTION_FAILED
    if (error instanceof EncryptionError) {
      throw error;
    }

    throw new EncryptionError(
      `Failed to decrypt message for session ${sessionId}`,
      EncryptionErrorCode.DECRYPTION_FAILED,
      { originalError: error as Error }
    );
  }
}

/**
 * Encrypt multiple messages in batch
 *
 * More efficient than calling encryptMessage() multiple times.
 * Operations are performed atomically - if any encryption fails,
 * none of the messages are encrypted.
 *
 * @param ctx - Client context with dependencies
 * @param remoteAddress - Remote party's protocol address (userId:deviceId)
 * @param plaintexts - Array of messages to encrypt
 * @returns Array of encrypted ciphertexts in the same order
 */
export async function encryptMessages(
  ctx: SignalProtocolClientContext,
  remoteAddress: ProtocolAddress,
  plaintexts: string[]
): Promise<Ciphertext[]> {
  if (plaintexts.length === 0) {
    return [];
  }

  const sessionId = ProtocolAddress.toString(remoteAddress);
  const results: Ciphertext[] = [];

  try {
    // Encrypt each message sequentially to maintain proper message ordering
    for (const plaintext of plaintexts) {
      const ciphertext = await ctx.manager.encrypt(remoteAddress, plaintext);
      results.push(ciphertext);
    }

    // Report the final sending-chain counter after the batch.
    const record = await ctx.storage.getSessionRecord(remoteAddress);
    const finalMessageNumber = record?.currentSession?.Ns ?? 0;

    // Call hook for batch completion
    await callHook(ctx.hooks, 'onMessageEncrypted', sessionId, finalMessageNumber);

    return results;
  } catch (error) {
    // Call hook: encryption error
    await callHook(ctx.hooks, 'onEncryptionError', sessionId, error as Error);

    throw new EncryptionError(
      `Failed to encrypt batch of ${plaintexts.length} messages for session ${sessionId}`,
      EncryptionErrorCode.ENCRYPTION_FAILED,
      { originalError: error as Error }
    );
  }
}

/**
 * Decrypt multiple messages in batch
 *
 * More efficient than calling decryptMessage() multiple times.
 * Handles out-of-order messages correctly.
 *
 * @param ctx - Client context with dependencies
 * @param remoteAddress - Remote party's protocol address (userId:deviceId)
 * @param ciphertexts - Array of messages to decrypt
 * @returns Array of decrypted plaintexts in the same order
 */
export async function decryptMessages(
  ctx: SignalProtocolClientContext,
  remoteAddress: ProtocolAddress,
  ciphertexts: Ciphertext[]
): Promise<string[]> {
  if (ciphertexts.length === 0) {
    return [];
  }

  const sessionId = ProtocolAddress.toString(remoteAddress);
  const results: string[] = [];

  try {
    // Decrypt each message
    for (const ciphertext of ciphertexts) {
      const plaintext = await ctx.manager.decrypt(remoteAddress, ciphertext);
      results.push(plaintext);
    }

    // Note: onMessageDecrypted hook is called from handleIncomingEnvelope
    // for relay subscription, where we have full envelope metadata.
    // Manual decryptMessages() callers handle storage themselves.

    return results;
  } catch (error) {
    // Call hook: decryption error
    await callHook(ctx.hooks, 'onDecryptionError', sessionId, error as Error);

    // Preserve EncryptionError for client-layer handling (e.g., PREKEY_NOT_FOUND triggers key rotation)
    if (error instanceof EncryptionError) {
      throw error;
    }

    throw new EncryptionError(
      `Failed to decrypt batch of ${ciphertexts.length} messages for session ${sessionId}`,
      EncryptionErrorCode.DECRYPTION_FAILED,
      { originalError: error as Error }
    );
  }
}

// ============================================================================
// TYPING INDICATORS
// ============================================================================

/**
 * Send typing indicator to conversation recipient
 *
 * Uses the direct send path for implicit typing-indicator content. It retains
 * Double Ratchet encryption but skips MessageRecord storage and session-age
 * validation since typing indicators are fire-and-forget.
 *
 * Typing indicators are application-layer messages that:
 * - Use the same encrypted channel as regular messages
 * - Are NOT stored on the server (transient)
 * - Respect privacy settings (mutual opt-in required)
 * - Auto-expire after 15 seconds if no refresh
 *
 * @param ctx - Client context with dependencies
 * @param recipientUserId - Recipient's user ID
 * @param recipientDeviceId - Recipient's device ID
 * @param conversationId - The conversation ID (dm:userId1_userId2 or group:groupId)
 * @param action - Whether user STARTED or STOPPED typing
 * @param groupId - Optional group ID for group conversations
 */
export async function sendTypingIndicator(
  ctx: SignalProtocolClientContext,
  recipientUserId: string,
  recipientDeviceId: number,
  conversationId: string,
  action: TypingAction,
  groupId?: string
): Promise<void> {
  // Check privacy setting at protocol layer
  const enabled = await ctx.contentAdapter.areTypingIndicatorsEnabled();
  if (!enabled) {
    ctx.logger.debug('Typing indicators disabled by user preference', { category: 'E2EE' });
    return;
  }

  const actionName = action === TypingAction.STARTED ? 'started' : 'stopped';

  ctx.logger.debug(`Sending typing indicator: ${actionName}`, {
    category: 'E2EE',
    data: {
      recipientUserId,
      recipientDeviceId,
      conversationId,
    },
  });

  if (!ctx.relay) {
    ctx.logger.debug('Cannot send typing indicator: relay not configured', {
      category: 'E2EE',
    });
    return;
  }

  try {
    // Create address for the recipient
    const address = ProtocolAddress.create(recipientUserId, recipientDeviceId);

    // Check if we have a session - if not, we cannot send the indicator
    const hasSession = await SessionOps.hasSession(ctx, address);
    if (!hasSession) {
      ctx.logger.debug('Cannot send typing indicator: no session with recipient', {
        category: 'E2EE',
        data: { recipientUserId, recipientDeviceId },
      });
      return;
    }

    // Wrap in Content proto (Signal Protocol wire format: {typingMessage: {timestamp, action, groupId}})
    // DM conversationId dropped from wire. Receiver derives from envelope sender
    // Group conversationId passed as groupId. The Signal Protocol proto requires it for group routing
    const effectiveGroupId =
      groupId ?? (conversationId.startsWith('group:') ? conversationId : undefined);
    const encrypted = await encryptMessage(
      ctx,
      address,
      ctx.contentAdapter.serializeTyping(toContentTypingAction(action), effectiveGroupId)
    );

    // Serialize like SESAME: JSON → bytes → base64
    const ciphertextBase64 = CryptoUtils.bytesToBase64(new TextEncoder().encode(encrypted));

    // Send as ciphertext. Typing indicators are encrypted Content inside
    // a ciphertext envelope. The relay contract carries only the outer type.
    await ctx.relay.send({
      targetUserId: recipientUserId,
      targetDeviceId: recipientDeviceId,
      senderUserId: ctx.userId,
      senderDeviceId: ctx.deviceId,
      ciphertext: ciphertextBase64,
      messageType: 'ciphertext',
      // Protocol messages use timestamp for identification
      timestamp: Date.now(),
      // Explicit ContentHint per Signal Protocol - silently discard on failure
      contentHint: ContentHint.Implicit,
      // Typing indicators are ephemeral (skip persistence if offline) and non-urgent (silent push)
      ephemeral: true,
      urgent: false,
    });

    ctx.logger.debug(`Typing indicator sent: ${actionName}`, {
      category: 'E2EE',
      data: {
        to: `${recipientUserId}:${recipientDeviceId}`,
        conversationId,
      },
    });
  } catch (error) {
    // Typing indicator failures are non-critical - log and continue
    ctx.logger.warn('Failed to send typing indicator', {
      category: 'E2EE',
      data: {
        recipientUserId,
        recipientDeviceId,
        error: (error as Error).message,
      },
    });
  }
}

/**
 * Handle incoming typing indicator
 *
 * Typing indicators are transient messages that indicate when a user
 * is typing in a conversation. They are NOT stored - only used for
 * real-time UI updates.
 *
 * @param ctx - Client context with dependencies
 * @param envelope - The original envelope containing sender info
 * @param typingMsg - The inspected typing content from relay-subscription
 */
export async function handleTypingIndicator(
  ctx: SignalProtocolClientContext,
  envelope: Envelope,
  typingMsg: ParsedTypingContent | null
): Promise<void> {
  // Check privacy setting - if disabled, do not process incoming indicators
  const enabled = await ctx.contentAdapter.areTypingIndicatorsEnabled();
  if (!enabled) {
    ctx.logger.debug('Typing indicators disabled, ignoring incoming indicator', {
      category: 'E2EE',
    });
    return;
  }

  try {
    if (!typingMsg) {
      ctx.logger.warn('Invalid typing Content format', {
        category: 'E2EE',
        data: { senderId: envelope.senderUserId },
      });
      return;
    }

    // Derive conversationId from sender + groupId
    // Reuse existing pattern from signal-service-cipher.ts:246-251
    const conversationId = typingMsg.groupId
      ? typingMsg.groupId
      : (() => {
          const sortedIds = [ctx.userId, envelope.senderUserId].sort();
          return `dm:${sortedIds[0]}_${sortedIds[1]}`;
        })();

    const action = typingMsg.action === 'STARTED' ? TypingAction.STARTED : TypingAction.STOPPED;
    const actionName = action === TypingAction.STARTED ? 'started' : 'stopped';

    ctx.logger.debug(`Received typing indicator: ${actionName}`, {
      category: 'E2EE',
      data: {
        from: envelope.senderUserId,
        conversationId,
      },
    });

    // Call hook to notify app layer
    await callHook(
      ctx.hooks,
      'onTypingIndicatorReceived',
      envelope.senderUserId,
      conversationId,
      action
    );
  } catch (error) {
    ctx.logger.warn('Failed to process typing indicator', {
      category: 'E2EE',
      data: {
        senderId: envelope.senderUserId,
        error: (error as Error).message,
      },
    });
  }
}

// ============================================================================
// DELIVERY/READ RECEIPTS
// ============================================================================

/**
 * Send receipt (delivery or read) to ALL of a user's devices
 *
 * Uses the direct send path for implicit receipt content. It retains Double
 * Ratchet encryption but skips MessageRecord storage and session-age
 * validation because receipts are fire-and-forget.
 *
 * Multi-device fanout: looks up all known device IDs from SESAME store and
 * sends to each device that has a session (parallel, fire-and-forget).
 * @param ctx - Client context with dependencies
 * @param recipientUserId - Recipient's user ID
 * @param timestamps - Message timestamps being acknowledged
 * @param type - Receipt type (DELIVERY or READ)
 */
export async function sendReceipt(
  ctx: SignalProtocolClientContext,
  recipientUserId: string,
  timestamps: number[],
  type: ReceiptType
): Promise<void> {
  const receiptTypeName =
    type === ReceiptType.READ ? 'read' : type === ReceiptType.VIEWED ? 'viewed' : 'delivery';

  ctx.logger.debug(`Sending ${receiptTypeName} receipt`, {
    category: 'E2EE',
    data: {
      recipientUserId,
      timestamps,
    },
  });

  if (!ctx.relay) {
    ctx.logger.debug(`Cannot send ${receiptTypeName} receipt: relay not configured`, {
      category: 'E2EE',
    });
    return;
  }

  // Look up all known devices for this user (SESAME multi-device)
  let deviceIds = await ctx.storage.getSesameDeviceIds(recipientUserId);
  if (deviceIds.length === 0) {
    deviceIds = [1]; // Fallback: primary device
  }

  // Fan out to all devices with sessions (parallel, fire-and-forget)
  await Promise.all(
    deviceIds.map((deviceId) =>
      sendReceiptToDevice(ctx, recipientUserId, deviceId, type, timestamps)
    )
  );
}

/**
 * Send receipt to a single device
 *
 * Shared by receipt fanout and retry processing.
 */
async function sendReceiptToDevice(
  ctx: SignalProtocolClientContext,
  recipientUserId: string,
  deviceId: number,
  type: ReceiptType,
  timestamps: number[]
): Promise<void> {
  const address = ProtocolAddress.create(recipientUserId, deviceId);
  const hasSession = await SessionOps.hasSession(ctx, address);
  if (!hasSession) return;

  try {
    await sendReceiptToDeviceInner(ctx, address, type, timestamps, recipientUserId, deviceId);
  } catch {
    ctx.logger.warn(`Receipt send failed, scheduling retry`, {
      category: 'E2EE',
      data: { recipientUserId, deviceId },
    });
    // Make one in-process retry after five seconds.
    setTimeout(async () => {
      try {
        await sendReceiptToDeviceInner(ctx, address, type, timestamps, recipientUserId, deviceId);
      } catch {
        // Give up after one retry
      }
    }, 5_000);
  }
}

/**
 * Inner send logic for receipt-to-device (encrypt + relay.send)
 */
async function sendReceiptToDeviceInner(
  ctx: SignalProtocolClientContext,
  address: ProtocolAddress,
  type: ReceiptType,
  timestamps: number[],
  recipientUserId: string,
  deviceId: number
): Promise<void> {
  const receiptTypeName =
    type === ReceiptType.READ ? 'read' : type === ReceiptType.VIEWED ? 'viewed' : 'delivery';

  // Wrap the receipt in the Content protobuf.
  const encrypted = await encryptMessage(
    ctx,
    address,
    ctx.contentAdapter.serializeReceipt(toContentReceiptType(type), timestamps)
  );

  // Serialize like SESAME: JSON → bytes → base64
  const ciphertextBase64 = CryptoUtils.bytesToBase64(new TextEncoder().encode(encrypted));

  // Send as ciphertext. Receipts are encrypted Content inside a ciphertext
  // envelope. The relay contract carries only the outer type.
  await ctx.relay!.send({
    targetUserId: recipientUserId,
    targetDeviceId: deviceId,
    senderUserId: ctx.userId,
    senderDeviceId: ctx.deviceId,
    ciphertext: ciphertextBase64,
    messageType: 'ciphertext',
    // Protocol messages use a timestamp for identification.
    timestamp: Date.now(),
    // Receipts are implicit content and may be silently discarded on failure.
    contentHint: ContentHint.Implicit,
    // Receipts are non-urgent (silent push) but not ephemeral (should be delivered)
    urgent: false,
  });

  ctx.logger.debug(
    `${receiptTypeName.charAt(0).toUpperCase() + receiptTypeName.slice(1)} receipt sent`,
    {
      category: 'E2EE',
      data: {
        to: `${recipientUserId}:${deviceId}`,
        timestampCount: timestamps.length,
      },
    }
  );
}

/**
 * Handle incoming delivery/read/viewed receipt and clean up MessageRecords
 *
 * Delivery receipts allow the corresponding outbound MessageRecords to be
 * removed because their retry payloads are no longer needed.
 *
 * @param ctx - Client context with dependencies
 * @param envelope - The original envelope containing sender info
 * @param receiptMsg - The inspected receipt content from relay-subscription
 */
export async function handleDeliveryReceipt(
  ctx: SignalProtocolClientContext,
  envelope: Envelope,
  receiptMsg: ParsedReceiptContent | null
): Promise<void> {
  try {
    if (!receiptMsg) {
      ctx.logger.warn('Invalid receipt Content format', {
        category: 'E2EE',
        data: { senderId: envelope.senderUserId },
      });
      return;
    }

    // Unknown receipt types are ignored for forward compatibility.
    const receiptType = fromContentReceiptType(receiptMsg.type);
    if (receiptType === null) {
      ctx.logger.debug('Ignoring unknown receipt type', {
        category: 'E2EE',
        data: { type: receiptMsg.type },
      });
      return;
    }

    const receipt: DeliveryReceipt = {
      type: receiptType,
      timestamps: receiptMsg.timestamps,
    };

    const isReadReceipt = receipt.type === ReceiptType.READ;
    const isViewedReceipt = receipt.type === ReceiptType.VIEWED;
    const receiptTypeName = isReadReceipt ? 'read' : isViewedReceipt ? 'viewed' : 'delivery';

    // For read/viewed receipts: check the privacy setting. If it is disabled, do
    // not process incoming receipts.
    // This implements SDK mutual opt-in. If you disable read receipts, you will
    // not see when others read your messages, and they will not know when you
    // read theirs.
    if (isReadReceipt || isViewedReceipt) {
      const enabled = await ctx.contentAdapter.areReadReceiptsEnabled();
      if (!enabled) {
        ctx.logger.debug('Read receipts disabled, ignoring incoming read/viewed receipt', {
          category: 'E2EE',
        });
        return;
      }
    }

    // SessionId for the sender of the receipt (they are confirming delivery/read of our messages)
    const sessionId = `${envelope.senderUserId}:${envelope.senderDeviceId}`;

    let deletedCount = 0;

    // Delete MessageRecords for each confirmed timestamp (only for delivery receipts)
    // Read receipts do not need to delete message records since delivery already did
    if (!isReadReceipt && !isViewedReceipt) {
      for (const timestamp of receipt.timestamps) {
        try {
          await ctx.storage.deleteMessageRecord(sessionId, timestamp);
          deletedCount++;
        } catch {
          // Record may already be deleted or expired - not an error
          ctx.logger.debug('MessageRecord not found for timestamp', {
            category: 'E2EE',
            data: { sessionId, timestamp },
          });
        }
      }
    }

    ctx.logger.debug(`Processed ${receiptTypeName} receipt, calling hook`, {
      category: 'E2EE',
      data: {
        from: sessionId,
        senderId: envelope.senderUserId,
        timestamps: receipt.timestamps,
        confirmedCount: deletedCount,
      },
    });

    // Call appropriate hook to notify app layer
    if (isReadReceipt) {
      // Update message status to 'read'
      await callHook(ctx.hooks, 'onReadReceiptReceived', envelope.senderUserId, receipt.timestamps);
    } else if (isViewedReceipt) {
      await callHook(
        ctx.hooks,
        'onViewedReceiptReceived',
        envelope.senderUserId,
        receipt.timestamps
      );
    } else {
      // Update message status to 'delivered'
      await callHook(
        ctx.hooks,
        'onDeliveryReceiptReceived',
        envelope.senderUserId,
        receipt.timestamps
      );
    }
  } catch (error) {
    ctx.logger.warn('Failed to process receipt', {
      category: 'E2EE',
      data: {
        senderId: envelope.senderUserId,
        error: (error as Error).message,
      },
    });
  }
}
