/**
 * Event Hooks System for SignalProtocolClient
 *
 * Provides lifecycle hooks for applications to react to Signal Protocol events.
 * All hooks are optional and can be async for flexibility.
 *
 * Common Use Cases:
 * - State management integration (Redux, Zustand, Context API)
 * - Content storage (ContentManager stores decrypted content)
 * - Analytics and monitoring (Sentry, DataDog)
 * - User notifications (key rotation, errors)
 * - Debugging and logging
 *
 * @example
 * ```typescript
 * import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
 *
 * const signal = await createSignalProtocolClient({
 *   identity: { userId },
 *   adapters: { storage, relay },
 *   hooks: {
 *     onMessageDecrypted: async (envelope) => {
 *       // Store decrypted content in your app database.
 *       await contentDb.storeMessage({
 *         messageId: envelope.messageId,
 *         conversationId: envelope.conversationId,
 *         content: envelope.content,
 *         // ...
 *       });
 *     },
 *     onKeyRotated: (keyType) => {
 *       analytics.track('Key Rotated', { keyType });
 *     }
 *   }
 * });
 * ```
 */

/**
 * Decrypted envelope passed to onMessageDecrypted hook
 *
 * Contains all metadata needed to store the decrypted message.
 * The content is the raw decrypted plaintext (typically JSON).
 */
export {};
export interface DecryptedEnvelope {
  /** Unique message ID (from server or generated) */
  messageId: string;
  /** Session ID used for decryption (userId.deviceId format) */
  sessionId: string;
  /** Sender's user ID */
  senderId: string;
  /** Sender's device ID */
  senderDeviceId: number;
  /** Conversation ID (groupId for groups, recipientId for 1:1) */
  conversationId: string;
  /** Decrypted plaintext content (typically JSON) */
  content: string;
  /** Message timestamp (from sender) */
  timestamp: number;
  /** Relay server timestamp when available */
  serverTimestamp?: number;
  /** When the device received the message locally */
  receivedAt: number;
  /** Whether this is a group message */
  isGroup: boolean;
  /** Message type hint (if available from envelope) - apps define their own type unions */
  messageType?: string;
}

/**
 * Event hooks that SignalProtocolClient accepts
 *
 * All hooks are optional and support both sync and async implementations.
 */
export interface SignalProtocolClientHooks {
  /**
   * Called after a new session is successfully established
   *
   * @param sessionId - The session identifier
   * @param remoteAddress - The remote user's address
   *
   * @example
   * ```typescript
   * onSessionEstablished: (sessionId, remoteAddress) => {
   *   // Invalidate cache
   *   ContentManager.invalidateSession(sessionId);
   *   // Update UI state
   *   setSessionStatus(sessionId, 'active');
   * }
   * ```
   */
  onSessionEstablished?: (sessionId: string, remoteAddress: string) => void | Promise<void>;

  /**
   * Runs after the client deletes a session
   *
   * @param sessionId - The identifier of the deleted session
   *
   * @example
   * ```typescript
   * onSessionDeleted: (sessionId) => {
   *   // Clear cache
   *   ContentManager.clearSession(sessionId);
   *   // Update UI
   *   removeSessionFromList(sessionId);
   * }
   * ```
   */
  onSessionDeleted?: (sessionId: string) => void | Promise<void>;

  /**
   * Runs after the client archives a session (moved to inactive list)
   *
   * Stale-device recovery archives the session so delayed messages can still
   * attempt decryption.
   * Per SESAME §3.2: "previously active session is moved to the head of the inactive sessions list"
   *
   * @param sessionId - The identifier of the archived session
   *
   * @example
   * ```typescript
   * onSessionArchived: (sessionId) => {
   *   console.log(`Session ${sessionId} archived, will be replaced with fresh session`);
   * }
   * ```
   */
  onSessionArchived?: (sessionId: string) => void | Promise<void>;

  /**
   * Called after a key rotation completes successfully
   *
   * @param keyType - Type of the rotated key
   *
   * @example
   * ```typescript
   * onKeyRotated: (keyType) => {
   *   console.log(`${keyType} rotated successfully`);
   *   analytics.track('Key Rotation', { keyType });
   * }
   * ```
   */
  onKeyRotated?: (keyType: 'ecSignedPreKey' | 'kemLastResortPreKey') => void | Promise<void>;

  /**
   * Called after a message is successfully encrypted
   *
   * Useful for analytics, monitoring, or cache warming.
   *
   * @param sessionId - The session used for encryption
   * @param counter - The message counter (Ns) - matches the reference implementation's proto field name
   *
   * @example
   * ```typescript
   * onMessageEncrypted: (sessionId, counter) => {
   *   analytics.track('Message Encrypted', {
   *     sessionId,
   *     counter
   *   });
   * }
   * ```
   */
  onMessageEncrypted?: (sessionId: string, counter: number) => void | Promise<void>;

  /**
   * Called after a message is successfully decrypted
   *
   * This is the primary hook for ContentManager integration.
   * The hook receives the full decrypted envelope with all metadata
   * needed to store the message in the encrypted content database.
   *
   * @param envelope - The decrypted message envelope
   *
   * @example
   * ```typescript
   * onMessageDecrypted: async (envelope) => {
   *   // Store in encrypted content database
   *   await contentDb.storeMessage({
   *     messageId: envelope.messageId,
   *     conversationId: envelope.conversationId,
   *     senderId: envelope.senderId,
   *     senderDeviceId: envelope.senderDeviceId,
   *     content: envelope.content,
   *     timestamp: envelope.timestamp,
   *     receivedAt: envelope.receivedAt,
   *     isOutgoing: false,
   *   });
   *   // Send read receipt
   *   sendReadReceipt(envelope.sessionId);
   * }
   * ```
   */
  onMessageDecrypted?: (envelope: DecryptedEnvelope) => void | Promise<void>;

  /**
   * Called when decryption fails
   *
   * Allows app to handle errors, log issues, or show user feedback.
   *
   * @param sessionId - The session where decryption failed
   * @param error - The encryption error that occurred
   *
   * @example
   * ```typescript
   * onDecryptionError: (sessionId, error) => {
   *   // Log to monitoring service
   *   Sentry.captureException(error, {
   *     tags: { sessionId, errorCode: error.code }
   *   });
   *   // Show user-friendly message
   *   showError('Failed to decrypt message');
   * }
   * ```
   */
  onDecryptionError?: (sessionId: string, error: Error) => void | Promise<void>;

  /**
   * Called when encryption fails
   *
   * Allows app to handle errors, log issues, or retry logic.
   *
   * @param sessionId - The session where encryption failed
   * @param error - The encryption error that occurred
   *
   * @example
   * ```typescript
   * onEncryptionError: (sessionId, error) => {
   *   // Log error
   *   console.error('Encryption failed:', error);
   *   // Attempt recovery
   *   if (error.code === 'SESSION_CORRUPTED') {
   *     reestablishSession(sessionId);
   *   }
   * }
   * ```
   */
  onEncryptionError?: (sessionId: string, error: Error) => void | Promise<void>;

  /**
   * Called during key cleanup (expired message keys removed)
   *
   * Useful for monitoring storage usage and cleanup operations.
   *
   * @param sessionId - The session where cleanup occurred
   * @param removedCount - Number of expired keys removed
   *
   * @example
   * ```typescript
   * onKeysCleanedUp: (sessionId, removedCount) => {
   *   console.log(`Cleaned up ${removedCount} expired keys`);
   *   analytics.track('Keys Cleaned', { sessionId, removedCount });
   * }
   * ```
   */
  onKeysCleanedUp?: (sessionId: string, removedCount: number) => void | Promise<void>;

  /**
   * Runs when the client receives a delivery receipt
   *
   * Allows the app to update message status from 'sent' to 'delivered'.
   * The timestamps array contains server timestamps of delivered messages.
   *
   * @param senderId - The user who sent the delivery receipt (message recipient)
   * @param timestamps - Array of message timestamps for the delivered messages
   *
   * @example
   * ```typescript
   * onDeliveryReceiptReceived: async (senderId, timestamps) => {
   *   for (const timestamp of timestamps) {
   *     await updateMessageStatus(timestamp, 'delivered');
   *   }
   * }
   * ```
   */
  onDeliveryReceiptReceived?: (senderId: string, timestamps: number[]) => void | Promise<void>;

  /**
   * Runs when the client receives a read receipt
   *
   * Allows the app to update message status from 'delivered' to 'read'.
   * The timestamps array contains server timestamps of read messages.
   *
   * @param senderId - The user who sent the read receipt (message recipient who viewed messages)
   * @param timestamps - Array of message timestamps for the read messages
   *
   * @example
   * ```typescript
   * onReadReceiptReceived: async (senderId, timestamps) => {
   *   for (const timestamp of timestamps) {
   *     await updateMessageStatus(timestamp, 'read');
   *   }
   * }
   * ```
   */
  onReadReceiptReceived?: (senderId: string, timestamps: number[]) => void | Promise<void>;

  /**
   * Runs when the client receives a viewed receipt (e.g., view-once media)
   *
   * Allows the app to update message status to 'viewed'.
   * The timestamps array contains server timestamps of viewed messages.
   *
   * @param senderId - The user who sent the viewed receipt (message recipient who viewed media)
   * @param timestamps - Array of message timestamps for the viewed messages
   *
   * @example
   * ```typescript
   * onViewedReceiptReceived: async (senderId, timestamps) => {
   *   for (const timestamp of timestamps) {
   *     await updateMessageStatus(timestamp, 'viewed');
   *   }
   * }
   * ```
   */
  onViewedReceiptReceived?: (senderId: string, timestamps: number[]) => void | Promise<void>;

  /**
   * Runs when the client receives a typing indicator
   *
   * Allows the app to update UI with the users who type.
   * Typing indicators are transient - they auto-expire after 15 seconds.
   *
   * @param senderId - The user who sent the typing indicator
   * @param conversationId - The conversation the typing indicator belongs to
   * @param action - Whether user STARTED or STOPPED typing
   *
   * @example
   * ```typescript
   * onTypingIndicatorReceived: async (senderId, conversationId, action) => {
   *   if (action === TypingAction.STARTED) {
   *     typingManager.setTyping(conversationId, senderId);
   *   } else {
   *     typingManager.clearTyping(conversationId, senderId);
   *   }
   * }
   * ```
   */
  onTypingIndicatorReceived?: (
    senderId: string,
    conversationId: string,
    action: import('./types').TypingAction
  ) => void | Promise<void>;
}

/**
 * Helper type to extract hook names from SignalProtocolClientHooks
 */
export type HookName = keyof SignalProtocolClientHooks;

/**
 * Helper to safely call a hook if it exists
 *
 * Handles both sync and async hooks, and catches any errors
 * to prevent hook failures from affecting core functionality.
 *
 * @internal
 */
export async function callHook<T extends HookName>(
  hooks: SignalProtocolClientHooks | undefined,
  hookName: T,
  ...args: Parameters<NonNullable<SignalProtocolClientHooks[T]>>
): Promise<void> {
  if (!hooks || !hooks[hookName]) {
    return;
  }

  try {
    const hook = hooks[hookName] as NonNullable<SignalProtocolClientHooks[T]>;
    await Promise.resolve(
      Reflect.apply(hook as (...hookArgs: unknown[]) => unknown, undefined, args as unknown[])
    );
  } catch (error) {
    // Log hook error but do not let it break core functionality
    console.error(`Hook ${hookName} failed:`, error);
  }
}
