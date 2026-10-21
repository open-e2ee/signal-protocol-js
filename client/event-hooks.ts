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

import type { RetryTerminalClass } from '../local/store/reliability';
import type { RelayProtocolError } from './device-set-reconciliation';
export type { RetryTerminalClass };
import { ReceiveHookTimeout } from './receive-hook-bound';
import { rethrowRelayWorkStopped } from './relay-work';

/**
 * Decrypted envelope passed to onMessageDecrypted hook
 *
 * Contains all metadata needed to store the decrypted message.
 * The content is the raw decrypted plaintext (typically JSON).
 */
export {};

/**
 * A source that reports that a recipient device has a message.
 *
 * - `'relay'`: the Relay handed the message to the device. The device has not
 *   yet decrypted it.
 * - `'e2ee'`: the device decrypted the message and sent an encrypted delivery
 *   receipt.
 */
export type DeliverySource = 'relay' | 'e2ee';

/** The delivery of one outgoing message to one recipient device. */
export interface DeliveredEvent {
  /** The client message ID of the send. */
  clientMessageId: string;
  /** The recipient user. For a group message, the group member. */
  recipientId: string;
  /** The recipient device. */
  recipientDeviceId: number;
  /** The source that this event reports. */
  source: DeliverySource;
  /** Each source of the delivery so far, in the order of arrival. */
  sources: DeliverySource[];
  /** True when `sources` includes `'e2ee'`: the device decrypted the message. */
  decryptionConfirmed: boolean;
  /** The time of the first source, in epoch milliseconds. */
  deliveredAt: number;
  /** The client timestamp of the send. */
  clientTimestamp: number;
  /** The group ID, for a group message. */
  groupId?: string;
}

/**
 * The end of a retry request with no resend. The device that asked for the
 * resend gets it for each class except `missing-prekey`. The device that
 * sent the failed message gets `missing-prekey`, when it cannot start a new
 * session with the requester. Each request ends once, and the hook runs once
 * for it.
 */
export interface RetryTerminalEvent {
  /** Why the request ended. */
  class: RetryTerminalClass;
  /** The Relay message ID of the envelope that the requester failed to decrypt. */
  failedEnvelopeId: string;
  /**
   * The session reset of the requester. Only an `expired-content` end of a
   * client with a Relay has it.
   */
  recovery?: RetryTerminalRecoveryEvent;
}

/**
 * The session reset of the requester after a retry request ends as
 * `expired-content`.
 *
 * The requester archived its session with the device that sent the failed
 * envelope, after each decrypt from that device in progress ended. The next
 * message to or from the device starts a new session.
 */
export interface RetryTerminalRecoveryEvent {
  /** The user ID of the device whose session the requester archived. */
  userId: string;
  /** The device ID of the device whose session the requester archived. */
  deviceId: number;
  /**
   * `applied`: the failed message is a group message, and the requester has
   * a sender key for that group. The reset does not rotate the key. A key
   * older than `maxSenderKeyAge` rotates at the next send, as at any send,
   * and the new key goes to each member.
   * `skipped`: a pairwise message, a group message whose group the receive
   * did not resolve, or a group with no local sender key.
   *
   * With each outcome, the reset deletes the handoff rows of each device of
   * that account in every group. The next send to each of those groups
   * gives the current key to each of those devices.
   */
  senderKey: 'applied' | 'skipped';
  /**
   * `sent`: one null message went to the device and started the new session.
   * `limited`: a null message went to the device in the last hour, so none
   * was sent. `failed`: the send failed. With `limited` and `failed`, the
   * next ordinary message starts the new session.
   */
  nullMessage: 'sent' | 'limited' | 'failed';
}

/**
 * Why the client reports a delivery error for a failed envelope.
 *
 * - `content-hint`: the failed envelope has the `Default` content hint, or
 *   no hint, so the error comes at the first failure.
 * - `deadline`: the failed envelope has the `Resendable` content hint, and
 *   its content did not come back within `RETRY_PLACEHOLDER_DEADLINE_MS`.
 * - `rate-limit`: a rate limit refused the retry request of the envelope.
 * - `request-ended`: the retry request ended with no resend, as
 *   `onRetryTerminal` reports.
 */
export type DeliveryErrorCause = 'content-hint' | 'deadline' | 'rate-limit' | 'request-ended';

/** The recovery of one failed incoming envelope that had a delivery error. */
export interface DeliveryRecoveredEvent {
  /** The Relay message ID of the envelope that the local device failed to decrypt. */
  failedEnvelopeId: string;
  /** The client message ID of the failed envelope, when its relay delivered one. */
  clientMessageId?: string;
  /** The user that sent the failed envelope. */
  senderUserId: string;
  /** The device that sent the failed envelope. */
  senderDeviceId: number;
  /** True when the failed envelope is a sender-key group message. */
  groupMessage: boolean;
  /**
   * The group of a failed group message, in the form of
   * `DecryptedEnvelope.conversationId`. A group envelope names no group, so
   * the client knows it only when it holds the sender key that the message
   * names. The error of a message that failed for a missing sender key has
   * none. Its recovery has one when the decrypt that gave the content
   * installed or used the sender key of the group. `processIncomingEnvelope`
   * gives a resend's distribution to the caller and installs no key, so
   * its recovery can have none.
   */
  groupId?: string;
  /** The time of the first failure of the envelope, in epoch milliseconds. */
  receivedAt: number;
}

/** The delivery error of one failed incoming envelope. */
export interface DeliveryErrorEvent extends DeliveryRecoveredEvent {
  /** Why the client reports the error now. */
  cause: DeliveryErrorCause;
}

/**
 * Received content that waited on this device for 30 days. The client
 * drops it after the hook.
 */
export interface ReceiveExpiredEvent {
  /** The receive record ID: the delivered fingerprint of the envelope. */
  workId: string;
  /** Why the content expired. */
  reason: 'max-age';
  /** When the device first admitted the content, in epoch milliseconds. */
  receivedAt: number;
  /**
   * Where the content waited: `decrypted` for content that the client did
   * not deliver yet, `awaiting-completion` for a helper receive that the
   * application did not complete.
   */
  stage: 'decrypted' | 'awaiting-completion';
  /** `relay` for a Relay message, `caller` for a helper receive. */
  origin: 'relay' | 'caller';
  /** The message ID. Absent for content stored before the receive queue. */
  messageId?: string;
  /** The sender. Absent for content stored before the receive queue. */
  senderId?: string;
  /** The sender device. Absent for content stored before the receive queue. */
  senderDeviceId?: number;
  /** The raw group of the content, when known. */
  groupId?: string;
  /** The failed envelope that the content resends, for a resend. */
  failedEnvelopeId?: string;
}

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
  /**
   * The sender's timestamp from the content, which a receipt for the
   * message names. Content with no timestamp gives `receivedAt`.
   */
  timestamp: number;
  /** Relay server timestamp when available */
  serverTimestamp?: number;
  /**
   * When the device first admitted the message locally, in epoch
   * milliseconds. A retry and a restart give the same time.
   */
  receivedAt: number;
  /** Whether this is a group message */
  isGroup: boolean;
  /**
   * Whether the message arrived through sealed sender, so the relay did not
   * see its sender.
   */
  arrivedSealed: boolean;
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
   * attempt decryption. When the recovery refreshes the session of a receipt
   * or a retry request, the new session archives the stale one in the same
   * write, and the hook runs after that session start succeeds. A failure
   * in the SESAME registration after that write keeps the new session and
   * runs no hook.
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
   * Delivery is at least once. The client stores the content before it
   * acknowledges the Relay message and runs the hook after that. A stop or
   * a crash before the client records the delivery runs the hook again
   * with the same `messageId`. Deduplicate on `messageId`.
   *
   * The hook must settle. The receive queue runs one hook call at a time,
   * so a hook that never settles stops the queue and `processPendingReceives`
   * until the process restarts.
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
   * Runs when a recipient device gets one of this client's messages
   *
   * A message to one device goes from accepted (the send resolved) to
   * delivered. The hook runs for each source that reports the delivery:
   * `'relay'` when the Relay hands the message to the device, and `'e2ee'`
   * when the device decrypts it and sends an encrypted delivery receipt. A
   * receipt that arrives before the send resolves runs the hook after the
   * send resolves.
   *
   * The hook runs at least once for each source. The client marks a source
   * announced only after the hook returns. An error from the hook fails the
   * receipt, so the relay delivers it again. A hook that throws, a client
   * stop during the hook, or a crash leaves the source unannounced, and the
   * hook runs again for it with the next receipt for the message. A second
   * report from the same source after the hook returned does not run the
   * hook. Make the hook idempotent for one `clientMessageId`,
   * `recipientDeviceId`, and `source`.
   *
   * @param event - The delivery and its sources so far
   *
   * @example
   * ```typescript
   * onDelivered: async (event) => {
   *   await updateMessageStatus(event.clientMessageId, event.recipientDeviceId, {
   *     status: 'delivered',
   *     decryptionConfirmed: event.decryptionConfirmed,
   *   });
   * }
   * ```
   */
  onDelivered?: (event: DeliveredEvent) => void | Promise<void>;

  /**
   * Runs when a retry request ends with no resend
   *
   * A failed decrypt asks the sender device for a resend. The request ends
   * when the Relay gives a conclusive answer to its post, when it does not
   * get its content before its deadline, 14 days after the first failure,
   * when the resend of the fifth attempt also fails, when the sender used up
   * its retry allowance, when the sender device has no prekey bundle of the
   * requester, or when the sender device refuses group content to a
   * requester that is not a current member of the group. The content of the
   * failed envelope is then lost. The hook runs at least once for each
   * request. The SDK marks the end emitted only after the hook returns. A
   * hook that throws, a client stop during the hook, or a crash leaves the
   * end not emitted, and the hook runs again at the next retry request pass,
   * start, or redelivery. Make the hook idempotent for one
   * `failedEnvelopeId`.
   *
   * Before the hook, an `expired-content` end resets the session with the
   * device that sent the failed envelope, and `event.recovery` tells what
   * the reset did. The other classes, and a post that fails and can be
   * posted again, reset nothing. `onSessionArchived` runs for the archive.
   *
   * @param event - The class of the end, the failed envelope, and the reset
   *
   * @example
   * ```typescript
   * onRetryTerminal: async (event) => {
   *   await messageStore.markUndecryptable(event.failedEnvelopeId, event.class);
   * }
   * ```
   */
  onRetryTerminal?: (event: RetryTerminalEvent) => void | Promise<void>;

  /**
   * Runs when an incoming message failed to decrypt and its content did not
   * come back
   *
   * A failed decrypt asks the sender device for a resend and acknowledges
   * the failed envelope. The content hint of the envelope sets when the
   * hook runs. With the `Default` hint, or no hint, it runs at the first
   * failure. With the `Resendable` hint, it runs when the content did not
   * come back within `RETRY_PLACEHOLDER_DEADLINE_MS`, one hour, of the
   * first failure. With the `Implicit` hint, it never runs. A rate limit
   * that refuses the retry request, and the end of the request, make it run
   * at once. The client checks the time at each redelivery of the envelope
   * and at each retry family write. With a relay, it also checks at
   * create() and, while the client runs, at the time when the error is due.
   *
   * The hook runs at least once for each failed envelope, also across a
   * restart. The client marks the error shown only after the hook returns.
   * A hook that throws, a client stop during the hook, or a crash leaves the
   * error not shown, and the hook runs again at the next retry request
   * pass, start, or redelivery. The receive path does not acknowledge a
   * failed envelope whose hook threw. Make the hook idempotent for one
   * `failedEnvelopeId`. The error deletes nothing: the retry request
   * continues, and when the content comes back, `onDeliveryRecovered` runs.
   *
   * @param event - The failed envelope, its sender and the cause
   *
   * @example
   * ```typescript
   * onDeliveryError: async (event) => {
   *   await messageStore.showUndelivered(event.failedEnvelopeId, event.senderUserId);
   * }
   * ```
   */
  onDeliveryError?: (event: DeliveryErrorEvent) => void | Promise<void>;

  /**
   * Runs when the content of a failed incoming message comes back after
   * `onDeliveryError` ran for it
   *
   * The content comes back in a resend from the sender device, or in a
   * redelivery of the failed envelope that now decrypts. The application
   * gets the content as for any message, and then this hook runs. Its
   * event carries the time of the first failure, so the application can put
   * the message back in its first place.
   *
   * The hook runs at least once for each failed envelope, also across a
   * restart. The client marks the recovery only after the hook returns. A
   * hook that throws, a client stop during the hook, or a crash leaves the
   * recovery not marked, and the hook runs again at the next retry request
   * pass, start, or receive of an envelope of the same retry family. An
   * error from the hook after the content does not fail that receive. Make
   * the hook idempotent for one `failedEnvelopeId`.
   *
   * @param event - The failed envelope and its sender
   *
   * @example
   * ```typescript
   * onDeliveryRecovered: async (event) => {
   *   await messageStore.clearUndelivered(event.failedEnvelopeId);
   * }
   * ```
   */
  onDeliveryRecovered?: (event: DeliveryRecoveredEvent) => void | Promise<void>;

  /**
   * Runs when received content waited on this device for 30 days, before
   * the client drops it.
   *
   * Content waits when its group state is not current, or when a helper
   * receive is not completed. The hook runs at least once: a stop or a
   * crash before the client records the expiry runs it again for the same
   * `workId`. The client sends no delivery receipt and no retry request for
   * expired content.
   *
   * @param event - The expired content, without its plaintext
   *
   * @example
   * ```typescript
   * onReceiveExpired: async (event) => {
   *   await messageStore.markLost(event.messageId ?? event.workId);
   * }
   * ```
   */
  onReceiveExpired?: (event: ReceiveExpiredEvent) => void | Promise<void>;

  /**
   * Runs once for a completed send whose Relay accepted a declared post
   * without the `deviceSetChecked` mark. A declared post is a post to a
   * recipient device or a sync copy to another device of the own account.
   *
   * The client declares the device set of each recipient account only to a
   * Relay that compares device sets. Such a Relay marks each post that it
   * compared. An accepted post without the mark is a Relay defect: the Relay
   * did not check the declared devices. The send is delivered, so its result
   * does not change and the client does not post it again. The error carries
   * the code `DEVICE_SET_UNCHECKED`, the `clientMessageId` of the send, and
   * the route of the post. The route is `identified-direct`,
   * `anonymous-direct`, or `anonymous-group`. A sync copy is an
   * `identified-direct` post. The client also logs one warning with the code
   * and the route.
   *
   * The hook also runs once for a sync payload of a method such as
   * `syncReadToLinkedDevices`. That error has no `clientMessageId`.
   *
   * The hook runs after the send completes. An error from the hook does not
   * change the send result. The client logs the error.
   *
   * @param error - The protocol error of the send
   *
   * @example
   * ```typescript
   * onRelayProtocolError: (error) => {
   *   monitoring.report('relay-protocol', { code: error.code, route: error.route });
   * }
   * ```
   */
  onRelayProtocolError?: (error: RelayProtocolError) => void | Promise<void>;

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

const HOOK_NAMES = {
  onSessionEstablished: true,
  onSessionDeleted: true,
  onSessionArchived: true,
  onKeyRotated: true,
  onMessageEncrypted: true,
  onMessageDecrypted: true,
  onDecryptionError: true,
  onEncryptionError: true,
  onKeysCleanedUp: true,
  onDelivered: true,
  onRetryTerminal: true,
  onDeliveryError: true,
  onDeliveryRecovered: true,
  onReceiveExpired: true,
  onRelayProtocolError: true,
  onReadReceiptReceived: true,
  onViewedReceiptReceived: true,
  onTypingIndicatorReceived: true,
} as const satisfies Record<HookName, true>;

/**
 * Throw for a name that is not a client hook, so that a misspelled or removed
 * hook fails at registration and not silently.
 *
 * @internal
 */
export function assertHookName(name: string): asserts name is HookName {
  if (!Object.prototype.hasOwnProperty.call(HOOK_NAMES, name)) {
    throw new Error(`Unknown Signal Protocol client hook: ${name}`);
  }
}

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
    rethrowRelayWorkStopped(error);
    // The receive hook bound logged its timeout.
    if (error instanceof ReceiveHookTimeout) return;
    // Log hook error but do not let it break core functionality
    console.error(`Hook ${hookName} failed:`, error);
  }
}

/**
 * Hooks that queue each call. A task that holds a lock calls the app through
 * these hooks, and flush() makes the queued calls after the task releases the
 * lock. So a hook can call a client method that takes the same lock.
 *
 * @internal
 */
export function deferHooks(hooks: SignalProtocolClientHooks | undefined): {
  hooks: SignalProtocolClientHooks;
  flush(): Promise<void>;
} {
  const queued: Array<[HookName, unknown[]]> = [];
  const deferred: Record<string, (...args: unknown[]) => void> = {};
  for (const [name, hook] of Object.entries(hooks ?? {})) {
    if (typeof hook !== 'function') continue;
    deferred[name] = (...args) => {
      queued.push([name as HookName, args]);
    };
  }
  const call = callHook as (
    hooks: SignalProtocolClientHooks | undefined,
    hookName: HookName,
    ...args: unknown[]
  ) => Promise<void>;
  return {
    hooks: deferred as SignalProtocolClientHooks,
    async flush() {
      for (let next = queued.shift(); next; next = queued.shift()) {
        await call(hooks, next[0], ...next[1]);
      }
    },
  };
}
