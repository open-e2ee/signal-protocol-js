/**
 * Signal Protocol blocking contracts.
 *
 * Blocking is account/contact state, not message content. The core package owns
 * the local blocking workflow and lets each app choose whether blocked state is
 * purely local, linked-device synced, mirrored to a backend, or all three.
 */

export interface BlockedRecipientEntry {
  recipientId: string;
  blockedAt: number;
}

/**
 * Durable local store for blocked recipients.
 */
export interface SignalBlockingStore {
  isBlocked(recipientId: string): Promise<boolean>;
  listBlockedRecipients(): Promise<BlockedRecipientEntry[]>;
  upsertBlockedRecipient(entry: BlockedRecipientEntry): Promise<void>;
  removeBlockedRecipient(recipientId: string): Promise<void>;
  replaceBlockedRecipients(entries: readonly BlockedRecipientEntry[]): Promise<void>;
}

/**
 * Optional app/backend mirror for local block changes.
 *
 * Examples:
 * - Linked-device blocklist snapshot sync
 * - A platform projection into another local runtime (for example, an NSE cache)
 * - No-op for a fully local-only app
 */
export interface SignalBlockingMirror {
  syncBlockedRecipients(entries: readonly BlockedRecipientEntry[]): Promise<void>;
}

/**
 * Optional local side effects that belong to the act of blocking itself.
 *
 * Example:
 * - Rotate the local profile key after a recipient loses profile access
 */
export interface SignalBlockingHooks {
  onRecipientBlocked?(entry: BlockedRecipientEntry): Promise<void>;
  onRecipientUnblocked?(recipientId: string): Promise<void>;
}
