import { resolveSignalLogger, type ILogger } from '../logger';
import type {
  BlockedRecipientEntry,
  SignalBlockingHooks,
  SignalBlockingMirror,
  SignalBlockingStore,
} from './types';

export interface SignalBlockingManagerOptions {
  store: SignalBlockingStore;
  mirror?: SignalBlockingMirror;
  hooks?: SignalBlockingHooks;
  logger?: ILogger;
}

/**
 * SDK blocking orchestration.
 *
 * The local store is authoritative for the current device. Optional mirrors can
 * project that state elsewhere without becoming a second mutation path.
 */
export class SignalBlockingManager {
  private readonly store: SignalBlockingStore;
  private readonly mirror?: SignalBlockingMirror;
  private readonly hooks?: SignalBlockingHooks;
  private readonly logger: Required<ILogger>;

  constructor(options: SignalBlockingManagerOptions) {
    this.store = options.store;
    this.mirror = options.mirror;
    this.hooks = options.hooks;
    this.logger = resolveSignalLogger(options.logger);
  }

  async isBlocked(recipientId: string): Promise<boolean> {
    return await this.store.isBlocked(recipientId);
  }

  async listBlockedRecipients(): Promise<BlockedRecipientEntry[]> {
    return await this.store.listBlockedRecipients();
  }

  async blockRecipient(
    recipientId: string,
    blockedAt: number = Date.now()
  ): Promise<BlockedRecipientEntry> {
    const entry: BlockedRecipientEntry = { recipientId, blockedAt };

    await this.store.upsertBlockedRecipient(entry);
    await this.hooks?.onRecipientBlocked?.(entry);

    try {
      const snapshot = await this.store.listBlockedRecipients();
      await this.mirror?.syncBlockedRecipients(snapshot);
    } catch (error) {
      this.logger.warn('Failed to project blocked-recipient snapshot', {
        category: 'Blocking',
        recipientId,
        error: error instanceof Error ? error.message : String(error),
      });
    }

    return entry;
  }

  async unblockRecipient(recipientId: string): Promise<void> {
    await this.store.removeBlockedRecipient(recipientId);
    await this.hooks?.onRecipientUnblocked?.(recipientId);

    try {
      const snapshot = await this.store.listBlockedRecipients();
      await this.mirror?.syncBlockedRecipients(snapshot);
    } catch (error) {
      this.logger.warn('Failed to project blocked-recipient snapshot', {
        category: 'Blocking',
        recipientId,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  async applySyncSnapshot(entries: readonly BlockedRecipientEntry[]): Promise<void> {
    await this.store.replaceBlockedRecipients(entries);
  }
}
