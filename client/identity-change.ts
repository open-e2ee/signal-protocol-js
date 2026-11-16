/**
 * The identity change of a contact, as the trust gate detects it, and the
 * reporter that gives each change to the `onIdentityChanged` hook once.
 */

import type { Logger } from '../logger';
import type { CompositeIdentityV1, IdentityTrustState, IdentityType } from '../keys/types';
import { encodeCompositeIdentityV1, evaluateContactIdentityCandidate } from '../keys/identity';
import { bytesToBase64 } from '../internal/crypto';
import type { UntrustedIdentityRefusal } from '../internal/session/untrusted-identity';
import type { IdentityKeyStore } from '../types/api';
import type { TrustDirection } from '../types/trust';

/**
 * An identity change of a contact that the client detected.
 *
 * The client detects a change when its trust gate refuses an identity that
 * differs from the pinned identity of the user. The refusal stays: the send or
 * the decrypt still fails with `UntrustedIdentityError`. To trust the new
 * identity, call `acceptIdentityRotation(userId, currentIdentity, identityType)`.
 */
export interface IdentityChangedEvent {
  /** The user whose identity changed. */
  readonly userId: string;
  /** The identity type of the pinned identity, `'aci'` or `'pni'`. */
  readonly identityType: IdentityType;
  /** The device of the user that presented `currentIdentity`. */
  readonly deviceId: number;
  /**
   * `'CHANGED'` for an identity that the client has not pinned before.
   * `'ROLLBACK'` for an identity that the client pinned before and retired
   * when it accepted a later identity.
   */
  readonly status: 'CHANGED' | 'ROLLBACK';
  /** The pinned identity of the user. */
  readonly previousIdentity: CompositeIdentityV1;
  /** The identity that the trust gate refused. */
  readonly currentIdentity: CompositeIdentityV1;
  /** The trust state of the pinned identity. */
  readonly trustState: IdentityTrustState;
  /** The path that detected the change: `sending` or `receiving`. */
  readonly direction: TrustDirection;
}

/**
 * Gives each refusal of a changed identity to `report` once.
 *
 * `observe` returns at once. It queues a read of the pinned identity, so the
 * locked session work that refused the identity does not wait for the store
 * or for the app. The reports run in order. The reporter remembers each
 * reported change for the life of the client, and keeps no state in the store.
 * It reports no refusal of a device of the own account.
 *
 * @internal
 */
export class IdentityChangeReporter {
  /** Each reported change, by user, identity type, pinned and refused identity. */
  private readonly reported = new Set<string>();
  /** The last report, so that the reports run in order. */
  private queue: Promise<void> = Promise.resolve();

  constructor(
    private readonly options: {
      storage: Pick<IdentityKeyStore, 'getContactIdentity'>;
      /** The own user ID. A refusal of an own device is no contact change. */
      ownUserId: string;
      isObserved: () => boolean;
      report: (event: IdentityChangedEvent) => Promise<void>;
      logger: Required<Logger>;
    }
  ) {}

  /** Queue the report of one refusal. No caller waits for the report. */
  readonly observe = (refusal: UntrustedIdentityRefusal): void => {
    if (refusal.address.userId === this.options.ownUserId) return;
    if (!this.options.isObserved()) return;
    this.queue = this.queue
      .then(() => this.reportRefusal(refusal))
      .catch((error: unknown) => {
        this.options.logger.warn('The identity change report failed', {
          category: 'SECURITY',
          data: {
            behavior: 'IDENTITY_CHANGE_REPORT_FAILED',
            userId: refusal.address.userId,
            error: error instanceof Error ? error.message : String(error),
          },
        });
      });
  };

  private async reportRefusal(refusal: UntrustedIdentityRefusal): Promise<void> {
    const pinned = await this.options.storage.getContactIdentity(
      refusal.address,
      refusal.identityType
    );
    // No pin is a first contact. The store pins it, and it is no change.
    if (pinned === null) return;
    const status = evaluateContactIdentityCandidate(pinned, refusal.identity);
    // The pin moved to the refused identity after the refusal.
    if (status !== 'CHANGED' && status !== 'ROLLBACK') return;
    const change = [
      refusal.address.userId,
      refusal.identityType,
      bytesToBase64(encodeCompositeIdentityV1(pinned.identity)),
      bytesToBase64(encodeCompositeIdentityV1(refusal.identity)),
    ].join(':');
    if (this.reported.has(change)) return;
    this.reported.add(change);
    await this.options.report({
      userId: refusal.address.userId,
      identityType: refusal.identityType,
      deviceId: refusal.address.deviceId,
      status,
      previousIdentity: pinned.identity,
      currentIdentity: refusal.identity,
      trustState: pinned.trustState,
      direction: refusal.direction,
    });
  }
}
