/**
 * The receive record that one decrypt commits with its ratchet step.
 *
 * The seed fixes the fields of the record before the decrypt: the arrival
 * order, the first admission time, the sender, and, for a Relay delivery,
 * the acknowledgment intent. The decrypt adds the plaintext and the raw
 * group in its commit. The seed never throws, so a seed failure never
 * rolls back a ratchet step.
 */

import type { Logger } from '../logger';
import type { Envelope } from '../remote/relay/types';
import type { ReceiveWorkRecord, SignalProtocolLocalStore } from '../types/api';
import { sizedReceiveWork } from '../local/store/receive-work';
import type { SignalProtocolContentAdapter } from './content-adapter';
import { admitReceive } from './receive-admission';
import type { RetryFamilyReceive } from './retry-family';
import type { ReceiveCommit } from './signal-service-cipher';
import type { ResolvedReceiveQueuePolicy } from './storage-protection';

/**
 * The arrival order steps 1,024 times per millisecond, so two records
 * that arrive in one millisecond keep their order. Each store has one
 * counter in a process, as it has one admission lock, and the counter
 * never steps back. The resume of the receive queue raises it to the
 * largest stored value before any receive path admits, so a record
 * admitted after a restart sorts after the stored records even when the
 * clock stepped back. This holds only when the first resume of the run
 * completes. It does not hold for a record admitted after a first resume
 * that failed, because the receive paths wait only for the first attempt,
 * for a record admitted after a `stop()` during the first resume, or for a
 * record admitted before the first `start()` of the queue. Two processes
 * that share one store, such as two browser tabs, each keep their own
 * counter, so a record of one process can sort before a record that the
 * other process admitted earlier.
 */
const ARRIVAL_SEQ_PER_MS = 1_024;
const lastArrivalSeqs = new WeakMap<object, number>();

function nextArrivalSeq(store: object, now: number): number {
  const next = Math.max(now * ARRIVAL_SEQ_PER_MS, (lastArrivalSeqs.get(store) ?? 0) + 1);
  lastArrivalSeqs.set(store, next);
  return next;
}

/**
 * Raise the arrival counter of a store to a stored arrival order, so the
 * next record of the store sorts after it.
 *
 * @param store - The store of the record
 * @param stored - The `arrivalSeq` of a stored receive record
 */
export function raiseArrivalSeq(store: object, stored: number): void {
  lastArrivalSeqs.set(store, Math.max(lastArrivalSeqs.get(store) ?? 0, stored));
}

/** The inputs of one receive commit. */
export interface ReceiveCommitOptions {
  readonly storage: Pick<SignalProtocolLocalStore, 'receiveWorkUsage'>;
  readonly policy: ResolvedReceiveQueuePolicy;
  readonly logger: Required<Logger>;
  readonly contentAdapter: Pick<SignalProtocolContentAdapter, 'inspectContent'>;
  /**
   * The retry family of the envelope. It names the failed envelope of a
   * resend, and binds a resend to the sender of the envelope that the seed
   * gets.
   */
  readonly family: Pick<RetryFamilyReceive, 'bindSender' | 'fulfills'> | undefined;
  /** The delivered fingerprint of the envelope. */
  readonly workId: string;
  /** `relay` for a Relay delivery, `caller` for an envelope that the application passed. */
  readonly origin: ReceiveWorkRecord['origin'];
  /**
   * True when the Relay of the delivery can own the receipt: the client
   * sends receipts in `auto` mode through a Relay with a receipt join.
   */
  readonly receiptJoin: boolean;
}

/** One receive commit, and whether its decrypt built the record. */
export interface ReceiveCommitHandle {
  readonly commit: ReceiveCommit;
  /**
   * True when the decrypt built the record. An error after this point is
   * a failure of the store commit or of a later step, not of the decrypt:
   * the caller asks for no resend and does not acknowledge.
   */
  seeded(): boolean;
}

/** Make the receive commit of one envelope. */
export function createReceiveCommit(options: ReceiveCommitOptions): ReceiveCommitHandle {
  const { workId, origin } = options;
  let seeded = false;
  const commit: ReceiveCommit = {
    workId,
    seed(envelope: Envelope, arrivedSealed: boolean) {
      // The seed gets the envelope that the decrypt opens: for a sealed
      // envelope, the envelope inside the seal. Its sender is the sender
      // that the decrypt authenticates.
      options.family?.bindSender(envelope);
      const now = Date.now();
      const relay = origin === 'relay';
      const base = {
        workId,
        revision: 0,
        stage: 'decrypted' as const,
        origin,
        arrivalSeq: nextArrivalSeq(options.storage, now),
        receivedAt: now,
        dueAt: now,
        messageId: envelope.id || `${envelope.senderUserId}-${now}`,
        ...(envelope.id && { envelopeId: envelope.id }),
        senderUserId: envelope.senderUserId,
        senderDeviceId: envelope.senderDeviceId,
        messageType: envelope.messageType as NonNullable<ReceiveWorkRecord['messageType']>,
        ...(envelope.serverTimestamp !== undefined && {
          serverTimestamp: envelope.serverTimestamp,
        }),
        arrivedSealed,
        // The replay check of a restored record compares this value with
        // the content. A caller envelope has no Relay timestamp to keep.
        ...(relay && Number.isSafeInteger(envelope.timestamp) && {
          senderTimestamp: envelope.timestamp,
        }),
        ...(relay && {
          ackIntent: {
            at: now,
            hasReceiptJoin:
              options.receiptJoin &&
              !!envelope.id &&
              !arrivedSealed &&
              envelope.deliveryClass !== 'ephemeral',
          },
        }),
      };
      return (content) => {
        seeded = true;
        let failedEnvelopeId: string | undefined;
        try {
          const inspected = options.contentAdapter.inspectContent(content.plaintext);
          if (!inspected.nullMessage) {
            failedEnvelopeId = options.family?.fulfills({
              senderKeyDistribution: inspected.senderKeyDistribution !== undefined,
              content:
                inspected.senderKeyDistribution === undefined ||
                inspected.senderKeyDistributionOnly === false,
            });
          }
        } catch {
          // Content that does not parse fulfills nothing. The checks after
          // the commit deny it.
        }
        return sizedReceiveWork({
          ...base,
          sizeBytes: 0,
          plaintext: content.plaintext,
          ...(content.groupId !== undefined && { groupId: content.groupId }),
          ...(failedEnvelopeId !== undefined && { failedEnvelopeId }),
        });
      };
    },
    admit: (groupId, decrypt) =>
      admitReceive(options.storage, options.policy, options.logger, groupId, decrypt),
  };
  return { commit, seeded: () => seeded };
}
