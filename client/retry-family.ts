/**
 * The retry family of a received envelope.
 *
 * A failed envelope, the request record that the requester keeps for it, and
 * each resend or null message that answers that record form one retry
 * family. The family index gives the failed envelope of a retry ID. Both
 * receive paths, the relay subscription route and `processIncomingEnvelope`,
 * receive each envelope through `receiveInRetryFamily`, so the application
 * gets the content of one failed envelope at most once, from the envelope
 * itself or from one family member.
 */

import type { Logger } from '../logger';
import {
  getProcessedEnvelope,
  getRetryRequest,
  markRetryRequestAnswered,
  resolveRetryFamilyMember,
  RetryRequestedEnvelopeChangedError,
  storeProcessedEnvelope,
  withProcessedEnvelopeLock,
  type ResolvedRetryFamilyMember,
  type StoredRetryRequest,
} from '../local/store/reliability';
import type { RetryRequestFailure } from './retry-request-envelope';

type RetryFamilyStore = Parameters<typeof withProcessedEnvelopeLock>[0];

/**
 * One received envelope in the retry family of its failed envelope. The
 * receive path calls `admit` before the decrypt, `fulfill` after a decrypt
 * that succeeds, and `requestRetry` after a decrypt that fails.
 */
export interface RetryFamilyReceive {
  /**
   * The resend or the null message that the envelope is, when the family
   * index of the local device holds its retry ID. Undefined for any other
   * envelope.
   */
  readonly member: ResolvedRetryFamilyMember | undefined;
  /**
   * Tell whether the envelope goes to the decrypt. False when the local
   * device processed the envelope, or when the application already has the
   * content of its failed envelope: the caller then acknowledges the
   * envelope and drops it, with no decrypt and no retry request. This
   * applies to the failed envelope and to each member. The check writes a
   * debug log line for a dropped envelope. A member that goes to the decrypt
   * marks the stored request attempt answered when the member has its
   * attempt number.
   */
  admit(): Promise<boolean>;
  /**
   * Record a decrypt that succeeded. For a member, and for a failed
   * envelope with a request record, one write marks the failed envelope
   * processed and fulfilled. A redelivery of the failed envelope on either
   * path is then dropped, and so is each later member. When the write
   * fails, it writes one warning with the behavior
   * RETRY_FULFILL_WRITE_FAILED and returns, so the caller continues as for
   * any decrypted envelope. A redelivery of the failed envelope or of
   * another member can then give the content again.
   */
  fulfill(): Promise<void>;
  /**
   * Record a decrypted null message, in place of `fulfill`. A null
   * message carries no content, so the caller never gives it to the
   * application. The null message is processed. For a member, the failed
   * envelope is processed and not fulfilled: a redelivery of the failed
   * envelope is dropped, the client asks for it no more, and a content
   * resend that comes later is still admitted. When a processed write
   * fails, it writes one warning with the behavior
   * RETRY_NULL_WRITE_FAILED and returns, as `fulfill` does, so the caller
   * still consumes the null message. A redelivery of the failed envelope
   * can then give the content.
   *
   * @param fingerprint - The fingerprint of the received envelope.
   */
  consumeNull(fingerprint: string | undefined): Promise<void>;
  /**
   * Name the sender of a member whose seal fails to open. Such a member
   * names no sender, and the request record that `admit` read names the
   * device that the request went to. The result is that envelope with the
   * sender of the record. Any other envelope, and a member with an
   * identified sender or with no request record, is returned as it is.
   */
  withRequestedSender<E extends { senderUserId: string; senderDeviceId: number }>(
    envelope: E
  ): E;
  /**
   * Ask the sender for a resend after a decrypt that failed. The request
   * record is keyed by the failed envelope of the family. A member never
   * starts a family of its own: it asks again for its failed envelope,
   * under the retry ID of the record, and the fingerprint check of the
   * failed envelope does not apply to it.
   *
   * @param fingerprint - The fingerprint of the received envelope.
   * @param post - Posts the request for the given failure. It returns false
   *   when it posts nothing, for example under the rate limit.
   * @returns True when `post` posted the request. After the post, a member
   *   is processed, so a redelivery of it on either path posts nothing. A
   *   failed post leaves it unprocessed. False with no post, and one warn
   *   line with the behavior RETRY_REQUEST_ENVELOPE_CHANGED, when the relay
   *   changed the failed envelope after its retry request.
   */
  requestRetry(
    fingerprint: string | undefined,
    post: (failed: RetryRequestFailure) => Promise<boolean>
  ): Promise<boolean>;
}

/**
 * Receive one envelope in the retry family of its failed envelope.
 *
 * A resend or a null message resolves to its failed envelope through the
 * family index, by its SDK ID: the client message ID, or the envelope ID
 * when the relay delivers no client message ID. A relay that assigns its
 * own envelope IDs delivers the SDK ID as the client message ID. The
 * receive then holds the processed-envelope lock of that failed envelope,
 * so the fulfilled check, the decrypt and the fulfilled store of one
 * family run one at a time on all paths. Any other envelope holds the lock
 * of its own ID. An envelope with no ID holds no lock and has no family.
 * The processed record and the acknowledgment use the delivered envelope
 * ID.
 *
 * @param storage - The local store that keeps the retry records.
 * @param logger - The client logger.
 * @param envelope - The IDs of the received envelope: the delivered
 *   envelope ID, and the client message ID when the relay delivers one.
 * @param receive - The receive path. It runs under the lock.
 */
export async function receiveInRetryFamily<T>(
  storage: RetryFamilyStore,
  logger: Required<Logger>,
  envelope: { readonly id?: string; readonly clientMessageId?: string },
  receive: (family: RetryFamilyReceive) => Promise<T>
): Promise<T> {
  const envelopeId = envelope.id;
  if (!envelopeId) return receive(retryFamilyReceive(storage, logger, undefined, undefined));
  const member = await resolveRetryFamilyMember(
    storage,
    envelope.clientMessageId ?? envelopeId
  );
  return withProcessedEnvelopeLock(storage, member?.failedEnvelopeId ?? envelopeId, () =>
    receive(retryFamilyReceive(storage, logger, envelopeId, member))
  );
}

function retryFamilyReceive(
  storage: RetryFamilyStore,
  logger: Required<Logger>,
  envelopeId: string | undefined,
  member: ResolvedRetryFamilyMember | undefined
): RetryFamilyReceive {
  const failedEnvelopeId = member?.failedEnvelopeId ?? envelopeId;
  // The read comes before the decrypt, so only writes follow the
  // application hook.
  let request: StoredRetryRequest | null = null;
  return {
    member,
    async admit() {
      if (failedEnvelopeId === undefined) return true;
      // A member that posted a request is processed, so its redelivery asks
      // for nothing again.
      if (envelopeId && (await getProcessedEnvelope(storage, envelopeId))) {
        logger.debug('Acknowledging previously processed relay envelope', {
          category: 'E2EE',
          data: { envelopeId, behavior: 'PERSISTENT_DUPLICATE_DISCARD' },
        });
        return false;
      }
      // The Relay frees a message ID after the acknowledgment, so a sender
      // can post a second resend attempt for one failed envelope, and the
      // failed envelope can arrive again after its resend. Process one.
      if (member && (await getProcessedEnvelope(storage, failedEnvelopeId))?.fulfilled) {
        logger.debug('Acknowledging a second envelope for one failed envelope', {
          category: 'E2EE',
          data: { envelopeId, behavior: 'RETRY_RESEND_DUPLICATE_DISCARD' },
        });
        return false;
      }
      // A member of attempt n answers attempt n, so a member failure then
      // posts the next attempt. A member of an earlier attempt answers
      // nothing, so its failure posts the stored attempt again.
      if (member) {
        await markRetryRequestAnswered(
          storage,
          failedEnvelopeId,
          member.retryId,
          member.attempt
        );
      }
      request = await getRetryRequest(storage, failedEnvelopeId);
      return true;
    },
    async fulfill() {
      try {
        // One write marks the failed envelope processed and fulfilled. A
        // redelivery of it is then acknowledged with no decrypt, and each
        // later member of its request is dropped.
        if (failedEnvelopeId !== undefined && (member || request)) {
          await storeProcessedEnvelope(storage, failedEnvelopeId, Date.now(), undefined, true);
        }
      } catch (error) {
        // The application gets the plaintext. Only a redelivery can
        // decrypt the content again.
        logger.warn('The retry family record of a decrypted envelope failed to store', {
          category: 'E2EE',
          data: {
            envelopeId,
            behavior: 'RETRY_FULFILL_WRITE_FAILED',
            error: (error as Error).message,
          },
        });
      }
    },
    async consumeNull(fingerprint) {
      try {
        if (member) await storeProcessedEnvelope(storage, member.failedEnvelopeId);
        if (envelopeId) {
          await storeProcessedEnvelope(storage, envelopeId, Date.now(), fingerprint);
        }
      } catch (error) {
        // The null message carries no content, so the caller still
        // consumes it. A redelivery of the failed envelope can then
        // decrypt the content.
        logger.warn('The retry family record of a null message failed to store', {
          category: 'E2EE',
          data: {
            envelopeId,
            behavior: 'RETRY_NULL_WRITE_FAILED',
            error: (error as Error).message,
          },
        });
      }
    },
    withRequestedSender(envelope) {
      if (!member || !request) return envelope;
      if (envelope.senderUserId && envelope.senderDeviceId >= 1) return envelope;
      const { targetUserId, targetDeviceId } = request.envelope;
      return { ...envelope, senderUserId: targetUserId, senderDeviceId: targetDeviceId };
    },
    async requestRetry(fingerprint, post) {
      if (failedEnvelopeId === undefined) return post({ stored: null });
      if (!member) {
        let stored: StoredRetryRequest | null;
        try {
          stored = await getRetryRequest(storage, failedEnvelopeId, Date.now(), fingerprint);
        } catch (error) {
          if (!(error instanceof RetryRequestedEnvelopeChangedError)) throw error;
          // The envelope stays unacknowledged, as for a failed retry request.
          logger.warn('No retry request: the relay changed an envelope after its retry request', {
            category: 'E2EE',
            data: { envelopeId, behavior: 'RETRY_REQUEST_ENVELOPE_CHANGED' },
          });
          return false;
        }
        return post({
          id: failedEnvelopeId,
          ...(fingerprint !== undefined && { fingerprint }),
          stored,
        });
      }
      // A member has its own content, so its fingerprint is not the
      // fingerprint of the failed envelope.
      const stored = await getRetryRequest(storage, failedEnvelopeId);
      const posted = await post({
        id: failedEnvelopeId,
        ...(stored?.fingerprint !== undefined && { fingerprint: stored.fingerprint }),
        stored,
        ...(envelopeId !== undefined && { member: envelopeId }),
      });
      if (posted && envelopeId) {
        await storeProcessedEnvelope(storage, envelopeId, Date.now(), fingerprint);
      }
      return posted;
    },
  };
}
