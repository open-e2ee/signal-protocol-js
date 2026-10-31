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
  updateRetryRequest,
  withProcessedEnvelopeLock,
  type ResolvedRetryFamilyMember,
  type StoredRetryRequest,
} from '../local/store/reliability';
import type { RetryRequestFailure } from './retry-request-envelope';
import type { SignalProtocolClientHooks } from './event-hooks';
import { reportDeliveryRecovered } from './delivery-error';
import type { RetryRequestOutcome } from './retry-request-lifecycle';

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
   * envelope, and after `bindSender` names a sender that is not the
   * requested sender: the envelope is then an ordinary envelope.
   */
  readonly member: ResolvedRetryFamilyMember | undefined;
  /**
   * Tell whether the envelope goes to the decrypt. False when the local
   * device processed the envelope, or when the application already has the
   * content of its failed envelope: the caller then acknowledges the
   * envelope and drops it, with no decrypt and no retry request. This
   * applies to the failed envelope and to each member. The check writes a
   * debug log line for a dropped envelope.
   *
   * An identified envelope names its sender, so `admit` binds the envelope
   * to that sender first. A member from another sender is then an ordinary
   * envelope. A member from the requested sender that goes to the decrypt
   * marks the stored request attempt answered when the member has its
   * attempt number. A sealed member names its sender only inside the seal,
   * so its mark waits for `bindSender`.
   *
   * @param fingerprint - The fingerprint of the received envelope. An
   *   envelope under the ID of a failed envelope fulfills the request of
   *   that ID only when this is the fingerprint that the record stores.
   */
  admit(fingerprint: string | undefined): Promise<boolean>;
  /**
   * Bind the envelope to the sender that the decrypt authenticates: the
   * sender of an identified envelope, or the sender inside a seal. The
   * receive commit calls it before the decrypt. A member answers its
   * request only when this sender is the account and the device that the
   * request record names. Any other sender makes the member an ordinary
   * envelope: it does not mark the request answered, and it does not
   * fulfill or process the failed envelope. One warn line with the behavior
   * RETRY_ANSWER_SENDER_MISMATCH records it.
   *
   * An envelope that is not a member fulfills the request record of its
   * own ID only when this sender is the sender of the failed envelope that
   * the record names.
   */
  bindSender(sender: { readonly senderUserId?: string; readonly senderDeviceId?: number }): void;
  /**
   * Tell which failed envelope a decrypt with this content fulfills: the
   * failed envelope of a member, or the envelope itself when it is the
   * failed envelope of the request record of its ID. Undefined when
   * `fulfill` writes nothing for it. The receive record of the content
   * names the result as its `failedEnvelopeId`. A member with no bound
   * sender fulfills nothing. Call it after `admit` and `bindSender`.
   *
   * The Relay names the envelope ID, so an ID does not prove that the
   * envelope is the failed envelope. An envelope under the ID of a failed
   * envelope is that envelope only when its fingerprint is the fingerprint
   * of the record and its bound sender is the sender of the failed envelope
   * that the record names. Any other envelope under that ID, also a member
   * from another sender, is an ordinary envelope and fulfills nothing.
   */
  fulfills(decrypted?: {
    readonly senderKeyDistribution: boolean;
    readonly content: boolean;
  }): string | undefined;
  /**
   * Record a decrypt that succeeded: outcome 1. The receive path calls it
   * right after the commit of the receive record, before the
   * acknowledgment or the return. For a member, and for a failed envelope
   * with a request record, one write marks the failed envelope processed
   * and fulfilled. That write stops the retry scheduler for the failed
   * envelope. A redelivery of the failed envelope on either path is then
   * dropped, and so is each later member. When the write fails, the error
   * propagates: the caller does not acknowledge the envelope, and its
   * redelivery finds the committed receive record and writes again.
   *
   * The fulfilled write does not run `onDeliveryRecovered`. That hook waits
   * for the completion of the receive record (outcome 2), as
   * `reportDeliveryRecovered` tells.
   *
   * A failed group message whose sender key was missing has a request
   * record with no group. When the decrypt that gives its content resolves
   * the group, the record gets it before the fulfilled write, so
   * `onDeliveryRecovered` names it. A record that names a group keeps it.
   *
   * A member that brings only a sender-key distribution, for a failed
   * envelope that is a sender-key group message, writes nothing and does
   * not fulfill the failed envelope. The member installs the sender key and
   * gives no content. A redelivery of the failed envelope then decrypts
   * with that key and gives its content, and a later member is admitted.
   * One debug line records the behavior RETRY_SENDER_KEY_RESEND. A member
   * that brings content beside the distribution fulfills the failed
   * envelope, as any other member does.
   *
   * A member with no bound sender writes nothing, as an ordinary envelope
   * with no request record. An envelope that `fulfills` does not name as
   * the failed envelope of the record of its ID also writes nothing.
   *
   * @param decrypted - The decrypted content. `senderKeyDistribution` is
   *   true when the content carries a sender-key distribution. `content` is
   *   true when it carries content other than a distribution. `groupId` is
   *   the group that the decrypt resolved for group content, in the form
   *   of `DecryptedEnvelope.conversationId`.
   */
  fulfill(decrypted?: {
    readonly senderKeyDistribution: boolean;
    readonly content: boolean;
    readonly groupId?: string;
  }): Promise<void>;
  /**
   * Record a decrypted null message, in place of `fulfill`. A null
   * message carries no content, so the caller never gives it to the
   * application. The null message is processed. For a member with a bound
   * sender, the failed envelope is processed and not fulfilled: a redelivery of the failed
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
   * identified sender or with no request envelope, is returned as it is.
   *
   * The name serves only the routing of the next retry request. It does not
   * bind the sender, so the member never fulfills the request.
   */
  withRequestedSender<E extends { senderUserId: string; senderDeviceId: number }>(
    envelope: E
  ): E;
  /**
   * Ask the sender for a resend after a decrypt that failed. The request
   * record is keyed by the failed envelope of the family. A member never
   * starts a family of its own: it asks again for its failed envelope,
   * under the retry ID of the record, and the fingerprint check of the
   * failed envelope does not apply to it. A member whose seal failed to
   * open marks the stored attempt answered here, so the post asks for the
   * next attempt.
   *
   * @param fingerprint - The fingerprint of the received envelope.
   * @param post - Posts the request for the given failure, and gives what
   *   it did.
   * @returns The outcome of `post`. After a `posted`, `waiting` or
   *   `terminal` outcome, a member is processed, so a redelivery of it on
   *   either path posts nothing. Any other outcome leaves it unprocessed. `skipped` with no
   *   post, and one warn line with the behavior
   *   RETRY_REQUEST_ENVELOPE_CHANGED, when the relay changed the failed
   *   envelope after its retry request.
   */
  requestRetry(
    fingerprint: string | undefined,
    post: (failed: RetryRequestFailure) => Promise<RetryRequestOutcome>
  ): Promise<RetryRequestOutcome>;
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
 * Under the lock and before the receive, it runs `onDeliveryRecovered` for
 * a failed envelope whose recovery the hook did not mark. An error from
 * that hook propagates, so the receive path does not acknowledge the
 * envelope, and its redelivery runs the hook again.
 *
 * @param storage - The local store that keeps the retry records.
 * @param logger - The client logger.
 * @param hooks - The client hooks, for `onDeliveryRecovered`.
 * @param envelope - The IDs of the received envelope: the delivered
 *   envelope ID, and the client message ID when the relay delivers one.
 *   The sender and the message type that the relay delivered bind a member
 *   of an identified envelope to its sender.
 * @param receive - The receive path. It runs under the lock.
 */
export async function receiveInRetryFamily<T>(
  storage: RetryFamilyStore,
  logger: Required<Logger>,
  hooks: SignalProtocolClientHooks | undefined,
  envelope: Parameters<typeof retryFamilyReceive>[2],
  receive: (family: RetryFamilyReceive) => Promise<T>
): Promise<T> {
  const envelopeId = envelope.id;
  if (!envelopeId) {
    return receive(retryFamilyReceive(storage, logger, envelope, undefined, undefined, undefined));
  }
  const member = await resolveRetryFamilyMember(
    storage,
    envelope.clientMessageId ?? envelopeId
  );
  const failedEnvelopeId = member?.failedEnvelopeId ?? envelopeId;
  return withProcessedEnvelopeLock(storage, failedEnvelopeId, async () => {
    // A recovery whose hook did not return runs again. An error from the
    // hook fails the receive, so the envelope is delivered again.
    await reportDeliveryRecovered(storage, hooks, failedEnvelopeId);
    const requested = member
      ? requestedSenderOf(await getRetryRequest(storage, member.failedEnvelopeId))
      : undefined;
    return receive(retryFamilyReceive(storage, logger, envelope, envelopeId, member, requested));
  });
}

/** The account and the device that a request record asked for a resend. */
interface RequestedSender {
  readonly userId: string;
  readonly deviceId: number;
}

/** The target of the request envelope of a record. A record with none names no sender. */
function requestedSenderOf(request: StoredRetryRequest | null): RequestedSender | undefined {
  if (!request?.envelope) return undefined;
  return { userId: request.envelope.targetUserId, deviceId: request.envelope.targetDeviceId };
}

function retryFamilyReceive(
  storage: RetryFamilyStore,
  logger: Required<Logger>,
  delivered: {
    readonly id?: string;
    readonly clientMessageId?: string;
    readonly senderUserId?: string;
    readonly senderDeviceId?: number;
    readonly messageType?: string;
  },
  envelopeId: string | undefined,
  resolved: ResolvedRetryFamilyMember | undefined,
  requested: RequestedSender | undefined
): RetryFamilyReceive {
  // A member from a sender that the request did not name becomes an
  // ordinary envelope, keyed by its own ID.
  let member = resolved;
  let failedEnvelopeId = member?.failedEnvelopeId ?? envelopeId;
  // The read comes before the decrypt, so only writes follow the commit.
  let request: StoredRetryRequest | null = null;
  // The request record of the envelope ID of a sealed member, for the case
  // that its seal names another sender.
  let ownRequest: StoredRetryRequest | null = null;
  // True when `bindSender` named the requested sender.
  let senderBound = false;
  // The sender that `bindSender` named last, for the record of the own ID.
  let boundSender: { readonly userId?: string; readonly deviceId?: number } | undefined;
  // The fingerprint of the received envelope, from `admit`.
  let receivedFingerprint: string | undefined;
  // True when the answered mark of a sealed member waits for its sender.
  let answerDue = false;

  function bindSender(sender: {
    readonly senderUserId?: string;
    readonly senderDeviceId?: number;
  }): void {
    boundSender = { userId: sender.senderUserId, deviceId: sender.senderDeviceId };
    if (!member) return;
    if (
      requested !== undefined &&
      sender.senderUserId === requested.userId &&
      sender.senderDeviceId === requested.deviceId
    ) {
      senderBound = true;
      return;
    }
    logger.warn('A retry answer came from a sender that its request did not name', {
      category: 'E2EE',
      data: { envelopeId, behavior: 'RETRY_ANSWER_SENDER_MISMATCH' },
    });
    member = undefined;
    failedEnvelopeId = envelopeId;
    request = ownRequest;
    senderBound = false;
    answerDue = false;
  }

  /**
   * Tell whether the envelope is the failed envelope of `request`, the
   * record of its own ID: the Relay delivered the envelope that the record
   * fingerprints, and the decrypt authenticated the sender of the failed
   * envelope. A record that names no such sender names no failed envelope.
   */
  function isFailedEnvelope(): boolean {
    if (!request || !boundSender) return false;
    if (request.fingerprint === undefined || request.fingerprint !== receivedFingerprint) {
      return false;
    }
    const sender = request.failedSender ?? requestedSenderOf(request);
    return (
      sender !== undefined &&
      boundSender.userId === sender.userId &&
      boundSender.deviceId === sender.deviceId
    );
  }

  /** Mark the stored attempt answered for a member whose mark waited. */
  async function markAnswered(): Promise<void> {
    if (!answerDue || !member || failedEnvelopeId === undefined) return;
    answerDue = false;
    await markRetryRequestAnswered(storage, failedEnvelopeId, member.retryId, member.attempt);
  }

  return {
    get member() {
      return member;
    },
    async admit(fingerprint) {
      if (failedEnvelopeId === undefined) return true;
      receivedFingerprint = fingerprint;
      // The relay names the sender of an identified envelope, and its decrypt
      // uses the session of that sender, so the binding comes first.
      if (delivered.messageType !== 'unidentified_sender' && delivered.senderUserId) {
        bindSender(delivered);
      }
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
      // nothing, so its failure posts the stored attempt again. A sealed
      // member marks it once its sender is known.
      if (member && senderBound) {
        await markRetryRequestAnswered(
          storage,
          failedEnvelopeId,
          member.retryId,
          member.attempt
        );
      } else if (member && envelopeId) {
        answerDue = true;
        ownRequest = await getRetryRequest(storage, envelopeId);
      }
      request = await getRetryRequest(storage, failedEnvelopeId);
      return true;
    },
    bindSender,
    fulfills(decrypted) {
      if (member && !senderBound) return undefined;
      if (
        member &&
        request?.groupMessage &&
        decrypted?.senderKeyDistribution &&
        !decrypted.content
      ) {
        return undefined;
      }
      if (failedEnvelopeId === undefined || !(member || isFailedEnvelope())) return undefined;
      return failedEnvelopeId;
    },
    async fulfill(decrypted) {
      if (member && !senderBound) return;
      await markAnswered();
      if (
        member &&
        request?.groupMessage &&
        decrypted?.senderKeyDistribution &&
        !decrypted.content
      ) {
        logger.debug('A resend gave the sender key of a failed group message', {
          category: 'E2EE',
          data: { envelopeId, behavior: 'RETRY_SENDER_KEY_RESEND' },
        });
        return;
      }
      if (failedEnvelopeId === undefined || !(member || isFailedEnvelope())) return;
      try {
        const groupId = decrypted?.groupId;
        if (request && request.groupId === undefined && groupId !== undefined) {
          request =
            (await updateRetryRequest(storage, failedEnvelopeId, request.retryId, request.attempt, {
              groupId,
            })) ?? request;
        }
        // One write marks the failed envelope processed and fulfilled. A
        // redelivery of it is then acknowledged with no decrypt, and each
        // later member of its request is dropped.
        await storeProcessedEnvelope(storage, failedEnvelopeId, Date.now(), undefined, true);
      } catch (error) {
        // The receive record holds the content. The caller does not
        // acknowledge, so the redelivery writes outcome 1 again.
        logger.warn('The retry family record of a decrypted envelope failed to store', {
          category: 'E2EE',
          data: {
            envelopeId,
            behavior: 'RETRY_FULFILL_WRITE_FAILED',
            error: (error as Error).message,
          },
        });
        throw error;
      }
    },
    async consumeNull(fingerprint) {
      try {
        if (member && senderBound) {
          await markAnswered();
          await storeProcessedEnvelope(storage, member.failedEnvelopeId);
        }
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
      if (!member || !request?.envelope) return envelope;
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
          return 'skipped';
        }
        return post({
          id: failedEnvelopeId,
          ...(fingerprint !== undefined && { fingerprint }),
          stored,
        });
      }
      // A member whose seal failed to open names no sender. Its failure
      // still answers the stored attempt, so the post asks for the next one.
      await markAnswered();
      // A member has its own content, so its fingerprint is not the
      // fingerprint of the failed envelope.
      const stored = await getRetryRequest(storage, failedEnvelopeId);
      const outcome = await post({
        id: failedEnvelopeId,
        ...(stored?.fingerprint !== undefined && { fingerprint: stored.fingerprint }),
        stored,
        ...(envelopeId !== undefined && { member: envelopeId }),
      });
      if ((outcome === 'posted' || outcome === 'waiting' || outcome === 'terminal') && envelopeId) {
        await storeProcessedEnvelope(storage, envelopeId, Date.now(), fingerprint);
      }
      return outcome;
    },
  };
}
