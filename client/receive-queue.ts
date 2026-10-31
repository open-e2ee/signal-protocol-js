/**
 * The receive queue: the processor of the stored receive records.
 *
 * A Relay receive commits its decrypted content as a receive record, and
 * holds the record while it runs. The Relay subscription and the hosted
 * pull hold the record until the acknowledgment of its envelope settles.
 * `receiveIncomingEnvelopes` and `processIncomingEnvelope` hold it until the
 * commit ends, because the application acknowledges after the call returns.
 * After the release, the queue decides on the group of the content, gives it
 * to the application, sends the E2EE delivery receipt, and completes the
 * record. A record that waits for its group state stays on the device, not
 * at the Relay.
 *
 * The queue processes the records of one conversation in arrival order. A
 * record that waits, for its group or after a failed hook below the attempt
 * cap, holds back each later record of its conversation. See "Order key".
 * Each pass runs these steps on each record, in arrival order:
 *
 * - A record that has expired (`MAX_RECEIVE_WORK_AGE_MS`, 30 days) and owes
 *   no receipt runs `onReceiveExpired`, then completes with the `expired`
 *   outcome. A `receipt-due` record that has expired, or whose receipt
 *   lifespan of 1 day after its `dueAt` has ended, completes with no
 *   receipt and no report: the application has its content.
 * - A `decrypted` record gets its group decision. Authorized content goes
 *   to the application, and the record then completes or moves to
 *   `receipt-due`. Denied content runs `onDecryptionError` and completes
 *   with the `denied` outcome. Content whose group state must update first
 *   waits until its retry time or until a fetch of its group completes.
 * - A `receipt-due` record waits for the receipt decision of the Relay for
 *   no longer than the reply window, then sends its receipt and completes.
 * - An `awaiting-completion` record waits for `completeReceive` or expiry.
 *
 * A pass runs after the release of each held record, when a fetch of a group
 * completes, at start, at the earliest due time of the records, and from
 * `processPendingReceives`. Each pass is relay work, so a client stop stops
 * it, and its hooks run through that work. At start, before the retry
 * request lifecycle starts, the queue writes outcome 1 again for each
 * stored resend, so the retry deadline never resets a session whose resend
 * content the device holds.
 *
 * Signal equivalence. The order is Signal's. Signal commits the ratchet
 * step and the decrypted content in one transaction, acknowledges after
 * that commit, and sends no acknowledgment when the commit fails. Content
 * that waits for its group stays on the device after the acknowledgment.
 * One Signal client keeps it in a job with a 30-day life. The E2EE delivery
 * receipt goes out only after the group checks, as in another Signal
 * client. It is the only proof that the
 * application processed the content. A Relay delivery receipt that the
 * acknowledgment produces means only that the device holds the content.
 * A resend clears its pending retry only after its processing, as in one
 * Signal client, so `onDeliveryRecovered` waits for the completed record.
 *
 * Order key. A waiting record holds back the later records of its
 * conversation, as one Signal client queues its message jobs per
 * conversation. Group
 * content keys by its group, a sent transcript of this account keys by its
 * destination, and other content keys by its sender account, not by its
 * sender device. So a blocked group holds back the later records of that
 * group from every sender, and direct chats and other groups make
 * progress. The pass learns the conversation of pairwise content only when
 * it restores the content, before the group decision. A record that the
 * pass has not restored keys by the group that it stores, otherwise by its
 * sender account. The queue keeps the key of each restored record in
 * memory, so a record in backoff holds back its conversation and not only
 * its sender account. A record of a group that waits behind an earlier
 * record of that group is written as a record that waits for an update of
 * the group, so the group share of the admission counts it. The commit
 * order stays per sender device by `(arrivalSeq, workId)`. Tests:
 * "processes the records of each sender account in arrival order", "a
 * direct message delivers while an earlier group message of its sender
 * waits for its group", "a message in another group makes progress while a
 * blocked group record of its sender waits", "a blocked head that expires
 * lets the later records of its conversation through", "direct messages
 * progress while global room exists with pairwise group overshoot", and
 * the conversation tests: "a sent transcript waits only behind an earlier
 * transcript to its destination", "a direct message from a second device
 * of a sender waits behind a refused record of its first device", "a
 * record that fails before its restore holds back only its sender
 * account", "a group record that blocks after its decrypt holds back its
 * group from every sender", "pairwise content of a blocked group waits
 * behind the group and delivers after the fetch", "a second sender in a
 * blocked group waits in the group and delivers its direct message".
 *
 * The deviations, each with its constraint and its tests:
 *
 * - Failed hook. One Signal client retries cached content every 2 minutes
 *   and deletes it after 10 attempts or 45 days. Another retries a job only
 *   on a network error, a missing redemption credential, or a busy group
 *   change, and drops the content on other errors. The queue keeps the content
 *   until it expires, because the hook is application code: the SDK cannot
 *   tell a lasting failure from a passing one, and a drop loses content
 *   whose ratchet step is spent. A timer retries the hook after
 *   `RECEIVE_RETRY_BACKOFF_MS`. The record keeps a durable `hookAttempts`
 *   count, written with the revision check before the hook runs. The first
 *   client also counts an attempt of an entry before it processes it. So a
 *   hook that ends the process counts as an attempt, and a pass that loses
 *   the revision check skips the record. Only the hook stage counts an
 *   attempt, so a throw in `restoreCommitted` or in the group decision adds
 *   no count and reaches no cap. After `RECEIVE_HOOK_ATTEMPT_CAP` attempts,
 *   the cap of 10 of the first client, the record no longer holds
 *   back the later records of its conversation, so one failing message
 *   never stalls its conversation, as on Signal. Each start then offers it
 *   to the hook once: in the start pass, or at the registration of
 *   `onMessageDecrypted` when the start pass had no hook. After that offer,
 *   or after the attempt that reaches the cap, only `processPendingReceives`
 *   runs it again before the next start, and `discardPendingReceive`
 *   removes it. In that pass, the record at the cap runs after the other
 *   records of the pass, so a hook that ends the process on it still lets
 *   the later records of its conversation deliver first. Only an earlier
 *   record of its conversation holds it back in that pass. A later record that
 *   waits, such as for its group, does not. A pass that ends before the
 *   records at the cap run, at its deadline or at any failed page read,
 *   leaves them to the next pass. The process then ends at each start until the
 *   record expires or the application discards it. The first client deletes
 *   the entry at the cap at startup, before it processes any entry, and loses the
 *   message. The SDK keeps the record because an application update can
 *   repair the hook. Tests: "keeps the content of a rejected application
 *   write across its replay", "a hook that always fails stops
 *   holding back its conversation after the attempt cap", "the hook attempt count
 *   survives a restart", "a hook that ends the process counts toward the
 *   attempt cap", "a hook that ends the process on a record at the cap lets
 *   the later records of its conversation deliver", "a record at the cap
 *   runs while a later record of its conversation waits for its group", "a
 *   record at the cap waits behind an earlier record of its conversation
 *   that waits for its group", "a record at the cap that holds back its
 *   conversation holds back the later records at the cap", "a start pass that fails at its first page
 *   read leaves the records at the cap to the next pass", "a capped-retry
 *   pass that fails at a page read leaves the records at the cap to the
 *   next pass", "a capped-retry pass that reaches its deadline before the
 *   records at the cap leaves them to the next pass", "a record that
 *   reaches the cap in a pass that reaches its deadline waits for a
 *   capped-retry trigger", "a call to processPendingReceives after a failed
 *   start pass retries the records at the cap once", "an ordinary pass
 *   that fails at a page read leaves no capped retry due", "a record at
 *   the cap is offered once at start and not again at the hook
 *   registration", "a record that reaches the cap is not offered again
 *   before the next start", "discardPendingReceive removes a record at the
 *   cap with no receipt, no hook call, and no expiry report".
 * - Missing hook. Signal always has its processor. `create()` resumes the
 *   stored records before the application can register
 *   `onMessageDecrypted`, so a stored record waits with no backoff, as a job
 *   of one Signal client waits for its network constraint, and the hook
 *   registration wakes it. The Relay subscription and `receiveIncomingEnvelopes` refuse
 *   to start without the hook. Test: "keeps a stored
 *   receive with no hook and no backoff, and the hook registration delivers
 *   it".
 * - Hook bound. One Signal client bounds its receive pipeline at 2 minutes
 *   and its application handlers at 30 minutes. The SDK waits for each
 *   application hook of a pass for at most `receiveHookTimeoutMs`, 2 minutes by default, as the founder ruling on the hook bound sets. A timeout counts
 *   as a hook failure of that call, and a late settle writes nothing.
 *   Tests: "onMessageDecrypted: a hung hook counts one attempt per pass and
 *   holds back its conversation until the cap", "onMessageDecrypted: a settle
 *   after the bound writes nothing, and the next attempt delivers", and one
 *   timeout test for each other await site.
 * - Expiry hook. One Signal client drops an expired job with no report,
 *   and another deletes the expired row. The queue
 *   runs `onReceiveExpired` first, because the application, not the SDK,
 *   shows the user that a message is lost. Before the hook, the queue reads
 *   the record again. A record that another path completed after the list
 *   of the pass and before this read, such as at the redelivery of its
 *   envelope, gets no report. A record that another path wrote in that time
 *   expires in a later pass, from its new revision. Expiry is by age only,
 *   never by the hook attempt count, because a pass also runs on events,
 *   such as an arrival or a group fetch, and a count would measure the
 *   events and not the wait (design v5 deviation 5). Tests: the expiry
 *   suite, and in it "a record that another path completes after the pass
 *   lists it expires with no report", "a record that another path writes
 *   after the pass lists it expires in a later pass".
 * - Helper completion. One Signal client confirms a receive after its own
 *   save. An SDK customer owns its message store,
 *   so a helper record waits in `awaiting-completion` for `completeReceive`
 *   (design v5 deviation 6). Tests: V11, V12, and the helper completion
 *   suite.
 * - Durable receipt. One Signal client batches the receipt in memory, so a
 *   crash can lose it. Another keeps it in a stored job with a 1-day life
 *   and no attempt limit. The queue keeps it durable, as that stored job
 *   does, in a `receipt-due` record. The Relay can own the receipt, and its decision
 *   comes in the reply to the acknowledgment, so the record keeps the
 *   receipt and the decision across a restart, and stays in flight until its
 *   completion is written. Tests: V7, V8,
 *   "a ReceiptSendTerminalError completes with no receipt", "a pass that
 *   listed a receipt-due record before its completion sends no second
 *   receipt", "keeps a Relay receipt decision that arrives while the record
 *   waits, across a restart".
 * - Receipt lifetime. The Signal client with the stored job stops its receipt
 *   retries 1 day after it creates the job, after the message is processed.
 *   The queue sends a receipt only until `RECEIPT_LIFESPAN_MS`, 1 day,
 *   after the `dueAt` that the move to `receipt-due` writes. That `dueAt` is
 *   when the receipt becomes owed, so the lifespan of that job starts there.
 *   It includes the receipt-join wait, and the in-memory receipt backoff
 *   does not change it. At the end of the lifespan, the record completes
 *   with no receipt, no `onMessageDecrypted` call, and no
 *   `onReceiveExpired` report. A
 *   `receipt-due` record past its 30-day age before then completes in the
 *   same way (ruling Q6). The completion of a resend record still reports
 *   `onDeliveryRecovered` through its gate. Two other
 *   limits of the queue have their own notes: two processes that share one
 *   store can overshoot a bound (Q16, see `receive-admission.ts`), and the
 *   memory store loses the queue at a restart (T-36). In Q16, each process
 *   also keeps its own arrival counter, so a record of one process can sort
 *   before a record that another process admitted earlier (see
 *   `receive-work-seed.ts`). Tests: "Q6 deletes a receipt-due record past
 *   its 30-day age with no receipt, no onMessageDecrypted call, and no
 *   onReceiveExpired report", "sends a receipt 1 ms before the end of its
 *   1-day lifespan", "completes a receipt-due record at the end of its
 *   1-day lifespan with no receipt and no report", "a resend record at the
 *   end of its receipt lifespan still reports onDeliveryRecovered", "a
 *   running client stops its receipt retries at the end of the lifespan".
 * - Bounds. Signal has no device bound on deferred content. The SDK shares a
 *   storage budget with the application in a browser and on mobile, so
 *   admission checks `maxItems`, `maxBytes`, and `blockedGroupShare` before
 *   decrypt, and a refusal is not acknowledged. A refused envelope stays at
 *   the Relay and expires there at the project TTL with no local hook. While
 *   the mailbox of the device is full, the Relay refuses a new message to it
 *   with `MAILBOX_FULL` to its sender. A refusal does not stall the messages
 *   behind it: the socket acknowledges each page, and an HTTP pull sends
 *   the Relay cursor of the page before it. Tests: the bounds suite.
 * - Outcome 1 before the acknowledgment. The SDK retry lifecycle can reset a
 *   session at its deadline, and Signal has no such reset. So the commit of
 *   a resend writes the failed envelope as fulfilled before the
 *   acknowledgment, and the start writes it again before the lifecycle
 *   starts. Tests: both V9 tests, "the retry deadline never deletes a
 *   committed receive record".
 * - The separate sender key install and its replay: see `restoreCommitted`.
 * - Converted SDK 11 rows have no Signal form. The data-preserving migration
 *   rule keeps them, and the redelivered envelope fills them. Tests: the
 *   legacy conversion suite and the converted row tests.
 */

import { bytesToBase64, sha256 } from '../internal/crypto';
import { extractGroupId } from '../internal/groups';
import type { Envelope } from '../remote/relay/types';
import type { ReceiveWorkQuery, ReceiveWorkRecord } from '../types/api';
import {
  completeReceiveRecord,
  getProcessedEnvelope,
  hasReceivedTimestamp,
  recordReceivedTimestamp,
  storeProcessedEnvelope,
  withProcessedEnvelopeLock,
  writeProcessedEnvelopes,
  type ProcessedEnvelopeOutcome,
  type ReceiveCompletionWrite,
  type ReceivedMessageKey,
} from '../local/store/reliability';
import { RECEIVE_WORK_DEFAULT_LIMIT, sizedReceiveWork } from '../local/store/receive-work';
import { reportDeliveryRecovered, reportReceiveDenial } from './delivery-error';
import {
  callHook,
  type ReceiveExpiredEvent,
  type SignalProtocolClientHooks,
} from './event-hooks';
import { classifyGroupContent, groupOfContext } from './group-receive-authorization';
import { ReceiptSendTerminalError } from './messages';
import { isReceiveExpired, receiveExpiresAt } from './receive-expiry';
import { ReceiveHookTimeout } from './receive-hook-bound';
import { RELAY_RECEIPT_REPLY_MS } from './relay-receipt-join';
import { raiseArrivalSeq } from './receive-work-seed';
import {
  accumulateDeliveryReceipt,
  type RelaySubscriptionCallbacks,
  type RelaySubscriptionContext,
  type RelaySubscriptionState,
} from './relay-subscription';
import {
  RelayWorkStopped,
  rethrowRelayWorkStopped,
  type RelayWork,
  type RelayWorkTracker,
} from './relay-work';
import type {
  CommittedContent,
  CommittedSender,
  GroupContentDecision,
} from './signal-service-cipher';
import type { ResolvedReceiveQueuePolicy } from './storage-protection';
import type { SignalProtocolClientContext } from './types';

/**
 * A failed hook or receipt send of one record runs again after this time.
 * Signal drops or counts such failures. See "Failed hook" in the module
 * comment for the reason the queue retries until expiry.
 */
export const RECEIVE_RETRY_BACKOFF_MS = 30_000;

/**
 * After this many `onMessageDecrypted` attempts, a record no longer
 * holds back the later records of its conversation. One Signal client
 * has the same cap. See "Failed hook" in the module comment.
 */
export const RECEIVE_HOOK_ATTEMPT_CAP = 10;

/**
 * A `receipt-due` record sends its receipt only for this time after the
 * `dueAt` of its receipt-due stage: 1 day, the lifespan of the stored
 * receipt job of one Signal client. See "Receipt lifetime" in the module comment.
 */
export const RECEIPT_LIFESPAN_MS = 24 * 60 * 60 * 1000;

/** The longest delay that one timer can hold. */
const MAX_TIMER_DELAY_MS = 2 ** 31 - 1;

/** The context of one queue pass. Its hooks call the app through the pass work. */
export interface ReceiveQueuePass {
  readonly ctx: RelaySubscriptionContext;
  readonly state: RelaySubscriptionState;
  readonly callbacks: RelaySubscriptionCallbacks;
}

/** The result of `processPendingReceives`. */
export interface ReceiveQueuePassResult {
  /** The records that the pass delivered, denied, expired, or completed. */
  readonly processed: number;
  /** The records that still wait for processing or for their receipt. */
  readonly remaining: number;
}

/** The step result of one record in one pass. */
interface RecordStep {
  /** The time at which the record needs the next pass. */
  readonly next: number;
  /** True when the pass changed the record. */
  readonly processed: boolean;
}

const WAIT = (next: number): RecordStep => ({ next, processed: false });
const DONE: RecordStep = { next: Infinity, processed: true };

/** The time at which a `receipt-due` record stops sending its receipt. */
const receiptEndsAt = (record: ReceiveWorkRecord): number => record.dueAt + RECEIPT_LIFESPAN_MS;

/** The result of one delivery of authorized content. */
interface Delivery {
  /** True when the content owes a delivery receipt. */
  readonly owesReceipt: boolean;
  /** The key of the content that the hook took, when it has a timestamp. */
  readonly received?: ReceivedMessageKey;
}

/** Content that the hook did not take, or that owes nothing. */
const NOT_DELIVERED: Delivery = { owesReceipt: false };

/** The application has not registered onMessageDecrypted yet. */
class ReceiveHookMissing extends Error {
  constructor() {
    super('Register onMessageDecrypted before receiving Relay messages');
    this.name = 'ReceiveHookMissing';
  }
}

/** The conversation key of a group, from its raw or prefixed ID. */
const groupConversation = (groupId: string): string => `group:${extractGroupId(groupId)}`;

/**
 * The conversation key of a record before the pass restores its content:
 * the group that the record stores, otherwise the sender account. A
 * converted legacy record has no sender, so it keys by itself. See "Order
 * key" in the module comment.
 */
function storedConversationOf(record: ReceiveWorkRecord): string {
  if (record.groupId !== undefined) return groupConversation(record.groupId);
  return record.senderUserId === undefined
    ? `work:${record.workId}`
    : `account:${record.senderUserId}`;
}

/**
 * The raw managed group of restored content before its group decision:
 * the group that the decision checks. Null for content of no managed group.
 */
function managedGroupOf(content: CommittedContent): string | null {
  const claim = classifyGroupContent(
    content.messageType === 'sender_key' ? content.transportGroupId : null,
    content.inspected
  );
  if (!claim) return null;
  const group = groupOfContext(claim);
  // The decision denies content whose context names no valid group.
  return 'groupId' in group ? group.groupId : (claim.groupId ?? null);
}

/**
 * The group of restored content before its group decision: its managed
 * group, or for content of no managed group the group that the
 * application gets. Null for content of no group.
 */
function groupOfContent(content: CommittedContent): string | null {
  const managed = managedGroupOf(content);
  if (managed !== null) return managed;
  return (
    content.transportGroupId ??
    (content.inspected.senderKeyDistributionOnly === false ? content.distributionGroupId : null)
  );
}

/**
 * The conversation key of restored content: the group of the record or of
 * the content, the destination of a sent transcript of this account,
 * otherwise the sender account. See "Order key" in the module comment.
 *
 * @param userId - The account of this client
 */
function conversationOf(
  record: ReceiveWorkRecord,
  content: CommittedContent,
  userId: string
): string {
  if (record.groupId !== undefined) return groupConversation(record.groupId);
  const groupId = groupOfContent(content);
  if (groupId !== null) return groupConversation(groupId);
  const sync = content.inspected.sync;
  if (content.senderUserId === userId && sync?.type === 'sent') {
    // A direct transcript names its recipient. A group transcript names
    // its group as its conversation.
    if (sync.recipientUserId !== undefined) return `account:${sync.recipientUserId}`;
    if (sync.conversationId !== undefined) return groupConversation(sync.conversationId);
  }
  return `account:${content.senderUserId}`;
}

/**
 * Write a record of a group that waits behind an earlier record of its
 * group as a record that waits for an update of that group. The group
 * share of the admission then counts it, as it counts a record whose own
 * decision waits. The record keeps its `dueAt`, so it waits only for its
 * conversation. A record that waits already, or whose stored revision
 * changed, is not written.
 */
async function waitForGroupUpdate(
  ctx: Pick<SignalProtocolClientContext, 'storage'>,
  record: ReceiveWorkRecord,
  groupId: string
): Promise<void> {
  if (record.blockedOn !== undefined) return;
  await ctx.storage.putReceiveWork(
    sizedReceiveWork({
      ...record,
      revision: record.revision + 1,
      blockedOn: 'group-update',
      groupId,
    }),
    record.revision
  );
}

/** The order key of a record: `(arrivalSeq, workId)`, as every store pages. */
type ReceiveOrderKey = Pick<ReceiveWorkRecord, 'arrivalSeq' | 'workId'>;

/**
 * The conversations that a pass holds back, each with the order key of
 * the earliest record that held it back in the pass.
 */
type BlockedConversations = Map<string, ReceiveOrderKey>;

/**
 * The records at the hook attempt cap that a pass runs: none, the records
 * that the hook did not get since the last start (`unoffered`), or all.
 */
type CappedRetry = 'none' | 'unoffered' | 'all';

/**
 * Tell whether a pass runs a record at the hook attempt cap.
 *
 * @param offered - The records at the cap that the hook got since the last
 *   start
 */
function retriesCap(
  record: ReceiveWorkRecord,
  cappedRetry: CappedRetry,
  offered: ReadonlySet<string>
): boolean {
  if ((record.hookAttempts ?? 0) < RECEIVE_HOOK_ATTEMPT_CAP) return false;
  return cappedRetry === 'all' || (cappedRetry === 'unoffered' && !offered.has(record.workId));
}

/** Tell whether one record sorts before another in the store order. */
function sortsBefore(a: ReceiveOrderKey, b: ReceiveOrderKey): boolean {
  return a.arrivalSeq < b.arrivalSeq || (a.arrivalSeq === b.arrivalSeq && a.workId < b.workId);
}

/** Hold back a conversation for the later records of the pass. */
function block(
  blocked: BlockedConversations,
  record: ReceiveWorkRecord,
  conversation: string
): void {
  const earliest = blocked.get(conversation);
  if (earliest === undefined || sortsBefore(record, earliest)) {
    blocked.set(conversation, { arrivalSeq: record.arrivalSeq, workId: record.workId });
  }
}

/**
 * Tell whether an earlier record of the same conversation holds back a
 * record. A record at the hook attempt cap runs after the page loop, so a
 * later record can hold back its conversation first. That later record
 * does not hold back the earlier record.
 */
function isBlocked(
  blocked: BlockedConversations,
  record: ReceiveWorkRecord,
  conversation: string
): boolean {
  const earliest = blocked.get(conversation);
  return earliest !== undefined && sortsBefore(earliest, record);
}

/** The record without its plaintext, its wait, and its hook attempts. */
function withoutContent(record: ReceiveWorkRecord): ReceiveWorkRecord {
  const {
    plaintext: _plaintext,
    blockedOn: _blockedOn,
    hookAttempts: _hookAttempts,
    ...rest
  } = record;
  return rest;
}

/**
 * Complete one receive record (outcome 2, or a terminal outcome): delete it
 * and write the processed record of its envelope in one store step. A
 * completed resend also marks its failed envelope fulfilled and completed in
 * the same step, then runs `onDeliveryRecovered` through the completion gate. An
 * expired or denied resend never marks its failed envelope completed.
 *
 * @param received - The key of the content that the application got. The
 *   step records it, so a later copy with the same key is dropped. A
 *   receipt record carries its key, and the step records that key again.
 * @returns False, with nothing written, when the stored revision changed.
 */
export async function completeReceiveWork(
  ctx: Pick<SignalProtocolClientContext, 'storage' | 'hooks' | 'logger'>,
  record: ReceiveWorkRecord,
  outcome?: ProcessedEnvelopeOutcome,
  received?: ReceivedMessageKey
): Promise<boolean> {
  const writes: ReceiveCompletionWrite[] = [];
  if (record.envelopeId !== undefined) {
    writes.push({
      envelopeId: record.envelopeId,
      fingerprint: record.workId,
      ...(outcome !== undefined && { outcome }),
    });
  }
  const recovered = outcome === undefined ? record.failedEnvelopeId : undefined;
  // The application has the content, so outcome 1 holds too. A pass that
  // completes the record before a failed outcome-1 write runs again still
  // stops the retry scheduler and drops each later member.
  if (recovered !== undefined) {
    writes.push({ envelopeId: recovered, fulfilled: true, completed: true });
  }
  const receivedMessage = received ?? record.received;
  if (receivedMessage !== undefined) writes.push({ receivedMessage });
  const done = await completeReceiveRecord(ctx.storage, record.workId, record.revision, writes);
  if (!done || recovered === undefined) return done;
  await reportResendRecovered(ctx, recovered);
  return true;
}

/**
 * Run `onDeliveryRecovered` through the completion gate for the failed
 * envelope of a completed resend. A failure is logged, and the retry request
 * lifecycle runs the hook again through the gate.
 *
 * @param markCompleted - Write the fulfilled and completed facts of the
 *   failed envelope first. A record that moves to `receipt-due` uses it:
 *   the application has the content, and the record completes after its
 *   receipt.
 */
async function reportResendRecovered(
  ctx: Pick<SignalProtocolClientContext, 'storage' | 'hooks' | 'logger'>,
  failedEnvelopeId: string,
  markCompleted = false
): Promise<void> {
  try {
    if (markCompleted) {
      await writeProcessedEnvelopes(ctx.storage, [
        { envelopeId: failedEnvelopeId, fulfilled: true, completed: true },
      ]);
    }
    await withProcessedEnvelopeLock(ctx.storage, failedEnvelopeId, () =>
      reportDeliveryRecovered(ctx.storage, ctx.hooks, failedEnvelopeId)
    );
  } catch (error) {
    rethrowRelayWorkStopped(error);
    // The receive hook bound logged its timeout.
    if (error instanceof ReceiveHookTimeout) return;
    ctx.logger.warn('The onDeliveryRecovered hook failed', {
      category: 'E2EE',
      data: {
        failedEnvelopeId,
        behavior: 'DELIVERY_RECOVERED_HOOK_FAILED',
        error: (error as Error).message,
      },
    });
  }
}

/**
 * Deny committed content: run `onDecryptionError`, then write the
 * processed `denied` record. With a receive record, the write is the
 * completion of the record. No receipt and no retry request go out.
 */
export async function denyReceiveWork(
  ctx: Pick<SignalProtocolClientContext, 'storage' | 'hooks' | 'logger'>,
  record: ReceiveWorkRecord | null,
  sender: CommittedSender & { readonly envelopeId?: string; readonly workId?: string },
  error: Error
): Promise<void> {
  ctx.logger.warn('Refusing received content', {
    category: 'E2EE',
    data: {
      messageId: sender.messageId,
      senderId: sender.senderUserId,
      behavior: 'RECEIVE_DENIED',
      error: error.message,
    },
  });
  await reportReceiveDenial(ctx.hooks, sender, error);
  if (record !== null) {
    await completeReceiveWork(ctx, record, 'denied');
  } else if (sender.envelopeId !== undefined) {
    await writeProcessedEnvelopes(ctx.storage, [
      {
        envelopeId: sender.envelopeId,
        ...(sender.workId !== undefined && { fingerprint: sender.workId }),
        outcome: 'denied',
      },
    ]);
  }
}

/**
 * Write a record whose group state must update first. The record waits
 * until its retry time, or until a fetch of its group completes.
 *
 * @returns The time of the next attempt. It is never after the expiry.
 */
export async function blockReceiveWork(
  ctx: Pick<SignalProtocolClientContext, 'storage' | 'logger'>,
  record: ReceiveWorkRecord,
  sender: CommittedSender,
  decision: Extract<GroupContentDecision, { kind: 'unavailable' }>,
  now: number,
  expiresAt: number
): Promise<number> {
  const dueAt = Math.min(now + Math.max(0, decision.error.retryAfterMs), expiresAt);
  ctx.logger.info('Group content waits for its group state', {
    category: 'E2EE',
    data: {
      messageId: sender.messageId,
      senderId: sender.senderUserId,
      behavior: 'GROUP_RECEIVE_UNAVAILABLE',
      reason: decision.error.reason,
    },
  });
  await ctx.storage.putReceiveWork(
    sizedReceiveWork({
      ...record,
      revision: record.revision + 1,
      blockedOn: 'group-update',
      groupId: decision.groupId,
      dueAt,
    }),
    record.revision
  );
  return dueAt;
}

/**
 * Move a helper record with authorized content to `awaiting-completion`.
 * The record then waits for `completeReceive` or for its expiry.
 *
 * @param groupId - The group of the authorized content, or null
 * @returns The written record, or null when the stored revision changed
 */
export async function awaitReceiveCompletion(
  ctx: Pick<SignalProtocolClientContext, 'storage'>,
  record: ReceiveWorkRecord,
  groupId: string | null,
  expiresAt: number
): Promise<ReceiveWorkRecord | null> {
  if (record.stage === 'awaiting-completion') return record;
  const { blockedOn: _blockedOn, ...rest } = record;
  const awaiting = sizedReceiveWork({
    ...rest,
    revision: record.revision + 1,
    stage: 'awaiting-completion',
    dueAt: expiresAt,
    ...(groupId !== null && rest.groupId === undefined && { groupId }),
  });
  return (await ctx.storage.putReceiveWork(awaiting, record.revision)) ? awaiting : null;
}

/**
 * Expire one record: read it again, run `onReceiveExpired`, then write
 * `expired` and delete it. When another path completed the record or wrote
 * a new revision after the list of the pass and before this read, there is
 * no report and no write.
 * Signal drops expired content with no report. See "Expiry hook" in the
 * module comment.
 */
async function expireReceiveWork(
  ctx: Pick<SignalProtocolClientContext, 'storage' | 'hooks' | 'logger'>,
  record: ReceiveWorkRecord
): Promise<void> {
  const current = await ctx.storage.getReceiveWork(record.workId);
  if (current === null || current.revision !== record.revision) return;
  const event: ReceiveExpiredEvent = {
    workId: record.workId,
    reason: 'max-age',
    receivedAt: record.receivedAt,
    stage: record.stage === 'awaiting-completion' ? 'awaiting-completion' : 'decrypted',
    origin: record.origin,
    ...(record.messageId !== undefined && { messageId: record.messageId }),
    ...(record.senderUserId !== undefined && { senderId: record.senderUserId }),
    ...(record.senderDeviceId !== undefined && { senderDeviceId: record.senderDeviceId }),
    ...(record.groupId !== undefined && { groupId: record.groupId }),
    ...(record.failedEnvelopeId !== undefined && { failedEnvelopeId: record.failedEnvelopeId }),
  };
  await callHook(ctx.hooks, 'onReceiveExpired', event);
  await completeReceiveWork(ctx, record, 'expired');
}

/**
 * The processor of the stored receive records. One instance serves one
 * client.
 *
 * @internal
 */
export class ReceiveQueue {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private armedAt = Infinity;
  private resumeTimer: ReturnType<typeof setTimeout> | undefined;
  private tail: Promise<void> = Promise.resolve();
  private queued = false;
  private stopped = true;
  /** The start time of this run. A join window that began earlier has passed. */
  private startedAt = Infinity;
  private afterResume: (() => void) | undefined;
  /** True once the resume of this run succeeded. */
  private resumed = false;
  private starting: Promise<void> = Promise.resolve();
  /** Settles when the first resume of this run ends, or at stop(). */
  private seeding: Promise<void> = Promise.resolve();
  private endSeeding: (() => void) | undefined;
  /** Records that a receive path holds. A pass skips them. */
  private readonly held = new Map<string, number>();
  /** The next attempt time of a record whose hook or receipt send failed. */
  private readonly backoff = new Map<string, number>();
  /**
   * The conversation key of each record that a pass restored and that is
   * still in the queue, so a record in backoff holds back its conversation
   * and not only its sender account. See "Order key" in the module comment.
   */
  private readonly conversations = new Map<string, string>();
  /**
   * Records whose receipt waits in the receipt batch, or whose completion
   * after the send is not written yet. stop() keeps them, so
   * a pass during stop() does not batch a receipt that stop() sends. start()
   * clears them, because stop() drops a batch that it does not send.
   */
  private readonly receiptsInFlight = new Set<string>();
  /** The receipt decisions of the Relay that are not written yet. */
  private readonly decisions = new Map<string, boolean>();
  /**
   * The receipt batch of each record that waits for the receipt decision of
   * the Relay. stop() keeps them: its release of the join decides each one,
   * and a record that the Relay does not receipt then puts its receipt in
   * the batch that stop() sends.
   */
  private readonly joinWaits = new Map<string, () => void>();
  /** Groups whose fetch completed since the last pass. */
  private wokenGroups = new Set<string>();
  /**
   * The next background pass also retries the records at the hook attempt
   * cap that the hook did not get since the last start.
   */
  private cappedRetryDue = false;
  /**
   * The records at the hook attempt cap that the hook got since the last
   * start. Only `processPending` runs them again before the next start.
   */
  private readonly offeredAtCap = new Set<string>();

  constructor(
    private readonly relayWork: RelayWorkTracker,
    /** The resolved `protocol.receiveQueue` policy. */
    readonly policy: ResolvedReceiveQueuePolicy,
    private readonly pass: (work: RelayWork) => ReceiveQueuePass,
    /**
     * Runs once in each run of the queue, after its resume and before its
     * first pass, which expires the records past their age. The client
     * starts the stale device record cleanup from it.
     */
    private readonly onResumed?: () => void
  ) {}

  /**
   * Start the queue. It writes outcome 1 again for each stored resend (the
   * V9 resume) and raises the arrival counter to the stored records, then
   * calls `afterResume`, then runs a pass. A resume that
   * fails is logged and runs again after the backoff, and `afterResume`
   * waits for it. The promise never rejects.
   *
   * @param afterResume - Starts the retry request lifecycle.
   */
  start(afterResume?: () => void): Promise<void> {
    if (!this.stopped) {
      // A start of a running queue waits for its resume.
      if (afterResume !== undefined) {
        if (this.resumed) afterResume();
        else {
          const earlier = this.afterResume;
          this.afterResume = () => {
            earlier?.();
            afterResume();
          };
        }
      }
      return this.starting;
    }
    this.stopped = false;
    this.resumed = false;
    this.startedAt = Date.now();
    // The join window of a waiting record began before this start, so it
    // has passed. A receipt batch of the earlier run is sent or dropped.
    this.joinWaits.clear();
    this.receiptsInFlight.clear();
    this.afterResume = afterResume;
    let endSeeding!: () => void;
    this.seeding = new Promise((resolve) => {
      endSeeding = resolve;
    });
    this.endSeeding = endSeeding;
    this.starting = this.resumeThenRun(endSeeding);
    return this.starting;
  }

  /**
   * Wait until the first resume of this run ends. The resume raises the
   * arrival counter to the stored records, so a record that a receive path
   * admits after this wait sorts after them, even when the clock stepped
   * back across a restart. A receive path waits before it takes a lock,
   * because the resume takes the processed envelope locks. After a failed
   * resume, the counter covers only the records that the resume paged.
   * A `stop()` during the first resume settles the promise, and the counter
   * then covers only the records that the resume paged before the stop.
   * The promise never rejects.
   */
  seeded(): Promise<void> {
    return this.seeding;
  }

  /** Clear the timers. No pass starts until the next start(). */
  stop(): void {
    this.stopped = true;
    this.clear();
    if (this.resumeTimer !== undefined) clearTimeout(this.resumeTimer);
    this.resumeTimer = undefined;
    this.afterResume = undefined;
    this.endSeeding?.();
    this.endSeeding = undefined;
    this.decisions.clear();
    this.backoff.clear();
    this.conversations.clear();
    this.wokenGroups.clear();
    this.cappedRetryDue = false;
    this.offeredAtCap.clear();
  }

  /**
   * Hold one record while a receive path commits it. The Relay subscription
   * and the hosted pull keep the hold until the acknowledgment of the
   * envelope settles. A pass skips a held record and each later record of
   * its conversation.
   *
   * @returns The release of the hold. The release does not wake the queue,
   * so the caller wakes it after the release.
   */
  hold(workId: string): () => void {
    this.held.set(workId, (this.held.get(workId) ?? 0) + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const count = (this.held.get(workId) ?? 1) - 1;
      if (count > 0) this.held.set(workId, count);
      else this.held.delete(workId);
    };
  }

  /**
   * Run a pass soon. With a group, the records that wait for that group get
   * their group decision again in that pass.
   */
  wake(groupId?: string): void {
    if (groupId !== undefined) this.wokenGroups.add(groupId);
    this.schedule(Date.now());
  }

  /**
   * Run a pass soon that also retries each record at the hook attempt cap
   * that the hook did not get since the last start. The registration of
   * `onMessageDecrypted` calls it.
   */
  retryFailedHooks(): void {
    this.cappedRetryDue = true;
    this.schedule(Date.now());
  }

  /**
   * Take the receipt decision of the Relay for one record. Each stored
   * record keeps it, so a restart in any stage before the completion does
   * not send a receipt that the Relay owns.
   *
   * @param owned - True when the Relay sends the receipt.
   */
  joinDecided(workId: string, owned: boolean): void {
    const batchReceipt = this.joinWaits.get(workId);
    this.joinWaits.delete(workId);
    if (this.stopped) {
      // stop() releases the join, and then sends the receipt batches. The
      // record stays receipt-due until a pass after the next start completes
      // it, so a stop that ends the send loses no receipt.
      if (!owned) batchReceipt?.();
      return;
    }
    this.decisions.set(workId, owned);
    // The write runs between passes, so a pass never acts on a revision that
    // this write replaced.
    void this.exclusive(() =>
      this.relayWork.run(async (work) => {
        const { storage } = this.pass(work).ctx;
        const record = await storage.getReceiveWork(workId);
        work.proceed();
        // The record keeps the decision once it is durable, or it completed.
        if (!record || record.relayOwnsReceipt !== undefined) {
          this.decisions.delete(workId);
          return;
        }
        const written = await storage.putReceiveWork(
          sizedReceiveWork({ ...record, revision: record.revision + 1, relayOwnsReceipt: owned }),
          record.revision
        );
        if (written) this.decisions.delete(workId);
      })
    )
      .catch(() => undefined)
      .finally(() => this.schedule(Date.now()));
  }

  /**
   * Run one pass now, in the caller's turn, and stop between records at the
   * deadline. A pass that runs waits first.
   */
  processPending(options: { readonly deadlineMs?: number } = {}): Promise<ReceiveQueuePassResult> {
    const deadline =
      options.deadlineMs === undefined ? Infinity : Date.now() + Math.max(0, options.deadlineMs);
    return this.exclusive(async () => {
      // This pass retries the records at the cap. A pass that ends before
      // them arms the capped retry again.
      this.cappedRetryDue = false;
      let result: ReceiveQueuePassResult = { processed: 0, remaining: 0 };
      await this.relayWork.run(async (work) => {
        result = await this.runPass(work, deadline, 'all');
      });
      return result;
    });
  }

  /** @param endSeeding - Settles `seeded()` of the run after the first attempt. */
  private async resumeThenRun(endSeeding?: () => void): Promise<void> {
    let resumed = false;
    await this.relayWork
      .run(async (work) => {
        resumed = await this.resume(work);
      })
      .catch(() => undefined);
    endSeeding?.();
    if (this.stopped) return;
    if (!resumed) {
      if (this.resumeTimer !== undefined) clearTimeout(this.resumeTimer);
      const timer = setTimeout(() => {
        if (this.resumeTimer !== timer) return;
        this.resumeTimer = undefined;
        void this.resumeThenRun();
      }, RECEIVE_RETRY_BACKOFF_MS);
      (timer as { unref?: () => void }).unref?.();
      this.resumeTimer = timer;
      return;
    }
    this.resumed = true;
    this.onResumed?.();
    const afterResume = this.afterResume;
    this.afterResume = undefined;
    afterResume?.();
    this.cappedRetryDue = true;
    await this.run();
  }

  /**
   * The V9 resume: write outcome 1 for each stored record of a resend whose
   * failed envelope has no fulfilled record. A crash between the receive
   * commit and the outcome-1 write leaves such a record. The resume also
   * raises the arrival counter to the largest stored `arrivalSeq`.
   *
   * @returns False when a store step failed. The failure is logged.
   */
  private async resume(work: RelayWork): Promise<boolean> {
    const { storage, logger } = this.pass(work).ctx;
    try {
      let after: ReceiveWorkQuery['after'];
      for (;;) {
        const page = await storage.listReceiveWork({
          ...(after !== undefined && { after }),
          limit: RECEIVE_WORK_DEFAULT_LIMIT,
        });
        for (const record of page) {
          work.proceed();
          after = { arrivalSeq: record.arrivalSeq, workId: record.workId };
          // The pages run in arrival order, so the counter ends at the
          // largest stored value.
          raiseArrivalSeq(storage, record.arrivalSeq);
          const failed = record.failedEnvelopeId;
          if (failed === undefined) continue;
          await withProcessedEnvelopeLock(storage, failed, async () => {
            if ((await getProcessedEnvelope(storage, failed))?.fulfilled) return;
            await storeProcessedEnvelope(storage, failed, Date.now(), undefined, true);
          });
        }
        if (page.length < RECEIVE_WORK_DEFAULT_LIMIT) return true;
      }
    } catch (error) {
      rethrowRelayWorkStopped(error);
      logger.warn('The receive queue failed to resume the stored resends', {
        category: 'E2EE',
        data: { behavior: 'RECEIVE_RESUME_FAILED', error: (error as Error).message },
      });
      return false;
    }
  }

  /**
   * Arm the timer for the given time when it is earlier than the armed time.
   * A pass that is due now holds the process open, so the work that woke
   * the queue completes. A later pass, such as a backoff or an expiry, does
   * not hold it.
   */
  private schedule(at: number): void {
    if (this.stopped || at >= this.armedAt) return;
    this.clear();
    this.armedAt = at;
    const delay = Math.min(MAX_TIMER_DELAY_MS, Math.max(0, at - Date.now()));
    const timer = setTimeout(() => {
      if (this.timer !== timer) return;
      this.timer = undefined;
      this.armedAt = Infinity;
      void this.run();
    }, delay);
    if (delay > 0) (timer as { unref?: () => void }).unref?.();
    this.timer = timer;
  }

  private clear(): void {
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
    this.armedAt = Infinity;
  }

  /** Run tasks one at a time. */
  private exclusive<T>(task: () => Promise<T>): Promise<T> {
    const result = this.tail.then(task);
    this.tail = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  /** Run a background pass. A call while a pass waits to start adds no pass. */
  private run(): Promise<void> {
    if (this.queued) return this.tail;
    this.queued = true;
    return this.exclusive(async () => {
      this.queued = false;
      if (this.stopped) return;
      const retryCapped = this.cappedRetryDue;
      this.cappedRetryDue = false;
      // A pass logs its own failures. RelayWorkStopped ends the pass.
      await this.relayWork
        .run((work) =>
          this.runPass(work, Infinity, retryCapped ? 'unoffered' : 'none').then(() => undefined)
        )
        .catch(() => undefined);
    });
  }

  /**
   * @param cappedRetry - The records at the hook attempt cap that the pass
   *   also retries.
   */
  private async runPass(
    work: RelayWork,
    deadline: number,
    cappedRetry: CappedRetry
  ): Promise<ReceiveQueuePassResult> {
    const pass = this.pass(work);
    const { storage, logger } = pass.ctx;
    const woken = this.wokenGroups;
    this.wokenGroups = new Set();
    const blocked: BlockedConversations = new Map();
    let next = Infinity;
    let processed = 0;
    let remaining = 0;
    let after: ReceiveWorkQuery['after'];
    let timedOut = false;
    // In a capped-retry pass, a record at the hook attempt cap runs after
    // every other record of the pass. See "Failed hook" in the module comment.
    const capped: ReceiveWorkRecord[] = [];
    const visit = async (record: ReceiveWorkRecord): Promise<void> => {
      if (!timedOut && Date.now() >= deadline) {
        timedOut = true;
        // The records that this pass skips get their group decision again
        // in the next pass.
        for (const groupId of woken) this.wokenGroups.add(groupId);
      }
      if (timedOut) {
        if (record.stage !== 'awaiting-completion') remaining++;
        return;
      }
      work.proceed();
      let step: RecordStep;
      try {
        step = await this.step(pass, work, record, blocked, woken, cappedRetry);
      } catch (error) {
        rethrowRelayWorkStopped(error);
        logger.warn('A receive record failed in the receive queue', {
          category: 'E2EE',
          data: {
            workId: record.workId,
            behavior: 'RECEIVE_QUEUE_RECORD_FAILED',
            error: (error as Error).message,
          },
        });
        block(blocked, record, this.conversationOf(record));
        const retryAt = Date.now() + RECEIVE_RETRY_BACKOFF_MS;
        this.backoff.set(record.workId, retryAt);
        step = WAIT(retryAt);
      }
      if (step.processed) processed++;
      else if (record.stage !== 'awaiting-completion') remaining++;
      next = Math.min(next, step.next);
    };
    let finished = false;
    try {
      for (;;) {
        const page = await storage.listReceiveWork({
          ...(after !== undefined && { after }),
          limit: RECEIVE_WORK_DEFAULT_LIMIT,
        });
        for (const record of page) {
          after = { arrivalSeq: record.arrivalSeq, workId: record.workId };
          if (retriesCap(record, cappedRetry, this.offeredAtCap)) {
            capped.push(record);
            continue;
          }
          await visit(record);
        }
        if (page.length < RECEIVE_WORK_DEFAULT_LIMIT) break;
      }
      for (const record of capped) await visit(record);
      finished = true;
    } finally {
      // A capped-retry pass that ends early, such as at a failed page read,
      // did not run the records at the cap, or did not reach them. The next
      // pass retries them.
      if (cappedRetry !== 'none' && !finished) this.cappedRetryDue = true;
    }
    // The next pass retries the records at the cap that this pass skipped.
    if (timedOut && capped.length > 0) this.cappedRetryDue = true;
    if (timedOut) next = Date.now();
    if (next !== Infinity) this.schedule(next);
    return { processed, remaining };
  }

  /**
   * Drop the in-memory state of a record that left the queue: it completed,
   * it waits for `completeReceive`, or the application discarded it.
   */
  forget(workId: string): void {
    this.decisions.delete(workId);
    this.backoff.delete(workId);
    this.conversations.delete(workId);
    this.offeredAtCap.delete(workId);
  }

  /**
   * The conversation key of a record: the key of its content when a pass
   * restored it, otherwise its stored key.
   */
  private conversationOf(record: ReceiveWorkRecord): string {
    return this.conversations.get(record.workId) ?? storedConversationOf(record);
  }

  /** Handle one record. */
  private async step(
    pass: ReceiveQueuePass,
    work: RelayWork,
    record: ReceiveWorkRecord,
    blocked: BlockedConversations,
    woken: ReadonlySet<string>,
    cappedRetry: CappedRetry
  ): Promise<RecordStep> {
    const { ctx } = pass;
    const now = Date.now();
    const conversation = this.conversationOf(record);
    // The receive path of a held record runs. It wakes the queue after the release.
    if (this.held.has(record.workId)) {
      block(blocked, record, conversation);
      return WAIT(Infinity);
    }
    const expiresAt = receiveExpiresAt(record);
    if (isReceiveExpired(record, now)) {
      // The application has the content of a receipt-due record.
      if (record.stage === 'receipt-due') await completeReceiveWork(ctx, record);
      else await expireReceiveWork(ctx, record);
      this.forget(record.workId);
      return DONE;
    }
    if (record.stage === 'receipt-due' && now >= receiptEndsAt(record)) {
      // The receipt lifespan ended. The application has the content.
      await completeReceiveWork(ctx, record);
      this.forget(record.workId);
      return DONE;
    }
    if (record.stage === 'awaiting-completion') return WAIT(expiresAt);
    if (record.stage === 'receipt-due') return this.receiptStep(pass, record, now);
    // A converted legacy record waits for its redelivery.
    if (record.awaitingEnvelope) return WAIT(expiresAt);
    // An earlier record of the conversation holds back this record. See
    // "Order key" in the module comment.
    if (isBlocked(blocked, record, conversation)) {
      // The next pass after the blocker clears decides on the woken group.
      if (record.groupId !== undefined && woken.has(record.groupId)) {
        this.wokenGroups.add(record.groupId);
      }
      if (record.groupId !== undefined && conversation === groupConversation(record.groupId)) {
        await waitForGroupUpdate(ctx, record, record.groupId);
      }
      return WAIT(expiresAt);
    }
    // A record at the hook attempt cap holds back no record. See "Failed
    // hook" in the module comment.
    if (
      (record.hookAttempts ?? 0) >= RECEIVE_HOOK_ATTEMPT_CAP &&
      !retriesCap(record, cappedRetry, this.offeredAtCap)
    ) {
      return WAIT(expiresAt);
    }
    const retryAt = this.backoff.get(record.workId);
    if (retryAt !== undefined && retryAt > now) {
      block(blocked, record, conversation);
      return WAIT(Math.min(retryAt, expiresAt));
    }
    if (
      record.blockedOn !== undefined &&
      record.dueAt > now &&
      !(record.groupId !== undefined && woken.has(record.groupId))
    ) {
      block(blocked, record, conversation);
      return WAIT(Math.min(record.dueAt, expiresAt));
    }
    return this.processRecord(pass, work, record, blocked, now, expiresAt);
  }

  /** Decide on the group of one decrypted record and deliver its content. */
  private async processRecord(
    pass: ReceiveQueuePass,
    work: RelayWork,
    record: ReceiveWorkRecord,
    blocked: BlockedConversations,
    now: number,
    expiresAt: number
  ): Promise<RecordStep> {
    const { ctx } = pass;
    const restored = await ctx.cipher.restoreCommitted(record, work.stopSignal);
    if (restored.kind === 'denied') {
      await denyReceiveWork(ctx, record, restored, restored.error);
      this.forget(record.workId);
      return DONE;
    }
    const { content } = restored;
    // A null message carries no content. Its receive consumed it.
    if (content.inspected.nullMessage) {
      await completeReceiveWork(ctx, record);
      this.forget(record.workId);
      return DONE;
    }
    // The pass knows the conversation of the content only now. An earlier
    // record of that conversation holds back this record before its group
    // decision, so a later record never applies a group change first. See
    // "Order key" in the module comment.
    const conversation = conversationOf(record, content, ctx.userId);
    this.conversations.set(record.workId, conversation);
    if (isBlocked(blocked, record, conversation)) {
      const groupId = record.groupId ?? managedGroupOf(content);
      if (groupId !== null && conversation === groupConversation(groupId)) {
        await waitForGroupUpdate(ctx, record, groupId);
      }
      return WAIT(expiresAt);
    }
    const decision = await ctx.cipher.decideGroupContent(content);
    work.proceed();
    if (decision.kind === 'denied') {
      await denyReceiveWork(ctx, record, content, decision.error);
      this.forget(record.workId);
      return DONE;
    }
    if (decision.kind === 'unavailable') {
      const dueAt = await blockReceiveWork(ctx, record, content, decision, now, expiresAt);
      block(blocked, record, conversation);
      return WAIT(dueAt);
    }
    if (record.origin === 'caller') {
      // The application completes a helper receive.
      await awaitReceiveCompletion(ctx, record, decision.groupId, expiresAt);
      this.forget(record.workId);
      return DONE;
    }
    // The attempt count is durable before the hook runs, so a hook that
    // ends the process counts as an attempt. A pass with no registered hook
    // makes no attempt. See "Failed hook" in the module comment.
    const receive = ctx.hooks?.onMessageDecrypted;
    let attempted = record;
    if (receive) {
      attempted = sizedReceiveWork({
        ...record,
        revision: record.revision + 1,
        hookAttempts: (record.hookAttempts ?? 0) + 1,
      });
      // Another writer changed the record. A later pass reads it again.
      if (!(await ctx.storage.putReceiveWork(attempted, record.revision))) {
        block(blocked, record, conversation);
        return WAIT(Math.min(Date.now() + RECEIVE_RETRY_BACKOFF_MS, expiresAt));
      }
      // The hook gets a record at the cap once per start.
      if ((attempted.hookAttempts ?? 0) >= RECEIVE_HOOK_ATTEMPT_CAP) {
        this.offeredAtCap.add(record.workId);
      }
    }
    const retryAt = Date.now() + RECEIVE_RETRY_BACKOFF_MS;
    let delivery: Delivery;
    try {
      delivery = await this.deliver(pass, attempted, content, decision.groupId, receive);
    } catch (error) {
      rethrowRelayWorkStopped(error);
      // The registration of onMessageDecrypted wakes the queue. See
      // "Missing hook" in the module comment.
      if (error instanceof ReceiveHookMissing) {
        block(blocked, record, conversation);
        return WAIT(expiresAt);
      }
      // The count of this attempt is already stored. A timeout counts as a
      // failure, and the receive hook bound logged it.
      const hookAttempts = attempted.hookAttempts ?? 0;
      if (!(error instanceof ReceiveHookTimeout)) {
        ctx.logger.warn('The application failed to take received content', {
          category: 'E2EE',
          data: {
            messageId: content.messageId,
            behavior: 'RECEIVE_HOOK_FAILED',
            hookAttempts,
            error: (error as Error).message,
          },
        });
      }
      if (hookAttempts >= RECEIVE_HOOK_ATTEMPT_CAP) {
        this.backoff.delete(record.workId);
        return WAIT(expiresAt);
      }
      this.backoff.set(record.workId, retryAt);
      block(blocked, record, conversation);
      return WAIT(Math.min(retryAt, expiresAt));
    }
    work.proceed();
    this.backoff.delete(record.workId);
    const { owesReceipt, received } = delivery;
    if (!owesReceipt) {
      await completeReceiveWork(ctx, attempted, undefined, received);
      this.forget(record.workId);
      return DONE;
    }
    const at = Date.now();
    const contentTimestamp = content.inspected.timestamp;
    const { senderTimestamp: _envelopeTimestamp, ...withoutTimestamp } =
      withoutContent(attempted);
    const decided = this.decisions.get(record.workId);
    const due = sizedReceiveWork({
      ...withoutTimestamp,
      revision: attempted.revision + 1,
      stage: 'receipt-due',
      // The receipt names the content timestamp, or receivedAt.
      ...(typeof contentTimestamp === 'number' &&
        Number.isSafeInteger(contentTimestamp) && { senderTimestamp: contentTimestamp }),
      dueAt: record.ackIntent?.hasReceiptJoin ? record.ackIntent.at + RELAY_RECEIPT_REPLY_MS : at,
      ...(decided !== undefined && { relayOwnsReceipt: decided }),
      ...(received !== undefined && { received }),
    });
    if (!(await ctx.storage.putReceiveWork(due, attempted.revision))) return DONE;
    // The key is recorded right after the receipt-due write, and again with
    // the completion of the receipt record, which carries it. A stop before
    // this write leaves the key to that completion.
    if (received !== undefined) await recordReceivedTimestamp(ctx.storage, received);
    // The record keeps the decision.
    if (decided !== undefined) this.decisions.delete(record.workId);
    // Outcome 2: the application has the content, and the receipt follows.
    if (due.failedEnvelopeId !== undefined) {
      await reportResendRecovered(ctx, due.failedEnvelopeId, true);
    }
    await this.receiptStep(pass, due, at);
    return DONE;
  }

  /**
   * Give authorized content to the application.
   *
   * @param receive - The `onMessageDecrypted` hook that the attempt count
   *   covers, or undefined when the application has not registered it.
   * @returns Whether the content owes a delivery receipt, and the key of
   *   content that the hook took.
   */
  private async deliver(
    pass: ReceiveQueuePass,
    record: ReceiveWorkRecord,
    content: CommittedContent,
    groupId: string | null,
    receive: SignalProtocolClientHooks['onMessageDecrypted']
  ): Promise<Delivery> {
    const { ctx, callbacks } = pass;
    const { inspected } = content;
    let decrypted = ctx.cipher.decryptedEnvelopeOf(content, groupId);
    // A resend with group content gives the content of its failed group
    // message, so the application gets it under the ID of that message.
    if (record.failedEnvelopeId !== undefined && decrypted.isGroup) {
      decrypted = { ...decrypted, messageId: record.failedEnvelopeId };
    }
    // A peer's profile key in authenticated 1:1 content. The exchange never throws.
    if (
      inspected.profileKey !== undefined &&
      !decrypted.isGroup &&
      decrypted.senderId !== ctx.userId
    ) {
      await ctx.profileKeys?.incoming(decrypted.senderId, inspected.profileKey);
    }
    // The commit installed the distribution. Content beside it continues.
    if (inspected.senderKeyDistribution && inspected.senderKeyDistributionOnly !== false) {
      return NOT_DELIVERED;
    }
    // A key-update DataMessage carries only the profile key, kept above.
    if (inspected.profileKeyUpdate) return NOT_DELIVERED;
    const authenticated: Envelope = {
      targetUserId: ctx.userId,
      targetDeviceId: ctx.deviceId,
      senderUserId: content.senderUserId,
      senderDeviceId: content.senderDeviceId,
      ciphertext: '',
      messageType: record.messageType ?? 'ciphertext',
      deliveryClass: 'ephemeral',
      timestamp: decrypted.timestamp,
      ...(record.envelopeId !== undefined && { id: record.envelopeId }),
      ...(content.serverTimestamp !== undefined && { serverTimestamp: content.serverTimestamp }),
    };
    if (inspected.receipt) {
      await callbacks.handleDeliveryReceipt(authenticated, inspected.receipt);
      return NOT_DELIVERED;
    }
    if (inspected.typing) {
      // Typing indicators are transient: no storage, no delivery receipt.
      await callbacks.handleTypingIndicator(authenticated, inspected.typing);
      return NOT_DELIVERED;
    }
    // A manual resend posts under a new message ID, so the envelope ID
    // check misses it. The device drops a copy whose sender device, content
    // timestamp and content digest match content that the application
    // already has. The key is recorded with the completion of the receive,
    // so a stop after the hook and before the completion runs the hook again.
    // When a receipt is owed, the key is recorded right after the
    // receipt-due write, and again with the completion of the receipt.
    const timestamp = inspected.timestamp;
    const delivered = ctx.contentAdapter.withoutGroupContext(decrypted.content);
    const received: ReceivedMessageKey | undefined =
      typeof timestamp === 'number'
        ? {
            senderUserId: content.senderUserId,
            senderDeviceId: content.senderDeviceId,
            timestamp,
            contentDigest: bytesToBase64(await sha256(new TextEncoder().encode(delivered))),
          }
        : undefined;
    if (received !== undefined && (await hasReceivedTimestamp(ctx.storage, received))) {
      return NOT_DELIVERED;
    }
    if (!receive) throw new ReceiveHookMissing();
    // The application gets the content as its sender gave it.
    await receive({ ...decrypted, content: delivered });
    const receipts = ctx.config.deliveryReceipts ?? 'auto';
    return {
      owesReceipt:
        inspected.shouldSendDeliveryReceipt &&
        ctx.relay !== undefined &&
        receipts !== 'off' &&
        Boolean(decrypted.timestamp),
      ...(received !== undefined && { received }),
    };
  }

  /**
   * Send the receipt of one `receipt-due` record, or complete the record
   * when the Relay owns the receipt or no receipt can go out. The record
   * keeps the receipt durable. See "Durable receipt" in the module comment.
   */
  private async receiptStep(
    pass: ReceiveQueuePass,
    record: ReceiveWorkRecord,
    now: number
  ): Promise<RecordStep> {
    const { ctx, state, callbacks } = pass;
    const owned = record.relayOwnsReceipt ?? this.decisions.get(record.workId);
    if (owned === true) {
      await completeReceiveWork(ctx, record);
      this.forget(record.workId);
      return DONE;
    }
    const { workId, senderUserId } = record;
    const receipts = ctx.config.deliveryReceipts ?? 'auto';
    const batchReceipt =
      ctx.relay !== undefined && receipts !== 'off' && senderUserId !== undefined
        ? (): void => {
            accumulateDeliveryReceipt(
              state.receiptAccumulator,
              senderUserId,
              record.senderTimestamp ?? record.receivedAt,
              callbacks.sendDeliveryReceipt,
              ctx.logger
            ).then(
              () => this.receiptSettled(workId, undefined),
              (error: unknown) =>
                this.receiptSettled(workId, error ?? new Error('Receipt send failed'))
            );
          }
        : undefined;
    const intent = record.ackIntent;
    // After a restart, an intent with no decision means the window passed.
    if (
      owned === undefined &&
      intent?.hasReceiptJoin === true &&
      intent.at >= this.startedAt &&
      now < intent.at + RELAY_RECEIPT_REPLY_MS
    ) {
      if (batchReceipt !== undefined) this.joinWaits.set(workId, batchReceipt);
      return WAIT(intent.at + RELAY_RECEIPT_REPLY_MS);
    }
    this.joinWaits.delete(workId);
    if (this.receiptsInFlight.has(workId)) return WAIT(Infinity);
    const retryAt = this.backoff.get(workId);
    if (retryAt !== undefined && retryAt > now) return WAIT(retryAt);
    if (batchReceipt === undefined) {
      await completeReceiveWork(ctx, record);
      this.forget(workId);
      return DONE;
    }
    this.receiptsInFlight.add(workId);
    batchReceipt();
    return WAIT(Infinity);
  }

  /** Complete a record whose receipt went out, or retry its send later. */
  private receiptSettled(workId: string, error: unknown): void {
    // A stopped send sends again after the next start.
    if (error instanceof RelayWorkStopped) {
      this.receiptsInFlight.delete(workId);
      return;
    }
    if (error !== undefined && !(error instanceof ReceiptSendTerminalError)) {
      if (this.stopped) {
        this.receiptsInFlight.delete(workId);
        return;
      }
      // A pass can expire the record while its send runs. Only a record that
      // still owes its receipt gets a backoff, so an expired record leaves no
      // in-memory state. The read and the backoff write run between passes,
      // so no pass expires the record between them. The record stays in
      // flight until the read ends, so a pass before then does not send its
      // receipt again. A failed read keeps the backoff, and a later pass
      // reads the record again.
      void this.exclusive(async () => {
        let owesReceipt = true;
        await this.relayWork
          .run(async (work) => {
            const { ctx } = this.pass(work);
            const record = await ctx.storage.getReceiveWork(workId);
            work.proceed();
            owesReceipt = record?.stage === 'receipt-due';
          })
          .catch(() => undefined);
        this.receiptsInFlight.delete(workId);
        if (this.stopped) return;
        if (!owesReceipt) {
          this.forget(workId);
          return;
        }
        const retryAt = Date.now() + RECEIVE_RETRY_BACKOFF_MS;
        this.backoff.set(workId, retryAt);
        this.schedule(retryAt);
      });
      return;
    }
    // The receipt went out, or the Relay refused it for good. The record
    // stays in flight until its completion is written, so a pass before that
    // write does not send its receipt again. The completion runs between
    // passes, so no pass that listed the record before the completion
    // visits it after the in-flight mark ends. A completion that a client
    // stop stops leaves the record, and its receipt goes out again after the
    // next start.
    void this.exclusive(async () => {
      let retryAt: number | undefined;
      await this.relayWork
        .run(async (work) => {
          const { ctx } = this.pass(work);
          const record = await ctx.storage.getReceiveWork(workId);
          work.proceed();
          if (record?.stage !== 'receipt-due') return;
          if (await completeReceiveWork(ctx, record)) this.forget(workId);
          else retryAt = Date.now();
        })
        .catch(() => {
          retryAt = Date.now() + RECEIVE_RETRY_BACKOFF_MS;
        });
      this.receiptsInFlight.delete(workId);
      if (retryAt !== undefined) this.schedule(retryAt);
    });
  }
}
