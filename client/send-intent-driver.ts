/**
 * The send driver of a sender device.
 *
 * The outbox stores an intent for each send before its first post. The
 * driver acts on the open intents that the store lists: at start(), at each
 * relay transition to connected, and when the earliest posting deadline of
 * an open intent comes, as the job runners of the Signal clients do. A pass
 * takes each listed intent in turn:
 * - An end that the driver wrote and did not report yet is reported.
 * - An intent at or past its posting deadline ends with the class that its
 *   stored progress gives. The driver posts nothing for it.
 * - An intent before its deadline replays through the send path of an
 *   application call, with its stored ID, timestamp and content. The send
 *   path takes the intent lock, so a replay and an application call for one
 *   ID run one after the other. The driver never holds the lock around a
 *   send. The content is the plaintext of a message record of the send, or
 *   of its send log entry, and only when its digest is the stored digest.
 *   Without such content, the driver reports `content-required` once for
 *   each client run, and the intent stays open until its deadline.
 *
 * The end write of a driver call marks the intent `outcomeReportPending`.
 * The driver clears the mark under the intent lock, then calls
 * `onSendOutcome` only when it cleared the mark. So a crash before the clear
 * reports the end at the next start, a crash between the clear and the call
 * loses the event, and of two drivers on one store only one reports: each
 * end is reported at most once.
 *
 * An internal send, such as a sender key distribution, keeps no content at
 * rest, so the driver never replays it. The driver lists it, ends it at its
 * deadline under the same end path, and reports nothing for it. A retry
 * request of the receiver recovers a lost distribution, as in the Signal
 * clients.
 * An intent that ended is not open, so the driver never replays it again.
 *
 * A manual resend (`resendMessage`) of an ended intent is a new operation
 * with its own stored epoch, bytes and posting deadline. The driver lists an
 * intent with an open resend, posts the resend again under its stored epoch
 * and bytes before its deadline, and ends it at its deadline from its stored
 * progress. It does not end or report the intent again. The end write of a
 * resend stores its outcome and `outcomeReportedAt` in one write, and only
 * the call that wrote the end reports it: so each resend end is reported at
 * most once, and a crash between the write and the hook loses the event.
 *
 * With a store that does not implement `listMetadataKeys`, start() logs one
 * line for each client run, and the driver stays disabled: no pass, no
 * subscription and no timer. Each pass is relay work, so a client stop
 * stops it.
 *
 * @internal
 */

import type { Logger } from '../logger';
import { base64ToBytes, bytesToBase64, sha256 } from '../internal/crypto';
import { utf8Decode } from '../internal/platform';
import {
  isOpenManualResend,
  listOpenOutgoingIntents,
  markOutgoingIntentReported,
  outgoingManualResends,
  outgoingMessageDeadlineAt,
  type OutgoingIntentEndReport,
  type StoredManualResend,
  type StoredOutgoingMessageIntent,
} from '../local/store/reliability';
import { ProtocolAddress } from '../types/address';
import type { SignalProtocolLocalStore } from '../types/api';
import { asBase64 } from '../types/utils';
import type { SendOutcomeEvent } from './event-hooks';
import { rethrowRelayWorkStopped, type RelayWork, type RelayWorkTracker } from './relay-work';
import {
  manualResendOutcomeEvent,
  sendOutcomeEvent,
  type ManualResendEndReport,
} from './send-deadline';

/** The store methods that a pass of the driver reads and writes. */
export type SendIntentStore = Pick<
  SignalProtocolLocalStore,
  | 'getMetadata'
  | 'setMetadata'
  | 'deleteMetadata'
  | 'listMetadataKeys'
  | 'getMessageRecord'
  | 'getSendLogRecipients'
  | 'getSendLogEntry'
>;

/** What one pass of the driver runs, for one relay work. */
export interface SendIntentPass {
  /**
   * End an open intent at or past its posting deadline, under its lock,
   * with the class that its stored progress gives. It posts nothing.
   */
  readonly end: (clientMessageId: string, report: OutgoingIntentEndReport) => Promise<void>;
  /**
   * Send the intent again through the send path of an application call. It
   * throws the error of the send.
   */
  readonly replay: (
    intent: StoredOutgoingMessageIntent,
    content: Uint8Array,
    report: OutgoingIntentEndReport
  ) => Promise<void>;
  /**
   * Post the open manual resend of an ended intent again, under its stored
   * epoch and bytes, through the send path of `resendMessage`. It throws
   * the error of the resend. When no resend is open under the intent lock,
   * it posts nothing and fills nothing in the report.
   */
  readonly resend: (clientMessageId: string, report: ManualResendEndReport) => Promise<void>;
  /**
   * End an open manual resend at or past its posting deadline, under the
   * intent lock, from its stored progress. It posts nothing, and returns
   * the end that it wrote.
   */
  readonly endResend: (
    clientMessageId: string,
    manualMessageId: string
  ) => Promise<ManualResendEndReport['ended']>;
  /** Call `onSendOutcome`. A hook that throws is logged. */
  readonly report: (event: SendOutcomeEvent) => Promise<void>;
}

/** @internal */
export class SendIntentDriver {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private running: Promise<void> | undefined;
  private again = false;
  private stopped = true;
  private disabledLogged = false;
  /** The intents that this client run reported as `content-required`. */
  private readonly contentRequired = new Set<string>();

  constructor(
    private readonly relayWork: RelayWorkTracker,
    private readonly storage: SendIntentStore,
    private readonly logger: Required<Logger>,
    private readonly pass: (work: RelayWork) => SendIntentPass
  ) {}

  /**
   * True when the store implements `listMetadataKeys`. The client subscribes
   * to relay connection states only then.
   */
  get enabled(): boolean {
    return typeof this.storage.listMetadataKeys === 'function';
  }

  /**
   * Run a pass now, or one more pass after the pass that runs. On a store
   * with no listing method, start() logs one line for the client run and
   * runs no pass. The promise never rejects.
   */
  start(): Promise<void> {
    if (!this.enabled) {
      if (!this.disabledLogged) {
        this.disabledLogged = true;
        this.logger.info(
          'The store does not implement listMetadataKeys, so the SDK does not replay open sends',
          { category: 'E2EE', data: { behavior: 'SEND_DRIVER_DISABLED' } }
        );
      }
      return Promise.resolve();
    }
    this.stopped = false;
    this.clear();
    return this.run();
  }

  /** Clear the deadline timer. No pass starts until the next start(). */
  stop(): void {
    this.stopped = true;
    this.clear();
  }

  /**
   * Test seam: settles when no pass runs and no further pass is due from a
   * trigger that came during a pass.
   */
  private async settled(): Promise<void> {
    while (this.running) await this.running;
  }

  private clear(): void {
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
  }

  private run(): Promise<void> {
    if (this.running) {
      this.again = true;
      return this.running;
    }
    let running: Promise<void> | undefined;
    let done = false;
    running = (async () => {
      try {
        do {
          this.again = false;
          if (this.stopped) return;
          // A pass logs its own failures. RelayWorkStopped ends the run.
          await this.relayWork.run((work) => this.runPass(work)).catch(() => undefined);
        } while (this.again);
      } finally {
        // Cleared on the tick of the last check of `again`, so a trigger
        // after that check starts a new run.
        done = true;
        if (this.running === running) this.running = undefined;
      }
    })();
    if (!done) this.running = running;
    return running;
  }

  private async runPass(work: RelayWork): Promise<void> {
    const pass = this.pass(work);
    const { logger } = this;
    let intents: StoredOutgoingMessageIntent[] | undefined;
    try {
      intents = await listOpenOutgoingIntents(this.storage);
    } catch (error) {
      rethrowRelayWorkStopped(error);
      logger.warn('The send driver failed to list the open sends', {
        category: 'E2EE',
        data: { behavior: 'SEND_DRIVER_RETRY', error: (error as Error).message },
      });
      return;
    }
    if (intents === undefined) return;
    let next: number | undefined;
    for (const intent of intents) {
      work.proceed();
      try {
        const deadlineAt = await this.drive(pass, intent);
        if (deadlineAt !== undefined && (next === undefined || deadlineAt < next)) {
          next = deadlineAt;
        }
      } catch (error) {
        rethrowRelayWorkStopped(error);
        logger.warn('A send of the send driver failed and stays open', {
          category: 'E2EE',
          data: {
            clientMessageId: intent.clientMessageId,
            behavior: 'SEND_DRIVER_RETRY',
            error: (error as Error).message,
          },
        });
        // A failure before the deadline runs again at the deadline. A failure
        // at or past it runs again at the next start or connect, so the
        // timer never runs a failing pass in a loop.
        const deadlineAt = drivenDeadlineAt(intent);
        if (Date.now() < deadlineAt && (next === undefined || deadlineAt < next)) next = deadlineAt;
      }
    }
    if (next !== undefined) this.armDeadline(next);
  }

  /**
   * Act on one listed intent. Returns the deadline of an intent that stays
   * open, or undefined.
   */
  private async drive(
    pass: SendIntentPass,
    intent: StoredOutgoingMessageIntent
  ): Promise<number | undefined> {
    if (intent.outcomeReportPending) await this.reportEnd(pass, intent);
    if (intent.result || intent.outcome !== undefined) {
      return this.driveManualResend(pass, intent);
    }
    const deadlineAt = outgoingMessageDeadlineAt(intent);
    const report: OutgoingIntentEndReport = { driven: true };
    if (Date.now() >= deadlineAt) {
      // The deadline has passed: classify the stored progress, post nothing.
      await pass.end(intent.clientMessageId, report);
      if (report.ended) await this.reportEnd(pass, report.ended);
      return undefined;
    }
    // With no stripping function, the logged bytes of a managed group send
    // do not match, so its replay waits for the application as before.
    const content = (await intentContent(this.storage, intent))?.content;
    if (!content) {
      // The application cannot supply the content of an internal send.
      if (!intent.internal && !this.contentRequired.has(intent.clientMessageId)) {
        this.contentRequired.add(intent.clientMessageId);
        await pass.report({
          clientMessageId: intent.clientMessageId,
          outcome: 'content-required',
          deadlineAt,
        });
      }
      return deadlineAt;
    }
    try {
      await pass.replay(intent, content, report);
    } catch (error) {
      rethrowRelayWorkStopped(error);
      // An end of the replay throws its error. The end is reported below.
      if (!report.ended) throw error;
    }
    // A replay that returns found the send completed, by this call or before.
    if (report.ended?.outcomeReportPending) await this.reportEnd(pass, report.ended);
    return undefined;
  }

  /**
   * Act on the open manual resend of an ended intent: end it at or past its
   * deadline, else post it again. Returns undefined. A post that leaves the
   * resend open throws, and the pass runs again at the resend deadline.
   */
  private async driveManualResend(
    pass: SendIntentPass,
    intent: StoredOutgoingMessageIntent
  ): Promise<number | undefined> {
    const resend = openManualResend(intent);
    if (!resend) return undefined;
    if (Date.now() >= resend.deadlineAt) {
      // The deadline has passed: classify the stored progress, post nothing.
      const ended = await pass.endResend(intent.clientMessageId, resend.manualMessageId);
      if (ended) await pass.report(manualResendOutcomeEvent(ended.intent, ended.resend));
      return undefined;
    }
    const report: ManualResendEndReport = {};
    try {
      await pass.resend(intent.clientMessageId, report);
    } catch (error) {
      rethrowRelayWorkStopped(error);
      // An end of the resend throws its error. The end is reported below.
      if (!report.ended) throw error;
    }
    if (report.ended) {
      await pass.report(manualResendOutcomeEvent(report.ended.intent, report.ended.resend));
    }
    return undefined;
  }

  /**
   * Clear the report mark of a driver end, then call the hook. Only the
   * driver that cleared the mark calls it, so another driver on the store, or
   * an end with no mark, such as the end of an internal send, reports nothing.
   */
  private async reportEnd(pass: SendIntentPass, intent: StoredOutgoingMessageIntent): Promise<void> {
    if (await markOutgoingIntentReported(this.storage, intent.clientMessageId)) {
      await pass.report(sendOutcomeEvent(intent));
    }
  }

  /** Arm one pass at the earliest deadline of an open intent. */
  private armDeadline(deadlineAt: number): void {
    if (this.stopped) return;
    this.clear();
    const timer = setTimeout(
      () => {
        if (this.timer !== timer) return;
        this.timer = undefined;
        void this.run();
      },
      Math.max(0, deadlineAt - Date.now())
    );
    (timer as { unref?: () => void }).unref?.();
    this.timer = timer;
  }
}

/** The open manual resend of an intent, if any. */
function openManualResend(intent: StoredOutgoingMessageIntent): StoredManualResend | undefined {
  return outgoingManualResends(intent).find(isOpenManualResend);
}

/**
 * The deadline at which the driver acts on a listed intent again: the
 * deadline of its open manual resend for an ended intent, else its own.
 */
function drivenDeadlineAt(intent: StoredOutgoingMessageIntent): number {
  const resend =
    intent.result || intent.outcome !== undefined ? openManualResend(intent) : undefined;
  return resend?.deadlineAt ?? outgoingMessageDeadlineAt(intent);
}

/**
 * The stored plaintext of an intent, and whether it carries the group
 * context of a managed group.
 */
export interface IntentContent {
  readonly content: Uint8Array;
  /**
   * True for the logged bytes of a group send that added the group context
   * to the caller content. A manual resend posts these bytes as they are.
   */
  readonly withGroupContext: boolean;
}

/**
 * Whether logged group content holds caller bytes whose SHA-256 digest is
 * `digest`. `withoutGroupContext` of the resolved content adapter strips
 * the group context and gives text. The default adapter gives the UTF-8
 * text of caller bytes that round-trip, else their base64. So the
 * candidates are the UTF-8 encoding of the stripped text and, when that
 * text decodes as base64, the decoded bytes. The digest guards each
 * candidate, so a custom adapter keeps working.
 */
export async function callerBytesMatch(
  content: Uint8Array,
  withoutGroupContext: (plaintext: string) => string,
  digest: string
): Promise<boolean> {
  const stripped = withoutGroupContext(utf8Decode(content));
  const matches = async (candidate: Uint8Array) =>
    bytesToBase64(await sha256(candidate)) === digest;
  if (await matches(new TextEncoder().encode(stripped))) return true;
  let decoded: Uint8Array;
  try {
    decoded = base64ToBytes(asBase64(stripped));
  } catch {
    return false;
  }
  return matches(decoded);
}

/**
 * The stored plaintext of an intent: the plaintext of a message record of
 * the send, or of its send log entry, whose SHA-256 digest is the stored
 * digest. A group send digests the caller bytes and logs them with the
 * group context, so with `withoutGroupContext` the logged bytes of a group
 * intent also match when `callerBytesMatch` finds the stored digest.
 * Undefined when no such plaintext is stored.
 */
export async function intentContent(
  storage: SendIntentStore,
  intent: StoredOutgoingMessageIntent,
  withoutGroupContext?: (plaintext: string) => string
): Promise<IntentContent | undefined> {
  const matches = async (content: Uint8Array) =>
    bytesToBase64(await sha256(content)) === intent.plaintextDigest;
  const sessions = new Set<string>();
  for (const message of [...intent.deviceMessages, ...intent.syncMessages]) {
    const sessionId = ProtocolAddress.toString(
      ProtocolAddress.create(message.recipientUserId, message.recipientDeviceId)
    );
    if (sessions.has(sessionId)) continue;
    sessions.add(sessionId);
    const record = await storage.getMessageRecord(sessionId, intent.clientTimestamp);
    if (!record) continue;
    const content = new TextEncoder().encode(record.plaintext);
    if (await matches(content)) return { content, withGroupContext: false };
  }
  const [recipient] = await storage.getSendLogRecipients(intent.clientMessageId);
  if (!recipient) return undefined;
  const entry = await storage.getSendLogEntry(intent.clientMessageId, recipient);
  if (!entry) return undefined;
  const logged = entry.payload.plaintext;
  if (await matches(logged)) return { content: logged, withGroupContext: false };
  if (
    intent.kind === 'group' &&
    withoutGroupContext &&
    (await callerBytesMatch(logged, withoutGroupContext, intent.plaintextDigest))
  ) {
    return { content: logged, withGroupContext: true };
  }
  return undefined;
}
