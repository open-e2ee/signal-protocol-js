import { deviceSetRefusal } from '../remote/relay/device-set';
import { followedRepeatedRequest } from '../remote/relay/request-admission';
import {
  outgoingDestinationProgressKey,
  outgoingMessageDeadlineAt,
  outgoingMessageIntentResult,
  type OutgoingIntentEndReport,
  type recordOutgoingDestinationProgress,
  type StoredDestinationProgress,
  type StoredManualResend,
  type StoredOutgoingMessageIntent,
} from '../local/store/reliability';
import {
  SealedSenderAuthError,
  SendAcceptanceUnknownError,
  SendNeverAcceptedByRelayError,
} from '../types/errors';
import {
  conflictAcceptance,
  isConflictAcceptance,
  relayHoldsMessageId,
  relayOperationRefusal,
  type RelayPostAcceptance,
} from './relay-acceptance';
import type { SendOutcomeEvent } from './event-hooks';
import { markRelayDeviceRefusal, relayDeviceRefusal } from './relay-device-refusal';

/**
 * The posting deadline of a direct or group send: the time after which the
 * SDK starts no relay request for the send, and the classification of the
 * send when it ends at that time.
 *
 * The outbox stores the deadline with the intent (`deadlineAt`). Each post
 * of the send checks it before each request, also before a transport repeat
 * and before the identified fallback of a sealed post. The outbox also
 * stores the progress of each destination: the requests that started for
 * it and the class of its last answer. The evidence of one `send()` call
 * records each answer that a request of the call got, and writes it to the
 * stored progress. A destination is one device under the client message ID
 * of its posts, so a pre-message and the group message of one device are
 * two destinations. When an open destination remains at the deadline, or
 * when every open destination got OPERATION_EXPIRED in the call or has a
 * stored refusal that the SDK cannot recover, the send ends, and the stored
 * progress decides its class.
 *
 * No package entry exports this module.
 */

/** The internal error of a request that the posting deadline refused. */
export class PostingDeadlineReachedError extends Error {
  override readonly name = 'PostingDeadlineReachedError';

  constructor(readonly deadlineAt: number) {
    super('The posting deadline of the send ended before the request');
  }
}

/** True when the posting deadline refused the request. */
export function isPostingDeadlineReached(error: unknown): error is PostingDeadlineReachedError {
  return error instanceof PostingDeadlineReachedError;
}

/**
 * The check that each request of a send meets before it starts. It rejects
 * with `PostingDeadlineReachedError` at or after the deadline.
 */
export function postingDeadlineCheck(
  deadlineAt: number,
  clock: () => number
): () => Promise<void> {
  return async () => {
    if (clock() >= deadlineAt) throw new PostingDeadlineReachedError(deadlineAt);
  };
}

/**
 * Record whether the posting deadline refused a request of one post. The
 * returned check runs the deadline check and records its refusal.
 */
export function recordDeadlineStop(check: (() => Promise<void>) | undefined): {
  readonly check: () => Promise<void>;
  stopped(): boolean;
} {
  let stopped = false;
  return {
    check: async () => {
      try {
        await check?.();
      } catch (error) {
        if (isPostingDeadlineReached(error)) stopped = true;
        throw error;
      }
    },
    stopped: () => stopped,
  };
}

/** One device of a send error. */
export interface SendDevice {
  readonly userId: string;
  readonly deviceId: number;
}

/** One destination of a send: a device and the client message ID of its posts. */
export interface SendDestination {
  readonly device: SendDevice;
  readonly postMessageId: string;
}

/** The class of the answer to the requests of one post (contract §3.5). */
type AnswerClass = 'accepted' | 'refused' | 'pending' | 'uncertain';

/** The class of one destination at the end of a send (contract §3.4). */
type DestinationState = 'accepted' | 'refused' | 'unknown';

/** The order in which the destinations of one device decide its class. */
const DESTINATION_STATE_RANK: Readonly<Record<DestinationState, number>> = {
  accepted: 0,
  refused: 1,
  unknown: 2,
};

interface DestinationEvidence {
  /**
   * The stored progress of the destination when the call started, or the
   * entry that a repair in the call returned.
   */
  entry?: StoredDestinationProgress;
  requests: number;
  answers: AnswerClass[];
  acceptance?: RelayPostAcceptance;
  /** True when the last answer was OPERATION_EXPIRED. */
  expired: boolean;
  /** True when a transport repeat followed an uncertain answer. */
  uncertainRepeat: boolean;
}

/** The codes of a refusal of one request. The Relay did not store the post. */
const REFUSAL_CODES: ReadonlySet<string> = new Set([
  'STALE_DEVICE',
  'NOT_FOUND',
  'TOKEN_INVALID',
  'AUTHORITY_DENIED',
  'SCOPE_MISMATCH',
]);

/** The codes of a refusal for now. The post can succeed later. */
const PENDING_CODES: ReadonlySet<string> = new Set([
  'MAILBOX_FULL',
  'QUOTA_EXCEEDED',
  'DEPLOYMENT_SUSPENDED',
  'PROTOCOL_UNSUPPORTED',
]);

/**
 * The codes of an error that keeps its own retry rule. The answer ends the
 * send at once as a terminal failure (contract C-7): no later request of
 * this SDK can change it.
 */
const OWN_RETRY_CODES: ReadonlySet<string> = new Set(['UPGRADE_REQUIRED', 'DEVICE_REVOKED']);

/**
 * The stored refusal codes that no recovery in a send call can change. A
 * replay does not post a device that has one of them. Each other refused
 * code counts only when the entry records a spent recovery.
 */
const TERMINAL_REFUSAL_CODES: ReadonlySet<string> = new Set([
  'NOT_FOUND',
  'TOKEN_INVALID',
  'AUTHORITY_DENIED',
  'SCOPE_MISMATCH',
  'OPERATION_EXPIRED',
  'UPGRADE_REQUIRED',
  'DEVICE_REVOKED',
]);

/** One write of the stored progress of a destination. */
type DestinationProgressUpdate = Parameters<typeof recordOutgoingDestinationProgress>[3];

/** The stored answer of a refused, pending or uncertain answer. */
type StoredAnswer = Extract<DestinationProgressUpdate, { answer: unknown }>;

/**
 * True when the stored entry proves that the Relay refused every request of
 * the destination, and that no recovery in a send call can change the
 * refusal: the entry is `refused` with no uncertain request, and its code
 * is terminal or its recovery already ran and the Relay refused the repost.
 */
export function provenRefused(entry: StoredDestinationProgress | undefined): boolean {
  return (
    entry?.state === 'refused' &&
    entry.uncertain !== true &&
    ((entry.refusalCode !== undefined && TERMINAL_REFUSAL_CODES.has(entry.refusalCode)) ||
      entry.repairSpent === true)
  );
}

/**
 * The acceptance of a destination that a stored entry records. The call got
 * no receipt for it, so it counts as a conflict acceptance: it carries the
 * stored Relay message ID when there is one, and no device-set mark.
 */
export function storedAcceptance(
  entry: StoredDestinationProgress,
  clock: () => number
): RelayPostAcceptance {
  const acceptance = conflictAcceptance(
    entry.messageId ?? entry.postMessageId,
    entry.enqueuedAt ?? clock()
  );
  if (entry.expiresAt !== undefined) acceptance.expiresAt = entry.expiresAt;
  if (entry.duplicate) acceptance.duplicate = true;
  return acceptance;
}

/** The stored fields of an accepted answer. A conflict acceptance has no receipt. */
function acceptedAnswer(acceptance: RelayPostAcceptance): DestinationProgressUpdate & {
  answer: 'accepted';
} {
  const receipt = isConflictAcceptance(acceptance) ? undefined : acceptance;
  return {
    answer: 'accepted',
    enqueuedAt: acceptance.serverTimestamp,
    ...(receipt && { messageId: receipt.messageId }),
    ...(receipt?.expiresAt !== undefined && { expiresAt: receipt.expiresAt }),
    ...(receipt?.duplicate === true && { duplicate: true as const }),
  } as DestinationProgressUpdate & { answer: 'accepted' };
}

function deviceKey(device: SendDevice): string {
  return `${device.userId}\u0000${String(device.deviceId)}`;
}

function destinationKey({ device, postMessageId }: SendDestination): string {
  return outgoingDestinationProgressKey(postMessageId, device);
}

/** The relay answer of one shared post, which names refused accounts and devices. */
interface SharedPostAnswer extends RelayPostAcceptance {
  uuids404: string[];
  refusals?: readonly { userId: string; deviceId: number; code: string }[];
}

function sendDevice(device: SendDevice): SendDevice {
  return { userId: device.userId, deviceId: device.deviceId };
}

function errorCode(error: object): unknown {
  const { code, data } = error as { code?: unknown; data?: unknown };
  if (typeof code === 'string') return code;
  return data !== null && typeof data === 'object' ? (data as { code?: unknown }).code : undefined;
}

/** The end of a send at its posting deadline. */
export interface SendEnd {
  readonly outcome: NonNullable<StoredOutgoingMessageIntent['outcome']>;
  readonly destinationProgress: Record<string, StoredDestinationProgress>;
  /** The error that `send()` throws. */
  readonly error: Error;
}

/**
 * The evidence of one `send()` call of a direct or group send: the requests
 * and the answers of each destination in the call, and the stored progress
 * of each destination when the call started.
 */
export class SendCallEvidence {
  /** The posting deadline check of each request of the call. */
  readonly check: () => Promise<void>;
  private readonly destinations = new Map<string, DestinationEvidence>();
  private firstRefusal: unknown;
  private lastError: unknown;
  private hasRefusal = false;
  private hasError = false;
  /** The first UPGRADE_REQUIRED or DEVICE_REVOKED answer of the call. */
  private terminalAnswer: Error | undefined;

  constructor(
    private readonly options: {
      readonly clientMessageId: string;
      readonly deadlineAt: number;
      /** The stored progress of the intent when the call started. */
      readonly progress?: Readonly<Record<string, StoredDestinationProgress>>;
      /**
       * True when the intent wrote progress before each of its requests. A
       * destination with no entry then had no request.
       */
      readonly progressFromStart?: boolean;
      /** True when the intent posts sealed and refuses identified delivery. */
      readonly sealedSenderRequired?: boolean;
      readonly clock: () => number;
      /** True for another error that refuses one request for its device. */
      readonly refusesDevice?: (error: unknown) => boolean;
      /**
       * Store one answer of a destination. It runs after each post settles,
       * and the post settles only after the write.
       */
      readonly recordProgress?: (
        key: string,
        update: DestinationProgressUpdate
      ) => Promise<StoredDestinationProgress | undefined>;
    }
  ) {
    this.check = postingDeadlineCheck(options.deadlineAt, options.clock);
    for (const [key, entry] of Object.entries(options.progress ?? {})) {
      if (entry.phase === 'recipient') this.evidenceAt(key).entry = entry;
    }
  }

  get deadlineAt(): number {
    return this.options.deadlineAt;
  }

  /**
   * Take the stored entry of a device that a repair in this call returned.
   * The entry names the client message ID of the repaired post. A later
   * RETRY_CONFLICT of that destination reads its repair mark.
   */
  refreshEntry(device: SendDevice, entry: StoredDestinationProgress): void {
    this.evidenceAt(destinationKey({ device, postMessageId: entry.postMessageId })).entry = entry;
  }

  /**
   * Run one post of a destination, record its answer, and store the class
   * of the answer. `post` gives `onRequest` to the control of the post,
   * which calls it when a request starts, also for a transport repeat and
   * the identified fallback. A RETRY_CONFLICT, or a version 2
   * DELIVERY_ALREADY_ACCEPTED, resolves the post as accepted when no repair
   * replaced the message of the destination. A
   * message that the stored progress records as accepted is not posted
   * again: the post resolves with the stored acceptance. The post resolves
   * only when the destination is accepted. Each other answer rejects.
   */
  async post(
    destination: SendDestination,
    post: (onRequest: (repeat?: 'uncertain' | 'token') => void) => Promise<RelayPostAcceptance>
  ): Promise<RelayPostAcceptance> {
    const key = destinationKey(destination);
    const evidence = this.evidenceAt(key);
    if (evidence.entry?.state === 'accepted') {
      return storedAcceptance(evidence.entry, this.options.clock);
    }
    const stored = {
      phase: 'recipient' as const,
      userId: destination.device.userId,
      deviceId: destination.device.deviceId,
      postMessageId: destination.postMessageId,
    };
    let requests = 0;
    let acceptance: RelayPostAcceptance;
    try {
      acceptance = await post((repeat) => {
        requests += 1;
        evidence.requests += 1;
        // The first request can have stored the post before the repeat.
        if (repeat === 'uncertain') evidence.uncertainRepeat = true;
      });
    } catch (error) {
      // A post that started no request is no evidence. The deadline check
      // rejects before its request starts.
      if (requests === 0) throw error;
      const answer = this.classifyAnswer(evidence.entry, error);
      if (answer === 'accepted') {
        const conflict = conflictAcceptance(destination.postMessageId, this.options.clock());
        this.accept(evidence, conflict);
        await this.options.recordProgress?.(key, { ...stored, ...acceptedAnswer(conflict) });
        return conflict;
      }
      evidence.answers.push(answer);
      evidence.expired = relayOperationRefusal(error) === 'OPERATION_EXPIRED';
      this.keepTerminalAnswer(error);
      if (answer === 'refused' && !this.hasRefusal) {
        this.hasRefusal = true;
        this.firstRefusal = error;
      }
      this.hasError = true;
      this.lastError = error;
      await this.options.recordProgress?.(key, {
        ...stored,
        ...storedAnswer(answer, error, this.options),
      });
      throw error;
    }
    this.accept(evidence, acceptance);
    await this.options.recordProgress?.(key, { ...stored, ...acceptedAnswer(acceptance) });
    return acceptance;
  }

  /**
   * Run one shared post of the destinations of a group body, and record its
   * one answer on each destination. `post` gives `onRequest` to the control
   * of the post, and each request counts for each destination. When the
   * stored progress records each destination as accepted, the body is not
   * posted again.
   *
   * - A receipt accepts each destination, except each destination of a user
   *   in `uuids404` and each destination that `refusals` names. Those are
   *   refused, as a thrown refusal of the post refuses its destination, and
   *   the first one gives the terminal error of a failed end. The count
   *   `refusedDestinationCount` names no device, so it refuses no
   *   destination.
   * - A RETRY_CONFLICT, or a version 2 DELIVERY_ALREADY_ACCEPTED, accepts
   *   each destination whose current entry has no repair mark, and it resolves the post with a conflict
   *   acceptance when each destination is accepted. A destination with a
   *   repair mark is uncertain, and the post rejects.
   * - Each other answer gives its class to each destination, so after
   *   OPERATION_EXPIRED each destination is expired.
   */
  async postShared<T extends SharedPostAnswer>(
    destinations: readonly SendDestination[],
    post: (onRequest: (repeat?: 'uncertain' | 'token') => void) => Promise<T>
  ): Promise<T> {
    const targets = destinations.map((destination) => {
      const key = destinationKey(destination);
      return {
        destination,
        key,
        evidence: this.evidenceAt(key),
        stored: {
          phase: 'recipient' as const,
          userId: destination.device.userId,
          deviceId: destination.device.deviceId,
          postMessageId: destination.postMessageId,
        },
      };
    });
    const storedEntries = targets.map(({ evidence }) => evidence.entry);
    // Only a body whose destinations are all stored as accepted stays
    // unposted. The receipt writes one entry at a time, so a crash between
    // them can leave some destinations accepted. The body is sealed for every
    // recipient and cannot go to a subset, so the replay posts it again to
    // each destination, and the Relay answers an accepted one from its dedup
    // record. Only the request count and the bytes of the replay grow.
    if (storedEntries.length > 0 && storedEntries.every((entry) => entry?.state === 'accepted')) {
      // The same object keeps the conflict mark of a stored acceptance.
      return Object.assign(storedAcceptance(storedEntries[0]!, this.options.clock), {
        uuids404: [],
      }) as unknown as T;
    }
    let requests = 0;
    let result: T;
    try {
      result = await post((repeat) => {
        requests += 1;
        for (const { evidence } of targets) {
          evidence.requests += 1;
          if (repeat === 'uncertain') evidence.uncertainRepeat = true;
        }
      });
    } catch (error) {
      if (requests === 0) throw error;
      const expired = relayOperationRefusal(error) === 'OPERATION_EXPIRED';
      const conflict = conflictAcceptance(this.options.clientMessageId, this.options.clock());
      let accepted = 0;
      for (const target of targets) {
        const answer = this.classifyAnswer(target.evidence.entry, error);
        if (answer === 'accepted') {
          accepted += 1;
          this.accept(target.evidence, conflict);
          await this.options.recordProgress?.(target.key, {
            ...target.stored,
            ...acceptedAnswer(conflict),
          });
          continue;
        }
        target.evidence.answers.push(answer);
        target.evidence.expired = expired;
        this.keepTerminalAnswer(error);
        if (answer === 'refused' && !this.hasRefusal) {
          this.hasRefusal = true;
          this.firstRefusal = error;
        }
        await this.options.recordProgress?.(target.key, {
          ...target.stored,
          ...storedAnswer(answer, error, this.options),
        });
      }
      if (accepted === targets.length) {
        // The same object keeps the conflict mark.
        return Object.assign(conflict, { uuids404: [] }) as unknown as T;
      }
      this.hasError = true;
      this.lastError = error;
      throw error;
    }
    const missing = new Set(result.uuids404);
    const refusals = new Map(
      (result.refusals ?? []).map((refusal) => [deviceKey(refusal), refusal.code])
    );
    for (const target of targets) {
      const { device } = target.destination;
      const code = missing.has(device.userId) ? 'NOT_FOUND' : refusals.get(deviceKey(device));
      if (code === undefined) {
        this.accept(target.evidence, result);
        await this.options.recordProgress?.(target.key, {
          ...target.stored,
          ...acceptedAnswer(result),
        });
        continue;
      }
      target.evidence.answers.push('refused');
      target.evidence.expired = code === 'OPERATION_EXPIRED';
      if (!this.hasRefusal) {
        this.hasRefusal = true;
        this.firstRefusal = receiptRefusal(device, code);
      }
      await this.options.recordProgress?.(target.key, {
        ...target.stored,
        answer: 'refused',
        refusalCode: code,
      });
    }
    return result;
  }

  /**
   * Run one sync copy of the send to an own device, and store its progress
   * under the device key `destination`. A sync entry never counts for the
   * end of the send. A copy that the stored progress records as accepted is
   * not posted again.
   *
   * `post` gets the gate of each request of the copy, by the client message
   * ID of the copy that the request posts. A copy with no client message ID
   * gets its gate by `undefined`, and its request is stored under the sync
   * ID of `destination`. The gate runs `check`, then stores the request.
   * After the copy settles, its answer is stored. An undefined result means
   * that the device refused the copy and its repair, and the copy left the
   * intent.
   */
  async postSync(
    destination: SendDestination,
    check: () => Promise<void>,
    post: (
      gate: (postMessageId: string | undefined) => () => Promise<void>
    ) => Promise<RelayPostAcceptance | undefined>
  ): Promise<RelayPostAcceptance | undefined> {
    const key = outgoingDestinationProgressKey(destination.postMessageId, destination.device);
    let entry = this.options.progress?.[key];
    if (entry?.state === 'accepted') return storedAcceptance(entry, this.options.clock);
    let postMessageId = destination.postMessageId;
    let requests = 0;
    const stored = () => ({
      phase: 'sync' as const,
      userId: destination.device.userId,
      deviceId: destination.device.deviceId,
      postMessageId,
    });
    const gate = (copy: string | undefined) => async () => {
      await check();
      postMessageId = copy ?? destination.postMessageId;
      entry =
        (await this.options.recordProgress?.(key, { ...stored(), request: true })) ?? entry;
      requests += 1;
    };
    let acceptance: RelayPostAcceptance | undefined;
    try {
      acceptance = await post(gate);
    } catch (error) {
      if (requests === 0) throw error;
      const answer = this.classifyAnswer(entry, error);
      if (answer === 'accepted') {
        const conflict = conflictAcceptance(postMessageId, this.options.clock());
        await this.options.recordProgress?.(key, { ...stored(), ...acceptedAnswer(conflict) });
        return conflict;
      }
      await this.options.recordProgress?.(key, {
        ...stored(),
        ...storedAnswer(answer, error, this.options),
      });
      throw error;
    }
    await this.options.recordProgress?.(
      key,
      acceptance
        ? { ...stored(), ...acceptedAnswer(acceptance) }
        : {
            ...stored(),
            answer: 'refused',
            refusalCode: 'device-rejection',
            repairSpent: true,
          }
    );
    return acceptance;
  }

  /**
   * The end of the send at a classification point, or undefined when the
   * send stays open. `progress` is the stored progress of the intent, read
   * under the intent lock. The send ends when `isDue` holds for its open
   * destinations: those with no acceptance in the call or in the stored
   * progress (contract §3.4). The end is the one that `classify` gives.
   */
  end(
    destinations: readonly SendDestination[],
    progress: Readonly<Record<string, StoredDestinationProgress>> = {}
  ): SendEnd | undefined {
    const open = this.openDestinations(destinations, progress);
    if (open.length === 0) return undefined;
    if (!this.isDue(open, progress)) return undefined;
    return this.classify(destinations, progress);
  }

  /**
   * The class of the send if it ended now (contract §3.4), or undefined when
   * the call or the stored progress accepted each destination. Unlike `end`,
   * it does not check that the send is due: the caller decides that the
   * send ends. The error of a failed end follows the rule of
   * `failedEndError`. Its thrown refusal is the first UPGRADE_REQUIRED or
   * DEVICE_REVOKED answer of this call, else the first refusal of this
   * call, and its entries are the progress that the end stores.
   */
  classify(
    destinations: readonly SendDestination[],
    progress: Readonly<Record<string, StoredDestinationProgress>> = {}
  ): SendEnd | undefined {
    const entryOf = (destination: SendDestination) => progress[destinationKey(destination)];
    if (this.openDestinations(destinations, progress).length === 0) return undefined;

    // A device with more than one destination, such as a pre-message and a
    // group message, is unknown when one of them is unknown, refused when one
    // of them is refused, and accepted only when each of them is accepted.
    const devices = new Map<string, { device: SendDevice; state: DestinationState }>();
    const destinationProgress: Record<string, StoredDestinationProgress> = {};
    for (const destination of destinations) {
      const { device, postMessageId } = destination;
      const evidence = this.destinations.get(destinationKey(destination));
      const entry = entryOf(destination);
      const state = this.classifyDestination(evidence, entry);
      const folded = devices.get(deviceKey(device));
      if (!folded) devices.set(deviceKey(device), { device: sendDevice(device), state });
      else if (DESTINATION_STATE_RANK[state] > DESTINATION_STATE_RANK[folded.state]) {
        folded.state = state;
      }
      const acceptance = evidence?.acceptance;
      const receipt = acceptance && !isConflictAcceptance(acceptance) ? acceptance : undefined;
      destinationProgress[outgoingDestinationProgressKey(postMessageId, device)] = {
        ...entry,
        phase: 'recipient',
        userId: device.userId,
        deviceId: device.deviceId,
        postMessageId,
        state,
        requests: Math.max(entry?.requests ?? 0, evidence?.requests ?? 0),
        ...((entry?.uncertain ||
          evidence?.uncertainRepeat ||
          evidence?.answers.includes('uncertain')) && {
          uncertain: true as const,
        }),
        ...(receipt && { messageId: receipt.messageId }),
        ...(receipt?.expiresAt !== undefined && { expiresAt: receipt.expiresAt }),
        ...(receipt?.duplicate === true && { duplicate: true as const }),
      };
    }
    const devicesIn = (state: DestinationState) =>
      [...devices.values()].filter((folded) => folded.state === state).map(({ device }) => device);
    const accepted = devicesIn('accepted');
    const unknown = devicesIn('unknown');
    const refused = devicesIn('refused');
    const details = {
      clientMessageId: this.options.clientMessageId,
      deadlineAt: this.options.deadlineAt,
      acceptedDevices: accepted,
      refusedDevices: refused,
    };
    if (unknown.length > 0) {
      return {
        outcome: 'acceptance-unknown',
        destinationProgress,
        error: new SendAcceptanceUnknownError({
          ...details,
          unknownDevices: unknown,
          ...(this.hasError && { cause: this.lastError }),
        }),
      };
    }
    return {
      outcome: 'failed',
      destinationProgress,
      error: failedEndError(
        destinations.map(
          ({ device, postMessageId }) =>
            destinationProgress[outgoingDestinationProgressKey(postMessageId, device)]
        ),
        details,
        this.terminalAnswer ?? (this.hasRefusal ? (this.firstRefusal as Error) : undefined)
      ),
    };
  }

  /** The destinations with no acceptance in the call or in `progress`. */
  private openDestinations(
    destinations: readonly SendDestination[],
    progress: Readonly<Record<string, StoredDestinationProgress>>
  ): SendDestination[] {
    return destinations.filter(
      (destination) =>
        this.destinations.get(destinationKey(destination))?.acceptance === undefined &&
        progress[destinationKey(destination)]?.state !== 'accepted'
    );
  }

  /** Keep the first UPGRADE_REQUIRED or DEVICE_REVOKED answer of the call. */
  private keepTerminalAnswer(error: unknown): void {
    if (this.terminalAnswer !== undefined) return;
    if (!(error instanceof Error)) return;
    const code = errorCode(error);
    if (typeof code === 'string' && OWN_RETRY_CODES.has(code)) this.terminalAnswer = error;
  }

  /**
   * True when the send ends now: at or after the deadline, after an
   * UPGRADE_REQUIRED or DEVICE_REVOKED answer in this call, or when each
   * open destination got OPERATION_EXPIRED as the last answer in this call
   * or has a stored refusal that no recovery in a call can change.
   */
  private isDue(
    open: readonly SendDestination[],
    progress: Readonly<Record<string, StoredDestinationProgress>>
  ): boolean {
    if (this.options.clock() >= this.options.deadlineAt) return true;
    if (this.terminalAnswer !== undefined) return true;
    return open.every(
      (destination) =>
        this.destinations.get(destinationKey(destination))?.expired === true ||
        provenRefused(progress[destinationKey(destination)])
    );
  }

  private evidenceAt(key: string): DestinationEvidence {
    let evidence = this.destinations.get(key);
    if (!evidence) {
      evidence = { requests: 0, answers: [], expired: false, uncertainRepeat: false };
      this.destinations.set(key, evidence);
    }
    return evidence;
  }

  private accept(evidence: DestinationEvidence, acceptance: RelayPostAcceptance): void {
    evidence.answers.push('accepted');
    evidence.expired = false;
    evidence.acceptance ??= acceptance;
  }

  /**
   * The class of the answer to one post that started a request (contract
   * §3.5). An answer that followed a repeat after an uncertain answer is
   * uncertain, because the first request can have stored the post. A
   * RETRY_CONFLICT is an earlier acceptance only when the current entry of
   * the destination has no repair mark: then the Relay holds the same bytes
   * under the message ID. A version 2 DELIVERY_ALREADY_ACCEPTED says that
   * the Relay holds an accepted post under the message ID, and it follows
   * the same rule. An intent that did not write progress from its start can
   * have had a repair that left no mark, so its answer stays uncertain.
   */
  private classifyAnswer(
    entry: StoredDestinationProgress | undefined,
    error: unknown
  ): AnswerClass {
    if (followedRepeatedRequest(error)) return 'uncertain';
    if (relayHoldsMessageId(error)) {
      return this.options.progressFromStart && !entry?.repaired
        ? 'accepted'
        : 'uncertain';
    }
    if (error === null || typeof error !== 'object') return 'uncertain';
    if (
      relayOperationRefusal(error) === 'OPERATION_EXPIRED' ||
      deviceSetRefusal(error) !== undefined ||
      relayDeviceRefusal(error) !== undefined ||
      error instanceof SealedSenderAuthError ||
      this.options.refusesDevice?.(error) === true
    ) {
      return 'refused';
    }
    const code = errorCode(error);
    if (typeof code === 'string' && REFUSAL_CODES.has(code)) return 'refused';
    // The Relay refused the request for this SDK or this device, so it did
    // not store the post.
    if (typeof code === 'string' && OWN_RETRY_CODES.has(code)) return 'refused';
    const { status } = error as { status?: unknown };
    if (status === 423 || status === 429) return 'pending';
    if (typeof code === 'string' && PENDING_CODES.has(code)) return 'pending';
    return 'uncertain';
  }

  /**
   * The class of a destination at the end (contract §3.4), from its stored
   * entry and the acceptance of this call. An `accepted` entry is accepted.
   * A destination is refused, so never accepted, when its stored entry is
   * `refused` or `pending`, or has no request, with no uncertain request.
   * The Relay gives a pending answer before it stores the post, so that
   * answer also proves that the request was not accepted. A destination
   * with no entry had no request when the intent wrote progress from its
   * start. Each other destination is unknown: a request with no answer, an
   * uncertain answer, and every entry with the uncertain flag.
   */
  private classifyDestination(
    evidence: DestinationEvidence | undefined,
    entry: StoredDestinationProgress | undefined
  ): DestinationState {
    if (evidence?.acceptance || entry?.state === 'accepted') return 'accepted';
    if (!entry) return this.options.progressFromStart ? 'refused' : 'unknown';
    if (entry.uncertain) return 'unknown';
    return entry.state === 'refused' || entry.state === 'pending' || entry.requests === 0 ? 'refused' : 'unknown';
  }
}

/**
 * The error of a destination that the receipt of a shared post refused, or
 * of the stored refusal that `failedEndError` reads. It carries the code of
 * the refusal, as a thrown refusal does. A NOT_FOUND or STALE_DEVICE refusal
 * also carries the refusal mark of its device.
 */
function receiptRefusal(device: SendDevice, code: string): Error {
  const error = Object.assign(
    new Error(`The Relay refused a destination of the send with ${code}`),
    { code }
  );
  if (code === 'NOT_FOUND' || code === 'STALE_DEVICE') {
    markRelayDeviceRefusal(error, { code, userId: device.userId, deviceId: device.deviceId });
  }
  return error;
}

/** The stored answer of a refused, pending or uncertain answer to a post. */
function storedAnswer(
  answer: Exclude<AnswerClass, 'accepted'>,
  error: unknown,
  options: {
    readonly sealedSenderRequired?: boolean;
    readonly refusesDevice?: (error: unknown) => boolean;
  }
): Pick<StoredAnswer, 'answer' | 'refusalCode' | 'repairSpent'> {
  if (answer === 'pending') return { answer: 'pending' };
  if (answer === 'uncertain') return { answer: 'unknown' };
  const sealedAuth = error instanceof SealedSenderAuthError;
  return {
    answer: 'refused',
    refusalCode: refusalCode(error, options.refusesDevice),
    // A required sealed post has no identified fallback to recover it.
    ...(sealedAuth && options.sealedSenderRequired && { repairSpent: true as const }),
  };
}

/** The Relay code of a refusal, or the kind of a refusal with no Relay code. */
function refusalCode(
  error: unknown,
  refusesDevice: ((error: unknown) => boolean) | undefined
): string | undefined {
  const operation = relayOperationRefusal(error);
  if (operation !== undefined) return operation;
  if (deviceSetRefusal(error) !== undefined) return 'device-set';
  const device = relayDeviceRefusal(error);
  if (device !== undefined) return device.code;
  if (error instanceof SealedSenderAuthError) return 'sealed-sender-auth';
  const code = error !== null && typeof error === 'object' ? errorCode(error) : undefined;
  if (typeof code === 'string' && (REFUSAL_CODES.has(code) || OWN_RETRY_CODES.has(code))) {
    return code;
  }
  if (refusesDevice?.(error) === true) return 'device-rejection';
  return undefined;
}

/** The destinations of the device messages of a direct intent. */
export function sendDestinations(
  clientMessageId: string,
  messages: readonly {
    readonly recipientUserId: string;
    readonly recipientDeviceId: number;
    readonly clientMessageId?: string;
  }[]
): SendDestination[] {
  return messages.map((message) => ({
    device: { userId: message.recipientUserId, deviceId: message.recipientDeviceId },
    postMessageId: message.clientMessageId ?? clientMessageId,
  }));
}

/**
 * The error of a replay of an ended send. The replay reads the stored end
 * and starts no request.
 *
 * An `acceptance-unknown` end gives `SendAcceptanceUnknownError`. A `failed`
 * end gives the error of `failedEndError` with no thrown refusal, from the
 * stored entries in the order of the destinations.
 */
export function storedSendEndError(intent: StoredOutgoingMessageIntent): Error {
  // The end stored the class of each destination of the intent. A device
  // with more than one destination takes the class of highest rank, as at
  // the end.
  const devices = new Map<string, { device: SendDevice; state: DestinationState }>();
  const destinations = sendDestinations(intent.clientMessageId, [
    ...(intent.preMessages ?? []),
    ...intent.deviceMessages,
  ]);
  const entries: StoredDestinationProgress[] = [];
  for (const destination of destinations) {
    const entry = intent.destinationProgress?.[destinationKey(destination)];
    if (entry?.phase !== 'recipient') continue;
    entries.push(entry);
    const state = storedDestinationState(entry.state);
    const folded = devices.get(deviceKey(entry));
    if (!folded) devices.set(deviceKey(entry), { device: sendDevice(entry), state });
    else if (DESTINATION_STATE_RANK[state] > DESTINATION_STATE_RANK[folded.state]) {
      folded.state = state;
    }
  }
  const devicesIn = (state: DestinationState): SendDevice[] =>
    [...devices.values()].filter((folded) => folded.state === state).map(({ device }) => device);
  const deadlineAt = outgoingMessageDeadlineAt(intent);
  const details = {
    clientMessageId: intent.clientMessageId,
    deadlineAt,
    acceptedDevices: devicesIn('accepted'),
    refusedDevices: devicesIn('refused'),
  };
  if (intent.outcome === 'acceptance-unknown') {
    return new SendAcceptanceUnknownError({ ...details, unknownDevices: devicesIn('unknown') });
  }
  return failedEndError(entries, details);
}

/**
 * The error of a failed end of a send. The end in the call
 * (`SendCallEvidence.end`) and each replay of the stored end
 * (`storedSendEndError`) use this one rule:
 *
 * 1. When a post of the call that ended the send threw a refusal, or the
 *    receipt of a shared body refused a destination, the first such refusal
 *    of the call is the error (`thrown`), even when a later post of the same
 *    call accepted that device. A replay has no thrown refusal.
 * 2. Otherwise the first entry in the order of the destinations that is
 *    `refused` and has a stored `refusalCode` gives a generic refusal
 *    `Error` with that code (`receiptRefusal`). A NOT_FOUND or STALE_DEVICE
 *    code also gives the refusal mark of its device. The store clears the
 *    code when a later request or answer supersedes the refusal, and a code
 *    on an entry in another state does not count.
 * 3. With no such entry, the error is `SendNeverAcceptedByRelayError`.
 *
 * The end stores the code of each refusal on the entry of its destination,
 * so a replay gives the code that the call threw only when the thrown
 * refusal is the first coded refusal in the order of the destinations. When
 * the thrown refusal and that first stored refusal are different
 * destinations, the call gives the thrown refusal and a replay gives the
 * first stored refusal. A thrown refusal with no Relay code stores its kind
 * (`device-set`, `sealed-sender-auth` or `device-rejection`), and a replay
 * gives that kind as the `code` of a generic refusal `Error`. Each error has
 * the fields of the end, and its `retryable` is false.
 */
function failedEndError(
  entries: readonly (StoredDestinationProgress | undefined)[],
  details: {
    readonly clientMessageId: string;
    readonly deadlineAt: number;
    readonly acceptedDevices: readonly SendDevice[];
    readonly refusedDevices: readonly SendDevice[];
  },
  thrown?: Error
): Error {
  if (thrown !== undefined) return attachTerminalFailure(thrown, details);
  let firstRefusal: { device: SendDevice; code: string } | undefined;
  for (const entry of entries) {
    if (entry === undefined || entry.state !== 'refused') continue;
    if (entry.refusalCode !== undefined) {
      firstRefusal ??= { device: sendDevice(entry), code: entry.refusalCode };
    }
  }
  return firstRefusal
    ? attachTerminalFailure(receiptRefusal(firstRefusal.device, firstRefusal.code), details)
    : new SendNeverAcceptedByRelayError(details);
}

/**
 * The class of a stored entry of an ended send. The end writes `accepted`,
 * `refused` or `unknown` on each destination. The open states read as
 * `classifyDestination` reads them: a `pending` entry proves that the Relay
 * did not accept it, and a `posted` entry has no answer.
 */
function storedDestinationState(state: StoredDestinationProgress['state']): DestinationState {
  if (state === 'accepted') return 'accepted';
  return state === 'refused' || state === 'pending' ? 'refused' : 'unknown';
}

function defineSendField(error: object, name: string, value: unknown): void {
  Object.defineProperty(error, name, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

/** Keep the Relay's own `retryable` hint in `relayRetryable`. */
function keepRelayRetryable(error: object): void {
  const { retryable, relayRetryable } = error as {
    retryable?: unknown;
    relayRetryable?: unknown;
  };
  if (relayRetryable === undefined && typeof retryable === 'boolean') {
    defineSendField(error, 'relayRetryable', retryable);
  }
}

/**
 * Mark an error of a send that failed before its posting deadline. The send
 * stays open, so a replay with the same `clientMessageId` before `deadlineAt`
 * can post it: `retryable` is true. The Relay's own hint moves to
 * `relayRetryable`. An error that keeps its own retry rule, such as
 * UPGRADE_REQUIRED or DEVICE_REVOKED, does not change.
 */
export function attachSendDeadline<T>(error: T, deadlineAt: number): T {
  if (error === null || typeof error !== 'object') return error;
  if (
    error instanceof PostingDeadlineReachedError ||
    error instanceof SendAcceptanceUnknownError ||
    error instanceof SendNeverAcceptedByRelayError
  ) {
    return error;
  }
  const code = (error as { code?: unknown }).code;
  if (typeof code === 'string' && OWN_RETRY_CODES.has(code)) return error;
  keepRelayRetryable(error);
  defineSendField(error, 'deadlineAt', deadlineAt);
  defineSendField(error, 'retryable', true);
  return error;
}

/**
 * Mark the raw refusal of a send that ended at its posting deadline with no
 * device of unknown acceptance. The error keeps its class, and `retryable`
 * is false.
 */
export function attachTerminalFailure<T extends Error>(
  error: T,
  details: {
    readonly acceptedDevices: readonly SendDevice[];
    readonly refusedDevices: readonly SendDevice[];
    readonly deadlineAt: number;
  }
): T {
  keepRelayRetryable(error);
  defineSendField(error, 'acceptedDevices', details.acceptedDevices);
  defineSendField(error, 'refusedDevices', details.refusedDevices);
  defineSendField(error, 'deadlineAt', details.deadlineAt);
  defineSendField(error, 'retryable', false);
  return error;
}

/** The key of the end report mark of a send call. No package subpath exports it. */
export const SEND_END_REPORT: unique symbol = Symbol('sendEndReport');

/**
 * The options of a send, with the end report of the call. The intent lock
 * of the send registers the report, so the end write or the completion write
 * of the intent records the end in it.
 */
export interface SendEndReportMark {
  readonly [SEND_END_REPORT]?: OutgoingIntentEndReport;
}

/**
 * The `onSendOutcome` event of an intent that ended or completed. A
 * completed intent gives `completed` with its result, and an ended intent
 * gives its outcome with the error that a replay of it throws.
 */
export function sendOutcomeEvent(intent: StoredOutgoingMessageIntent): SendOutcomeEvent {
  const deadlineAt = outgoingMessageDeadlineAt(intent);
  const result = outgoingMessageIntentResult(intent);
  if (result) {
    return {
      clientMessageId: intent.clientMessageId,
      outcome: 'completed',
      deadlineAt,
      result: { ...result, clientTimestamp: intent.clientTimestamp },
    };
  }
  if (intent.outcome === undefined) {
    throw new Error('An open outgoing message intent has no send outcome');
  }
  return {
    clientMessageId: intent.clientMessageId,
    outcome: intent.outcome,
    deadlineAt,
    error: storedSendEndError(intent),
  };
}

/**
 * A manual resend of an intent, read as an intent of its own: its device
 * messages, its progress, its end and its posting deadline. It has no
 * sync phase. `storedSendEndError` and `sendOutcomeEvent` read it as they
 * read an intent.
 */
export function manualResendIntent(
  intent: StoredOutgoingMessageIntent,
  resend: StoredManualResend
): StoredOutgoingMessageIntent {
  const view: StoredOutgoingMessageIntent = {
    ...intent,
    createdAt: resend.createdAt,
    deadlineAt: resend.deadlineAt,
    deviceMessages: resend.messages.map(({ message }) => message),
    syncMessages: [],
    progressFromStart: true,
  };
  delete view.manualResends;
  delete view.preMessages;
  delete view.syncPending;
  delete view.outcomeReportPending;
  delete view.destinationProgress;
  delete view.result;
  delete view.outcome;
  if (resend.destinationProgress) view.destinationProgress = resend.destinationProgress;
  if (resend.result) view.result = resend.result;
  if (resend.outcome !== undefined) view.outcome = resend.outcome;
  return view;
}

/**
 * The end of a manual resend that a call wrote: the intent and the ended
 * resend. Only the call that wrote the end fills it, and its caller reports
 * the end.
 */
export interface ManualResendEndReport {
  ended?: { intent: StoredOutgoingMessageIntent; resend: StoredManualResend };
}

/**
 * The `onSendOutcome` event of a manual resend that ended. It carries the
 * `clientMessageId` of the intent, the posting deadline of the resend, and
 * `manualResend`, the number of the resend from 1.
 */
export function manualResendOutcomeEvent(
  intent: StoredOutgoingMessageIntent,
  resend: StoredManualResend
): SendOutcomeEvent {
  const number = Number(resend.manualMessageId.slice(resend.manualMessageId.lastIndexOf(':') + 1));
  return { ...sendOutcomeEvent(manualResendIntent(intent, resend)), manualResend: number };
}
