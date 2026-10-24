import { parseUrl, type ParsedUrl } from '../internal/platform';
import type { DefaultSignalProtocolClient } from './client';
import type { IncomingEnvelope } from './types';
import type { RelayDeliveryReceipt } from './relay-receipt-intake';

const PUSH_TOKEN_MAXIMUM_LENGTH = 4_096;
const PUSH_ENDPOINT_MAXIMUM_LENGTH = 2_048;

export type HostedRelayPushProfile =
  'background-only' | 'visible-alert' | 'nse-visible' | 'nse-filtering';

export type HostedRelayPushPlatform = 'android' | 'ios' | 'web';

/** Native or Expo provider token registered for this authenticated device. */
export type HostedRelayTokenPushRegistration =
  | {
      readonly platform: 'ios';
      readonly profile: HostedRelayPushProfile;
      readonly provider: 'apns' | 'expo';
      readonly token: string;
    }
  | {
      readonly platform: 'android';
      readonly profile: 'background-only' | 'visible-alert';
      readonly provider: 'expo' | 'fcm';
      readonly token: string;
    };

/** Browser Push API subscription registered for this authenticated device. */
export interface HostedRelayWebPushRegistration {
  readonly endpoint: string;
  readonly keys: {
    readonly auth: string;
    readonly p256dh: string;
  };
  readonly platform: 'web';
  readonly profile: 'background-only' | 'visible-alert';
  readonly provider: 'web-push';
}

/** Supported best-effort wake and generic-alert registration shapes. */
export type HostedRelayPushRegistration =
  HostedRelayTokenPushRegistration | HostedRelayWebPushRegistration;

/**
 * @internal One mailbox pull: the retained messages, then the retained Relay
 * delivery receipts.
 */
export interface HostedMailboxPage {
  readonly messages: readonly IncomingEnvelope[];
  readonly receipts: readonly RelayDeliveryReceipt[];
  /**
   * The opaque Relay cursor after the last message of a page that is not
   * empty. A pull with it starts after that message.
   */
  readonly nextCursor?: string;
  /**
   * True when the Relay keeps a message after the page, or a Relay receipt
   * that the page does not carry. Absent when the Relay does not report it.
   */
  readonly retainedWork?: boolean;
  /**
   * Each retained message that the page read and the Relay could not serve,
   * with the reason, such as `body-missing` or `body-integrity`. The page
   * omits it from `messages`, and it stays in the mailbox. Absent when the
   * Relay does not report it.
   */
  readonly failedEntries?: readonly {
    readonly messageId: string;
    readonly reason: string;
  }[];
}

/** @internal SDK-owned transport for one authenticated hosted client. */
export interface HostedRelayPushRuntime {
  acknowledgeMailbox(
    messageIds: readonly string[],
    receiptIds: readonly string[],
  ): Promise<void>;
  /** Pulls the page after `cursor`, or the head page without one. */
  pullMailbox(cursor?: string): Promise<HostedMailboxPage>;
  /** Hands one Relay receipt off. A rejection leaves it unacknowledged. */
  receiveRelayReceipt(receipt: RelayDeliveryReceipt): Promise<void>;
  registerPush(registration: HostedRelayPushRegistration): Promise<void>;
  removePush(): Promise<void>;
}

export interface HostedRelayWakeClient {
  receiveIncomingEnvelopes(
    envelopes: IncomingEnvelope[],
  ): ReturnType<DefaultSignalProtocolClient['receiveIncomingEnvelopes']>;
  processPendingReceives(
    options?: Parameters<DefaultSignalProtocolClient['processPendingReceives']>[0],
  ): ReturnType<DefaultSignalProtocolClient['processPendingReceives']>;
}

export interface HostedRelayWakeOptions {
  readonly client: HostedRelayWakeClient;
  /**
   * The time in milliseconds that the stored receives may take after the
   * acknowledgment. The pass stops between records at the deadline, and
   * the next pass continues. No limit by default.
   */
  readonly deadlineMs?: number;
}

export interface HostedRelayWakeResult {
  readonly acknowledgedMessageIds: readonly string[];
  readonly failedMessageIds: readonly string[];
  readonly pulled: number;
  /**
   * True when the Relay keeps work after the page of this pass: a message
   * after the page, or a Relay receipt that the page does not carry. Run
   * another pass to get it. False when the page carried all retained work.
   * Absent when the Relay does not report it. Then the retained work is
   * unknown, so do not read an absent value as false.
   */
  readonly retainedWork?: boolean;
}

const hostedRuntimes = new WeakMap<object, HostedRelayPushRuntime>();
/**
 * The pull cursor of each runtime. It lives in memory only, so a new runtime
 * pulls from the head of the mailbox.
 */
const pullCursors = new WeakMap<HostedRelayPushRuntime, string>();

/** @internal Bind the SDK-owned transport to the client that uses it. */
export function bindHostedRelayPushRuntime(
  client: HostedRelayWakeClient,
  runtime: HostedRelayPushRuntime,
): void {
  hostedRuntimes.set(client, runtime);
}

function hostedRuntime(client: HostedRelayWakeClient): HostedRelayPushRuntime {
  const runtime = hostedRuntimes.get(client);
  if (runtime === undefined) {
    throw new Error('The client is not connected to the OpenE2EE Signal Protocol Relay');
  }
  return runtime;
}

function assertToken(token: string): string {
  if (!token || token.length > PUSH_TOKEN_MAXIMUM_LENGTH) {
    throw new Error('Signal Protocol Relay push token is invalid');
  }
  return token;
}

function validatedRegistration(
  registration: HostedRelayPushRegistration,
): HostedRelayPushRegistration {
  if (
    registration.profile !== 'background-only' &&
    registration.profile !== 'visible-alert' &&
    registration.profile !== 'nse-visible' &&
    registration.profile !== 'nse-filtering'
  ) {
    throw new Error('Signal Protocol Relay push profile is invalid');
  }
  if (registration.profile === 'nse-filtering') {
    throw new Error(
      'Signal Protocol Relay notification filtering is unavailable until signed physical-device verification passes',
    );
  }
  if (registration.provider !== 'web-push') {
    if (
      (registration.provider === 'apns' && registration.platform !== 'ios') ||
      (registration.provider === 'fcm' &&
        registration.platform !== 'android') ||
      (registration.provider === 'expo' &&
        registration.platform !== 'ios' &&
        registration.platform !== 'android') ||
      (registration.platform !== 'ios' &&
        registration.profile !== 'background-only' &&
        registration.profile !== 'visible-alert')
    ) {
      throw new Error(
        'Signal Protocol Relay push profile is not supported by this platform',
      );
    }
    return {
      ...registration,
      token: assertToken(registration.token),
    };
  }
  if (
    registration.platform !== 'web' ||
    (registration.profile !== 'background-only' &&
      registration.profile !== 'visible-alert')
  ) {
    throw new Error(
      'Signal Protocol Relay push profile is not supported by this platform',
    );
  }
  let endpoint: ParsedUrl;
  try {
    endpoint = parseUrl(registration.endpoint);
  } catch {
    throw new Error('Signal Protocol Relay Web Push endpoint is invalid');
  }
  if (
    endpoint.protocol !== 'https:' ||
    registration.endpoint.length > PUSH_ENDPOINT_MAXIMUM_LENGTH
  ) {
    throw new Error('Signal Protocol Relay Web Push endpoint is invalid');
  }
  return {
    endpoint: registration.endpoint,
    keys: {
      auth: assertToken(registration.keys.auth),
      p256dh: assertToken(registration.keys.p256dh),
    },
    platform: registration.platform,
    profile: registration.profile,
    provider: 'web-push',
  };
}

/** Register a best-effort wake profile for this hosted client's device. */
export async function registerHostedRelayPush(options: {
  readonly client: HostedRelayWakeClient;
  readonly registration: HostedRelayPushRegistration;
}): Promise<void> {
  const registration = validatedRegistration(options.registration);
  await hostedRuntime(options.client).registerPush(registration);
}

/** Remove the wake destination for this hosted client's device. */
export async function removeHostedRelayPush(options: {
  readonly client: HostedRelayWakeClient;
}): Promise<void> {
  await hostedRuntime(options.client).removePush();
}

/**
 * Commit the pulled envelopes. The SDK client holds each committed record
 * until `release` runs, so a queue pass gives no content to the application
 * before the acknowledgment settles. A client without that path receives as
 * its `receiveIncomingEnvelopes` does.
 */
async function commitHeld(
  client: HostedRelayWakeClient,
  envelopes: IncomingEnvelope[],
): Promise<{
  readonly processedMessageIds: readonly string[];
  readonly failedMessageIds: readonly string[];
  readonly release: () => void;
}> {
  const held = client as Partial<
    Pick<DefaultSignalProtocolClient, 'commitIncomingEnvelopes'>
  >;
  if (typeof held.commitIncomingEnvelopes === 'function') {
    return held.commitIncomingEnvelopes(envelopes);
  }
  return {
    ...(await client.receiveIncomingEnvelopes(envelopes)),
    release: () => {},
  };
}

/**
 * Authenticate, pull the durable mailbox, commit each envelope to the local
 * store, hand off each Relay receipt after the envelopes, acknowledge the
 * committed envelopes and the receipts, then process the stored receives
 * until `deadlineMs`. Register onMessageDecrypted to persist application
 * content before calling this function. Push is not required.
 *
 * Group content that waits for its group state is committed and
 * acknowledged, and waits in the local store. Three kinds of envelope stay
 * unacknowledged: an envelope that the receive bounds refuse, a decrypt
 * failure that no retry request owns, and a retry request that waits for
 * the next group fetch. A full page of such envelopes does not stall the
 * pull: the next wake pulls the page after it with the Relay cursor. A
 * wake whose page past the cursor is empty clears the cursor, so the wake
 * after it pulls from the head and offers those envelopes again. A failed
 * wake also clears the cursor.
 *
 * One call makes one pull. The result copies `retainedWork` from the Relay
 * page. When it is true, the caller runs the next pass.
 */
export async function pullHostedRelayAfterWake(
  options: HostedRelayWakeOptions,
): Promise<HostedRelayWakeResult> {
  const runtime = hostedRuntime(options.client);
  // A wake that fails anywhere leaves the cursor cleared, so the next wake
  // pulls from the head. This includes a Relay refusal of the cursor.
  const cursor = pullCursors.get(runtime);
  pullCursors.delete(runtime);
  const {
    messages: envelopes,
    receipts,
    nextCursor,
    retainedWork,
    failedEntries,
  } = await runtime.pullMailbox(cursor);
  const inputIds = new Set(envelopes.map((envelope) => envelope.id));
  if (
    inputIds.size !== envelopes.length ||
    envelopes.some((envelope) => !envelope.id)
  ) {
    throw new Error(
      'Signal Protocol Relay mailbox returned invalid envelope identities',
    );
  }
  const results = await commitHeld(options.client, [...envelopes]);
  const acknowledgedMessageIds = [...results.processedMessageIds];
  const failedMessageIds = [...results.failedMessageIds];
  try {
    const resultIds = [...acknowledgedMessageIds, ...failedMessageIds];
    if (
      resultIds.length !== inputIds.size ||
      new Set(resultIds).size !== resultIds.length ||
      resultIds.some((id) => !inputIds.has(id))
    ) {
      throw new Error(
        'Signal Protocol Relay mailbox processing returned an invalid result',
      );
    }
    // A receipt whose hand-off fails stays in the mailbox for a replay.
    const receiptIds: string[] = [];
    for (const receipt of receipts) {
      try {
        await runtime.receiveRelayReceipt(receipt);
        receiptIds.push(receipt.receiptId);
      } catch {
        // The Relay replays it on the next pull or connect.
      }
    }
    if (acknowledgedMessageIds.length > 0 || receiptIds.length > 0) {
      await runtime.acknowledgeMailbox(acknowledgedMessageIds, receiptIds);
    }
  } finally {
    // The acknowledgment settled, so the queue may give the content to the
    // application. The content is committed after a failed acknowledgment
    // too, and the redelivery finds its record. The release wakes the queue.
    results.release();
  }
  // A page that holds an envelope or a failed entry keeps its `nextCursor`,
  // so the next wake pulls past that page. A page that holds neither keeps
  // the cursor cleared, so the next wake pulls from the head. A Relay page
  // without a `nextCursor` keeps the cursor cleared too. That branch is
  // removed in the first release after every Relay lane serves the cursor.
  if (
    (envelopes.length > 0 ||
      (failedEntries !== undefined && failedEntries.length > 0)) &&
    nextCursor !== undefined
  ) {
    pullCursors.set(runtime, nextCursor);
  }
  // The committed receives are durable, so they run after the acknowledgment
  // settles.
  await options.client.processPendingReceives(
    options.deadlineMs === undefined ? {} : { deadlineMs: options.deadlineMs },
  );
  return {
    acknowledgedMessageIds,
    failedMessageIds,
    pulled: envelopes.length,
    ...(retainedWork === undefined ? {} : { retainedWork }),
  };
}
