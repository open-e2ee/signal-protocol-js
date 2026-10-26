import type { SendLogDevice, SignalProtocolLocalStore } from '../types';
import { EncryptionError, EncryptionErrorCode } from '../types';
import { SealedSenderAuthError } from '../types/errors';
import { ContentHint } from '../types/messages';
import * as CryptoUtils from '../internal/crypto';
import type {
  GroupMemberDevice,
  SignalProtocolRelayServer,
  SealedSenderAuth,
} from '../remote/relay/types';
import {
  completeOutgoingMessageIntent,
  completeOutgoingSyncPhase,
  confirmOutgoingPreMessages,
  getOutgoingMessageIntent,
  outgoingMessageIntentResult,
  reconcileOutgoingGroupDeviceSet,
  reconcileOutgoingSyncMessages,
  repairOutgoingDeviceSet,
  replaceOutgoingGroupPreMessages,
  restartOutgoingDeviceSet,
  storeOutgoingMessageIntent,
  withOutgoingMessageIntentLock,
  type OutgoingGroupDeviceSetChange,
  type StoredGroupSharedMessage,
  type StoredOutgoingDeviceMessage,
  type StoredOutgoingMessageIntent,
} from '../local/store/reliability';
import { deviceSetRefusal, markDeviceSetRefusal } from '../remote/relay/device-set';
import {
  runDeviceSetPhase,
  type DeviceSetAccountRepair,
  type DeviceSetDevice,
  type DeviceSetPost,
  type DeviceSetUnresolved,
  type RelayProtocolRoute,
  syncPostReceipts,
  type DeclaredPostReceipt,
  type DeclaredSyncOutcome,
} from './device-set-reconciliation';
import { isStaleDeviceRefusal } from './relay-device-refusal';
import { newSendClientTimestamp, type SendTimestampOrigin } from './send-timestamp';
import type { SendOptions, SendResult } from './types';
import {
  groupDeviceKey,
  listedGroupDeviceChange,
  listedOwnDeviceChange,
  sharedBodyDevices,
} from './group-device-set';
import { aggregateRelayAcceptance, type RelayPostAcceptance } from './relay-acceptance';

/** The relay phases of a group send, in their order. */
export type GroupSendPhase = 'pre-message' | 'device' | 'sync';

/** The transport of one sender-key pre-message for one dispatch. */
export interface PreMessageTransport {
  /** The pre-message as the intent stores it. */
  message: StoredOutgoingDeviceMessage;
  /** The sealed-sender authorization of the post. Absent for an identified post. */
  auth?: SealedSenderAuth;
}

/**
 * The pre-message of one post, and whether the Relay accepted it, the send
 * dropped it, or the send dropped it because the device list no longer shows
 * the device.
 */
export interface PreMessagePostResult {
  message: StoredOutgoingDeviceMessage;
  outcome: 'accepted' | 'dropped' | 'removed';
  /**
   * True when a repair in the post refreshed the session of the device. The
   * stored device message of the send then names the earlier registration.
   */
  refreshed?: boolean;
}

/**
 * The work of a group send on a relay that compares device sets (§5.5 of the
 * device-set contract). The cipher gives it only for such a relay.
 */
export interface GroupDeviceSetContext {
  /**
   * Repair the refused devices of one account in the repair turn of the
   * account. `postedRegistration` gives the registration that the refused
   * post named for a device. `unposted` is true when the pass refused the
   * account here, because each of its stored devices lacked a bundle. Then a
   * device that still has no bundle leaves the send, and each other device
   * that the account record still holds is ready when it has a session or a
   * bundle. An account left with no device record gets one list read. Resolves to
   * the devices that leave the send, the refreshed or added devices that
   * have a current session, and the devices that got no session.
   */
  repairDevices(
    repair: DeviceSetAccountRepair,
    postedRegistration: (device: DeviceSetDevice) => number | undefined,
    unposted: boolean
  ): Promise<{
    removed: DeviceSetDevice[];
    ready: DeviceSetDevice[];
    bundleMissing: DeviceSetDevice[];
  }>;
  /** Read the own device list, for a receipt that sets `needsSync` when no own device has a record. */
  readOwnDevices(): Promise<GroupMemberDevice[]>;
  /**
   * Run the declared sync phase of a completed intent. A failure or an
   * unresolved end is logged and leaves the phase pending. The outcome keeps
   * the receipt of each accepted sync post, also when the phase fails.
   */
  runSyncPhase(
    intent: StoredOutgoingMessageIntent,
    rebuild: (device: DeviceSetDevice) => Promise<StoredOutgoingDeviceMessage | undefined>
  ): Promise<DeclaredSyncOutcome>;
  /** Record the terminal state of the recipient phase. */
  unresolve(clientMessageId: string, unresolved: DeviceSetUnresolved): Promise<void>;
  /** Wait before the next pass. Rejects when the send stops. */
  wait(milliseconds: number): Promise<void>;
  /** Log a failed post of a pass that does not decide the phase. */
  logFailure(device: DeviceSetDevice, error: unknown): void;
  /** Log a failure that does not fail the send. */
  warn(message: string, error: unknown): void;
  /**
   * Mark a result whose relay accepted a declared post without the
   * `deviceSetChecked` mark. The result does not change otherwise.
   */
  markUnchecked<T extends object>(
    result: T,
    receipts: readonly DeclaredPostReceipt[],
    clientMessageId: string
  ): T;
}

/**
 * The work of one group send.
 *
 * The phases of a send run in order, with a barrier between phases: the
 * pre-messages and their handoff rows, then the group message and its device
 * posts, then the sync copies. Inside a phase, the items run at the
 * same time. Each relay request takes a slot of the client's relay request
 * bound, and a phase holds no slot.
 */
export interface GroupOutboxContext {
  storage: SignalProtocolLocalStore;
  relay?: SignalProtocolRelayServer;
  senderUserId: string;
  senderDeviceId: number;
  deliveryMode: 'preferred' | 'required' | 'disabled';
  /**
   * Prepare the sender-key payload and a distribution pre-message for each
   * member device that needs the current key. The preparation gets the
   * member devices from readMembers, so the send reads each member's device
   * list once.
   */
  preparePayload(
    groupId: string,
    plaintextBytes: Uint8Array,
    options: SendOptions & { clientMessageId: string; timestamp: number },
    readMembers: () => Promise<GroupMemberDevice[]>
  ): Promise<{
    ciphertext: string;
    preMessages: StoredOutgoingDeviceMessage[];
    senderKeyDistributionId?: string;
  }>;
  /**
   * Record the handoff row of a pre-message that the Relay accepted. It runs
   * after the acceptance and before the intent confirms the pre-message.
   */
  recordSenderKeyHandoff(groupId: string, message: StoredOutgoingDeviceMessage): Promise<void>;
  /**
   * The content of a new send as the group gets it: with the group context
   * of a managed group in it, or unchanged. The payload, the sent-sync
   * transcript, and the send log entry all carry the result.
   */
  prepareContent(groupId: string, plaintextBytes: Uint8Array): Promise<Uint8Array>;
  resolveMemberDevices(
    groupId: string,
    options: SendOptions & { clientMessageId: string }
  ): Promise<GroupMemberDevice[]>;
  /** Seal the group message for every member with a known identity. The seal carries the hint. */
  prepareSharedMessage(
    groupId: string,
    members: GroupMemberDevice[],
    ciphertext: string,
    contentHint: ContentHint | undefined
  ): Promise<StoredOutgoingMessageIntent['groupSharedMessage']>;
  /** Prepare the group message for one device. A sealed copy carries the hint. */
  prepareDeviceMessage(
    member: GroupMemberDevice,
    groupId: string,
    ciphertext: string,
    timestamp: number,
    contentHint: ContentHint | undefined
  ): Promise<StoredOutgoingDeviceMessage>;
  /**
   * Read the device list of the sender's own account. Each listed own device
   * other than the sending device gets a session first, and each own device
   * record that the list does not show is removed. Resolves to the listed own
   * devices other than the sending device.
   */
  resolveOwnDevices(): Promise<GroupMemberDevice[]>;
  /** Prepare a sent-sync transcript of the content for each device in `ownDevices`. */
  prepareSyncMessages(
    groupId: string,
    plaintextBytes: Uint8Array,
    timestamp: number,
    clientMessageId: string,
    ownDevices: readonly GroupMemberDevice[]
  ): Promise<StoredOutgoingDeviceMessage[]>;
  resolveGroupAuthorization(
    groupId: string,
    recipientUserIds: string[]
  ): Promise<Extract<SealedSenderAuth, { type: 'groupSendToken' }> | null>;
  reportIdentifiedFallback(recipientUserId: string): Promise<void>;
  /**
   * Refresh the group's endorsements for the recipients of a dispatch before
   * its pre-messages resolve their transports. A membership change clears
   * the endorsements, and a pre-message to a member with no access key needs
   * one to stay sealed.
   */
  refreshPreMessageEndorsements(groupId: string, recipientUserIds: string[]): Promise<void>;
  /**
   * Resolve the transport of one stored pre-message before any post of the
   * dispatch. A pre-message with no sealed transport is sealed from its
   * stored ciphertext, with no new ratchet effect. When `required` is true
   * and the pre-message cannot be sealed, it throws SEALED_SENDER_REQUIRED.
   */
  authorizePreMessage(
    groupId: string,
    message: StoredOutgoingDeviceMessage,
    required: boolean
  ): Promise<PreMessageTransport>;
  /**
   * Post one pre-message. A rejected access key falls back to the group
   * endorsement. A preferred sealed post goes identified only after each
   * sealed authorization is rejected. A conclusive refusal of the device
   * refreshes its session once, and the repair replaces the stored
   * pre-message before it posts. A NOT_FOUND refusal of a device that the
   * device list no longer shows removes the device from the send, and the
   * result names no refresh. Resolves to the pre-message that the relay
   * accepted or that the send dropped, with the outcome.
   */
  postPreMessage(
    intent: StoredOutgoingMessageIntent,
    transport: PreMessageTransport,
    required: boolean
  ): Promise<PreMessagePostResult>;
  /**
   * The sender-key pre-messages that give the key of the send to the listed
   * devices of other members that have no handoff row. `listed` holds only
   * the devices that can get a pre-message. Three outbox steps call this
   * method. The device additions of a post and the device-list change of a
   * replay pass the complete list of each member that they name. The
   * shared-body leave passes only the leaving devices. The stale-device
   * repair does not call this method: it calls the cipher preparer directly
   * with only the refused device. Each device of such a subset has a
   * session, so the preparation reads no device list. Only the listed
   * devices count for the failure rule. The attempt fails for a member when
   * each listed device of the member that needs the key fails, and no other
   * listed device of the member has the key. A listed device has the key
   * when it has a handoff row, or when a pending pre-message of the send
   * targets it. A failed repair fails by the same rule.
   */
  prepareSenderKeyHandoffs(
    intent: StoredOutgoingMessageIntent,
    listed: readonly GroupMemberDevice[]
  ): Promise<StoredOutgoingDeviceMessage[]>;
  /** The registration of the current session of a device, or undefined with no session. */
  remoteRegistrationId(device: GroupMemberDevice): Promise<number | undefined>;
  /** True when the relay refused a one-device post because of its device. */
  isConclusiveDeviceRejection(error: unknown): boolean;
  /**
   * Repair the device of a refused group device post. Resolves to the
   * pre-messages that give the device the key of the send, and to a new
   * device message with the registration of the current session.
   */
  repairStaleDevice(
    intent: StoredOutgoingMessageIntent,
    message: StoredOutgoingDeviceMessage
  ): Promise<{
    preMessages: StoredOutgoingDeviceMessage[];
    deviceMessage: StoredOutgoingDeviceMessage;
  }>;
  /**
   * Post one sync copy to an own device. When the relay refuses the device as
   * stale, the session of the device is refreshed once, `rebuild` encrypts
   * the transcript again for the device, the new copy replaces the refused
   * copy in the intent, and the new copy is posted under a repair ID. When
   * the relay refuses the new copy as stale too, the session is archived,
   * the copy leaves the intent, and the post resolves, so the send completes
   * without it. When the refresh fails or the rebuild gives no copy, the
   * post throws, and the copy and the refreshed session stay.
   */
  postSyncMessage(
    intent: StoredOutgoingMessageIntent,
    message: StoredOutgoingDeviceMessage,
    rebuild: (deviceId: number) => Promise<StoredOutgoingDeviceMessage | undefined>
  ): Promise<void>;
  /**
   * Post one sealed device message. With `declaredDeviceIds`, the post
   * declares the devices of its account.
   */
  sendPreparedSealedDevice(
    intent: StoredOutgoingMessageIntent,
    message: StoredOutgoingDeviceMessage,
    auth: SealedSenderAuth,
    declaredDeviceIds?: readonly number[]
  ): Promise<RelayPostAcceptance>;
  /**
   * Run local work for each item at the same time. It rejects after every
   * item settles, with the error of the first failed item in input order. A
   * stop does not end it.
   */
  prepareEach<T, R>(items: readonly T[], task: (item: T) => Promise<R>): Promise<R[]>;
  /**
   * Run one relay phase: a task for each device message at the same time.
   * Every device is attempted. It rejects after every device settles, with
   * the error of the first failed device in input order.
   */
  sendPhase<R>(
    messages: readonly StoredOutgoingDeviceMessage[],
    task: (message: StoredOutgoingDeviceMessage) => Promise<R>,
    phase: GroupSendPhase
  ): Promise<R[]>;
  /** Send one relay request of a device post under a slot of the bound. */
  postToRelay<T>(send: () => Promise<T>, sealed: boolean): Promise<T>;
  /**
   * The declared work of the send. Present only for a relay that compares
   * device sets. Without it, the send keeps the per-send device list reads.
   */
  deviceSets?: GroupDeviceSetContext;
}

/**
 * The declaration of one device post of a declared group send. The post
 * declares `deviceIds` for its account, and `routes` records the route of
 * each declared acceptance.
 */
interface DevicePostDeclaration {
  deviceIds: readonly number[];
  routes: Map<RelayPostAcceptance, RelayProtocolRoute>;
}

/**
 * Post one stored device message. With a declaration, an identified post
 * and an access-key sealed post declare the devices of the account. A
 * group-token sealed post stays undeclared: the Relay takes a declaration on
 * the group route only when each declared device has a destination in the
 * post, and the post has one destination.
 */
async function sendStoredDeviceMessage(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent,
  message: StoredOutgoingDeviceMessage,
  forceIdentified = false,
  declaration?: DevicePostDeclaration
): Promise<RelayPostAcceptance> {
  const relay = context.relay;
  if (!relay) throw new Error('Relay is required for a stored group transmission');
  if (message.sealedSenderMessage && !relay.sendMultiRecipientUnidentified) {
    if (message.sealedSenderDeliveryMode === 'required') {
      throw new EncryptionError(
        'Required group sealed-sender transport is unavailable',
        EncryptionErrorCode.SEALED_SENDER_REQUIRED,
        { recipientUserId: message.recipientUserId }
      );
    }
    return sendStoredDeviceMessage(context, intent, message, true, declaration);
  }
  if (forceIdentified || !message.sealedSenderMessage) {
    const acceptance = await context.postToRelay(
      () =>
        relay.send({
          targetUserId: message.recipientUserId,
          targetDeviceId: message.recipientDeviceId,
          senderUserId: context.senderUserId,
          senderDeviceId: context.senderDeviceId,
          ciphertext: message.ciphertext,
          messageType: message.messageType,
          deliveryClass: 'user-visible',
          timestamp: message.timestamp,
          clientMessageId: intent.clientMessageId,
          ...(message.recipientRegistrationId !== undefined && {
            recipientRegistrationId: message.recipientRegistrationId,
          }),
          ...(intent.contentHint !== undefined && { contentHint: intent.contentHint }),
          ...(declaration && { declaredDeviceIds: declaration.deviceIds }),
        }),
      false
    );
    declaration?.routes.set(acceptance, 'identified-direct');
    return acceptance;
  }

  const auth: SealedSenderAuth | null =
    message.sealedSenderAuthorization === 'access_key' && message.sealedSenderAccessKey
      ? {
          type: 'accessKey',
          unidentifiedAccessKey: message.sealedSenderAccessKey,
        }
      : message.sealedSenderAuthorization === 'group_send_token'
        ? await context.resolveGroupAuthorization(intent.recipientId, [message.recipientUserId])
        : null;
  if (!auth) {
    if (message.sealedSenderDeliveryMode === 'required') {
      throw new Error('Required group sealed-sender authorization is unavailable');
    }
    return sendStoredDeviceMessage(context, intent, message, true, declaration);
  }
  if (!declaration || auth.type !== 'accessKey') {
    return context.sendPreparedSealedDevice(intent, message, auth);
  }
  const acceptance = await context.sendPreparedSealedDevice(
    intent,
    message,
    auth,
    declaration.deviceIds
  );
  declaration.routes.set(acceptance, 'anonymous-direct');
  return acceptance;
}

/**
 * Post one `sender_key` device message of a group send. When the Relay
 * refuses the device conclusively, the device is repaired once in this
 * attempt: its session is refreshed, it gets the key of the send, and the
 * new device message goes out after the pre-message. One intent write
 * replaces the messages of the device before the posts. When a repair of
 * the pre-message refreshes the session again, the device message is
 * prepared again under the new session before its post. A second refusal of
 * the device message fails the item. When `refused` is true, the Relay has
 * already refused the device as stale in the shared post, so the repair
 * starts with no first post. When the device list no longer shows the device
 * at the repair of its pre-message, the intent has dropped the device
 * message. The destination then settles as refused with no post, and the
 * function resolves to undefined.
 */
async function sendGroupDeviceMessage(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent,
  message: StoredOutgoingDeviceMessage,
  forceIdentified: boolean,
  required: boolean,
  refused = false
): Promise<RelayPostAcceptance | undefined> {
  if (!refused || message.messageType !== 'sender_key') {
    try {
      return await sendStoredDeviceMessage(context, intent, message, forceIdentified);
    } catch (error) {
      if (message.messageType !== 'sender_key' || !context.isConclusiveDeviceRejection(error)) {
        throw error;
      }
    }
  }
  const repair = await context.repairStaleDevice(intent, message);
  await reconcileOutgoingGroupDeviceSet(context.storage, intent.clientMessageId, {
    removed: [{ userId: message.recipientUserId, deviceId: message.recipientDeviceId }],
    preMessages: repair.preMessages,
    deviceMessages: [repair.deviceMessage],
    syncMessages: [],
  });
  const dispatched = await dispatchPreMessages(context, intent, repair.preMessages, required);
  const device = { userId: message.recipientUserId, deviceId: message.recipientDeviceId };
  if (dispatched.removed.some((removed) => groupDeviceKey(removed) === groupDeviceKey(device))) {
    return undefined;
  }
  const { renewed } = await renewRefreshedDeviceMessages(
    context,
    dispatched.intent,
    dispatched.refreshed,
    [repair.deviceMessage]
  );
  return sendStoredDeviceMessage(
    context,
    intent,
    renewed[0] ?? repair.deviceMessage,
    forceIdentified
  );
}

/**
 * Post stored pre-messages. Each one is authorized before any post, and a
 * pre-message sealed at this dispatch is stored before its post, so a replay
 * posts the same sealed bytes. Each pre-message is then accepted or dropped.
 * The handoff row of an accepted pre-message is written after the acceptance
 * and before the intent confirms the pre-message, so a crash between them
 * sends at most one extra distribution. A dropped pre-message writes no row.
 * The intent then keeps only the pre-messages that the relay did not accept,
 * so a replay posts only those. The same write removes the device message of
 * each device that the device list no longer shows. Resolves to the intent
 * after the confirmation, to each device whose session a repair refreshed,
 * and to each device that the device list no longer shows.
 */
async function dispatchPreMessages(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent,
  preMessages: readonly StoredOutgoingDeviceMessage[],
  required: boolean
): Promise<{
  intent: StoredOutgoingMessageIntent;
  refreshed: GroupMemberDevice[];
  removed: GroupMemberDevice[];
}> {
  let current = intent;
  const transports = await context.prepareEach(preMessages, (message) =>
    context.authorizePreMessage(intent.recipientId, message, required)
  );
  const sealedNow = transports.flatMap((transport, index) =>
    transport.message === preMessages[index]
      ? []
      : [{ expected: preMessages[index]!, replacement: transport.message }]
  );
  if (sealedNow.length > 0) {
    current = await replaceOutgoingGroupPreMessages(
      context.storage,
      intent.clientMessageId,
      sealedNow
    );
  }

  const transportOf = new Map(transports.map((transport) => [transport.message, transport]));
  const dispatched = current;
  const settled: string[] = [];
  const refreshed: GroupMemberDevice[] = [];
  const removed: GroupMemberDevice[] = [];
  try {
    await context.sendPhase(
      transports.map((transport) => transport.message),
      async (message) => {
        const posted = await context.postPreMessage(
          dispatched,
          transportOf.get(message)!,
          required
        );
        if (posted.outcome === 'accepted') {
          await context.recordSenderKeyHandoff(intent.recipientId, posted.message);
        }
        const device = {
          userId: posted.message.recipientUserId,
          deviceId: posted.message.recipientDeviceId,
        };
        if (posted.outcome === 'removed') removed.push(device);
        if (posted.refreshed) refreshed.push(device);
        if (posted.message.clientMessageId !== undefined) {
          settled.push(posted.message.clientMessageId);
        }
      },
      'pre-message'
    );
  } finally {
    if (settled.length > 0 || removed.length > 0) {
      current = await confirmOutgoingPreMessages(
        context.storage,
        intent.clientMessageId,
        settled,
        removed
      );
    }
  }
  return { intent: current, refreshed, removed };
}

/**
 * The devices that leave the shared body of this attempt, and the intent
 * after their device messages are renewed. A device leaves when a
 * pre-message repair in this attempt refreshed its session, or when its
 * current session has a registration other than the one that the stored
 * shared body names. The second check reads the sessions on each attempt, so
 * a replay finds the device after an attempt that failed or stopped before
 * the device got its own post. The Relay refuses the copy of such a device in
 * the shared body, so the device gets its own post. A refreshed device gets a
 * new device message. Another leaving device gets one only when its stored
 * device message names a registration other than that of the session.
 *
 * A leaving device whose session has no handoff row gets the key of the send
 * in a pre-message, as the repair of a refused device does. The renewal and
 * the pre-messages go in one intent write, and the pre-messages are accepted
 * or dropped before the device posts. On the attempt that prepared the send,
 * the distribution is at the chain index of the group message, so the device
 * decrypts it. A replay gives the current distribution, and the device
 * recovers the stored message through its retry request and the resend of a
 * logged send. A device that a repair of its pre-message refreshes gets a
 * device message under its new session, and the confirmation removes the
 * device message of a device that the device list no longer shows.
 */
async function leaveStaleSharedBody(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent,
  refreshed: readonly GroupMemberDevice[],
  groupCiphertext: string,
  required: boolean
): Promise<{ intent: StoredOutgoingMessageIntent; left: Set<string> }> {
  const left = new Set(refreshed.map(groupDeviceKey));
  const leaving = [...refreshed];
  const body = intent.groupSharedMessage
    ? sharedBodyDevices(intent.groupSharedMessage)
    : new Map<string, number>();
  const checks = await context.prepareEach(intent.deviceMessages, async (message) => {
    const device = { userId: message.recipientUserId, deviceId: message.recipientDeviceId };
    const named = body.get(groupDeviceKey(device));
    if (named === undefined || left.has(groupDeviceKey(device))) return undefined;
    const current = await context.remoteRegistrationId(device);
    if (current === undefined || current === named) return undefined;
    return { device, renew: message.recipientRegistrationId !== current };
  });
  const renew = [...refreshed];
  for (const check of checks) {
    if (!check) continue;
    left.add(groupDeviceKey(check.device));
    leaving.push(check.device);
    if (check.renew) renew.push(check.device);
  }
  const preMessages =
    leaving.length > 0 ? await context.prepareSenderKeyHandoffs(intent, leaving) : [];
  const renewal = await renewRefreshedDeviceMessages(
    context,
    intent,
    renew,
    intent.deviceMessages,
    groupCiphertext,
    preMessages
  );
  if (preMessages.length === 0) return { intent: renewal.intent, left };
  const dispatched = await dispatchPreMessages(context, renewal.intent, preMessages, required);
  const again = await renewRefreshedDeviceMessages(
    context,
    dispatched.intent,
    dispatched.refreshed,
    dispatched.intent.deviceMessages,
    groupCiphertext
  );
  return { intent: again.intent, left };
}

/**
 * Give each device in `refreshed` that has a message in `messages` a new
 * device message with the registration of its current session, in one intent
 * write. The earlier message names the earlier registration, so the Relay
 * refuses it, and the shared body of the send names the earlier registration
 * too. The new device message goes in its own post. The same write stores
 * `preMessages`. Resolves to the intent after the write, and to the new
 * device messages.
 */
async function renewRefreshedDeviceMessages(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent,
  refreshed: readonly GroupMemberDevice[],
  messages: readonly StoredOutgoingDeviceMessage[],
  groupCiphertext = intent.groupCiphertext,
  preMessages: readonly StoredOutgoingDeviceMessage[] = []
): Promise<{ intent: StoredOutgoingMessageIntent; renewed: StoredOutgoingDeviceMessage[] }> {
  const keys = new Set(refreshed.map(groupDeviceKey));
  const stale = messages.filter((message) =>
    keys.has(
      groupDeviceKey({ userId: message.recipientUserId, deviceId: message.recipientDeviceId })
    )
  );
  if (stale.length === 0 && preMessages.length === 0) return { intent, renewed: [] };
  if (!groupCiphertext) throw new Error('Corrupt group outbox intent');
  const renewed = await context.prepareEach(stale, (message) =>
    context.prepareDeviceMessage(
      { userId: message.recipientUserId, deviceId: message.recipientDeviceId },
      intent.recipientId,
      groupCiphertext,
      intent.clientTimestamp,
      intent.contentHint
    )
  );
  const written = await reconcileOutgoingGroupDeviceSet(context.storage, intent.clientMessageId, {
    removed: stale.map((message) => ({
      userId: message.recipientUserId,
      deviceId: message.recipientDeviceId,
    })),
    preMessages,
    deviceMessages: renewed,
    syncMessages: [],
  });
  return { intent: written, renewed };
}

async function sendStoredGroupIntent(
  context: GroupOutboxContext,
  initialIntent: StoredOutgoingMessageIntent,
  plaintextBytes: Uint8Array
): Promise<SendResult> {
  let intent = initialIntent;
  if (intent.kind !== 'group') throw new Error('Expected a group outbox intent');
  const groupCiphertext = intent.groupCiphertext;
  if (!groupCiphertext) throw new Error('Corrupt group outbox intent');
  const relay = context.relay;
  if (!relay) {
    const localResult = {
      clientMessageId: intent.clientMessageId,
      messageId: `local-${intent.clientTimestamp}`,
      timestamp: intent.clientTimestamp,
      recipientDeviceCount: intent.groupRecipientDeviceCount ?? 0,
      groupId: intent.recipientId,
    };
    await completeOutgoingMessageIntent(context.storage, intent.clientMessageId, localResult);
    await completeSendLog(context, intent);
    return localResult;
  }

  let messageId = `group-${intent.recipientId}-${String(intent.clientTimestamp)}`;
  let timestamp = intent.clientTimestamp;
  let sharedSucceeded = false;
  let skippedUsers: string[] = [];
  let refusedDestinationCount: number | undefined;
  let sharedRefusals: readonly { userId: string; deviceId: number; code: string }[] = [];
  // The relay's answer to each post of the group message, for the send's acceptance.
  const acceptances: RelayPostAcceptance[] = [];

  // The privacy policy of the pre-messages is checked before any post. A
  // required send posts no pre-message that names the sender, and a send
  // that cannot seal one posts nothing.
  const preMessages = intent.preMessages ?? [];
  const required =
    context.deliveryMode === 'required' ||
    intent.transportMode === 'sealed_sender_required' ||
    preMessages.some((message) => message.sealedSenderDeliveryMode === 'required');
  if (preMessages.length > 0) {
    // One refresh covers the pre-messages and the group message.
    await context.refreshPreMessageEndorsements(intent.recipientId, [
      ...new Set([
        ...preMessages.map((message) => message.recipientUserId),
        ...(intent.groupSharedMessage?.recipientUserIds ?? []),
      ]),
    ]);
  }
  // Every pre-message is accepted or dropped before the group message.
  const dispatched = await dispatchPreMessages(context, intent, preMessages, required);
  intent = dispatched.intent;
  // A device that a pre-message repair refreshed, or whose session no longer
  // has the registration that the shared body names, leaves the shared body
  // of this attempt. It gets the key of the send when it has no handoff row,
  // and its own post under its current registration.
  const leaving = await leaveStaleSharedBody(
    context,
    intent,
    dispatched.refreshed,
    groupCiphertext,
    required
  );
  intent = leaving.intent;

  if (
    intent.groupSharedMessage?.deliveryMode === 'required' &&
    !relay.sendMultiRecipientUnidentified
  ) {
    throw new EncryptionError(
      'Required group sealed-sender transport is unavailable',
      EncryptionErrorCode.SEALED_SENDER_REQUIRED,
      { groupId: intent.recipientId }
    );
  }

  if (intent.groupSharedMessage && relay.sendMultiRecipientUnidentified) {
    const auth = await context.resolveGroupAuthorization(
      intent.groupSharedMessage.groupId,
      intent.groupSharedMessage.recipientUserIds
    );
    if (!auth) {
      if (intent.groupSharedMessage.deliveryMode === 'required') {
        throw new Error('Required group sealed-sender authorization is unavailable');
      }
    } else {
      const shared = intent.groupSharedMessage;
      try {
        const result = await context.postToRelay(
          () =>
            relay.sendMultiRecipientUnidentified!(
              shared.sentMessageBase64,
              auth,
              intent.clientTimestamp,
              'user-visible',
              shared.recipientUserIds,
              intent.clientMessageId
            ),
          true
        );
        messageId = result.messageId;
        timestamp = result.serverTimestamp;
        skippedUsers = result.uuids404;
        refusedDestinationCount = result.refusedDestinationCount;
        sharedRefusals = result.refusals ?? [];
        sharedSucceeded = true;
        acceptances.push(result);
      } catch (error) {
        if (!(error instanceof SealedSenderAuthError)) throw error;
        if (intent.groupSharedMessage.deliveryMode === 'required') throw error;
        await context.prepareEach(intent.groupSharedMessage.recipientUserIds, (recipientUserId) =>
          context.reportIdentifiedFallback(recipientUserId)
        );
      }
    }
  }

  // A device that the shared body does not name gets its own post. A replay
  // keeps the stored body, so a device that the replay added is one. A
  // device that left the shared body of this attempt is one too.
  const sharedDevices = sharedSucceeded
    ? sharedBodyDevices(intent.groupSharedMessage!)
    : new Map<string, number>();
  for (const device of leaving.left) sharedDevices.delete(device);
  // The group-token receipt names each refused destination with its code. A
  // destination that the Relay refused as STALE_DEVICE leaves the shared set
  // and gets the device repair once. The refused count alone names no
  // device, so the send infers nothing from it.
  const refusedDevices = new Set(
    sharedRefusals
      .filter((refusal) => refusal.code === 'STALE_DEVICE')
      .map(groupDeviceKey)
      .filter((key) => sharedDevices.has(key))
  );
  for (const key of refusedDevices) sharedDevices.delete(key);
  const usersToRepair = new Set(skippedUsers);
  const forceIdentified = Boolean(intent.groupSharedMessage && !sharedSucceeded);
  const devicePosts = intent.deviceMessages.filter(
    (message) =>
      !sharedDevices.has(
        groupDeviceKey({ userId: message.recipientUserId, deviceId: message.recipientDeviceId })
      ) || usersToRepair.has(message.recipientUserId)
  );
  const posting = intent;
  const results = await context.sendPhase(
    devicePosts,
    (message) =>
      sendGroupDeviceMessage(
        context,
        posting,
        message,
        forceIdentified,
        required,
        refusedDevices.has(
          groupDeviceKey({ userId: message.recipientUserId, deviceId: message.recipientDeviceId })
        )
      ),
    'device'
  );
  const posted = results.filter((result) => result !== undefined);
  acceptances.push(...posted);
  if (messageId.startsWith('group-') && posted[0]) {
    messageId = posted[0].messageId;
    timestamp = posted[0].serverTimestamp;
  }

  if (skippedUsers.length > 0) {
    const refreshed = await context.resolveMemberDevices(intent.recipientId, {
      clientMessageId: intent.clientMessageId,
      groupMemberUserIds: skippedUsers,
    });
    const { added } = listedGroupDeviceChange(intent, refreshed, context.senderUserId);
    if (added.length > 0) {
      // The pre-messages come first. They give each added device a session
      // and the key of the send, so its device message names the
      // registration of that session, and the device can decrypt it.
      const handoffs = await context.prepareSenderKeyHandoffs(intent, refreshed);
      const additions = await context.prepareEach(added, (member) =>
        context.prepareDeviceMessage(
          member,
          intent.recipientId,
          groupCiphertext,
          intent.clientTimestamp,
          intent.contentHint
        )
      );
      // A device that the repair adds gets a send log row before its post.
      if (isLoggedSend(intent)) {
        await context.storage.appendSendLogRecipients(
          intent.clientMessageId,
          sendLogDevices(additions)
        );
      }
      intent = await reconcileOutgoingGroupDeviceSet(context.storage, intent.clientMessageId, {
        removed: [],
        preMessages: handoffs,
        deviceMessages: additions,
        syncMessages: [],
      });
      const dispatchedHandoffs = await dispatchPreMessages(context, intent, handoffs, required);
      // A device that a repair of its pre-message refreshed gets a device
      // message under its new session before its post.
      const renewal = await renewRefreshedDeviceMessages(
        context,
        dispatchedHandoffs.intent,
        dispatchedHandoffs.refreshed,
        additions,
        groupCiphertext
      );
      intent = renewal.intent;
      // The confirmation of the pre-messages removed the device message of
      // each device that the device list no longer shows. Only the additions
      // that the intent still holds get a post.
      const removedKeys = new Set(dispatchedHandoffs.removed.map(groupDeviceKey));
      const renewedOf = new Map(
        renewal.renewed.map((message) => [
          groupDeviceKey({ userId: message.recipientUserId, deviceId: message.recipientDeviceId }),
          message,
        ])
      );
      const extended = intent;
      const additionResults = await context.sendPhase(
        additions.flatMap((message) => {
          const key = groupDeviceKey({
            userId: message.recipientUserId,
            deviceId: message.recipientDeviceId,
          });
          return removedKeys.has(key) ? [] : [renewedOf.get(key) ?? message];
        }),
        (message) => sendGroupDeviceMessage(context, extended, message, false, required),
        'device'
      );
      acceptances.push(...additionResults.filter((result) => result !== undefined));
    }
  }

  // The sync copies start after every device post settles. They go to the
  // sender's own devices, so they are identified in every privacy mode: the
  // relay already knows the account that owns the destination mailbox.
  const syncing = intent;
  const rebuildSyncMessage = async (deviceId: number) => {
    const [message] = await context.prepareSyncMessages(
      syncing.recipientId,
      await transcriptContent(context, syncing, plaintextBytes),
      syncing.clientTimestamp,
      syncing.clientMessageId,
      [{ userId: context.senderUserId, deviceId }]
    );
    return message;
  };
  await context.sendPhase(
    intent.syncMessages,
    (message) => context.postSyncMessage(syncing, message, rebuildSyncMessage),
    'sync'
  );

  const result = {
    clientMessageId: intent.clientMessageId,
    messageId,
    timestamp,
    recipientDeviceCount: intent.groupRecipientDeviceCount ?? intent.deviceMessages.length,
    ...aggregateRelayAcceptance(acceptances),
    ...(refusedDestinationCount !== undefined && { refusedDestinationCount }),
    groupId: intent.recipientId,
  };
  await completeOutgoingMessageIntent(context.storage, intent.clientMessageId, result);
  await completeSendLog(context, intent);
  return result;
}

/** The device of a stored device message. */
function messageDevice(message: StoredOutgoingDeviceMessage): DeviceSetDevice {
  return { userId: message.recipientUserId, deviceId: message.recipientDeviceId };
}

/** True when a send must not post a pre-message or a body that names the sender. */
function requiresSealedSender(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent
): boolean {
  return (
    context.deliveryMode === 'required' ||
    intent.transportMode === 'sealed_sender_required' ||
    (intent.preMessages ?? []).some((message) => message.sealedSenderDeliveryMode === 'required')
  );
}

/**
 * Seal the shared body of a declared group send again, for the device
 * messages that the intent holds after a repair (RQ3 of the device-set
 * contract). The group ciphertext does not change, so a device post that
 * the Relay accepted in the same pass replays byte for byte. Only the
 * accounts of the refused body take part, and each account is wholly in the
 * new body or wholly out of it. Resolves to null when no account remains in
 * a body.
 */
async function resealSharedBody(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent,
  deviceMessages: readonly StoredOutgoingDeviceMessage[]
): Promise<StoredGroupSharedMessage | null> {
  const body = intent.groupSharedMessage!;
  const accounts = new Set(body.recipientUserIds);
  const members = deviceMessages
    .filter((message) => accounts.has(message.recipientUserId))
    .map(messageDevice);
  const resealed = await context.prepareSharedMessage(
    intent.recipientId,
    members,
    intent.groupCiphertext!,
    intent.contentHint
  );
  return resealed ?? null;
}

/**
 * Mark a refusal of an undeclared device post as a stale refusal of its
 * device, so the reconciliation repairs the device with the others of the
 * pass. Any other error is returned unchanged.
 */
function asDeviceSetFailure(error: unknown, device: DeviceSetDevice): unknown {
  if (deviceSetRefusal(error) || !isStaleDeviceRefusal(error) || !(error instanceof Error)) {
    return error;
  }
  return markDeviceSetRefusal(error, {
    kind: 'stale',
    accounts: [{ userId: device.userId, staleDeviceIds: [device.deviceId] }],
  });
}

/**
 * Post a stored group intent on a relay that compares device sets (§5.5 of
 * the device-set contract).
 *
 * Each pass posts the pending pre-messages, then the shared body, then a
 * device post for each device that the body does not name. The shared post
 * declares the devices of the body for each account. Each device post
 * declares the devices of its account that the device posts address. After
 * a refusal, the repair archives and removes each extra device, refreshes
 * each stale device, starts a session with each missing device, gives each
 * refreshed or added device the key of the send and a device message of the
 * stored group ciphertext, and seals the body again while the Relay has not
 * accepted it. The repair and the new restart count commit in one write.
 *
 * An account is wholly in the body or wholly in the device posts. A repair
 * of an account of the body seals the body again with all devices of the
 * account, and never moves one device of it to a device post. After the
 * Relay accepts the body, no pass posts it again, and no refusal names an
 * account of it, because the Relay refuses a whole post.
 *
 * The recipient result is stored before the sync phase. A failed sync phase
 * gives `syncPending` and does not fail the send.
 */
async function sendDeclaredGroupIntent(
  context: GroupOutboxContext,
  deviceSets: GroupDeviceSetContext,
  initialIntent: StoredOutgoingMessageIntent,
  plaintextBytes: Uint8Array
): Promise<SendResult> {
  let intent = initialIntent;
  if (intent.kind !== 'group') throw new Error('Expected a group outbox intent');
  const groupCiphertext = intent.groupCiphertext;
  if (!groupCiphertext) throw new Error('Corrupt group outbox intent');
  const relay = context.relay;
  if (!relay) throw new Error('Relay is required for a declared group send');
  const clientMessageId = intent.clientMessageId;
  const groupId = intent.recipientId;

  // The body receipt, once the Relay accepted the body in a pass.
  let sharedReceipt: Awaited<
    ReturnType<NonNullable<SignalProtocolRelayServer['sendMultiRecipientUnidentified']>>
  > | undefined;
  // True when the body cannot go out sealed, so every device gets its own
  // identified post, as in an 11.x send.
  let forceIdentified = false;
  // The route of each declared acceptance of the last pass. A pass that
  // reuses the body receipt records its route again.
  const routes = new Map<RelayPostAcceptance, RelayProtocolRoute>();
  // The registration that each post of the last pass named, for the repair.
  let posted = new Map<string, number | undefined>();
  // The listed devices with no prekey bundle at the last repair. The intent
  // stores them, so a replay starts a session with each before its first post.
  let unposted: DeviceSetDevice[] = [...(intent.deviceSetBundleMissing?.recipient ?? [])];
  // The accounts that the last pass refused here, because they had no post.
  let unpostedAccounts = new Set<string>();
  const bodyOpen = () => Boolean(intent.groupSharedMessage && !sharedReceipt && !forceIdentified);

  const pass = async (): Promise<DeviceSetPost<RelayPostAcceptance>[]> => {
    routes.clear();
    posted = new Map();
    const required = requiresSealedSender(context, intent);
    const pending = intent.preMessages ?? [];
    if (pending.length > 0) {
      // One refresh covers the pre-messages and the group message.
      await context.refreshPreMessageEndorsements(groupId, [
        ...new Set([
          ...pending.map((message) => message.recipientUserId),
          ...(bodyOpen() ? intent.groupSharedMessage!.recipientUserIds : []),
        ]),
      ]);
      // Every pre-message is accepted or dropped before the group message.
      const dispatched = await dispatchPreMessages(context, intent, pending, required);
      intent = dispatched.intent;
      const touched = [...dispatched.refreshed, ...dispatched.removed];
      if (touched.length > 0) {
        // A device that a pre-message repair refreshed gets a device message
        // under its new session. A body that names a touched device is
        // sealed again in the same write.
        const refreshedKeys = new Set(dispatched.refreshed.map(groupDeviceKey));
        const stale = intent.deviceMessages.filter((message) =>
          refreshedKeys.has(groupDeviceKey(messageDevice(message)))
        );
        const renewed = await context.prepareEach(stale, (message) =>
          context.prepareDeviceMessage(
            messageDevice(message),
            groupId,
            groupCiphertext,
            intent.clientTimestamp,
            intent.contentHint
          )
        );
        const touchedAccounts = new Set(touched.map((device) => device.userId));
        let groupSharedMessage: StoredGroupSharedMessage | null | undefined;
        if (
          bodyOpen() &&
          intent.groupSharedMessage!.recipientUserIds.some((userId) => touchedAccounts.has(userId))
        ) {
          groupSharedMessage = await resealSharedBody(context, intent, [
            ...intent.deviceMessages.filter(
              (message) => !refreshedKeys.has(groupDeviceKey(messageDevice(message)))
            ),
            ...renewed,
          ]);
        }
        if (stale.length > 0 || groupSharedMessage !== undefined) {
          intent = await reconcileOutgoingGroupDeviceSet(context.storage, clientMessageId, {
            removed: stale.map(messageDevice),
            preMessages: [],
            deviceMessages: renewed,
            syncMessages: [],
            ...(groupSharedMessage !== undefined && { groupSharedMessage }),
          });
        }
      }
    }

    const posts: DeviceSetPost<RelayPostAcceptance>[] = [];
    let bodyDevices = new Map<string, number>();
    const body = intent.groupSharedMessage;
    if (body?.deliveryMode === 'required' && !relay.sendMultiRecipientUnidentified) {
      throw new EncryptionError(
        'Required group sealed-sender transport is unavailable',
        EncryptionErrorCode.SEALED_SENDER_REQUIRED,
        { groupId }
      );
    }
    if (body && !relay.sendMultiRecipientUnidentified) forceIdentified = true;
    if (body && !forceIdentified) {
      bodyDevices = sharedBodyDevices(body);
      const bodyPosts = (outcome: DeviceSetPost<RelayPostAcceptance>['outcome']) => {
        for (const key of bodyDevices.keys()) {
          const [userId, deviceId] = key.split('\u0000') as [string, string];
          posts.push({ device: { userId, deviceId: Number(deviceId) }, outcome });
        }
      };
      if (sharedReceipt) {
        routes.set(sharedReceipt, 'anonymous-group');
        bodyPosts({ ok: true, value: sharedReceipt });
      } else {
        const auth = await context.resolveGroupAuthorization(body.groupId, body.recipientUserIds);
        if (!auth) {
          if (body.deliveryMode === 'required') {
            throw new Error('Required group sealed-sender authorization is unavailable');
          }
          forceIdentified = true;
          bodyDevices = new Map();
        } else {
          const declared = new Map<string, number[]>();
          for (const [key, registrationId] of bodyDevices) {
            const [userId, deviceId] = key.split('\u0000') as [string, string];
            declared.set(userId, [...(declared.get(userId) ?? []), Number(deviceId)]);
            posted.set(key, registrationId);
          }
          const deviceSetsOfBody = [...declared].map(([userId, deviceIds]) => ({
            userId,
            deviceIds: deviceIds.sort((a, b) => a - b),
          }));
          try {
            const receipt = await context.postToRelay(
              () =>
                relay.sendMultiRecipientUnidentified!(
                  body.sentMessageBase64,
                  auth,
                  intent.clientTimestamp,
                  'user-visible',
                  body.recipientUserIds,
                  clientMessageId,
                  undefined,
                  undefined,
                  deviceSetsOfBody
                ),
              true
            );
            sharedReceipt = receipt;
            routes.set(receipt, 'anonymous-group');
            bodyPosts({ ok: true, value: receipt });
          } catch (error) {
            if (!(error instanceof SealedSenderAuthError)) {
              bodyPosts({ ok: false, error });
            } else {
              if (body.deliveryMode === 'required') throw error;
              await context.prepareEach(body.recipientUserIds, (recipientUserId) =>
                context.reportIdentifiedFallback(recipientUserId)
              );
              forceIdentified = true;
              bodyDevices = new Map();
            }
          }
        }
      }
    }

    // A device that the body does not name gets its own post. Each post
    // declares the devices of its account that the device posts address.
    const devicePosts = intent.deviceMessages.filter(
      (message) => !bodyDevices.has(groupDeviceKey(messageDevice(message)))
    );
    const declared = new Map<string, number[]>();
    for (const message of devicePosts) {
      declared.set(message.recipientUserId, [
        ...(declared.get(message.recipientUserId) ?? []),
        message.recipientDeviceId,
      ]);
      posted.set(groupDeviceKey(messageDevice(message)), message.recipientRegistrationId);
    }
    for (const deviceIds of declared.values()) deviceIds.sort((a, b) => a - b);
    const posting = intent;
    posts.push(
      ...(await context.sendPhase(
        devicePosts,
        async (message): Promise<DeviceSetPost<RelayPostAcceptance>> => {
          const device = messageDevice(message);
          try {
            const value = await sendStoredDeviceMessage(context, posting, message, forceIdentified, {
              deviceIds: declared.get(message.recipientUserId)!,
              routes,
            });
            return { device, outcome: { ok: true, value } };
          } catch (error) {
            return { device, outcome: { ok: false, error: asDeviceSetFailure(error, device) } };
          }
        },
        'device'
      ))
    );

    // An account whose devices all lack a bundle has no post to refuse. It
    // is refused here as missing those devices, so the pass counts.
    const addressed = new Set([
      ...declared.keys(),
      ...[...bodyDevices.keys()].map((key) => key.split('\u0000')[0]!),
    ]);
    const refusedHere = new Map<string, number[]>();
    for (const device of unposted) {
      if (addressed.has(device.userId)) continue;
      refusedHere.set(device.userId, [...(refusedHere.get(device.userId) ?? []), device.deviceId]);
    }
    unpostedAccounts = new Set(refusedHere.keys());
    for (const [userId, missingDeviceIds] of refusedHere) {
      posts.push({
        device: { userId, deviceId: missingDeviceIds[0]! },
        outcome: {
          ok: false,
          error: markDeviceSetRefusal(new Error('No device of the account has a session'), {
            kind: 'mismatch',
            accounts: [{ userId, missingDeviceIds, extraDeviceIds: [] }],
          }),
        },
      });
    }
    return posts;
  };

  const repair = async (repairs: readonly DeviceSetAccountRepair[], restarts: number) => {
    const removed: DeviceSetDevice[] = [];
    const ready: DeviceSetDevice[] = [];
    const bundleMissing: DeviceSetDevice[] = [];
    for (const account of repairs) {
      const repaired = await deviceSets.repairDevices(
        account,
        (device) => posted.get(groupDeviceKey(device)),
        unpostedAccounts.has(account.userId)
      );
      removed.push(...repaired.removed);
      ready.push(...repaired.ready);
      bundleMissing.push(...repaired.bundleMissing);
    }
    const removedKeys = new Set(removed.map(groupDeviceKey));
    // A removed device loses its pending pre-message in the repair write, so
    // the handoff of a refreshed device is prepared without it.
    const remaining: StoredOutgoingMessageIntent = {
      ...intent,
      preMessages: (intent.preMessages ?? []).filter(
        (message) => !removedKeys.has(groupDeviceKey(messageDevice(message)))
      ),
    };
    const preMessages =
      ready.length > 0 ? await context.prepareSenderKeyHandoffs(remaining, ready) : [];
    const deviceMessages = await context.prepareEach(ready, (device) =>
      context.prepareDeviceMessage(
        device,
        groupId,
        groupCiphertext,
        intent.clientTimestamp,
        intent.contentHint
      )
    );
    // A device that the repair adds gets a send log row before its post.
    if (isLoggedSend(intent) && deviceMessages.length > 0) {
      await context.storage.appendSendLogRecipients(clientMessageId, sendLogDevices(deviceMessages));
    }
    let groupSharedMessage: StoredGroupSharedMessage | null | undefined;
    const bodyAccounts = new Set(intent.groupSharedMessage?.recipientUserIds ?? []);
    if (bodyOpen() && repairs.some((account) => bodyAccounts.has(account.userId))) {
      groupSharedMessage = await resealSharedBody(context, intent, [
        ...intent.deviceMessages.filter(
          (message) => !removedKeys.has(groupDeviceKey(messageDevice(message)))
        ),
        ...deviceMessages,
      ]);
    }
    intent = await repairOutgoingDeviceSet(context.storage, clientMessageId, {
      phase: 'recipient',
      restarts,
      removed,
      bundleMissing,
      preMessages,
      deviceMessages,
      ...(groupSharedMessage !== undefined && { groupSharedMessage }),
    });
    unposted = bundleMissing;
    return { bundleMissing };
  };

  const posts = await runDeviceSetPhase<RelayPostAcceptance>({
    phase: 'recipient',
    clientMessageId,
    restarts: intent.deviceSetRestarts?.recipient ?? 0,
    pass,
    repair,
    unresolve: (unresolved) => deviceSets.unresolve(clientMessageId, unresolved),
    wait: (milliseconds) => deviceSets.wait(milliseconds),
    logFailure: (device, error) => deviceSets.logFailure(device, error),
  });

  // The body receipt answers each device of the body, so it counts once.
  const accepted = [
    ...new Set(posts.flatMap((post) => (post.outcome.ok ? [post.outcome.value] : []))),
  ];
  const first = sharedReceipt ?? accepted[0];
  const result = {
    clientMessageId,
    messageId: first?.messageId ?? `group-${groupId}-${String(intent.clientTimestamp)}`,
    timestamp: first?.serverTimestamp ?? intent.clientTimestamp,
    recipientDeviceCount: intent.groupRecipientDeviceCount ?? intent.deviceMessages.length,
    ...aggregateRelayAcceptance(accepted),
    ...(sharedReceipt?.refusedDestinationCount !== undefined && {
      refusedDestinationCount: sharedReceipt.refusedDestinationCount,
    }),
    groupId,
  };

  // The sync phase runs when the intent holds a sync copy, or when a
  // receipt sets needsSync. With needsSync and no own record, the send
  // reads the own list once. When that read fails, the sync phase stays
  // pending with no sync messages, and a replay reads it.
  let current = (await getOutgoingMessageIntent(context.storage, clientMessageId)) ?? intent;
  let syncUnread = false;
  if (
    current.syncMessages.length === 0 &&
    accepted.some((acceptance) => acceptance.needsSync === true)
  ) {
    const added = await addDeclaredGroupSync(context, deviceSets, current, plaintextBytes);
    current = added.intent;
    syncUnread = added.unread;
  }
  const syncPhase = current.syncMessages.length > 0;
  await completeOutgoingMessageIntent(context.storage, clientMessageId, result, {
    syncPending: syncPhase || syncUnread,
  });
  const sync: DeclaredSyncOutcome = syncPhase
    ? await runDeclaredGroupSync(context, deviceSets, current, plaintextBytes)
    : { synced: true, accepted: [] };
  await completeSendLog(context, current);
  const completed = {
    ...result,
    ...((!sync.synced || syncUnread) && { syncPending: true as const }),
  };
  return deviceSets.markUnchecked(
    completed,
    [
      ...accepted.flatMap((acceptance): DeclaredPostReceipt[] => {
        const route = routes.get(acceptance);
        return route ? [[acceptance, route]] : [];
      }),
      ...syncPostReceipts(sync.accepted),
    ],
    clientMessageId
  );
}

/**
 * Add the sync copies of a group intent from one read of the own device
 * list. A logged send gets a send log row for each copy. A failed read is
 * logged and does not fail the send.
 *
 * @returns The intent, and true when the read failed
 */
async function addDeclaredGroupSync(
  context: GroupOutboxContext,
  deviceSets: GroupDeviceSetContext,
  intent: StoredOutgoingMessageIntent,
  plaintextBytes: Uint8Array
): Promise<{ intent: StoredOutgoingMessageIntent; unread: boolean }> {
  try {
    const ownDevices = await deviceSets.readOwnDevices();
    const syncMessages =
      ownDevices.length > 0
        ? await context.prepareSyncMessages(
            intent.recipientId,
            await transcriptContent(context, intent, plaintextBytes),
            intent.clientTimestamp,
            intent.clientMessageId,
            ownDevices
          )
        : [];
    if (syncMessages.length === 0) return { intent, unread: false };
    if (isLoggedSend(intent)) {
      await context.storage.appendSendLogRecipients(
        intent.clientMessageId,
        sendLogDevices(syncMessages)
      );
    }
    return {
      intent: await reconcileOutgoingSyncMessages(
        context.storage,
        intent.clientMessageId,
        [],
        syncMessages
      ),
      unread: false,
    };
  } catch (error) {
    deviceSets.warn('Could not read the own device list for the sync phase of a send', error);
    return { intent, unread: true };
  }
}

/**
 * Run the declared sync phase of a completed group intent. A device that a
 * repair refreshes or adds gets a transcript of the logged content when the
 * send is logged, and a send log row.
 */
function runDeclaredGroupSync(
  context: GroupOutboxContext,
  deviceSets: GroupDeviceSetContext,
  intent: StoredOutgoingMessageIntent,
  plaintextBytes: Uint8Array
): Promise<DeclaredSyncOutcome> {
  return deviceSets.runSyncPhase(intent, async (device) => {
    const [message] = await context.prepareSyncMessages(
      intent.recipientId,
      await transcriptContent(context, intent, plaintextBytes),
      intent.clientTimestamp,
      intent.clientMessageId,
      [{ userId: context.senderUserId, deviceId: device.deviceId }]
    );
    if (message && isLoggedSend(intent)) {
      await context.storage.appendSendLogRecipients(
        intent.clientMessageId,
        sendLogDevices([message])
      );
    }
    return message;
  });
}

/**
 * Replay a stored group send on a relay that compares device sets. A
 * terminal send starts a new run at 0 restarts. A completed send with a
 * pending sync phase posts only its sync messages. A send that is not
 * terminal resumes with its stored restart count. The replay reads no device
 * list: the Relay comparison finds each change. The one exception is a
 * pending sync phase with no sync message and no stored own device with no
 * bundle: the send could not read the own device list, and the replay reads
 * it. A stored device with no bundle goes through the sync phase, which
 * refuses it as missing and retries it as the live run does.
 */
async function replayDeclaredGroupIntent(
  context: GroupOutboxContext,
  deviceSets: GroupDeviceSetContext,
  existing: StoredOutgoingMessageIntent,
  plaintextBytes: Uint8Array
): Promise<SendResult> {
  const intent = await restartOutgoingDeviceSet(context.storage, existing.clientMessageId);
  const stored = outgoingMessageIntentResult(intent);
  if (!stored) return sendDeclaredGroupIntent(context, deviceSets, intent, plaintextBytes);
  if (!intent.syncPending) {
    await completeSendLog(context, intent);
    return stored;
  }
  const { syncPending: _pending, ...result } = stored;
  let current = intent;
  if (
    current.syncMessages.length === 0 &&
    (current.deviceSetBundleMissing?.sync ?? []).length === 0
  ) {
    const added = await addDeclaredGroupSync(context, deviceSets, current, plaintextBytes);
    if (added.unread) return stored;
    current = added.intent;
    if (current.syncMessages.length === 0) {
      await completeOutgoingSyncPhase(context.storage, current.clientMessageId);
      await completeSendLog(context, current);
      return result;
    }
  }
  const sync = await runDeclaredGroupSync(context, deviceSets, current, plaintextBytes);
  await completeSendLog(context, current);
  return deviceSets.markUnchecked(
    sync.synced ? result : { ...result, syncPending: true as const },
    syncPostReceipts(sync.accepted),
    current.clientMessageId
  );
}

/**
 * Read the device lists of the members and of the sender's own account again
 * before the replay of a stored group send, and apply them to the intent in
 * one write. Each message of a device that the reads no longer list leaves
 * the intent. The stored shared body does not change.
 */
async function rereadStoredGroupDevices(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent,
  plaintextBytes: Uint8Array
): Promise<StoredOutgoingMessageIntent> {
  if (!context.relay) return intent;
  const members = await rereadMemberDevices(context, intent);
  const own = await rereadOwnDevices(context, intent, plaintextBytes);
  if (!members && !own) return intent;
  return reconcileOutgoingGroupDeviceSet(context.storage, intent.clientMessageId, {
    removed: [...(members?.removed ?? []), ...(own?.removed ?? [])],
    preMessages: members?.preMessages ?? [],
    deviceMessages: members?.deviceMessages ?? [],
    syncMessages: own?.syncMessages ?? [],
  });
}

/**
 * The change that a new read of the member device lists makes to a stored
 * group send, or undefined when the read changes nothing. Each listed device
 * of another member that the send does not reach gets the key of the send
 * from the current distribution, and a device message of the stored group
 * ciphertext. A device that the replay adds cannot decrypt the stored
 * message, because the current distribution is past its chain index. It
 * recovers through its retry request and the resend of a logged send, so it
 * gets a send log row here.
 *
 * Signal encrypts the message again for the devices of each attempt. The
 * replay here keeps the stored ciphertext. The Relay keys each delivery
 * operation by its message ID and refuses another operation under the same
 * ID with RETRY_CONFLICT, so a new group ciphertext under the clientMessageId
 * of the send would conflict with the posts that the Relay already holds. A
 * device that the replay adds therefore gets the content only when the send
 * is `Resendable`.
 */
async function rereadMemberDevices(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent
): Promise<OutgoingGroupDeviceSetChange | undefined> {
  const groupCiphertext = intent.groupCiphertext;
  if (!groupCiphertext || !intent.groupMemberUserIds?.length) return undefined;
  const listed = await context.resolveMemberDevices(intent.recipientId, {
    clientMessageId: intent.clientMessageId,
    groupMemberUserIds: intent.groupMemberUserIds,
  });
  const { unlisted, added } = listedGroupDeviceChange(intent, listed, context.senderUserId);
  if (unlisted.length === 0 && added.length === 0) return undefined;

  // The complete device list of each member with an added device.
  const addedUsers = new Set(added.map((member) => member.userId));
  const handoffs = await context.prepareSenderKeyHandoffs(
    intent,
    listed.filter((member) => addedUsers.has(member.userId))
  );
  const deviceMessages = await context.prepareEach(added, (member) =>
    context.prepareDeviceMessage(
      member,
      intent.recipientId,
      groupCiphertext,
      intent.clientTimestamp,
      intent.contentHint
    )
  );
  if (isLoggedSend(intent) && deviceMessages.length > 0) {
    await context.storage.appendSendLogRecipients(
      intent.clientMessageId,
      sendLogDevices(deviceMessages)
    );
  }
  return { removed: unlisted, preMessages: handoffs, deviceMessages, syncMessages: [] };
}

/**
 * The change that a new read of the sender's own device list makes to the
 * sync copies of a stored group send, or undefined when the read changes
 * nothing. Each sync copy of an own device that the read no longer lists
 * leaves the intent. Each listed own device with no sync copy gets a
 * transcript. The transcript of a logged send carries the logged content, so
 * it is equal to the content that the other devices got. With no logged
 * content, the transcript carries the content as the group gets it now.
 */
async function rereadOwnDevices(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent,
  plaintextBytes: Uint8Array
): Promise<OutgoingGroupDeviceSetChange | undefined> {
  const ownDevices = await context.resolveOwnDevices();
  const { unlisted, added } = listedOwnDeviceChange(
    intent.syncMessages,
    ownDevices.map((device) => device.deviceId)
  );
  if (unlisted.length === 0 && added.length === 0) return undefined;

  const addedDevices = ownDevices.filter((device) => added.includes(device.deviceId));
  const syncMessages =
    addedDevices.length > 0
      ? await context.prepareSyncMessages(
          intent.recipientId,
          await transcriptContent(context, intent, plaintextBytes),
          intent.clientTimestamp,
          intent.clientMessageId,
          addedDevices
        )
      : [];
  if (isLoggedSend(intent) && syncMessages.length > 0) {
    await context.storage.appendSendLogRecipients(
      intent.clientMessageId,
      sendLogDevices(syncMessages)
    );
  }
  return {
    removed: unlisted.map((deviceId) => ({ userId: context.senderUserId, deviceId })),
    preMessages: [],
    deviceMessages: [],
    syncMessages,
  };
}

/**
 * The content of a sent transcript of a stored group send. A logged send
 * gives its logged content, so the transcript is equal to the content that
 * the other devices got. With no logged content, the transcript carries the
 * content as the group gets it now.
 */
async function transcriptContent(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent,
  plaintextBytes: Uint8Array
): Promise<Uint8Array> {
  return (
    (await loggedContent(context, intent)) ??
    (await context.prepareContent(intent.recipientId, plaintextBytes))
  );
}

/** The logged content of a send, or undefined when the send is not logged or no row remains. */
async function loggedContent(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent
): Promise<Uint8Array | undefined> {
  if (!isLoggedSend(intent)) return undefined;
  const [row] = await context.storage.getSendLogRecipients(intent.clientMessageId);
  if (!row) return undefined;
  const entry = await context.storage.getSendLogEntry(intent.clientMessageId, row);
  return entry?.payload.plaintext;
}

/** True when the send logs its content for a resend. Only a `Resendable` send is logged. */
function isLoggedSend(intent: StoredOutgoingMessageIntent): boolean {
  return intent.contentHint === ContentHint.Resendable;
}

/** The devices of stored device messages, as send log recipients. */
function sendLogDevices(messages: readonly StoredOutgoingDeviceMessage[]): SendLogDevice[] {
  return messages.map((message) => ({
    userId: message.recipientUserId,
    deviceId: message.recipientDeviceId,
  }));
}

/** Every device that a group intent sends the content to: the members, then the sync devices. */
function intentSendLogDevices(intent: StoredOutgoingMessageIntent): SendLogDevice[] {
  return sendLogDevices([...intent.deviceMessages, ...intent.syncMessages]);
}

/**
 * Write the send log entry of a resendable send. The entry is written before
 * the intent and before any post, so a device that gets the message always
 * has a row. A failed write throws, and the send posts nothing. The entry is
 * written once: a stored intent proves it was written, so a replay never
 * writes it again. A row that an E2EE receipt, `forgetSentContent`, or the
 * retention sweep deleted stays deleted.
 */
async function storeSendLog(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent,
  plaintextBytes: Uint8Array
): Promise<void> {
  const recipients = intentSendLogDevices(intent);
  if (!isLoggedSend(intent) || recipients.length === 0) return;
  await context.storage.storeSendLogEntry(
    {
      clientMessageId: intent.clientMessageId,
      groupId: intent.recipientId,
      clientTimestamp: intent.clientTimestamp,
      contentHint: ContentHint.Resendable,
      plaintext: plaintextBytes,
    },
    recipients
  );
}

/** Mark the send log entry of a finished resendable send complete. */
async function completeSendLog(
  context: GroupOutboxContext,
  intent: StoredOutgoingMessageIntent
): Promise<void> {
  if (isLoggedSend(intent)) await context.storage.markSendLogComplete(intent.clientMessageId);
}

export async function sendGroupWithExactOutbox(
  context: GroupOutboxContext,
  groupId: string,
  plaintextBytes: Uint8Array,
  options: SendOptions & SendTimestampOrigin & { clientMessageId: string }
): Promise<SendResult> {
  return withOutgoingMessageIntentLock(context.storage, options.clientMessageId, async () => {
    const plaintextDigest = CryptoUtils.bytesToBase64(await CryptoUtils.sha256(plaintextBytes));
    const groupMemberUserIds = [...new Set(options.groupMemberUserIds ?? [])].sort();
    const existing = await getOutgoingMessageIntent(context.storage, options.clientMessageId);

    if (existing) {
      if (
        existing.kind !== 'group' ||
        existing.recipientId !== groupId ||
        existing.plaintextDigest !== plaintextDigest ||
        (options.timestamp !== undefined && existing.clientTimestamp !== options.timestamp) ||
        JSON.stringify(existing.groupMemberUserIds) !== JSON.stringify(groupMemberUserIds)
      ) {
        throw new Error('A clientMessageId cannot identify two different logical sends');
      }
      if (context.deviceSets && context.relay) {
        return replayDeclaredGroupIntent(context, context.deviceSets, existing, plaintextBytes);
      }
      if (existing.result) {
        await completeSendLog(context, existing);
        return existing.result;
      }
      return sendStoredGroupIntent(
        context,
        await rereadStoredGroupDevices(context, existing, plaintextBytes),
        plaintextBytes
      );
    }

    // A new send checks the timestamp before it prepares or posts anything.
    // The replays above keep the stored timestamp.
    const clientTimestamp = newSendClientTimestamp(options);
    // The digest above covers the caller's content, so a replay compares
    // like with like. The group gets the content with its context.
    const contentBytes = await context.prepareContent(groupId, plaintextBytes);
    // One device-list read for each member in this send.
    let memberRead: Promise<GroupMemberDevice[]> | undefined;
    const readMembers = () => (memberRead ??= context.resolveMemberDevices(groupId, options));
    const preparedPayload = await context.preparePayload(
      groupId,
      contentBytes,
      { ...options, timestamp: clientTimestamp },
      readMembers
    );
    const encryptedMessageBase64 = preparedPayload.ciphertext;
    const members = context.relay ? await readMembers() : [];
    const otherMembers = members.filter((member) => member.userId !== context.senderUserId);
    const groupSharedMessage = await context.prepareSharedMessage(
      groupId,
      otherMembers,
      encryptedMessageBase64,
      options.contentHint
    );
    const deviceMessages = await context.prepareEach(otherMembers, (member) =>
      context.prepareDeviceMessage(
        member,
        groupId,
        encryptedMessageBase64,
        clientTimestamp,
        options.contentHint
      )
    );
    const syncMessages = context.relay
      ? await context.prepareSyncMessages(
          groupId,
          contentBytes,
          clientTimestamp,
          options.clientMessageId,
          await context.resolveOwnDevices()
        )
      : [];

    const intent: StoredOutgoingMessageIntent = {
      kind: 'group',
      clientMessageId: options.clientMessageId,
      recipientId: groupId,
      plaintextDigest,
      clientTimestamp,
      createdAt: Date.now(),
      transportMode: groupSharedMessage
        ? context.deliveryMode === 'required'
          ? 'sealed_sender_required'
          : 'sealed_sender_preferred'
        : 'identified',
      ...(preparedPayload.preMessages.length > 0 && {
        preMessages: preparedPayload.preMessages,
      }),
      deviceMessages,
      syncMessages,
      groupMemberUserIds,
      groupRecipientDeviceCount: otherMembers.length,
      groupCiphertext: encryptedMessageBase64,
      ...(preparedPayload.senderKeyDistributionId && {
        groupSenderKeyDistributionId: preparedPayload.senderKeyDistributionId,
      }),
      ...(groupSharedMessage && { groupSharedMessage }),
      ...(options.contentHint !== undefined && { contentHint: options.contentHint }),
    };
    await storeSendLog(context, intent, contentBytes);
    await storeOutgoingMessageIntent(context.storage, intent);
    if (context.deviceSets && context.relay) {
      return sendDeclaredGroupIntent(context, context.deviceSets, intent, plaintextBytes);
    }
    return sendStoredGroupIntent(context, intent, plaintextBytes);
  });
}
