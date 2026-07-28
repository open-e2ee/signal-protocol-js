import {
  MINUTE,
  RateLimiter,
  isRateLimitError,
} from '@convex-dev/rate-limiter';
import { ConvexError, v } from 'convex/values';
import {
  base64ToBytes,
  bytesToBase64,
} from '../../../../internal/crypto/utils';
import { MAX_DEVICES } from '../../../../device/constants';
import { serializeReceivedMessage } from '../../../../internal/protocol/sealed-sender/v2-binary';
import { asBase64 } from '../../../../types/utils';
import { components } from './_generated/api';
import { mutation, query } from './_generated/server';
import type { MutationCtx } from './_generated/server';
import {
  authorizeAccessKey,
  authorizeGroupSendToken,
  callerIdentityArgs,
  rememberAccount,
} from './accounts';
import { relayError, unauthorized } from './errors';

const MESSAGE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_PENDING_MESSAGES = 1000;
const MAX_PENDING_RETRY_REQUESTS = 1000;
const MAX_MULTI_RECIPIENT_DEVICES = 1000;

/**
 * Ceiling on a single message's content, before base64 framing.
 *
 * 96 KiB for a single-recipient envelope and 256 KiB for the shared
 * multi-recipient payload, matching the reference implementation's bounds.
 * The columns are base64 strings, so the byte ceilings are enforced as
 * string-length ceilings: base64 emits 4 characters per started group of 3
 * bytes, which is 4 * ceil(n / 3) — the ceiling belongs inside the division,
 * or a payload whose size is not a multiple of 3 encodes 2 characters past
 * the advertised limit and full-size messages are refused.
 */
const base64LengthOf = (byteLength: number): number =>
  4 * Math.ceil(byteLength / 3);
const MAX_MESSAGE_BYTES = 96 * 1024;
const MAX_MULTI_RECIPIENT_MESSAGE_BYTES = 256 * 1024;
const MAX_CIPHERTEXT_LENGTH = base64LengthOf(MAX_MESSAGE_BYTES);
const MAX_MULTI_RECIPIENT_CIPHERTEXT_LENGTH = base64LengthOf(
  MAX_MULTI_RECIPIENT_MESSAGE_BYTES
);

/**
 * Inbound budget per recipient, spent in ciphertext bytes.
 *
 * Keyed by the *target*, because that is the only stable identity on these
 * paths: a sealed sender is anonymous by design, so any per-sender limit is
 * either meaningless or a hole. The reference implementation bounds inbound
 * message bytes per destination the same way, on its identified and sealed
 * single-recipient paths alike.
 *
 * What this closes is unbounded queue flooding: without it, one anonymous
 * caller holding a valid access key — or any account-authenticated caller on
 * the identified path — can grow a victim's `messages` table without limit
 * for the whole retention window. The budget is generous for real traffic
 * (sealed envelopes run 1-2 KiB, so the sustained rate is hundreds of
 * messages a minute per recipient) and fatal for floods.
 *
 * The multi-recipient path is deliberately not metered, matching the
 * reference: a group-send token already prices that path, and a per-recipient
 * budget there would let one noisy group partially starve delivery to its
 * quietest member. Verified against the reference's MessageController: its
 * inbound-bytes limiter is validated only in `sendIndividualMessage`, never
 * on the multi-recipient route. Metering here would also have to fail the
 * whole fan-out rather than one recipient, since the charge and the inserts
 * share a transaction — so a single recipient at their ceiling would block
 * delivery to everyone else in the call.
 *
 * What the exemption assumes is that one call fans out to distinct devices.
 * The reference gets that from its wire format, which parses recipients into
 * a map keyed by service ID; the flat array here does not, so the handler
 * rejects a repeated device explicitly.
 */
const rateLimiter = new RateLimiter(components.rateLimiter, {
  inboundMessageBytes: {
    kind: 'token bucket',
    rate: 1024 * 1024,
    period: MINUTE,
    capacity: 4 * 1024 * 1024,
  },
  // Sub-limit for the identified path, keyed by (sender, target). The
  // shared per-target bucket is forced on the sealed path — there is no
  // sender identity to key on — but on the identified path there is one,
  // and without this a single authenticated account could drain a victim's
  // whole shared budget and 429 every other sender indefinitely. A quarter
  // of the shared bucket keeps one sender from monopolizing it while
  // leaving any real conversation far below the ceiling.
  inboundMessageBytesPerSender: {
    kind: 'token bucket',
    rate: 256 * 1024,
    period: MINUTE,
    capacity: 1024 * 1024,
  },
  // Counted, not metered by size: a retry request is a fixed-shape row. A
  // client coming back from a broken session legitimately asks for one per
  // message it could not decrypt, so the burst allowance is generous; what
  // it refuses is a caller that keeps asking indefinitely.
  retryRequests: {
    kind: 'token bucket',
    rate: 120,
    period: MINUTE,
    capacity: 240,
  },
});

/** Approximate decoded size of a base64 column, for budget accounting. */
function ciphertextBytes(encoded: string): number {
  return Math.floor((encoded.length * 3) / 4);
}

function requireCiphertextWithin(
  encoded: string,
  maxLength: number
): void {
  if (encoded.length > maxLength) {
    throw relayError(
      'INVALID_REQUEST',
      413,
      'Message content exceeds the maximum size'
    );
  }
}

/**
 * Re-throw a limiter rejection as a 429, or pass anything else through.
 *
 * The component's limiter writes inside the caller's transaction, so this
 * only ever shapes the error — the charges themselves are undone by the
 * throw, whichever limit produced it.
 */
function rethrowRateLimited(error: unknown, message: string): never {
  if (isRateLimitError(error)) {
    throw relayError('RATE_LIMITED', 429, message, {
      retryAfter: error.data.retryAfter,
    });
  }
  if (error instanceof ConvexError) {
    const data = error.data as { kind?: unknown; retryAfter?: unknown };
    if (data.kind === 'RateLimited') {
      throw relayError('RATE_LIMITED', 429, message, {
        retryAfter:
          typeof data.retryAfter === 'number' ? data.retryAfter : undefined,
      });
    }
  }
  throw error;
}

async function chargeInboundBudget(
  ctx: MutationCtx,
  targetUserId: string,
  bytes: number,
  senderUserId?: string
): Promise<void> {
  try {
    // Order between the two buckets carries no meaning: both charges are
    // written in this mutation's transaction, so whichever limit throws
    // discards the other's spend along with everything else. The sub-limit
    // runs first only because it is the more specific diagnosis of the two.
    if (senderUserId !== undefined) {
      await rateLimiter.limit(ctx, 'inboundMessageBytesPerSender', {
        key: JSON.stringify([senderUserId, targetUserId]),
        count: bytes,
        throws: true,
      });
    }
    await rateLimiter.limit(ctx, 'inboundMessageBytes', {
      key: targetUserId,
      count: bytes,
      throws: true,
    });
  } catch (error) {
    rethrowRateLimited(
      error,
      'Inbound message rate limit exceeded for this recipient'
    );
  }
}

/**
 * Bound how fast one account can create retry-request rows.
 *
 * These rows carry no caller-supplied content, so there is nothing to bound
 * by size — the cost is the row itself, held for the full retention window.
 * Nothing else on this path constrains them: the request names an original
 * sender it never has to have talked to, so there is no relationship to
 * check either.
 */
async function chargeRetryRequest(
  ctx: MutationCtx,
  requesterUserId: string
): Promise<void> {
  try {
    await rateLimiter.limit(ctx, 'retryRequests', {
      key: requesterUserId,
      throws: true,
    });
  } catch (error) {
    rethrowRateLimited(error, 'Retry-request rate limit exceeded');
  }
}

/**
 * Reject a sealed single-recipient send whose target device does not exist.
 *
 * The multi-recipient path already reports unknown devices through
 * `uuids404`, and the reference implementation refuses sealed sends to
 * unknown destinations outright. Without this check the path is a write
 * primitive for rows nothing will ever read: an anonymous caller can address
 * arbitrary device IDs and every insert sits in the table for the full
 * retention window.
 */
async function requireActiveDevice(
  ctx: MutationCtx,
  userId: string,
  deviceId: number
): Promise<void> {
  const device = await ctx.db
    .query('devices')
    .withIndex('by_user_id_and_device_id', (q) =>
      q.eq('userId', userId).eq('deviceId', deviceId)
    )
    .unique();
  if (!device?.registered || !device.enabled) {
    throw relayError('NOT_FOUND', 404, 'Unknown destination device');
  }
}

const messageTypeValidator = v.union(
  v.literal('ciphertext'),
  v.literal('prekey_bundle'),
  v.literal('sender_key'),
  v.literal('server_delivery_receipt'),
  v.literal('unidentified_sender')
);

const receiptValidator = v.object({
  messageId: v.string(),
  serverTimestamp: v.number(),
});

const pendingMessageValidator = v.object({
  id: v.string(),
  targetUserId: v.string(),
  targetDeviceId: v.number(),
  senderUserId: v.string(),
  senderDeviceId: v.number(),
  ciphertext: v.string(),
  messageType: messageTypeValidator,
  urgent: v.optional(v.boolean()),
  ephemeral: v.optional(v.boolean()),
  timestamp: v.number(),
  serverTimestamp: v.number(),
  clientMessageId: v.optional(v.string()),
  expiresAt: v.number(),
});

const retryReasonValidator = v.union(
  v.literal('NO_SESSION'),
  v.literal('DECRYPTION_FAILED'),
  v.literal('SESSION_EXPIRED'),
  v.literal('INVALID_MESSAGE'),
  v.literal('STALE_DEVICE_LIST'),
  v.literal('IDENTITY_KEY_MISMATCH')
);

type StoredMessage = {
  targetUserId: string;
  targetDeviceId: number;
  senderUserId: string;
  senderDeviceId: number;
  ciphertext: string;
  messageType:
    | 'ciphertext'
    | 'prekey_bundle'
    | 'sender_key'
    | 'server_delivery_receipt'
    | 'unidentified_sender';
  urgent?: boolean;
  ephemeral?: boolean;
  timestamp: number;
  clientMessageId?: string;
};

async function insertMessage(
  ctx: MutationCtx,
  input: StoredMessage
): Promise<{ messageId: string; serverTimestamp: number }> {
  if (input.clientMessageId !== undefined) {
    const existing = await ctx.db
      .query('messages')
      .withIndex('by_target_and_client_message_id', (q) =>
        q
          .eq('targetUserId', input.targetUserId)
          .eq('targetDeviceId', input.targetDeviceId)
          .eq('senderUserId', input.senderUserId)
          .eq('clientMessageId', input.clientMessageId)
      )
      .unique();
    if (existing) {
      return {
        messageId: existing.messageId,
        serverTimestamp: existing.serverTimestamp,
      };
    }
  }
  const serverTimestamp = Date.now();
  const messageId = crypto.randomUUID();
  await ctx.db.insert('messages', {
    ...input,
    messageId,
    serverTimestamp,
    expiresAt: serverTimestamp + MESSAGE_TTL_MS,
  });
  return { messageId, serverTimestamp };
}

export const send = mutation({
  args: {
    ...callerIdentityArgs,
    targetUserId: v.string(),
    targetDeviceId: v.number(),
    senderDeviceId: v.number(),
    ciphertext: v.string(),
    messageType: messageTypeValidator,
    urgent: v.optional(v.boolean()),
    ephemeral: v.optional(v.boolean()),
    timestamp: v.number(),
    clientMessageId: v.optional(v.string()),
    recipientRegistrationId: v.optional(v.number()),
  },
  returns: receiptValidator,
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    requireCiphertextWithin(input.ciphertext, MAX_CIPHERTEXT_LENGTH);
    if (input.recipientRegistrationId !== undefined) {
      const registration = await ctx.db
        .query('identityRegistrations')
        .withIndex(
          'by_user_id_and_device_id_and_identity_type',
          (q) =>
            q
              .eq('userId', input.targetUserId)
              .eq('deviceId', input.targetDeviceId)
              .eq('identityType', 'aci')
        )
        .unique();
      if (
        registration &&
        registration.registrationId !== input.recipientRegistrationId
      ) {
        // Names only the stale device, matching the reference's 410 body.
        // The current registration ID stays out: the sender re-fetches the
        // prekey bundle to recover, and that path is rate limited, whereas
        // this one would otherwise hand any account-authenticated caller a
        // free oracle for registration-ID changes on arbitrary devices.
        throw relayError(
          'STALE_DEVICE',
          410,
          'Recipient device registration changed',
          {
            staleDevices: [input.targetDeviceId],
            reason: 'device_reinstalled',
          }
        );
      }
    }
    // Placed after the registration check for readability, not for safety: a
    // send that 410s could charge first and still cost nothing, because the
    // throw rolls the charge back with the rest of the mutation. Nothing on
    // this path depends on the order.
    await chargeInboundBudget(
      ctx,
      input.targetUserId,
      ciphertextBytes(input.ciphertext),
      input.callerUserId
    );
    return await insertMessage(ctx, {
      targetUserId: input.targetUserId,
      targetDeviceId: input.targetDeviceId,
      senderUserId: input.callerUserId,
      senderDeviceId: input.senderDeviceId,
      ciphertext: input.ciphertext,
      messageType: input.messageType,
      urgent: input.urgent,
      ephemeral: input.ephemeral,
      timestamp: input.timestamp,
      clientMessageId: input.clientMessageId,
    });
  },
});

export const getPendingMessages = query({
  args: {
    ...callerIdentityArgs,
    deviceId: v.number(),
  },
  returns: v.array(pendingMessageValidator),
  handler: async (ctx, input) => {
    // Read-time expiry filter: the hourly cron eventually deletes expired
    // rows, but until it runs they must neither be delivered nor consume
    // the pending-message budget.
    //
    // Date.now() is fixed per transaction and cached with the query result,
    // so a subscribed client does not see a row drop out the instant it
    // expires — only when a write to this index range invalidates the
    // subscription, which any new message for this device or the cron's
    // delete does. Staleness is therefore bounded by the cron interval, and
    // the effect is a message delivered late rather than one delivered
    // wrongly: expiresAt is a retention bound, not an authorization gate.
    const now = Date.now();
    const rows = (
      await ctx.db
        .query('messages')
        .withIndex('by_target_user_id_and_target_device_id', (q) =>
          q
            .eq('targetUserId', input.callerUserId)
            .eq('targetDeviceId', input.deviceId)
        )
        .take(MAX_PENDING_MESSAGES)
    ).filter((row) => row.expiresAt > now);
    return rows.map(
      ({
        messageId,
        targetUserId,
        targetDeviceId,
        senderUserId,
        senderDeviceId,
        ciphertext,
        messageType,
        urgent,
        ephemeral,
        timestamp,
        serverTimestamp,
        clientMessageId,
        expiresAt,
      }) => ({
        id: messageId,
        targetUserId,
        targetDeviceId,
        senderUserId,
        senderDeviceId,
        ciphertext,
        messageType,
        urgent,
        ephemeral,
        timestamp,
        serverTimestamp,
        clientMessageId,
        expiresAt,
      })
    );
  },
});

export const markDelivered = mutation({
  args: {
    ...callerIdentityArgs,
    messageId: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const message = await ctx.db
      .query('messages')
      .withIndex('by_message_id', (q) =>
        q.eq('messageId', input.messageId)
      )
      .unique();
    if (!message) return null;
    if (message.targetUserId !== input.callerUserId) {
      throw unauthorized(
        'only the target account can mark a message delivered'
      );
    }
    await ctx.db.delete(message._id);
    return null;
  },
});

// There is deliberately no `getGroupMembers` endpoint, and the component
// derives no membership map from group state: group authorization is proved
// entirely by zero-knowledge presentations, so `groups` rows never name an
// account. Membership is local-first — senders resolve fan-out recipients
// from their own decrypted group state and supply them to the send path.
//
// Nothing a `messages` row stores *names* a group either. The row carries a
// `sender_key` message type, which says the payload is group traffic without
// saying which group, and the distribution identifier inside the frame is
// opaque.
//
// That closes the group's name, not the group partition, and the difference is
// easy to overstate. The distribution identifier is unencrypted, sits inside
// the `ciphertext` column, and is stable for the life of a sender key — keys
// rotate on membership change, never on a timer — so grouping rows by it
// recovers a sender's group traffic. One send also produces byte-identical
// ciphertext on every recipient row, and the multi-recipient sealed path is
// handed the roster outright. An operator therefore sees who talked to whom
// and can partition those pairs into unlabeled groups; what it cannot do is
// put a meaningful, cross-send label on one. See the group metadata privacy
// note in README.md, which states the remaining channels in full.

export const getActiveDevices = query({
  args: {
    ...callerIdentityArgs,
    userId: v.string(),
  },
  returns: v.array(
    v.object({
      userId: v.string(),
      deviceId: v.number(),
    })
  ),
  handler: async (ctx, input) => {
    const rows = await ctx.db
      .query('devices')
      .withIndex('by_user_id', (q) => q.eq('userId', input.userId))
      .take(MAX_DEVICES);
    return rows
      .filter((row) => row.registered && row.enabled)
      .map((row) => ({
        userId: input.userId,
        deviceId: row.deviceId,
      }));
  },
});

async function authorizeUnidentified(
  ctx: MutationCtx,
  recipients: Array<{ userId: string; aciBytes?: ArrayBuffer }>,
  auth: {
    unidentifiedAccessKey?: string;
    groupSendToken?: ArrayBuffer;
  }
): Promise<void> {
  const hasAccessKey = auth.unidentifiedAccessKey !== undefined;
  const hasGroupToken = auth.groupSendToken !== undefined;
  if (hasAccessKey === hasGroupToken) {
    throw unauthorized(
      'exactly one sealed-sender authorization is required'
    );
  }
  if (auth.groupSendToken !== undefined) {
    // The caller names the ACI it claims for each recipient so the token —
    // which endorses ACIs, not user IDs — can be verified before any account
    // is read. See authorizeGroupSendToken for why that ordering matters.
    const named: Array<{ userId: string; aciBytes: ArrayBuffer }> = [];
    for (const recipient of recipients) {
      if (recipient.aciBytes === undefined) {
        throw unauthorized(
          'a group-send token requires an ACI for every recipient'
        );
      }
      named.push({ userId: recipient.userId, aciBytes: recipient.aciBytes });
    }
    await authorizeGroupSendToken(ctx, named, auth.groupSendToken);
    return;
  }
  const distinctRecipients = [
    ...new Set(recipients.map((recipient) => recipient.userId)),
  ];
  for (const userId of distinctRecipients) {
    await authorizeAccessKey(
      ctx,
      userId,
      auth.unidentifiedAccessKey!
    );
  }
}

export const sendUnidentified = mutation({
  args: {
    targetUserId: v.string(),
    targetDeviceId: v.number(),
    /** The recipient ACI the caller claims; required with a group-send
     * token, which endorses ACIs rather than user IDs. */
    targetAciBytes: v.optional(v.bytes()),
    ciphertext: v.string(),
    timestamp: v.number(),
    clientMessageId: v.optional(v.string()),
    unidentifiedAccessKey: v.optional(v.string()),
    groupSendToken: v.optional(v.bytes()),
  },
  returns: receiptValidator,
  handler: async (ctx, input) => {
    requireCiphertextWithin(input.ciphertext, MAX_CIPHERTEXT_LENGTH);
    await authorizeUnidentified(
      ctx,
      [{ userId: input.targetUserId, aciBytes: input.targetAciBytes }],
      input
    );
    await requireActiveDevice(
      ctx,
      input.targetUserId,
      input.targetDeviceId
    );
    await chargeInboundBudget(
      ctx,
      input.targetUserId,
      ciphertextBytes(input.ciphertext)
    );
    return await insertMessage(ctx, {
      targetUserId: input.targetUserId,
      targetDeviceId: input.targetDeviceId,
      senderUserId: '',
      senderDeviceId: 0,
      ciphertext: input.ciphertext,
      messageType: 'unidentified_sender',
      timestamp: input.timestamp,
      clientMessageId: input.clientMessageId,
    });
  },
});

const multiRecipientValidator = v.object({
  userId: v.string(),
  deviceId: v.number(),
  registrationId: v.number(),
  /** The recipient ACI the caller claims; required with a group-send token,
   * which endorses ACIs rather than user IDs. */
  aciBytes: v.optional(v.bytes()),
  encryptedMessageKeyBase64: v.string(),
  authenticationTagBase64: v.string(),
});

export const sendMultiRecipientUnidentified = mutation({
  args: {
    recipients: v.array(multiRecipientValidator),
    ephemeralPublicBase64: v.string(),
    messageCiphertextBase64: v.string(),
    timestamp: v.number(),
    clientMessageId: v.optional(v.string()),
    unidentifiedAccessKey: v.optional(v.string()),
    groupSendToken: v.optional(v.bytes()),
  },
  returns: v.object({
    messageId: v.string(),
    serverTimestamp: v.number(),
    uuids404: v.array(v.string()),
  }),
  handler: async (ctx, input) => {
    if (input.recipients.length > MAX_MULTI_RECIPIENT_DEVICES) {
      throw relayError(
        'INVALID_REQUEST',
        400,
        `Multi-recipient delivery supports at most ${MAX_MULTI_RECIPIENT_DEVICES} devices`
      );
    }
    requireCiphertextWithin(
      input.messageCiphertextBase64,
      MAX_MULTI_RECIPIENT_CIPHERTEXT_LENGTH
    );
    // Per-recipient key material is a fixed-size key and tag; the reference
    // budgets ~100 bytes per recipient block. 512 base64 characters is far
    // above any real encoding and far below a useful flood.
    //
    // One entry per (userId, deviceId). The fan-out below stores a full copy
    // of the shared ciphertext for every entry it accepts, so a request
    // naming one device N times stores N copies of it — and a group-send
    // token endorses the recipient *set*, saying nothing about how many
    // times a member may appear in it. Rejecting rather than collapsing: a
    // repeat is a client bug, and quietly picking one of two conflicting key
    // blocks would bury it.
    const seenDevices = new Set<string>();
    for (const recipient of input.recipients) {
      requireCiphertextWithin(recipient.encryptedMessageKeyBase64, 512);
      requireCiphertextWithin(recipient.authenticationTagBase64, 512);
      const deviceKey = JSON.stringify([recipient.userId, recipient.deviceId]);
      if (seenDevices.has(deviceKey)) {
        throw relayError(
          'INVALID_REQUEST',
          400,
          'Multi-recipient delivery names the same device more than once'
        );
      }
      seenDevices.add(deviceKey);
    }
    await authorizeUnidentified(
      ctx,
      input.recipients.map((recipient) => ({
        userId: recipient.userId,
        aciBytes: recipient.aciBytes,
      })),
      input
    );
    const ephemeralPublic = base64ToBytes(
      asBase64(input.ephemeralPublicBase64)
    );
    const messageCiphertext = base64ToBytes(
      asBase64(input.messageCiphertextBase64)
    );
    let first:
      { messageId: string; serverTimestamp: number } | undefined;
    const uuids404 = new Set<string>();
    for (const recipient of input.recipients) {
      const device = await ctx.db
        .query('devices')
        .withIndex('by_user_id_and_device_id', (q) =>
          q
            .eq('userId', recipient.userId)
            .eq('deviceId', recipient.deviceId)
        )
        .unique();
      if (!device?.registered || !device.enabled) {
        uuids404.add(recipient.userId);
        continue;
      }
      const registration = await ctx.db
        .query('identityRegistrations')
        .withIndex(
          'by_user_id_and_device_id_and_identity_type',
          (q) =>
            q
              .eq('userId', recipient.userId)
              .eq('deviceId', recipient.deviceId)
              .eq('identityType', 'aci')
        )
        .unique();
      if (
        registration &&
        registration.registrationId !== recipient.registrationId
      ) {
        uuids404.add(recipient.userId);
        continue;
      }
      const receivedMessage = serializeReceivedMessage(
        base64ToBytes(asBase64(recipient.encryptedMessageKeyBase64)),
        base64ToBytes(asBase64(recipient.authenticationTagBase64)),
        ephemeralPublic,
        messageCiphertext
      );
      const result = await insertMessage(ctx, {
        targetUserId: recipient.userId,
        targetDeviceId: recipient.deviceId,
        senderUserId: '',
        senderDeviceId: 0,
        ciphertext: bytesToBase64(receivedMessage),
        messageType: 'unidentified_sender',
        timestamp: input.timestamp,
        clientMessageId: input.clientMessageId,
      });
      first ??= result;
    }
    const fallbackTimestamp = Date.now();
    return {
      messageId: first?.messageId ?? `multi-${crypto.randomUUID()}`,
      serverTimestamp: first?.serverTimestamp ?? fallbackTimestamp,
      uuids404: [...uuids404],
    };
  },
});

export const sendRetryRequest = mutation({
  args: {
    ...callerIdentityArgs,
    requesterDeviceId: v.number(),
    originalSenderUserId: v.string(),
    originalSenderDeviceId: v.number(),
    failedTimestamp: v.number(),
    timestamp: v.number(),
    reason: retryReasonValidator,
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    await chargeRetryRequest(ctx, input.callerUserId);
    await ctx.db.insert('retryRequests', {
      requestId: crypto.randomUUID(),
      requesterUserId: input.callerUserId,
      requesterDeviceId: input.requesterDeviceId,
      originalSenderUserId: input.originalSenderUserId,
      originalSenderDeviceId: input.originalSenderDeviceId,
      failedTimestamp: input.failedTimestamp,
      timestamp: input.timestamp,
      reason: input.reason,
      expiresAt: Date.now() + MESSAGE_TTL_MS,
    });
    return null;
  },
});

const retryRequestValidator = v.object({
  id: v.string(),
  requesterUserId: v.string(),
  requesterDeviceId: v.number(),
  originalSenderUserId: v.string(),
  originalSenderDeviceId: v.number(),
  failedTimestamp: v.number(),
  timestamp: v.number(),
  reason: retryReasonValidator,
});

export const getPendingRetryRequests = query({
  args: {
    ...callerIdentityArgs,
    deviceId: v.number(),
  },
  returns: v.array(retryRequestValidator),
  handler: async (ctx, input) => {
    // Same read-time expiry filter and the same transaction-fixed clock as
    // getPendingMessages: an expired retry request may survive in a cached
    // subscription until the hourly cron deletes it. Acting on a stale retry
    // request costs one redundant re-send, so the window is harmless.
    const now = Date.now();
    const rows = (
      await ctx.db
        .query('retryRequests')
        .withIndex(
          'by_original_sender_user_id_and_original_sender_device_id',
          (q) =>
            q
              .eq('originalSenderUserId', input.callerUserId)
              .eq('originalSenderDeviceId', input.deviceId)
        )
        .take(MAX_PENDING_RETRY_REQUESTS)
    ).filter((row) => row.expiresAt > now);
    return rows.map(({ requestId, ...request }) => ({
      id: requestId,
      requesterUserId: request.requesterUserId,
      requesterDeviceId: request.requesterDeviceId,
      originalSenderUserId: request.originalSenderUserId,
      originalSenderDeviceId: request.originalSenderDeviceId,
      failedTimestamp: request.failedTimestamp,
      timestamp: request.timestamp,
      reason: request.reason,
    }));
  },
});

export const markRetryRequestHandled = mutation({
  args: {
    ...callerIdentityArgs,
    requestId: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const request = await ctx.db
      .query('retryRequests')
      .withIndex('by_request_id', (q) =>
        q.eq('requestId', input.requestId)
      )
      .unique();
    if (!request) return null;
    if (request.originalSenderUserId !== input.callerUserId) {
      throw unauthorized(
        'only the original sender can handle a retry request'
      );
    }
    await ctx.db.delete(request._id);
    return null;
  },
});
