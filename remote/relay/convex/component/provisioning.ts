import { v } from 'convex/values';
import {
  MAX_DEVICES,
  PROVISIONING_SESSION_TTL_MS,
} from '../../../../device/constants';
import { mutation, query } from './_generated/server';
import type { MutationCtx, QueryCtx } from './_generated/server';
import { callerIdentityArgs, rememberAccount } from './accounts';
import { purgeDeviceStorage } from './devices';
import { relayError, unauthorized } from './errors';

const statusValidator = v.union(
  v.literal('waiting'),
  v.literal('connected'),
  v.literal('ready'),
  v.literal('linked_pending_ack'),
  v.literal('completed'),
  v.literal('rolled_back'),
  v.literal('expired')
);

const deviceMetadataValidator = v.object({
  platform: v.optional(v.string()),
  appVersion: v.optional(v.string()),
  osVersion: v.optional(v.string()),
});

async function session(
  ctx: MutationCtx | QueryCtx,
  sessionId: string
) {
  return await ctx.db
    .query('provisioningSessions')
    .withIndex('by_session_id', (q) => q.eq('sessionId', sessionId))
    .unique();
}

function requireOwner(
  row: { userId: string },
  callerUserId: string
): void {
  if (row.userId !== callerUserId) {
    throw unauthorized(
      'the provisioning session belongs to another account'
    );
  }
}

/**
 * Reject an expired session. Deliberately throw-only: a mutation throw
 * rolls the whole transaction back, so a `patch({status: 'expired'})`
 * before a throw would never persist. Expired rows are simply rejected
 * here and garbage-collected (with device teardown where owed) by the
 * every-minute cleanup cron; `getProvisioningMessage` reports expiry as
 * a computed status.
 */
function requireLive(
  row: { expiresAt: number },
  sessionId: string
): void {
  if (row.expiresAt <= Date.now()) {
    throw relayError(
      'CONFLICT',
      409,
      `Provisioning session ${sessionId} expired`
    );
  }
}

export const createProvisioningSession = mutation({
  args: {
    ...callerIdentityArgs,
    ephemeralPublicKey: v.string(),
  },
  returns: v.object({ sessionId: v.string() }),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const now = Date.now();
    const reserved = new Set<number>();
    const devices = await ctx.db
      .query('devices')
      .withIndex('by_user_id', (q) =>
        q.eq('userId', input.callerUserId)
      )
      .take(MAX_DEVICES);
    for (const device of devices) {
      if (
        device.deviceId !== 1 &&
        device.registered &&
        device.linked
      ) {
        reserved.add(device.deviceId);
      }
    }
    const sessions = await ctx.db
      .query('provisioningSessions')
      .withIndex('by_user_id', (q) =>
        q.eq('userId', input.callerUserId)
      )
      .order('desc')
      .take(32);
    for (const candidate of sessions) {
      // `expired` is never stored, so live-vs-dead is purely the
      // expiresAt comparison plus the two terminal statuses.
      if (
        candidate.assignedDeviceId !== undefined &&
        candidate.expiresAt > now &&
        candidate.status !== 'completed' &&
        candidate.status !== 'rolled_back'
      ) {
        reserved.add(candidate.assignedDeviceId);
      }
    }
    const assignedDeviceId = Array.from(
      { length: MAX_DEVICES - 1 },
      (_, index) => index + 2
    ).find((deviceId) => !reserved.has(deviceId));
    if (assignedDeviceId === undefined) {
      throw relayError(
        'CONFLICT',
        409,
        `No linked device slots available for ${input.callerUserId}`
      );
    }
    const sessionId = crypto.randomUUID();
    await ctx.db.insert('provisioningSessions', {
      sessionId,
      userId: input.callerUserId,
      ephemeralPublicKey: input.ephemeralPublicKey,
      assignedDeviceId,
      status: 'waiting',
      createdAt: now,
      expiresAt: now + PROVISIONING_SESSION_TTL_MS,
    });
    return { sessionId };
  },
});

export const connectNewDevice = mutation({
  args: {
    ...callerIdentityArgs,
    sessionId: v.string(),
    ephemeralPublicKey: v.string(),
    deviceMetadata: deviceMetadataValidator,
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const row = await session(ctx, input.sessionId);
    if (!row) {
      throw relayError(
        'NOT_FOUND',
        404,
        `Provisioning session ${input.sessionId} not found`
      );
    }
    requireOwner(row, input.callerUserId);
    if (row.status !== 'waiting') {
      throw relayError(
        'CONFLICT',
        409,
        `Provisioning session ${input.sessionId} is not in waiting state`
      );
    }
    requireLive(row, input.sessionId);
    await ctx.db.patch(row._id, {
      newDeviceEphemeralPublicKey: input.ephemeralPublicKey,
      deviceMetadata: input.deviceMetadata,
      status: 'connected',
    });
    return null;
  },
});

export const sendProvisioningMessage = mutation({
  args: {
    ...callerIdentityArgs,
    sessionId: v.string(),
    encryptedMessage: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const row = await session(ctx, input.sessionId);
    if (!row) {
      throw relayError(
        'NOT_FOUND',
        404,
        `Provisioning session ${input.sessionId} not found`
      );
    }
    requireOwner(row, input.callerUserId);
    requireLive(row, input.sessionId);
    if (row.status !== 'connected') {
      throw relayError(
        'CONFLICT',
        409,
        `Provisioning session ${input.sessionId} is not in connected state`
      );
    }
    await ctx.db.patch(row._id, {
      encryptedMessage: input.encryptedMessage,
      status: 'ready',
    });
    return null;
  },
});

export const getProvisioningMessage = query({
  args: {
    ...callerIdentityArgs,
    sessionId: v.string(),
  },
  returns: v.object({
    status: statusValidator,
    message: v.union(v.string(), v.null()),
    expiresAt: v.union(v.number(), v.null()),
  }),
  handler: async (ctx, input) => {
    const row = await session(ctx, input.sessionId);
    if (!row) {
      return { status: 'expired' as const, message: null, expiresAt: null };
    }
    requireOwner(row, input.callerUserId);
    // Expiry is a computed status: `expired` is never stored (a mutation
    // throw rolls back any patch, and the cleanup cron deletes expired rows
    // outright). Date.now() in a query is fixed per transaction and cached
    // with the result, so a subscribed client will not observe this branch
    // flip on wall-clock time alone — `expiresAt` is returned so clients can
    // compute expiry locally; the cron's row deletion invalidates the
    // subscription as a backstop.
    if (
      row.status !== 'completed' &&
      row.status !== 'rolled_back' &&
      row.expiresAt <= Date.now()
    ) {
      return {
        status: 'expired' as const,
        message: null,
        expiresAt: row.expiresAt,
      };
    }
    return {
      status: row.status,
      message:
        row.status === 'ready' || row.status === 'linked_pending_ack'
          ? (row.encryptedMessage ?? null)
          : null,
      expiresAt: row.expiresAt,
    };
  },
});

export const completeProvisioning = mutation({
  args: {
    ...callerIdentityArgs,
    sessionId: v.string(),
    deviceMetadata: v.object({
      encryptedDeviceName: v.bytes(),
      platform: v.optional(v.string()),
      appVersion: v.optional(v.string()),
      osVersion: v.optional(v.string()),
    }),
  },
  returns: v.object({ deviceId: v.number() }),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const row = await session(ctx, input.sessionId);
    if (!row) {
      throw relayError(
        'NOT_FOUND',
        404,
        `Provisioning session ${input.sessionId} not found`
      );
    }
    requireOwner(row, input.callerUserId);
    // Reject completion of an expired session — including one already in
    // `linked_pending_ack`, whose device the cleanup cron is entitled to
    // reap. Waving expired sessions through here is exactly the stranded
    // device hazard: a success response for a device the server is about
    // to erase.
    requireLive(row, input.sessionId);
    if (
      row.status !== 'ready' &&
      row.status !== 'linked_pending_ack'
    ) {
      throw relayError(
        'CONFLICT',
        409,
        `Provisioning session ${input.sessionId} is not ready`
      );
    }
    if (row.assignedDeviceId === undefined) {
      throw relayError(
        'CONFLICT',
        409,
        `Provisioning session ${input.sessionId} has no assigned device ID`
      );
    }
    if (row.status === 'linked_pending_ack') {
      return { deviceId: row.assignedDeviceId };
    }
    const existing = await ctx.db
      .query('devices')
      .withIndex('by_user_id_and_device_id', (q) =>
        q
          .eq('userId', row.userId)
          .eq('deviceId', row.assignedDeviceId!)
      )
      .unique();
    if (existing?.registered && existing.linked) {
      throw relayError(
        'CONFLICT',
        409,
        `Provisioning session ${input.sessionId} has no available linked device slot`
      );
    }
    const now = Date.now();
    const state = {
      userId: row.userId,
      deviceId: row.assignedDeviceId,
      encryptedDeviceName: input.deviceMetadata.encryptedDeviceName,
      deviceType: 'mobile' as const,
      registered: true,
      linked: true,
      enabled: true,
      active: true,
      lastSeen: now,
      createdAt: now,
      linkedAt: now,
      linkToken: crypto.randomUUID(),
    };
    if (existing) {
      await ctx.db.replace(existing._id, state);
    } else {
      await ctx.db.insert('devices', state);
    }
    // Grant the acknowledgment its own full TTL window. Without this the
    // ack deadline is whatever remains of the original session TTL — a
    // session completed near the edge leaves the new device seconds before
    // the cron deletes it, after the client has already persisted identity
    // keys and group state. Record the device's link token so teardown
    // deletes only the device this session created: device rows are reused
    // across registrations (`db.replace` keeps the row id), so the token —
    // not the row id, the slot number, or a wall-clock stamp two links can
    // share — is the identity.
    await ctx.db.patch(row._id, {
      status: 'linked_pending_ack',
      expiresAt: now + PROVISIONING_SESSION_TTL_MS,
      linkedDeviceToken: state.linkToken,
    });
    return { deviceId: row.assignedDeviceId };
  },
});

export const acknowledgeProvisioning = mutation({
  args: {
    ...callerIdentityArgs,
    sessionId: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const row = await session(ctx, input.sessionId);
    if (!row) {
      throw relayError(
        'NOT_FOUND',
        404,
        `Provisioning session ${input.sessionId} not found`
      );
    }
    requireOwner(row, input.callerUserId);
    if (row.status !== 'linked_pending_ack') {
      throw relayError(
        'CONFLICT',
        409,
        `Provisioning session ${input.sessionId} is not awaiting acknowledgment`
      );
    }
    // An expired ack window is a rolled-back link, not a race the ack can
    // win: without this guard, whether the device survives is decided by
    // whether the ack beats the next cleanup-cron tick.
    requireLive(row, input.sessionId);
    await ctx.db.patch(row._id, {
      status: 'completed',
      encryptedMessage: undefined,
      newDeviceEphemeralPublicKey: undefined,
    });
    return null;
  },
});

async function rollback(
  ctx: MutationCtx,
  row: Awaited<ReturnType<typeof session>>
): Promise<void> {
  if (
    !row ||
    row.assignedDeviceId === undefined ||
    row.status !== 'linked_pending_ack'
  ) {
    return;
  }
  await teardownLinkedDevice(ctx, row);
  await ctx.db.patch(row._id, { status: 'rolled_back' });
}

/**
 * Delete the device a `linked_pending_ack` session created — and only that
 * device. The link token recorded at completion is the identity check:
 * device rows are reused across registrations, so matching on
 * (userId, deviceId) alone would delete an unrelated device that was
 * legitimately re-registered into the freed slot. Cascades through
 * `purgeDeviceStorage` so no key material survives a reaped device.
 */
export async function teardownLinkedDevice(
  ctx: MutationCtx,
  row: {
    userId: string;
    assignedDeviceId?: number;
    linkedDeviceToken?: string;
  }
): Promise<void> {
  if (
    row.assignedDeviceId === undefined ||
    row.linkedDeviceToken === undefined
  ) {
    return;
  }
  const linkedDevice = await ctx.db
    .query('devices')
    .withIndex('by_user_id_and_device_id', (q) =>
      q.eq('userId', row.userId).eq('deviceId', row.assignedDeviceId!)
    )
    .unique();
  if (
    !linkedDevice ||
    linkedDevice.linkToken !== row.linkedDeviceToken
  ) {
    return;
  }
  await ctx.db.delete(linkedDevice._id);
  await purgeDeviceStorage(ctx, row.userId, row.assignedDeviceId);
}

export const rollbackProvisioning = mutation({
  args: {
    ...callerIdentityArgs,
    sessionId: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const row = await session(ctx, input.sessionId);
    if (row) {
      requireOwner(row, input.callerUserId);
      await rollback(ctx, row);
    }
    return null;
  },
});

export const deleteProvisioningSession = mutation({
  args: {
    ...callerIdentityArgs,
    sessionId: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const row = await session(ctx, input.sessionId);
    if (!row) return null;
    requireOwner(row, input.callerUserId);
    await rollback(ctx, row);
    await ctx.db.delete(row._id);
    return null;
  },
});
