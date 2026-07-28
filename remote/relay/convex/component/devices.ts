import { v } from 'convex/values';
import { MAX_DEVICES } from '../../../../device/constants';
import { internal } from './_generated/api';
import {
  internalMutation,
  mutation,
  query,
} from './_generated/server';
import type { MutationCtx } from './_generated/server';
import type { Id, TableNames } from './_generated/dataModel';
import { callerIdentityArgs, rememberAccount } from './accounts';
import { relayError } from './errors';

/**
 * Rows a single teardown transaction will delete from the unbounded tables
 * before handing the rest to a scheduled continuation.
 *
 * A device's one-time prekeys and queued messages have no fixed ceiling: the
 * component marks a consumed prekey rather than deleting it, and no cron
 * reclaims consumed rows, so a long-lived device accumulates them for its
 * whole lifetime. Any single `.take(n)` therefore truncates rather than
 * drains for some device, which is what left orphaned key material behind a
 * removed device — rows keyed to a deviceId that a later link can reuse.
 */
export const PURGE_BUDGET = 512;

const deviceTypeValidator = v.union(
  v.literal('mobile'),
  v.literal('desktop'),
  v.literal('tablet'),
  v.literal('web')
);

const deviceValidator = v.object({
  deviceId: v.number(),
  encryptedDeviceName: v.optional(v.bytes()),
  deviceType: v.optional(deviceTypeValidator),
  registered: v.boolean(),
  linked: v.boolean(),
  enabled: v.boolean(),
  active: v.boolean(),
  lastSeen: v.number(),
  createdAt: v.number(),
  linkedAt: v.optional(v.number()),
});

async function device(
  ctx: MutationCtx,
  userId: string,
  deviceId: number
) {
  return await ctx.db
    .query('devices')
    .withIndex('by_user_id_and_device_id', (q) =>
      q.eq('userId', userId).eq('deviceId', deviceId)
    )
    .unique();
}

export const getDevices = query({
  args: {
    ...callerIdentityArgs,
    userId: v.string(),
  },
  returns: v.array(deviceValidator),
  handler: async (ctx, input) => {
    const rows = await ctx.db
      .query('devices')
      .withIndex('by_user_id', (q) => q.eq('userId', input.userId))
      .take(MAX_DEVICES);
    return rows.map(
      ({
        deviceId,
        encryptedDeviceName,
        deviceType,
        registered,
        linked,
        enabled,
        active,
        lastSeen,
        createdAt,
        linkedAt,
      }) => ({
        deviceId,
        encryptedDeviceName,
        deviceType,
        registered,
        linked,
        enabled,
        active,
        lastSeen,
        createdAt,
        linkedAt,
      })
    );
  },
});

export const registerDevice = mutation({
  args: {
    ...callerIdentityArgs,
    deviceId: v.optional(v.number()),
    encryptedDeviceName: v.optional(v.bytes()),
    deviceType: v.optional(deviceTypeValidator),
  },
  returns: v.object({ deviceId: v.number() }),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const existing = await ctx.db
      .query('devices')
      .withIndex('by_user_id', (q) =>
        q.eq('userId', input.callerUserId)
      )
      .take(MAX_DEVICES);
    const occupied = new Set(
      existing
        .filter((candidate) => candidate.registered)
        .map((candidate) => candidate.deviceId)
    );
    const requested = input.deviceId;
    if (
      requested !== undefined &&
      (!Number.isInteger(requested) ||
        requested < 1 ||
        requested > MAX_DEVICES)
    ) {
      throw relayError(
        'INVALID_REQUEST',
        400,
        `Device ID must be between 1 and ${MAX_DEVICES}`
      );
    }
    const assigned =
      requested ??
      Array.from(
        { length: MAX_DEVICES },
        (_, index) => index + 1
      ).find((candidate) => !occupied.has(candidate));
    if (assigned === undefined || occupied.has(assigned)) {
      throw relayError(
        'CONFLICT',
        409,
        'Maximum devices limit reached'
      );
    }
    const now = Date.now();
    const state = {
      userId: input.callerUserId,
      deviceId: assigned,
      encryptedDeviceName: input.encryptedDeviceName,
      deviceType: input.deviceType,
      registered: true,
      linked: assigned !== 1,
      enabled: true,
      active: false,
      lastSeen: now,
      createdAt: now,
      linkedAt: assigned === 1 ? undefined : now,
      // Minted on every registration, including one that replaces a row in
      // a freed slot, so a pending provisioning session's teardown cannot
      // mistake this device for the one it linked.
      linkToken: crypto.randomUUID(),
    };
    const reusable = existing.find(
      (candidate) => candidate.deviceId === assigned
    );
    if (reusable) {
      await ctx.db.replace(reusable._id, state);
    } else {
      await ctx.db.insert('devices', state);
    }
    return { deviceId: assigned };
  },
});

async function deleteRows(
  rows: Array<{ _id: Id<TableNames> }>,
  ctx: MutationCtx
): Promise<void> {
  for (const row of rows) {
    await ctx.db.delete(row._id);
  }
}

/**
 * Delete every row keyed to a device: identity registrations, all four
 * prekey kinds, sender certificates, queued messages, and heartbeats.
 * Shared by `removeDevice` and the provisioning teardown paths so a
 * device can never be deleted while its key material keeps serving
 * prekey bundles for a device that no longer exists.
 *
 * Deletes at most {@link PURGE_BUDGET} rows from the unbounded tables and
 * schedules itself to continue when it hits that budget, so a device with
 * more accumulated key material than one transaction can delete converges
 * across ticks instead of leaving the remainder orphaned.
 *
 * The bounded rows — identity registrations, signed and last-resort prekeys,
 * sender certificates, heartbeats — are always deleted in this first pass,
 * before any budget is spent. That ordering is what makes the continuation
 * safe to defer: `fetchPreKeyBundle` gates on the `identityRegistrations`
 * row, so once this returns, no bundle can be served for the device no
 * matter how many one-time prekeys are still queued for deletion.
 *
 * @returns `drained` — false when a continuation was scheduled.
 */
export async function purgeDeviceStorage(
  ctx: MutationCtx,
  userId: string,
  deviceId: number
): Promise<{ drained: boolean }> {
  const identityTypes = ['aci', 'pni'] as const;
  for (const identityType of identityTypes) {
    for (const table of [
      'identityRegistrations',
      'ecSignedPreKeys',
      'kemLastResortPreKeys',
      'senderCertificates',
    ] as const) {
      const rows = await ctx.db
        .query(table)
        .withIndex(
          'by_user_id_and_device_id_and_identity_type',
          (q) =>
            q
              .eq('userId', userId)
              .eq('deviceId', deviceId)
              .eq('identityType', identityType)
        )
        .take(1);
      await deleteRows(rows, ctx);
    }
  }
  await deleteRows(
    await ctx.db
      .query('deviceHeartbeats')
      .withIndex('by_user_id_and_device_id', (q) =>
        q.eq('userId', userId).eq('deviceId', deviceId)
      )
      .take(1),
    ctx
  );

  let budget = PURGE_BUDGET;
  const oneTimeKeyTables = ['ecPreKeys', 'kemOneTimePreKeys'] as const;
  for (const identityType of identityTypes) {
    for (const table of oneTimeKeyTables) {
      if (budget === 0) break;
      const rows = await ctx.db
        .query(table)
        .withIndex(
          'by_user_id_and_device_id_and_identity_type_and_consumed_at',
          (q) =>
            q
              .eq('userId', userId)
              .eq('deviceId', deviceId)
              .eq('identityType', identityType)
        )
        .take(budget);
      await deleteRows(rows, ctx);
      budget -= rows.length;
    }
  }
  if (budget > 0) {
    const rows = await ctx.db
      .query('messages')
      .withIndex('by_target_user_id_and_target_device_id', (q) =>
        q
          .eq('targetUserId', userId)
          .eq('targetDeviceId', deviceId)
      )
      .take(budget);
    await deleteRows(rows, ctx);
    budget -= rows.length;
  }

  // Budget left over means every query returned short of what it was
  // allowed, so nothing remains. Spending it exactly is inconclusive —
  // there may or may not be more — so schedule and let the continuation
  // find out. A continuation that finds nothing simply drains.
  if (budget > 0) {
    return { drained: true };
  }
  await ctx.scheduler.runAfter(0, internal.devices.continuePurge, {
    userId,
    deviceId,
  });
  return { drained: false };
}

/**
 * Continuation for a {@link purgeDeviceStorage} that exhausted its budget.
 * Re-entrant and idempotent: the device row is already gone, so this only
 * ever finds leftover key material and queued messages, and it reschedules
 * itself until none remains.
 */
export const continuePurge = internalMutation({
  args: {
    userId: v.string(),
    deviceId: v.number(),
  },
  returns: v.object({ drained: v.boolean() }),
  handler: async (ctx, input) =>
    await purgeDeviceStorage(ctx, input.userId, input.deviceId),
});

export const removeDevice = mutation({
  args: {
    ...callerIdentityArgs,
    deviceId: v.number(),
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const existing = await device(
      ctx,
      input.callerUserId,
      input.deviceId
    );
    if (existing) {
      await ctx.db.patch(existing._id, {
        registered: false,
        linked: false,
        enabled: false,
        active: false,
      });
    }
    await purgeDeviceStorage(ctx, input.callerUserId, input.deviceId);
    return null;
  },
});

async function updateConnection(
  ctx: MutationCtx,
  input: {
    callerUserId: string;
    callerAciBytes: ArrayBuffer;
    callerPniBytes?: ArrayBuffer;
    deviceId: number;
  },
  active: boolean
): Promise<null> {
  await rememberAccount(ctx, input);
  const existing = await device(
    ctx,
    input.callerUserId,
    input.deviceId
  );
  if (existing) {
    await ctx.db.patch(existing._id, {
      active,
      lastSeen: Date.now(),
    });
  }
  return null;
}

export const markDeviceConnected = mutation({
  args: {
    ...callerIdentityArgs,
    deviceId: v.number(),
  },
  returns: v.null(),
  handler: async (ctx, input) =>
    await updateConnection(ctx, input, true),
});

export const markDeviceDisconnected = mutation({
  args: {
    ...callerIdentityArgs,
    deviceId: v.number(),
  },
  returns: v.null(),
  handler: async (ctx, input) =>
    await updateConnection(ctx, input, false),
});

export const presenceHeartbeat = mutation({
  args: {
    ...callerIdentityArgs,
    deviceId: v.number(),
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const existing = await ctx.db
      .query('deviceHeartbeats')
      .withIndex('by_user_id_and_device_id', (q) =>
        q
          .eq('userId', input.callerUserId)
          .eq('deviceId', input.deviceId)
      )
      .unique();
    const lastSeen = Date.now();
    if (existing) {
      await ctx.db.patch(existing._id, { lastSeen });
    } else {
      await ctx.db.insert('deviceHeartbeats', {
        userId: input.callerUserId,
        deviceId: input.deviceId,
        lastSeen,
      });
    }
    return null;
  },
});
