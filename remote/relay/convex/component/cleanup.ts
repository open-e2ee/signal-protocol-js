import { v } from 'convex/values';
import { internal } from './_generated/api';
import { internalMutation } from './_generated/server';
import { teardownLinkedDevice } from './provisioning';

const CLEANUP_BATCH_SIZE = 100;
/**
 * The provisioning sweep is the one cron whose per-row work is unbounded: a
 * `linked_pending_ack` row cascades into a full device teardown. Sweeping
 * 100 of those in one transaction can exceed Convex's per-mutation limits,
 * and a cron that fails does not degrade — it stalls, and expired sessions
 * stop being reaped at all. A smaller batch keeps each tick inside the
 * limits; the self-reschedule below is what preserves throughput.
 */
const PROVISIONING_CLEANUP_BATCH_SIZE = 10;
const STALE_KEM_AGE_MS = 30 * 24 * 60 * 60 * 1000;

const cleanupResultValidator = v.object({
  deleted: v.number(),
  continued: v.boolean(),
});

export const cleanupExpiredMessages = internalMutation({
  args: { cutoff: v.optional(v.number()) },
  returns: cleanupResultValidator,
  handler: async (ctx, input) => {
    const cutoff = input.cutoff ?? Date.now();
    const rows = await ctx.db
      .query('messages')
      .withIndex('by_expires_at', (q) => q.lt('expiresAt', cutoff))
      .take(CLEANUP_BATCH_SIZE);
    for (const row of rows) {
      await ctx.db.delete(row._id);
    }
    const continued = rows.length === CLEANUP_BATCH_SIZE;
    if (continued) {
      await ctx.scheduler.runAfter(
        0,
        internal.cleanup.cleanupExpiredMessages,
        {
          cutoff,
        }
      );
    }
    return { deleted: rows.length, continued };
  },
});

export const cleanupExpiredMultiRecipientPayloads = internalMutation({
  args: { cutoff: v.optional(v.number()) },
  returns: cleanupResultValidator,
  handler: async (ctx, input) => {
    const cutoff = input.cutoff ?? Date.now();
    const rows = await ctx.db
      .query('multiRecipientPayloads')
      .withIndex('by_expires_at', (q) => q.lt('expiresAt', cutoff))
      .take(CLEANUP_BATCH_SIZE);
    for (const row of rows) {
      await ctx.db.delete(row._id);
    }
    const continued = rows.length === CLEANUP_BATCH_SIZE;
    if (continued) {
      await ctx.scheduler.runAfter(
        0,
        internal.cleanup.cleanupExpiredMultiRecipientPayloads,
        { cutoff }
      );
    }
    return { deleted: rows.length, continued };
  },
});

export const cleanupExpiredRetryRequests = internalMutation({
  args: { cutoff: v.optional(v.number()) },
  returns: cleanupResultValidator,
  handler: async (ctx, input) => {
    const cutoff = input.cutoff ?? Date.now();
    const rows = await ctx.db
      .query('retryRequests')
      .withIndex('by_expires_at', (q) => q.lt('expiresAt', cutoff))
      .take(CLEANUP_BATCH_SIZE);
    for (const row of rows) {
      await ctx.db.delete(row._id);
    }
    const continued = rows.length === CLEANUP_BATCH_SIZE;
    if (continued) {
      await ctx.scheduler.runAfter(
        0,
        internal.cleanup.cleanupExpiredRetryRequests,
        { cutoff }
      );
    }
    return { deleted: rows.length, continued };
  },
});

export const cleanupExpiredProvisioningSessions = internalMutation({
  args: { cutoff: v.optional(v.number()) },
  returns: cleanupResultValidator,
  handler: async (ctx, input) => {
    const cutoff = input.cutoff ?? Date.now();
    const rows = await ctx.db
      .query('provisioningSessions')
      .withIndex('by_expires_at', (q) => q.lt('expiresAt', cutoff))
      .take(PROVISIONING_CLEANUP_BATCH_SIZE);
    for (const row of rows) {
      if (row.status === 'linked_pending_ack') {
        // A linked-but-never-acknowledged session past its (extended) ack
        // window is a rolled-back link: tear down the device it created.
        // teardownLinkedDevice matches the recorded link token so a device
        // legitimately re-registered into the freed slot survives, and
        // cascades the device's key material and queues.
        await teardownLinkedDevice(ctx, row);
      }
      await ctx.db.delete(row._id);
    }
    const continued = rows.length === PROVISIONING_CLEANUP_BATCH_SIZE;
    if (continued) {
      await ctx.scheduler.runAfter(
        0,
        internal.cleanup.cleanupExpiredProvisioningSessions,
        { cutoff }
      );
    }
    return { deleted: rows.length, continued };
  },
});

export const cleanupStaleKemPreKeys = internalMutation({
  args: {
    cutoff: v.optional(v.number()),
  },
  returns: v.object({
    deletedOneTime: v.number(),
    deletedLastResort: v.number(),
    continued: v.boolean(),
  }),
  handler: async (ctx, input) => {
    const now = Date.now();
    const cutoff = input.cutoff ?? now - STALE_KEM_AGE_MS;
    const oneTimeRows = await ctx.db
      .query('kemOneTimePreKeys')
      .withIndex('by_consumed_at_and_uploaded_at', (q) =>
        q.eq('consumedAt', undefined).lt('uploadedAt', cutoff)
      )
      .take(CLEANUP_BATCH_SIZE);
    const lastResortRows = await ctx.db
      .query('kemLastResortPreKeys')
      .withIndex('by_expires_at', (q) => q.lt('expiresAt', now))
      .take(CLEANUP_BATCH_SIZE);
    for (const row of oneTimeRows) {
      await ctx.db.delete(row._id);
    }
    for (const row of lastResortRows) {
      await ctx.db.delete(row._id);
    }
    const continued =
      oneTimeRows.length === CLEANUP_BATCH_SIZE ||
      lastResortRows.length === CLEANUP_BATCH_SIZE;
    if (continued) {
      await ctx.scheduler.runAfter(
        0,
        internal.cleanup.cleanupStaleKemPreKeys,
        {
          cutoff,
        }
      );
    }
    return {
      deletedOneTime: oneTimeRows.length,
      deletedLastResort: lastResortRows.length,
      continued,
    };
  },
});
