import {
  MINUTE,
  RateLimiter,
  isRateLimitError,
} from '@convex-dev/rate-limiter';
import { ConvexError, v } from 'convex/values';
import {
  base64ToBytes,
  constantTimeEqual,
} from '../../../../internal/crypto/utils';
import {
  compositeIdentitiesEqual,
  decodeCompositeIdentityV1,
  deriveIdentityCommitment,
} from '../../../../keys/identity';
import { asBase64 } from '../../../../types/utils';
import { components } from './_generated/api';
import type { Doc, Id, TableNames } from './_generated/dataModel';
import { mutation, query } from './_generated/server';
import type { MutationCtx } from './_generated/server';
import { callerIdentityArgs, rememberAccount } from './accounts';
import { relayError } from './errors';

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_KEY_UPLOAD = 1000;
const MAX_STORED_KEYS = 8192;

const identityTypeValidator = v.union(
  v.literal('aci'),
  v.literal('pni')
);

const preKeyUploadValidator = v.object({
  type: v.union(
    v.literal('ecPreKey'),
    v.literal('ecSignedPreKey'),
    v.literal('kemOneTimePreKey'),
    v.literal('kemLastResortPreKey')
  ),
  keyId: v.number(),
  publicKey: v.string(),
  signature: v.optional(v.string()),
});

const signedPreKeyValidator = v.object({
  keyId: v.number(),
  publicKey: v.string(),
  signature: v.string(),
});

const oneTimePreKeyValidator = v.object({
  keyId: v.number(),
  publicKey: v.string(),
});

const kemPreKeyValidator = v.object({
  keyId: v.number(),
  publicKey: v.string(),
  signature: v.string(),
});

const preKeyBundleValidator = v.object({
  registrationId: v.number(),
  deviceId: v.number(),
  compositeIdentity: v.string(),
  ecSignedPreKey: signedPreKeyValidator,
  ecOneTimePreKey: v.union(oneTimePreKeyValidator, v.null()),
  kemLastResortPreKey: v.union(kemPreKeyValidator, v.null()),
  kemOneTimePreKey: v.union(kemPreKeyValidator, v.null()),
});

const metadataValidator = v.object({
  keyId: v.number(),
  createdAt: v.number(),
  expiresAt: v.number(),
  publicKey: v.string(),
});

const rateLimiter = new RateLimiter(components.rateLimiter, {
  preKeyBundleFetch: {
    kind: 'fixed window',
    rate: 10,
    period: MINUTE,
    capacity: 10,
    start: 0,
  },
});

function decodeIdentity(encoded: string) {
  try {
    return decodeCompositeIdentityV1(
      base64ToBytes(asBase64(encoded))
    );
  } catch {
    throw relayError(
      'INVALID_REQUEST',
      400,
      'compositeIdentity must be a canonical encoded identity'
    );
  }
}

function decodeCommitment(encoded: string): Uint8Array {
  try {
    return base64ToBytes(asBase64(encoded));
  } catch {
    throw relayError(
      'INVALID_REQUEST',
      400,
      'expectedCurrentCommitment must be canonical base64'
    );
  }
}

async function registration(
  ctx: MutationCtx,
  userId: string,
  deviceId: number,
  identityType: 'aci' | 'pni'
) {
  return await ctx.db
    .query('identityRegistrations')
    .withIndex('by_user_id_and_device_id_and_identity_type', (q) =>
      q
        .eq('userId', userId)
        .eq('deviceId', deviceId)
        .eq('identityType', identityType)
    )
    .unique();
}

async function upsertRegistration(
  ctx: MutationCtx,
  userId: string,
  deviceId: number,
  identityType: 'aci' | 'pni',
  registrationId: number
): Promise<void> {
  const existing = await registration(
    ctx,
    userId,
    deviceId,
    identityType
  );
  const value = {
    userId,
    deviceId,
    identityType,
    registrationId,
    updatedAt: Date.now(),
  };
  if (existing) {
    await ctx.db.replace(existing._id, value);
  } else {
    await ctx.db.insert('identityRegistrations', value);
  }
}

async function deleteRows(
  ctx: MutationCtx,
  rows: Array<{ _id: Id<TableNames> }>
): Promise<void> {
  for (const row of rows) {
    await ctx.db.delete(row._id);
  }
}

async function clearIdentityPreKeys(
  ctx: MutationCtx,
  userId: string,
  identityType: 'aci' | 'pni'
): Promise<void> {
  for (const table of [
    'identityRegistrations',
    'ecPreKeys',
    'ecSignedPreKeys',
    'kemOneTimePreKeys',
    'kemLastResortPreKeys',
    'senderCertificates',
  ] as const) {
    const rows = await ctx.db
      .query(table)
      .withIndex('by_user_id_and_identity_type', (q) =>
        q.eq('userId', userId).eq('identityType', identityType)
      )
      .take(MAX_STORED_KEYS);
    await deleteRows(ctx, rows);
  }
}

export const uploadIdentityKey = mutation({
  args: {
    ...callerIdentityArgs,
    mode: v.union(v.literal('provision'), v.literal('rotate')),
    deviceId: v.number(),
    compositeIdentity: v.string(),
    registrationId: v.number(),
    identityType: identityTypeValidator,
    expectedCurrentCommitment: v.optional(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const nextIdentity = decodeIdentity(input.compositeIdentity);
    const existing = await ctx.db
      .query('identityKeys')
      .withIndex('by_user_id_and_identity_type', (q) =>
        q
          .eq('userId', input.callerUserId)
          .eq('identityType', input.identityType)
      )
      .unique();
    const now = Date.now();

    if (input.mode === 'provision') {
      if (
        existing &&
        !compositeIdentitiesEqual(
          decodeIdentity(existing.compositeIdentity),
          nextIdentity
        )
      ) {
        throw relayError(
          'CONFLICT',
          409,
          'Account identity already exists with a different composite tuple; explicit rotation required'
        );
      }
      if (!existing) {
        await ctx.db.insert('identityKeys', {
          userId: input.callerUserId,
          identityType: input.identityType,
          compositeIdentity: input.compositeIdentity,
          createdAt: now,
          updatedAt: now,
        });
      }
      await upsertRegistration(
        ctx,
        input.callerUserId,
        input.deviceId,
        input.identityType,
        input.registrationId
      );
      return null;
    }

    if (!existing) {
      throw relayError(
        'NOT_FOUND',
        404,
        'Cannot rotate an account identity that has not been provisioned'
      );
    }
    if (input.expectedCurrentCommitment === undefined) {
      throw relayError(
        'INVALID_REQUEST',
        400,
        'expectedCurrentCommitment is required for rotation'
      );
    }
    const currentIdentity = decodeIdentity(
      existing.compositeIdentity
    );
    if (
      !constantTimeEqual(
        deriveIdentityCommitment(currentIdentity),
        decodeCommitment(input.expectedCurrentCommitment)
      )
    ) {
      throw relayError(
        'CONFLICT',
        409,
        'Account identity rotation compare-and-swap failed'
      );
    }
    if (compositeIdentitiesEqual(currentIdentity, nextIdentity)) {
      throw relayError(
        'INVALID_REQUEST',
        400,
        'Account identity rotation requires a different composite tuple'
      );
    }

    await ctx.db.patch(existing._id, {
      compositeIdentity: input.compositeIdentity,
      updatedAt: now,
    });
    await clearIdentityPreKeys(
      ctx,
      input.callerUserId,
      input.identityType
    );
    await upsertRegistration(
      ctx,
      input.callerUserId,
      input.deviceId,
      input.identityType,
      input.registrationId
    );
    return null;
  },
});

export const getIdentityKey = query({
  args: {
    ...callerIdentityArgs,
    userId: v.string(),
    identityType: identityTypeValidator,
  },
  returns: v.union(v.string(), v.null()),
  handler: async (ctx, input) => {
    const identity = await ctx.db
      .query('identityKeys')
      .withIndex('by_user_id_and_identity_type', (q) =>
        q
          .eq('userId', input.userId)
          .eq('identityType', input.identityType)
      )
      .unique();
    return identity?.compositeIdentity ?? null;
  },
});

function requireKeyId(keyId: number): void {
  if (!Number.isSafeInteger(keyId) || keyId < 0) {
    throw relayError(
      'INVALID_REQUEST',
      400,
      'keyId must be a non-negative safe integer'
    );
  }
}

async function upsertOneTimeKey(
  ctx: MutationCtx,
  table: 'ecPreKeys' | 'kemOneTimePreKeys',
  input: {
    userId: string;
    deviceId: number;
    identityType: 'aci' | 'pni';
    keyId: number;
    publicKey: string;
    signature?: string;
  }
): Promise<void> {
  const existing = await ctx.db
    .query(table)
    .withIndex(
      'by_user_id_and_device_id_and_identity_type_and_key_id',
      (q) =>
        q
          .eq('userId', input.userId)
          .eq('deviceId', input.deviceId)
          .eq('identityType', input.identityType)
          .eq('keyId', input.keyId)
    )
    .unique();
  if (existing?.consumedAt !== undefined) return;
  const value = {
    userId: input.userId,
    deviceId: input.deviceId,
    identityType: input.identityType,
    keyId: input.keyId,
    publicKey: input.publicKey,
    signature: input.signature,
    uploadedAt: Date.now(),
  };
  if (existing) {
    await ctx.db.patch(existing._id, value);
  } else if (table === 'ecPreKeys') {
    const { signature: _signature, ...ecValue } = value;
    await ctx.db.insert('ecPreKeys', ecValue);
  } else {
    await ctx.db.insert('kemOneTimePreKeys', value);
  }
}

async function upsertReusableKey(
  ctx: MutationCtx,
  table: 'ecSignedPreKeys' | 'kemLastResortPreKeys',
  input: {
    userId: string;
    deviceId: number;
    identityType: 'aci' | 'pni';
    keyId: number;
    publicKey: string;
    signature: string;
  }
): Promise<void> {
  const existing = await ctx.db
    .query(table)
    .withIndex('by_user_id_and_device_id_and_identity_type', (q) =>
      q
        .eq('userId', input.userId)
        .eq('deviceId', input.deviceId)
        .eq('identityType', input.identityType)
    )
    .unique();
  const now = Date.now();
  const value = {
    ...input,
    createdAt: now,
    expiresAt: now + THIRTY_DAYS_MS,
  };
  if (existing) {
    await ctx.db.replace(existing._id, value);
  } else {
    await ctx.db.insert(table, value);
  }
}

async function storePreKeys(
  ctx: MutationCtx,
  input: {
    userId: string;
    deviceId: number;
    identityType: 'aci' | 'pni';
    keys: Array<{
      type:
        | 'ecPreKey'
        | 'ecSignedPreKey'
        | 'kemOneTimePreKey'
        | 'kemLastResortPreKey';
      keyId: number;
      publicKey: string;
      signature?: string;
    }>;
  }
): Promise<void> {
  for (const key of input.keys) {
    requireKeyId(key.keyId);
    if (
      (key.type === 'ecSignedPreKey' ||
        key.type === 'kemOneTimePreKey' ||
        key.type === 'kemLastResortPreKey') &&
      key.signature === undefined
    ) {
      throw relayError(
        'INVALID_REQUEST',
        400,
        `${key.type} requires a signature`
      );
    }
    if (key.type === 'ecPreKey') {
      await upsertOneTimeKey(ctx, 'ecPreKeys', {
        ...input,
        ...key,
      });
    } else if (key.type === 'kemOneTimePreKey') {
      await upsertOneTimeKey(ctx, 'kemOneTimePreKeys', {
        ...input,
        ...key,
      });
    } else {
      await upsertReusableKey(
        ctx,
        key.type === 'ecSignedPreKey'
          ? 'ecSignedPreKeys'
          : 'kemLastResortPreKeys',
        {
          userId: input.userId,
          deviceId: input.deviceId,
          identityType: input.identityType,
          keyId: key.keyId,
          publicKey: key.publicKey,
          signature: key.signature!,
        }
      );
    }
  }
}

export const uploadPreKeys = mutation({
  args: {
    ...callerIdentityArgs,
    deviceId: v.number(),
    identityType: identityTypeValidator,
    keys: v.array(preKeyUploadValidator),
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    if (input.keys.length > MAX_KEY_UPLOAD) {
      throw relayError(
        'INVALID_REQUEST',
        400,
        `A prekey upload supports at most ${MAX_KEY_UPLOAD} keys`
      );
    }
    await storePreKeys(ctx, {
      userId: input.callerUserId,
      deviceId: input.deviceId,
      identityType: input.identityType,
      keys: input.keys,
    });
    return null;
  },
});

function rateLimitData(error: unknown): {
  retryAfter?: number;
} | null {
  if (isRateLimitError(error)) {
    return { retryAfter: error.data.retryAfter };
  }
  if (error instanceof ConvexError) {
    const data = error.data as {
      kind?: unknown;
      retryAfter?: unknown;
    };
    if (data.kind === 'RateLimited') {
      return {
        retryAfter:
          typeof data.retryAfter === 'number'
            ? data.retryAfter
            : undefined,
      };
    }
  }
  return null;
}

export const fetchPreKeyBundle = mutation({
  args: {
    ...callerIdentityArgs,
    userId: v.string(),
    deviceId: v.number(),
    identityType: identityTypeValidator,
  },
  returns: v.union(preKeyBundleValidator, v.null()),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    try {
      await rateLimiter.limit(ctx, 'preKeyBundleFetch', {
        key: JSON.stringify([input.callerUserId, input.userId]),
        throws: true,
      });
    } catch (error) {
      const data = rateLimitData(error);
      if (data) {
        throw relayError(
          'RATE_LIMITED',
          429,
          'Prekey bundle fetch rate limit exceeded',
          data
        );
      }
      throw error;
    }

    const identity = await ctx.db
      .query('identityKeys')
      .withIndex('by_user_id_and_identity_type', (q) =>
        q
          .eq('userId', input.userId)
          .eq('identityType', input.identityType)
      )
      .unique();
    const registrationRow = await ctx.db
      .query('identityRegistrations')
      .withIndex('by_user_id_and_device_id_and_identity_type', (q) =>
        q
          .eq('userId', input.userId)
          .eq('deviceId', input.deviceId)
          .eq('identityType', input.identityType)
      )
      .unique();
    const signed = await ctx.db
      .query('ecSignedPreKeys')
      .withIndex('by_user_id_and_device_id_and_identity_type', (q) =>
        q
          .eq('userId', input.userId)
          .eq('deviceId', input.deviceId)
          .eq('identityType', input.identityType)
      )
      .unique();
    if (!identity || !registrationRow || !signed) return null;

    const ecOneTime = await ctx.db
      .query('ecPreKeys')
      .withIndex(
        'by_user_id_and_device_id_and_identity_type_and_consumed_at',
        (q) =>
          q
            .eq('userId', input.userId)
            .eq('deviceId', input.deviceId)
            .eq('identityType', input.identityType)
            .eq('consumedAt', undefined)
      )
      .first();
    const kemOneTime = await ctx.db
      .query('kemOneTimePreKeys')
      .withIndex(
        'by_user_id_and_device_id_and_identity_type_and_consumed_at',
        (q) =>
          q
            .eq('userId', input.userId)
            .eq('deviceId', input.deviceId)
            .eq('identityType', input.identityType)
            .eq('consumedAt', undefined)
      )
      .first();
    const lastResort = await ctx.db
      .query('kemLastResortPreKeys')
      .withIndex('by_user_id_and_device_id_and_identity_type', (q) =>
        q
          .eq('userId', input.userId)
          .eq('deviceId', input.deviceId)
          .eq('identityType', input.identityType)
      )
      .unique();
    const consumedAt = Date.now();
    if (ecOneTime) {
      await ctx.db.patch(ecOneTime._id, { consumedAt });
    }
    if (kemOneTime) {
      await ctx.db.patch(kemOneTime._id, { consumedAt });
    }
    return {
      registrationId: registrationRow.registrationId,
      deviceId: input.deviceId,
      compositeIdentity: identity.compositeIdentity,
      ecSignedPreKey: {
        keyId: signed.keyId,
        publicKey: signed.publicKey,
        signature: signed.signature,
      },
      ecOneTimePreKey: ecOneTime
        ? {
            keyId: ecOneTime.keyId,
            publicKey: ecOneTime.publicKey,
          }
        : null,
      kemLastResortPreKey: lastResort
        ? {
            keyId: lastResort.keyId,
            publicKey: lastResort.publicKey,
            signature: lastResort.signature,
          }
        : null,
      kemOneTimePreKey: kemOneTime
        ? {
            keyId: kemOneTime.keyId,
            publicKey: kemOneTime.publicKey,
            signature: kemOneTime.signature!,
          }
        : null,
    };
  },
});

export const getPreKeyCount = query({
  args: {
    ...callerIdentityArgs,
    deviceId: v.number(),
    type: v.union(v.literal('ec'), v.literal('kem')),
    identityType: identityTypeValidator,
  },
  returns: v.number(),
  handler: async (ctx, input) => {
    const table =
      input.type === 'ec' ? 'ecPreKeys' : 'kemOneTimePreKeys';
    const rows = await ctx.db
      .query(table)
      .withIndex(
        'by_user_id_and_device_id_and_identity_type_and_consumed_at',
        (q) =>
          q
            .eq('userId', input.callerUserId)
            .eq('deviceId', input.deviceId)
            .eq('identityType', input.identityType)
            .eq('consumedAt', undefined)
      )
      .take(MAX_STORED_KEYS);
    return rows.length;
  },
});

export const clearStaleKemPreKeys = mutation({
  args: {
    ...callerIdentityArgs,
    deviceId: v.number(),
    identityType: identityTypeValidator,
  },
  returns: v.object({ cleared: v.number() }),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    const rows = await ctx.db
      .query('kemOneTimePreKeys')
      .withIndex(
        'by_user_id_and_device_id_and_identity_type_and_consumed_at',
        (q) =>
          q
            .eq('userId', input.callerUserId)
            .eq('deviceId', input.deviceId)
            .eq('identityType', input.identityType)
            .eq('consumedAt', undefined)
      )
      .take(MAX_STORED_KEYS);
    await deleteRows(ctx, rows);
    return { cleared: rows.length };
  },
});

export const uploadEcSignedPreKey = mutation({
  args: {
    ...callerIdentityArgs,
    identityType: identityTypeValidator,
    ecSignedPreKey: v.object({
      id: v.number(),
      deviceId: v.number(),
      publicKey: v.string(),
      signature: v.string(),
      timestamp: v.number(),
    }),
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    await storePreKeys(ctx, {
      userId: input.callerUserId,
      deviceId: input.ecSignedPreKey.deviceId,
      identityType: input.identityType,
      keys: [
        {
          type: 'ecSignedPreKey',
          keyId: input.ecSignedPreKey.id,
          publicKey: input.ecSignedPreKey.publicKey,
          signature: input.ecSignedPreKey.signature,
        },
      ],
    });
    return null;
  },
});

export const uploadKemLastResortPreKey = mutation({
  args: {
    ...callerIdentityArgs,
    identityType: identityTypeValidator,
    kemLastResortPreKey: v.object({
      id: v.number(),
      deviceId: v.number(),
      publicKey: v.string(),
      signature: v.string(),
      timestamp: v.number(),
    }),
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    await rememberAccount(ctx, input);
    await storePreKeys(ctx, {
      userId: input.callerUserId,
      deviceId: input.kemLastResortPreKey.deviceId,
      identityType: input.identityType,
      keys: [
        {
          type: 'kemLastResortPreKey',
          keyId: input.kemLastResortPreKey.id,
          publicKey: input.kemLastResortPreKey.publicKey,
          signature: input.kemLastResortPreKey.signature,
        },
      ],
    });
    return null;
  },
});

function metadata(
  row: Doc<'ecSignedPreKeys'> | Doc<'kemLastResortPreKeys'> | null
) {
  return row
    ? {
        keyId: row.keyId,
        createdAt: row.createdAt,
        expiresAt: row.expiresAt,
        publicKey: row.publicKey,
      }
    : null;
}

export const getEcSignedPreKeyMetadata = query({
  args: {
    ...callerIdentityArgs,
    deviceId: v.number(),
    identityType: identityTypeValidator,
  },
  returns: v.union(metadataValidator, v.null()),
  handler: async (ctx, input) =>
    metadata(
      await ctx.db
        .query('ecSignedPreKeys')
        .withIndex(
          'by_user_id_and_device_id_and_identity_type',
          (q) =>
            q
              .eq('userId', input.callerUserId)
              .eq('deviceId', input.deviceId)
              .eq('identityType', input.identityType)
        )
        .unique()
    ),
});

export const getKemLastResortPreKeyMetadata = query({
  args: {
    ...callerIdentityArgs,
    deviceId: v.number(),
    identityType: identityTypeValidator,
  },
  returns: v.union(metadataValidator, v.null()),
  handler: async (ctx, input) =>
    metadata(
      await ctx.db
        .query('kemLastResortPreKeys')
        .withIndex(
          'by_user_id_and_device_id_and_identity_type',
          (q) =>
            q
              .eq('userId', input.callerUserId)
              .eq('deviceId', input.deviceId)
              .eq('identityType', input.identityType)
        )
        .unique()
    ),
});
