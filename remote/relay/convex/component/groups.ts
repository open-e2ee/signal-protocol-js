import { ConvexError, v } from 'convex/values';
import type {
  GroupAuthorization,
  GroupChangeLogEntry,
} from '../../../../internal/groups/manager';
import {
  GROUP_CHANGE_LOG_PAGE_LIMIT,
  GroupAuthorizationServerEngine,
  type GroupServerEngineRuntime,
  type GroupServerPersistedGroup,
  type GroupServerPersistedSnapshot,
} from '../../../../internal/groups/server-engine';
import { deserializeEncryptedGroup } from '../../../../internal/groups/wire';
import {
  defaultExpiration,
  deriveForExpiration,
  issueEndorsements,
  serializeEndorsementsResponse,
} from '../../../../internal/protocol/zk/groups/group-send-endorsement';
import type { ServerSecretParams } from '../../../../internal/protocol/zk/groups/server-params';
import { UidEncryptionDomain } from '../../../../internal/protocol/zk/groups/uid-encryption';
import { Ciphertext } from '../../../../internal/protocol/zk/credentials/attributes';
import { RistrettoPoint } from '../../../../internal/protocol/zk/proofs/sho';
import type { Doc } from './_generated/dataModel';
import {
  mutation,
  query,
  type MutationCtx,
  type QueryCtx,
} from './_generated/server';
import {
  groupServerRuntime,
  groupServerSecretParams,
  translateEngineErrors,
} from './runtime';

// Group functions deliberately take NO caller identity. The zero-knowledge
// presentation alone authorizes reads and writes, so the server never
// learns which account ran a group operation. Identity flows only into
// the zkAuth issuance functions.

const MAX_CHANGE_BATCH = 4096;

const changeResultValidator = v.object({
  version: v.number(),
  actions: v.bytes(),
  serverSignature: v.bytes(),
  changeEpoch: v.number(),
  timestamp: v.number(),
});

const snapshotResultValidator = v.object({
  encryptedState: v.bytes(),
  version: v.number(),
  baselineSignature: v.bytes(),
});

type GroupQueryContext = Pick<QueryCtx, 'db'>;
type GroupMutationContext = Pick<MutationCtx, 'db'>;

function toUint8Array(value: ArrayBuffer): Uint8Array {
  return new Uint8Array(value);
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(
    value.byteOffset,
    value.byteOffset + value.byteLength
  ) as ArrayBuffer;
}

function groupIdKey(groupId: Uint8Array): string {
  return Array.from(groupId, (byte) =>
    byte.toString(16).padStart(2, '0')
  ).join('');
}

function authorization(input: {
  presentation: ArrayBuffer;
  groupPublicParams: ArrayBuffer;
}): GroupAuthorization {
  return {
    presentation: toUint8Array(input.presentation),
    groupPublicParams: toUint8Array(input.groupPublicParams),
  };
}

async function getGroupDocument(
  ctx: GroupQueryContext,
  key: string
): Promise<Doc<'groups'> | null> {
  return await ctx.db
    .query('groups')
    .withIndex('by_group_id', (query) => query.eq('groupId', key))
    .unique();
}

async function getSnapshotDocument(
  ctx: GroupQueryContext,
  key: string,
  version: number
): Promise<Doc<'groupSnapshots'> | null> {
  return await ctx.db
    .query('groupSnapshots')
    .withIndex('by_group_id_version', (query) =>
      query.eq('groupId', key).eq('version', version)
    )
    .unique();
}

function persistedSnapshot(
  document: Doc<'groupSnapshots'>
): GroupServerPersistedSnapshot {
  return {
    version: document.version,
    encryptedState: toUint8Array(document.encryptedState),
    baselineSignature: toUint8Array(document.baselineSignature),
  };
}

async function loadEngine(
  ctx: GroupQueryContext,
  groupId: Uint8Array,
  secretParams: ServerSecretParams,
  runtime: GroupServerEngineRuntime,
  options: {
    snapshotVersions?: number[];
    changesAfterVersion?: number;
    /** Cap on restored changes (and their post-state snapshots). */
    changeLimit?: number;
  } = {}
): Promise<{
  engine: GroupAuthorizationServerEngine;
  groupDocument: Doc<'groups'> | null;
}> {
  const engine = new GroupAuthorizationServerEngine(
    secretParams,
    runtime
  );
  const key = groupIdKey(groupId);
  const groupDocument = await getGroupDocument(ctx, key);
  if (!groupDocument) return { engine, groupDocument: null };

  const snapshots: GroupServerPersistedSnapshot[] = [];
  for (const version of new Set(options.snapshotVersions ?? [])) {
    const snapshot = await getSnapshotDocument(ctx, key, version);
    if (snapshot) snapshots.push(persistedSnapshot(snapshot));
  }

  const changes: GroupChangeLogEntry[] = [];
  if (options.changesAfterVersion !== undefined) {
    const changesAfterVersion = options.changesAfterVersion;
    const documents = await ctx.db
      .query('groupChanges')
      .withIndex('by_group_id_version', (query) =>
        query
          .eq('groupId', key)
          .gt('version', changesAfterVersion)
      )
      .order('asc')
      .take(Math.min(options.changeLimit ?? MAX_CHANGE_BATCH, MAX_CHANGE_BATCH));
    for (const document of documents) {
      changes.push({
        version: document.version,
        actions: toUint8Array(document.actions),
        serverSignature: toUint8Array(document.serverSignature),
        changeEpoch: document.changeEpoch,
        timestamp: document.timestamp,
      });
      const snapshot = await getSnapshotDocument(
        ctx,
        key,
        document.version
      );
      if (!snapshot) {
        // ConvexError so the structured {code, status} survives
        // serialization to clients, matching the rest of the module's
        // rejection contract.
        throw new ConvexError({
          code: 'INTERNAL_ERROR',
          status: 500,
          message: `Missing group snapshot ${document.version}`,
        });
      }
      snapshots.push(persistedSnapshot(snapshot));
    }
  }

  const persisted: GroupServerPersistedGroup = {
    encryptedState: toUint8Array(groupDocument.encryptedState),
    changes,
    snapshots,
  };
  engine.restoreGroup(groupId, persisted);
  return { engine, groupDocument };
}

async function insertSnapshot(
  ctx: GroupMutationContext,
  key: string,
  snapshot: GroupServerPersistedSnapshot
): Promise<void> {
  await ctx.db.insert('groupSnapshots', {
    groupId: key,
    version: snapshot.version,
    encryptedState: toArrayBuffer(snapshot.encryptedState),
    baselineSignature: toArrayBuffer(snapshot.baselineSignature),
  });
}

async function insertChange(
  ctx: GroupMutationContext,
  key: string,
  change: GroupChangeLogEntry
): Promise<void> {
  await ctx.db.insert('groupChanges', {
    groupId: key,
    version: change.version,
    actions: toArrayBuffer(change.actions),
    serverSignature: toArrayBuffer(change.serverSignature),
    changeEpoch: change.changeEpoch,
    timestamp: change.timestamp,
  });
}

function memberCiphertexts(encryptedState: Uint8Array): Ciphertext[] {
  const state = deserializeEncryptedGroup(encryptedState);
  return state.members.map((member) => {
    if (member.userId.length !== 65) {
      throw new Error('Stored member identifier must be 65 bytes');
    }
    return new Ciphertext(
      RistrettoPoint.fromBytes(member.userId.slice(1, 33)),
      RistrettoPoint.fromBytes(member.userId.slice(33, 65)),
      UidEncryptionDomain
    );
  });
}

export const createGroup = mutation({
  args: {
    groupId: v.bytes(),
    encryptedState: v.bytes(),
    presentation: v.bytes(),
    groupPublicParams: v.bytes(),
  },
  returns: v.null(),
  handler: async (ctx, input): Promise<null> => {
    const groupId = toUint8Array(input.groupId);
    const secretParams = groupServerSecretParams();
    const runtime = groupServerRuntime();
    const { engine, groupDocument } = await loadEngine(
      ctx,
      groupId,
      secretParams,
      runtime
    );
    if (groupDocument) {
      throw new ConvexError({
        code: 'VERSION_CONFLICT',
        status: 409,
        message: 'Group already exists',
      });
    }
    await translateEngineErrors(() =>
      engine.createGroup(
        groupId,
        toUint8Array(input.encryptedState),
        authorization(input)
      )
    );
    const persisted = engine.exportGroup(groupId);
    if (!persisted || persisted.snapshots.length !== 1) {
      throw new Error('Group creation did not produce one snapshot');
    }
    const key = groupIdKey(groupId);
    const state = deserializeEncryptedGroup(persisted.encryptedState);
    await ctx.db.insert('groups', {
      groupId: key,
      encryptedState: toArrayBuffer(persisted.encryptedState),
      version: state.version,
    });
    await insertSnapshot(ctx, key, persisted.snapshots[0]!);
    return null;
  },
});

export const getGroup = query({
  args: {
    groupId: v.bytes(),
    presentation: v.bytes(),
    groupPublicParams: v.bytes(),
    version: v.optional(v.number()),
  },
  returns: v.union(snapshotResultValidator, v.null()),
  handler: async (ctx, input) => {
    const groupId = toUint8Array(input.groupId);
    const key = groupIdKey(groupId);
    const groupDocument = await getGroupDocument(ctx, key);
    if (!groupDocument) return null;
    const version = input.version ?? groupDocument.version;
    const secretParams = groupServerSecretParams();
    const runtime = groupServerRuntime();
    const { engine } = await loadEngine(
      ctx,
      groupId,
      secretParams,
      runtime,
      { snapshotVersions: [version] }
    );
    const result = await translateEngineErrors(() =>
      engine.getGroup(groupId, authorization(input), input.version)
    );
    return result
      ? {
          encryptedState: toArrayBuffer(result.encryptedState),
          version: result.version,
          baselineSignature: toArrayBuffer(result.baselineSignature),
        }
      : null;
  },
});

export const getGroupJoinInfo = query({
  args: {
    groupId: v.bytes(),
    inviteLinkPassword: v.bytes(),
    presentation: v.bytes(),
    groupPublicParams: v.bytes(),
  },
  returns: v.union(
    v.object({
      encryptedJoinInfo: v.bytes(),
      version: v.number(),
    }),
    v.null()
  ),
  handler: async (ctx, input) => {
    const groupId = toUint8Array(input.groupId);
    const { engine, groupDocument } = await loadEngine(
      ctx,
      groupId,
      groupServerSecretParams(),
      groupServerRuntime()
    );
    if (!groupDocument) return null;
    const result = await translateEngineErrors(() =>
      engine.getGroupJoinInfo(
        groupId,
        toUint8Array(input.inviteLinkPassword),
        authorization(input)
      )
    );
    return result
      ? {
          encryptedJoinInfo: toArrayBuffer(result.encryptedJoinInfo),
          version: result.version,
        }
      : null;
  },
});

export const getGroupChanges = query({
  args: {
    groupId: v.bytes(),
    fromVersion: v.number(),
    presentation: v.bytes(),
    groupPublicParams: v.bytes(),
  },
  returns: v.object({
    entries: v.array(changeResultValidator),
    hasMore: v.boolean(),
  }),
  handler: async (ctx, input) => {
    const groupId = toUint8Array(input.groupId);
    const { engine, groupDocument } = await loadEngine(
      ctx,
      groupId,
      groupServerSecretParams(),
      groupServerRuntime(),
      {
        snapshotVersions: [input.fromVersion],
        changesAfterVersion: input.fromVersion,
        // One page plus the single look-ahead entry that decides hasMore. The
        // engine caps its walk at the page limit, so restoring more than this
        // is pure read amplification.
        changeLimit: GROUP_CHANGE_LOG_PAGE_LIMIT + 1,
      }
    );
    if (!groupDocument) return { entries: [], hasMore: false };
    const result = await translateEngineErrors(() =>
      engine.getGroupChanges(
        groupId,
        input.fromVersion,
        authorization(input)
      )
    );
    return {
      entries: result.entries.map((entry) => ({
        version: entry.version,
        actions: toArrayBuffer(entry.actions),
        serverSignature: toArrayBuffer(entry.serverSignature),
        changeEpoch: entry.changeEpoch,
        timestamp: entry.timestamp,
      })),
      hasMore: result.hasMore,
    };
  },
});

export const submitGroupChange = mutation({
  args: {
    groupId: v.bytes(),
    expectedVersion: v.number(),
    actions: v.bytes(),
    inviteLinkPassword: v.bytes(),
    presentation: v.bytes(),
    groupPublicParams: v.bytes(),
  },
  returns: changeResultValidator,
  handler: async (ctx, input) => {
    const groupId = toUint8Array(input.groupId);
    const { engine, groupDocument } = await loadEngine(
      ctx,
      groupId,
      groupServerSecretParams(),
      groupServerRuntime()
    );
    if (!groupDocument) {
      throw new ConvexError({
        code: 'INVALID_REQUEST',
        status: 400,
        message: 'Group does not exist',
      });
    }
    const result = await translateEngineErrors(() =>
      engine.submitGroupChange(
        groupId,
        input.expectedVersion,
        toUint8Array(input.actions),
        toUint8Array(input.inviteLinkPassword),
        authorization(input)
      )
    );
    const persisted = engine.exportGroup(groupId);
    const nextSnapshot = persisted?.snapshots.find(
      (snapshot) => snapshot.version === result.version
    );
    if (!persisted || !nextSnapshot) {
      throw new Error('Accepted change did not produce a snapshot');
    }
    const key = groupIdKey(groupId);
    await ctx.db.patch(groupDocument._id, {
      encryptedState: toArrayBuffer(persisted.encryptedState),
      version: result.version,
    });
    await insertChange(ctx, key, result);
    await insertSnapshot(ctx, key, nextSnapshot);
    return {
      version: result.version,
      actions: toArrayBuffer(result.actions),
      serverSignature: toArrayBuffer(result.serverSignature),
      changeEpoch: result.changeEpoch,
      timestamp: result.timestamp,
    };
  },
});

export const refreshGroupSendEndorsements = mutation({
  args: {
    groupId: v.bytes(),
    presentation: v.bytes(),
    groupPublicParams: v.bytes(),
  },
  returns: v.object({
    endorsements: v.bytes(),
    expiration: v.number(),
  }),
  handler: async (ctx, input) => {
    const groupId = toUint8Array(input.groupId);
    const key = groupIdKey(groupId);
    const groupDocument = await getGroupDocument(ctx, key);
    if (!groupDocument) throw new Error('Group not found');
    const version = groupDocument.version;
    const secretParams = groupServerSecretParams();
    const runtime = groupServerRuntime();
    const { engine } = await loadEngine(
      ctx,
      groupId,
      secretParams,
      runtime,
      { snapshotVersions: [version] }
    );
    const group = await translateEngineErrors(() =>
      engine.getGroup(groupId, authorization(input))
    );
    if (!group) throw new Error('Group not found');
    const members = memberCiphertexts(group.encryptedState);
    if (members.length === 0) throw new Error('Empty group');
    const expiration = defaultExpiration(
      Math.floor(runtime.now() / 1000)
    );
    const response = issueEndorsements(
      members,
      deriveForExpiration(
        secretParams.endorsementKeyPair,
        expiration
      ),
      runtime.randomBytes(32)
    );
    return {
      endorsements: toArrayBuffer(
        serializeEndorsementsResponse(response)
      ),
      expiration,
    };
  },
});
