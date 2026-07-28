import {
  defineTable,
  mutationGeneric,
  queryGeneric,
  type GenericDataModel,
  type GenericMutationCtx,
  type GenericQueryCtx,
} from 'convex/server';
import { ConvexError, v } from 'convex/values';
import type {
  GroupAuthorization,
  GroupChangeLogEntry,
} from '../../../internal/groups/manager';
import {
  GroupAuthorizationServerEngine,
  type GroupServerEngineRuntime,
  type GroupServerPersistedGroup,
  type GroupServerPersistedSnapshot,
} from '../../../internal/groups/server-engine';
import { deserializeEncryptedGroup } from '../../../internal/groups/wire';
import {
  base64ToBytes,
  bytesToBase64,
} from '../../../internal/crypto/utils';
import { asBase64 } from '../../../types/utils';
import {
  generateServerSecretParams,
  type ServerSecretParams,
} from '../../../internal/protocol/zk/groups/server-params';
import {
  issueAuthCredential,
  serializeAuthCredentialResponse,
} from '../../../internal/protocol/zk/groups/auth-credential';
import {
  issueProfileKeyCredential,
  serializeProfileKeyCredentialResponse,
} from '../../../internal/protocol/zk/groups/profile-key-credential';
import {
  SERVICE_ID_ACI,
  SERVICE_ID_PNI,
  type ServiceId,
} from '../../../internal/protocol/zk/groups/uid-struct';
import { SECONDS_PER_DAY } from '../../../internal/protocol/zk/groups/group-params';
import {
  defaultExpiration,
  deriveForExpiration,
  issueEndorsements,
  serializeEndorsementsResponse,
} from '../../../internal/protocol/zk/groups/group-send-endorsement';
import { UidEncryptionDomain } from '../../../internal/protocol/zk/groups/uid-encryption';
import { Ciphertext } from '../../../internal/protocol/zk/credentials/attributes';
import { RistrettoPoint } from '../../../internal/protocol/zk/proofs/sho';

/** Convex environment variable containing the deployment's base64 32-byte seed. */
export const CONVEX_GROUP_SERVER_SECRET_ENV_VAR =
  'OE_GROUPS_SERVER_SECRET';

const GROUPS_TABLE = 'oeGroupServerGroups';
const CHANGES_TABLE = 'oeGroupServerChanges';
const SNAPSHOTS_TABLE = 'oeGroupServerSnapshots';
const UUID_LENGTH = 16;
const PROFILE_KEY_LENGTH = 32;

/**
 * Tables owned by `defineConvexGroupServer`.
 *
 * Spread this object into the application's `defineSchema` call. The names are
 * package-scoped so the enforcing server can be mounted without app callbacks.
 */
export const convexGroupServerTables = {
  [GROUPS_TABLE]: defineTable({
    groupId: v.string(),
    encryptedState: v.bytes(),
    version: v.number(),
  }).index('by_group_id', ['groupId']),
  [CHANGES_TABLE]: defineTable({
    groupId: v.string(),
    version: v.number(),
    actions: v.bytes(),
    serverSignature: v.bytes(),
    changeEpoch: v.number(),
    timestamp: v.number(),
  }).index('by_group_id_version', ['groupId', 'version']),
  [SNAPSHOTS_TABLE]: defineTable({
    groupId: v.string(),
    version: v.number(),
    encryptedState: v.bytes(),
    baselineSignature: v.bytes(),
  }).index('by_group_id_version', ['groupId', 'version']),
};

type GroupQueryContext = Pick<
  GenericQueryCtx<GenericDataModel>,
  'db'
>;
type GroupMutationContext = Pick<
  GenericMutationCtx<GenericDataModel>,
  'db'
>;

export interface ConvexGroupServerIdentity {
  /** Raw 16-byte ACI UUID. */
  aciBytes: Uint8Array;
  /** Raw 16-byte PNI UUID, absent when the deployment has no PNI concept. */
  pniBytes?: Uint8Array;
}

export interface DefineConvexGroupServerConfig<
  Context = GenericMutationCtx<GenericDataModel>,
> {
  /**
   * Resolve the authenticated app session to protocol identifiers.
   *
   * This hook is used only by credential issuance. Anonymous group operations
   * authenticate exclusively through their zero-knowledge presentation.
   */
  identify(ctx: Context): Promise<ConvexGroupServerIdentity>;
}

interface InternalDefineConvexGroupServerConfig<Context>
  extends DefineConvexGroupServerConfig<Context> {
  secretParams?: ServerSecretParams;
  runtime?: GroupServerEngineRuntime;
}

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

function defaultConvexRuntime(): GroupServerEngineRuntime {
  return {
    now: () => Date.now(),
    randomBytes: (length) => crypto.getRandomValues(new Uint8Array(length)),
  };
}

/**
 * Derived server parameters, cached per isolate and keyed by the exact
 * environment value so a rotated secret is picked up on the next request.
 * Derivation costs tens of milliseconds; without the cache every query and
 * mutation would pay it before doing any work.
 */
let cachedSecretParams: {
  readonly encoded: string;
  readonly params: ServerSecretParams;
} | null = null;

function secretParamsFromEnvironment(): ServerSecretParams {
  const encoded = process.env[CONVEX_GROUP_SERVER_SECRET_ENV_VAR];
  if (!encoded) {
    throw new Error(
      `${CONVEX_GROUP_SERVER_SECRET_ENV_VAR} is not configured; run npx oe-groups trust-root before deploying the group server`
    );
  }
  if (cachedSecretParams && cachedSecretParams.encoded === encoded) {
    return cachedSecretParams.params;
  }
  let seed: Uint8Array;
  try {
    seed = base64ToBytes(asBase64(encoded));
  } catch {
    throw new Error(
      `${CONVEX_GROUP_SERVER_SECRET_ENV_VAR} must be canonical base64`
    );
  }
  try {
    if (seed.length !== 32) {
      throw new Error(
        `${CONVEX_GROUP_SERVER_SECRET_ENV_VAR} must decode to exactly 32 bytes`
      );
    }
    if (bytesToBase64(seed) !== encoded) {
      throw new Error(
        `${CONVEX_GROUP_SERVER_SECRET_ENV_VAR} must be canonical base64`
      );
    }
    const params = generateServerSecretParams(seed);
    cachedSecretParams = { encoded, params };
    return params;
  } finally {
    seed.fill(0);
  }
}

function requireUuid(value: Uint8Array, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== UUID_LENGTH) {
    throw new Error(`${label} must be a ${UUID_LENGTH}-byte UUID`);
  }
  if (value.every((byte) => byte === 0)) {
    throw new Error(`${label} must not be the nil UUID`);
  }
  return value;
}

function requireProfileKey(value: ArrayBuffer): Uint8Array {
  const profileKey = toUint8Array(value);
  if (profileKey.length !== PROFILE_KEY_LENGTH) {
    throw new Error(`profileKey must be ${PROFILE_KEY_LENGTH} bytes`);
  }
  return profileKey;
}

/**
 * Translate an engine rejection into a `ConvexError` so its structured
 * `{ code, status }` data survives serialization to real deployments.
 * Production Convex strips custom properties (including `data`) from plain
 * `Error`s and replaces their messages with a generic server error; only
 * `ConvexError` payloads reach the client, and the client's VERSION_CONFLICT
 * rebase-and-retry loop depends on reading `error.data.code`.
 */
async function translateEngineErrors<T>(
  operation: () => Promise<T>
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (!(error instanceof ConvexError) && error instanceof Error) {
      const data = (error as { data?: { code?: unknown; status?: unknown } })
        .data;
      if (
        data !== null &&
        typeof data === 'object' &&
        typeof data.code === 'string' &&
        typeof data.status === 'number'
      ) {
        throw new ConvexError({
          code: data.code,
          status: data.status,
          message: error.message,
        });
      }
    }
    throw error;
  }
}

function serviceIds(
  identity: ConvexGroupServerIdentity
): { aci: ServiceId; pni?: ServiceId } {
  if (identity === null || typeof identity !== 'object') {
    throw new ConvexError({
      code: 'UNAUTHORIZED',
      status: 401,
      message: 'identify() returned no identity',
    });
  }
  const aci: ServiceId = {
    kind: SERVICE_ID_ACI,
    uuid: requireUuid(identity.aciBytes, 'identify().aciBytes'),
  };
  const pni =
    identity.pniBytes === undefined
      ? undefined
      : {
          kind: SERVICE_ID_PNI,
          uuid: requireUuid(identity.pniBytes, 'identify().pniBytes'),
        };
  return { aci, pni };
}

async function getGroupDocument(
  ctx: GroupQueryContext,
  key: string
): Promise<any | null> {
  return await ctx.db
    .query(GROUPS_TABLE)
    .withIndex('by_group_id', (query) => query.eq('groupId', key))
    .unique();
}

async function getSnapshotDocument(
  ctx: GroupQueryContext,
  key: string,
  version: number
): Promise<any | null> {
  return await ctx.db
    .query(SNAPSHOTS_TABLE)
    // The generic data model loses the chained index-range builder type;
    // the runtime builder supports the full compound range.
    .withIndex('by_group_id_version', (query: any) =>
      query.eq('groupId', key).eq('version', version)
    )
    .unique();
}

function persistedSnapshot(document: any): GroupServerPersistedSnapshot {
  return {
    version: document.version as number,
    encryptedState: toUint8Array(document.encryptedState as ArrayBuffer),
    baselineSignature: toUint8Array(
      document.baselineSignature as ArrayBuffer
    ),
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
  } = {}
): Promise<{
  engine: GroupAuthorizationServerEngine;
  groupDocument: any | null;
}> {
  const engine = new GroupAuthorizationServerEngine(secretParams, runtime);
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
    const documents = await ctx.db
      .query(CHANGES_TABLE)
      // The generic data model loses the chained index-range builder type;
      // the runtime builder supports the full compound range.
      .withIndex('by_group_id_version', (query: any) =>
        query
          .eq('groupId', key)
          .gt('version', options.changesAfterVersion!)
      )
      .order('asc')
      .collect();
    for (const document of documents) {
      changes.push({
        version: document.version as number,
        actions: toUint8Array(document.actions as ArrayBuffer),
        serverSignature: toUint8Array(
          document.serverSignature as ArrayBuffer
        ),
        changeEpoch: document.changeEpoch as number,
        timestamp: document.timestamp as number,
      });
      const snapshot = await getSnapshotDocument(
        ctx,
        key,
        document.version as number
      );
      if (!snapshot) {
        throw new Error(
          `Missing group snapshot ${document.version as number}`
        );
      }
      snapshots.push(persistedSnapshot(snapshot));
    }
  }

  const persisted: GroupServerPersistedGroup = {
    encryptedState: toUint8Array(
      groupDocument.encryptedState as ArrayBuffer
    ),
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
  await ctx.db.insert(SNAPSHOTS_TABLE, {
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
  await ctx.db.insert(CHANGES_TABLE, {
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

function buildConvexGroupServer<Context>(
  config: InternalDefineConvexGroupServerConfig<Context>
) {
  const runtime = config.runtime ?? defaultConvexRuntime();
  const getSecretParams = (): ServerSecretParams =>
    config.secretParams ?? secretParamsFromEnvironment();

  return {
    createGroup: mutationGeneric({
      args: {
        groupId: v.bytes(),
        encryptedState: v.bytes(),
        presentation: v.bytes(),
        groupPublicParams: v.bytes(),
      },
      returns: v.null(),
      handler: async (ctx, input): Promise<null> => {
        const groupId = toUint8Array(input.groupId);
        const secretParams = getSecretParams();
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
        await ctx.db.insert(GROUPS_TABLE, {
          groupId: key,
          encryptedState: toArrayBuffer(persisted.encryptedState),
          version: state.version,
        });
        await insertSnapshot(ctx, key, persisted.snapshots[0]!);
        return null;
      },
    }),

    getGroup: queryGeneric({
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
        const version =
          input.version ?? (groupDocument.version as number);
        const secretParams = getSecretParams();
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
    }),

    getGroupJoinInfo: queryGeneric({
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
          getSecretParams(),
          runtime
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
    }),

    getGroupChanges: queryGeneric({
      args: {
        groupId: v.bytes(),
        fromVersion: v.number(),
        presentation: v.bytes(),
        groupPublicParams: v.bytes(),
      },
      returns: v.array(changeResultValidator),
      handler: async (ctx, input) => {
        const groupId = toUint8Array(input.groupId);
        const { engine, groupDocument } = await loadEngine(
          ctx,
          groupId,
          getSecretParams(),
          runtime,
          {
            snapshotVersions: [input.fromVersion],
            changesAfterVersion: input.fromVersion,
          }
        );
        if (!groupDocument) return [];
        const result = await translateEngineErrors(() =>
          engine.getGroupChanges(
            groupId,
            input.fromVersion,
            authorization(input)
          )
        );
        return result.map((entry) => ({
          version: entry.version,
          actions: toArrayBuffer(entry.actions),
          serverSignature: toArrayBuffer(entry.serverSignature),
          changeEpoch: entry.changeEpoch,
          timestamp: entry.timestamp,
        }));
      },
    }),

    submitGroupChange: mutationGeneric({
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
          getSecretParams(),
          runtime
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
    }),

    refreshGroupSendEndorsements: mutationGeneric({
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
        const version = groupDocument.version as number;
        const secretParams = getSecretParams();
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
    }),

    issueAuthCredentialMutation: mutationGeneric({
      args: {},
      returns: v.bytes(),
      handler: async (ctx) => {
        const { aci, pni } = serviceIds(
          await config.identify(ctx as unknown as Context)
        );
        const nowSeconds = Math.floor(runtime.now() / 1000);
        const redemptionTime =
          Math.floor(nowSeconds / SECONDS_PER_DAY) *
          SECONDS_PER_DAY;
        const response = issueAuthCredential(
          getSecretParams().credentialKeyPair,
          aci,
          pni,
          redemptionTime,
          runtime.randomBytes(32)
        );
        return toArrayBuffer(serializeAuthCredentialResponse(response));
      },
    }),

    issueProfileKeyCredentialMutation: mutationGeneric({
      args: { profileKey: v.bytes() },
      returns: v.bytes(),
      handler: async (ctx, input) => {
        const { aci } = serviceIds(
          await config.identify(ctx as unknown as Context)
        );
        const nowSeconds = Math.floor(runtime.now() / 1000);
        const redemptionTime =
          Math.floor(nowSeconds / SECONDS_PER_DAY) *
            SECONDS_PER_DAY +
          2 * SECONDS_PER_DAY;
        const response = issueProfileKeyCredential(
          getSecretParams().profileKeyCredentialKeyPair,
          aci,
          requireProfileKey(input.profileKey),
          redemptionTime,
          runtime.randomBytes(32)
        );
        return toArrayBuffer(
          serializeProfileKeyCredentialResponse(response)
        );
      },
    }),
  };
}

/**
 * Define the production Convex group-server functions.
 *
 * The returned registered functions own S1–S14 enforcement and persistence.
 * The application supplies only the app-auth-to-protocol-identity hook used
 * by the two credential issuance mutations.
 */
type ConvexGroupServerHandlers = ReturnType<
  typeof buildConvexGroupServer
>;

export function defineConvexGroupServer(
  config: DefineConvexGroupServerConfig
): ConvexGroupServerHandlers;
export function defineConvexGroupServer<Context>(
  config: DefineConvexGroupServerConfig<Context>
): ConvexGroupServerHandlers;
export function defineConvexGroupServer(
  config: DefineConvexGroupServerConfig<unknown>
): ConvexGroupServerHandlers {
  return buildConvexGroupServer(config);
}

/** @internal Test-only deterministic secret/runtime injection seam. */
export function defineConvexGroupServerForTest(
  config: DefineConvexGroupServerConfig<
    GenericMutationCtx<GenericDataModel>
  > & {
    secretParams: ServerSecretParams;
    runtime?: GroupServerEngineRuntime;
  }
) {
  return buildConvexGroupServer(config);
}
