/**
 * ConvexGroupServer
 *
 * Implementation of IGroupServer using Convex mutations/queries for
 * server-side encrypted group state storage.
 *
 * This is a client transport adapter, not an enforcing group server. The
 * application-supplied Convex functions must implement the enforcing-server
 * obligations. This adapter bridges IGroupServer (Uint8Array) to Convex
 * v.bytes() (ArrayBuffer).
 *
 * The application supplies its generated Convex function references. Those
 * functions retain responsibility for authentication, authorization, and
 * persistence policy.
 */

import type { ConvexReactClient } from 'convex/react';
import type { ConvexHttpClient } from 'convex/browser';
import type { FunctionReference } from 'convex/server';
import type {
  IGroupServer,
  GroupAuthorization,
  GroupChangeLogEntry,
  GroupChangeLogPage,
  GroupSnapshot,
} from '../../../internal/groups/manager';

/**
 * Either ConvexReactClient or ConvexHttpClient can be used.
 * This allows the adapter to work in both React contexts and background tasks.
 */
export {};
type ConvexClient = ConvexReactClient | ConvexHttpClient;

export interface ConvexGroupServerApi {
  createGroup: FunctionReference<'mutation'>;
  getGroup: FunctionReference<'query'>;
  getGroupJoinInfo: FunctionReference<'query'>;
  getGroupChanges: FunctionReference<'query'>;
  submitGroupChange: FunctionReference<'mutation'>;
}

/**
 * ConvexGroupServer - Implementation of IGroupServer
 *
 * Bridges IGroupServer (Uint8Array-based) to Convex group mutations/queries
 * (ArrayBuffer-based). All binary conversion happens at this boundary.
 *
 * @example
 * ```typescript
 * import { ConvexReactClient } from 'convex/react';
 * import {
 *   ConvexGroupServer,
 *   type ConvexGroupServerApi,
 * } from '@open-e2ee/signal-protocol-sdk/remote/relay/convex';
 * import { api } from '../convex/_generated/api';
 *
 * const convex = new ConvexReactClient(process.env.CONVEX_URL!);
 * const groupApi = api.signal.groups satisfies ConvexGroupServerApi;
 * const groupServer = new ConvexGroupServer(convex, groupApi);
 *
 * // Use with GroupManager
 * const manager = new GroupManager({
 *   server: groupServer,
 *   store: localStore,
 *   ...
 * });
 * ```
 */
export class ConvexGroupServer implements IGroupServer {
  constructor(
    private convex: ConvexClient,
    private api: ConvexGroupServerApi
  ) {}

  // ════════════════════════════════════════════════════════════════════════════
  // GROUP CRUD
  // ════════════════════════════════════════════════════════════════════════════

  /**
   * Create a new encrypted group on the server.
   *
   * @param groupId - 32-byte group identifier (derived from GroupSecretParams)
   * @param encryptedState - Serialized EncryptedGroup (JSON with hex-encoded binary fields)
   * @param authorization - ZK auth credential presentation + group public params
   */
  async createGroup(
    groupId: Uint8Array,
    encryptedState: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<void> {
    await this.convex.mutation(this.api.createGroup, {
      groupId: this.toBytes(groupId),
      encryptedState: this.toBytes(encryptedState),
      presentation: this.toBytes(authorization.presentation),
      groupPublicParams: this.toBytes(authorization.groupPublicParams),
    });
  }

  /**
   * Get encrypted group state from the server.
   *
   * @param groupId - 32-byte group identifier
   * @param authorization - ZK auth credential presentation + group public params
   * @param version - Optional exact historical version
   * @returns Encrypted state and version, or null if group/version does not exist
   */
  async getGroup(
    groupId: Uint8Array,
    authorization: GroupAuthorization,
    version?: number
  ): Promise<GroupSnapshot | null> {
    const result = await this.convex.query(this.api.getGroup, {
      groupId: this.toBytes(groupId),
      presentation: this.toBytes(authorization.presentation),
      groupPublicParams: this.toBytes(authorization.groupPublicParams),
      version,
    });

    if (!result) return null;

    return {
      encryptedState: new Uint8Array(result.encryptedState),
      version: result.version,
      baselineSignature: new Uint8Array(result.baselineSignature),
    };
  }

  async getGroupJoinInfo(
    groupId: Uint8Array,
    inviteLinkPassword: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<{ encryptedJoinInfo: Uint8Array; version: number } | null> {
    const result = await this.convex.query(this.api.getGroupJoinInfo, {
      groupId: this.toBytes(groupId),
      inviteLinkPassword: this.toBytes(inviteLinkPassword),
      presentation: this.toBytes(authorization.presentation),
      groupPublicParams: this.toBytes(authorization.groupPublicParams),
    });

    if (!result) return null;

    return {
      encryptedJoinInfo: new Uint8Array(result.encryptedJoinInfo),
      version: result.version,
    };
  }

  /**
   * Get one page of change log entries from a given version.
   *
   * Used for incremental group state sync. The enforcing backend authorizes
   * at the requested snapshot, requires the requester to be a member there —
   * pending principals catch up by snapshot instead (S10a) — and returns
   * changes through the first transition that revokes the requester,
   * inclusive. A page cut for size sets `hasMore`; resume from the last
   * served version.
   *
   * @param groupId - 32-byte group identifier
   * @param fromVersion - Version to start from (exclusive)
   * @param authorization - ZK auth credential presentation + group public params
   * @returns One change-log page with encrypted changes and server signatures
   */
  async getGroupChanges(
    groupId: Uint8Array,
    fromVersion: number,
    authorization: GroupAuthorization
  ): Promise<GroupChangeLogPage> {
    const result = await this.convex.query(this.api.getGroupChanges, {
      groupId: this.toBytes(groupId),
      fromVersion,
      presentation: this.toBytes(authorization.presentation),
      groupPublicParams: this.toBytes(authorization.groupPublicParams),
    });

    return {
      entries: result.entries.map(
        (entry: {
          version: number;
          actions: ArrayBuffer;
          serverSignature: ArrayBuffer;
          changeEpoch: number;
          timestamp: number;
        }) => ({
          version: entry.version,
          actions: new Uint8Array(entry.actions),
          serverSignature: new Uint8Array(entry.serverSignature),
          changeEpoch: entry.changeEpoch,
          timestamp: entry.timestamp,
        })
      ),
      hasMore: result.hasMore,
    };
  }

  /**
   * Submit a group change with optimistic concurrency control.
   *
   * The application server validates and applies the ciphertext Actions,
   * signs the exact accepted bytes, and stores the transition atomically.
   *
   * @param groupId - 32-byte group identifier
   * @param expectedVersion - Current version for optimistic concurrency
   * @param actions - Client-proposed serialized encrypted Actions
   * @param inviteLinkPassword - Independently verified link-join credential
   * @param authorization - ZK auth credential presentation + group public params
   * @returns Exact accepted Actions and their server signature
   */
  async submitGroupChange(
    groupId: Uint8Array,
    expectedVersion: number,
    actions: Uint8Array,
    inviteLinkPassword: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<GroupChangeLogEntry> {
    if (arguments.length !== 5) {
      throw new Error(
        'INVALID_REQUEST: Group change submission must not carry an epoch'
      );
    }
    const result = await this.convex.mutation(this.api.submitGroupChange, {
      groupId: this.toBytes(groupId),
      expectedVersion,
      actions: this.toBytes(actions),
      inviteLinkPassword: this.toBytes(inviteLinkPassword),
      presentation: this.toBytes(authorization.presentation),
      groupPublicParams: this.toBytes(authorization.groupPublicParams),
    });

    return {
      version: result.version,
      actions: new Uint8Array(result.actions),
      serverSignature: new Uint8Array(result.serverSignature),
      changeEpoch: result.changeEpoch,
      timestamp: result.timestamp,
    };
  }

  // ════════════════════════════════════════════════════════════════════════════
  // UTILITY METHODS
  // ════════════════════════════════════════════════════════════════════════════

  /**
   * Convert Uint8Array to ArrayBuffer for Convex v.bytes() args.
   *
   * Handles the case where the Uint8Array is a view into a larger buffer
   * by slicing to the exact byte range.
   */
  private toBytes(data: Uint8Array): ArrayBuffer {
    return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  }
}
