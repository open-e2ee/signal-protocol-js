/**
 * ConvexGroupServer
 *
 * Implementation of IGroupServer using Convex mutations/queries for
 * server-side encrypted group state storage.
 *
 * The server stores encrypted (opaque) group state and enforces version
 * sequencing. It never decrypts group content. This adapter bridges
 * the IGroupServer interface (Uint8Array) to Convex's v.bytes() (ArrayBuffer).
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
} from '../../../internal/groups-v2/manager';

/**
 * Either ConvexReactClient or ConvexHttpClient can be used.
 * This allows the adapter to work in both React contexts and background tasks.
 */
export {};
type ConvexClient = ConvexReactClient | ConvexHttpClient;

export interface ConvexGroupServerApi {
  createGroup: FunctionReference<'mutation'>;
  getGroup: FunctionReference<'query'>;
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
 * // Use with GroupsV2Manager
 * const manager = new GroupsV2Manager({
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
   * Get the latest encrypted group state from the server.
   *
   * @param groupId - 32-byte group identifier
   * @param authorization - ZK auth credential presentation + group public params
   * @returns Encrypted state and version, or null if group does not exist
   */
  async getGroup(
    groupId: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<{ encryptedState: Uint8Array; version: number } | null> {
    const result = await this.convex.query(this.api.getGroup, {
      groupId: this.toBytes(groupId),
      presentation: this.toBytes(authorization.presentation),
      groupPublicParams: this.toBytes(authorization.groupPublicParams),
    });

    if (!result) return null;

    return {
      encryptedState: new Uint8Array(result.encryptedState),
      version: result.version,
    };
  }

  /**
   * Get change log entries from a given version.
   *
   * Used for incremental group state sync. The server returns all changes
   * after the specified version, allowing the client to replay them locally.
   *
   * @param groupId - 32-byte group identifier
   * @param fromVersion - Version to start from (exclusive)
   * @param authorization - ZK auth credential presentation + group public params
   * @returns Array of change log entries with encrypted changes and server signatures
   */
  async getGroupChanges(
    groupId: Uint8Array,
    fromVersion: number,
    authorization: GroupAuthorization
  ): Promise<GroupChangeLogEntry[]> {
    const result = await this.convex.query(this.api.getGroupChanges, {
      groupId: this.toBytes(groupId),
      fromVersion,
      presentation: this.toBytes(authorization.presentation),
      groupPublicParams: this.toBytes(authorization.groupPublicParams),
    });

    return result.map(
      (entry: {
        version: number;
        encryptedChange: ArrayBuffer;
        serverSignature: ArrayBuffer;
        timestamp: number;
      }) => ({
        version: entry.version,
        encryptedChange: new Uint8Array(entry.encryptedChange),
        serverSignature: new Uint8Array(entry.serverSignature),
        timestamp: entry.timestamp,
      })
    );
  }

  /**
   * Submit a group change with optimistic concurrency control.
   *
   * The server validates the expected version matches the current version,
   * computes a Schnorr server signature over the encrypted change, stores
   * the change log entry, and updates the group state atomically.
   *
   * @param groupId - 32-byte group identifier
   * @param expectedVersion - Current version for optimistic concurrency
   * @param encryptedChange - Serialized EncryptedGroupChange
   * @param updatedEncryptedState - New full encrypted state after applying the change
   * @param authorization - ZK auth credential presentation + group public params
   * @returns Server signature over the encrypted change (for client-side verification)
   */
  async submitGroupChange(
    groupId: Uint8Array,
    expectedVersion: number,
    encryptedChange: Uint8Array,
    updatedEncryptedState: Uint8Array,
    authorization: GroupAuthorization
  ): Promise<{ serverSignature: Uint8Array }> {
    const result = await this.convex.mutation(this.api.submitGroupChange, {
      groupId: this.toBytes(groupId),
      expectedVersion,
      encryptedChange: this.toBytes(encryptedChange),
      updatedEncryptedState: this.toBytes(updatedEncryptedState),
      presentation: this.toBytes(authorization.presentation),
      groupPublicParams: this.toBytes(authorization.groupPublicParams),
    });

    return { serverSignature: new Uint8Array(result.serverSignature) };
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
