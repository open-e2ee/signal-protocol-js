/**
 * EndorsementManager — client-side fetch, cache, and token generation
 * for GroupSendEndorsements.
 *
 * Lifecycle:
 *   1. Client calls fetchAndCacheEndorsements() after group state sync
 *   2. Endorsements are validated (batch proof) and cached to SQLite
 *   3. On send, getTokenForRecipient() produces a 24-byte bearer token
 *   4. For Sender Key multi-recipient sends, getCombinedToken() combines
 *      endorsements into a single token covering all recipients
 *   5. On membership change, the app-owned cache adapter invalidates the cache
 *
 * Refresh strategy:
 * - Endorsements expire daily (day-aligned UTC)
 * - Refresh when less than 2 hours remain before expiration
 * - On cache miss during send, fall back to identified delivery
 *
 */

import {
  receiveEndorsements,
  deserializeEndorsementsResponse,
  createFullToken,
  serializeFullToken,
  combineEndorsements,
} from '../internal/protocol/zk/groups/group-send-endorsement';
import {
  ClientDecryptionKey,
  CompressedEndorsement,
  Endorsement,
} from '../internal/protocol/zk/credentials/endorsements';
import type { ServerRootPublicKey } from '../internal/protocol/zk/credentials/endorsements';
import type { GroupSecretParams } from '../internal/protocol/zk/groups/group-params';
import type { ServiceId } from '../internal/protocol/zk/groups/uid-struct';
import { defaultSignalLogger, type ILogger } from '../logger';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Refresh endorsements when less than 2 hours remain before expiration.
 */
export {};
const ENDORSEMENT_REFRESH_THRESHOLD_SECONDS = 2 * 60 * 60;

// ---------------------------------------------------------------------------
// EndorsementManager
// ---------------------------------------------------------------------------

export interface EndorsementCacheStore {
  getCachedEndorsements(
    groupId: string
  ): Promise<{ endorsements: Map<string, Uint8Array>; expiration: number } | null>;
  cacheEndorsements(
    groupId: string,
    endorsements: Map<string, Uint8Array>,
    expiration: number
  ): Promise<void>;
  clearEndorsements(groupId: string): Promise<void>;
}

export class EndorsementManager {
  constructor(
    private readonly cache: EndorsementCacheStore,
    private readonly endorsementRootPublicKey: ServerRootPublicKey,
    private readonly logger: Required<ILogger> = defaultSignalLogger
  ) {}

  /**
   * Check if cached endorsements need refresh.
   *
   * @param expiration - Cached endorsement expiration in epoch seconds
   * @returns true if endorsements expire within 2 hours
   */
  needsRefresh(expiration: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return expiration - now < ENDORSEMENT_REFRESH_THRESHOLD_SECONDS;
  }

  /**
   * Check if cached endorsements are expired.
   *
   * @param expiration - Cached endorsement expiration in epoch seconds
   * @returns true if endorsements are past expiration
   */
  isExpired(expiration: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= expiration;
  }

  /**
   * Process an endorsement response from the server, validate the batch
   * proof, and cache per-member endorsements to SQLite.
   *
   * The caller is responsible for fetching the response via the
   * `refreshGroupSendEndorsements` mutation.
   *
   * @param groupId - Group identifier for cache key
   * @param endorsementsResponseBytes - Serialized GroupSendEndorsementsResponse from server
   * @param memberServiceIds - ServiceIds of all group members (must match server order)
   * @param memberUserIds - Convex user IDs parallel to memberServiceIds (used as cache keys)
   * @param localUserId - Self user ID to exclude from the cache
   *
   * @throws VerificationFailure if batch proof validation fails
   */
  async processAndCacheEndorsements(
    groupId: string,
    endorsementsResponseBytes: Uint8Array,
    memberServiceIds: ServiceId[],
    memberUserIds: string[],
    localUserId: string,
    groupSecretParams: GroupSecretParams
  ): Promise<void> {
    if (memberServiceIds.length !== memberUserIds.length) {
      throw new Error('memberServiceIds and memberUserIds must have the same length');
    }

    // 1. Deserialize the response
    const endorsementsResponse = deserializeEndorsementsResponse(endorsementsResponseBytes);

    // 2. Validate batch proof and extract per-member endorsements
    const nowSeconds = Math.floor(Date.now() / 1000);
    const receivedEndorsements = receiveEndorsements(
      endorsementsResponse,
      memberServiceIds,
      nowSeconds,
      groupSecretParams,
      this.endorsementRootPublicKey
    );

    // Build the compressed endorsement map without a self-endorsement.
    const endorsementMap = new Map<string, Uint8Array>();
    for (let i = 0; i < memberServiceIds.length; i++) {
      const userId = memberUserIds[i];
      // Skip self — we never send sealed sender to ourselves
      if (userId === localUserId) {
        continue;
      }
      const compressed = receivedEndorsements[i].endorsement.compress();
      endorsementMap.set(userId, compressed.R);
    }

    // 4. Cache via the app-owned endorsement adapter
    await this.cache.cacheEndorsements(groupId, endorsementMap, endorsementsResponse.expiration);

    this.logger.debug('Cached group send endorsements', {
      category: 'E2EE',
      data: {
        groupId,
        memberCount: memberServiceIds.length,
        cachedCount: endorsementMap.size,
        expiration: endorsementsResponse.expiration,
      },
    });
  }

  /**
   * Get a serialized GroupSendFullToken for a single recipient.
   *
   * Decompresses the cached endorsement, unblinds it with the group's
   * UID encryption key, and produces a 24-byte token suitable for
   * sending via the relay.
   *
   * @param groupId - Group identifier
   * @param recipientUserId - User ID of the recipient (used as cache key)
   * @returns Serialized 24-byte full token and expiration, or null if unavailable
   */
  async getTokenForRecipient(
    groupId: string,
    recipientUserId: string,
    groupSecretParams?: GroupSecretParams
  ): Promise<{ token: Uint8Array; expiration: number } | null> {
    const cached = await this.cache.getCachedEndorsements(groupId);
    if (!cached) return null;

    // Reject expired endorsements (clear stale cache)
    if (this.isExpired(cached.expiration)) {
      await this.cache.clearEndorsements(groupId);
      return null;
    }

    const compressedBytes = cached.endorsements.get(recipientUserId);
    if (!compressedBytes) {
      // Member may have been added after last endorsement fetch
      return null;
    }

    if (!groupSecretParams) {
      // Cannot generate token without group secret params
      return null;
    }

    // Decompress → toToken (unblind) → createFullToken → serialize
    const compressed = new CompressedEndorsement(compressedBytes);
    const endorsement = compressed.decompress();
    const clientKey = ClientDecryptionKey.forFirstPointOfAttribute(
      groupSecretParams.uidEncKeyPair.a1
    );
    const rawToken = endorsement.toToken(clientKey);
    const fullToken = createFullToken({ token: rawToken }, cached.expiration);
    return { token: serializeFullToken(fullToken), expiration: cached.expiration };
  }

  /**
   * Get a combined token for multi-recipient (Sender Key) sends.
   *
   * Combines individual endorsements for all specified recipients into
   * a single token. This is the algebraic set-union operation on
   * endorsement points before unblinding and hashing.
   *
   * @param groupId - Group identifier
   * @param recipientUserIds - User IDs of all recipients (excluding self)
   * @returns Serialized 24-byte full token and expiration, or null if unavailable
   *
   */
  async getCombinedToken(
    groupId: string,
    recipientUserIds: string[],
    groupSecretParams?: GroupSecretParams
  ): Promise<{ token: Uint8Array; expiration: number } | null> {
    if (recipientUserIds.length === 0) return null;

    const cached = await this.cache.getCachedEndorsements(groupId);
    if (!cached) return null;

    if (this.isExpired(cached.expiration)) {
      await this.cache.clearEndorsements(groupId);
      return null;
    }

    // Decompress all endorsements — if any member is missing, bail out
    const endorsements: Endorsement[] = [];
    for (const userId of recipientUserIds) {
      const compressedBytes = cached.endorsements.get(userId);
      if (!compressedBytes) {
        // Missing member endorsement — can't produce valid combined token.
        // Caller should use shouldRefreshEndorsements() pre-send to avoid this.
        this.logger.debug('Missing endorsement for member in getCombinedToken', {
          category: 'E2EE',
          data: { groupId, userId },
        });
        return null;
      }
      const compressed = new CompressedEndorsement(compressedBytes);
      endorsements.push(compressed.decompress());
    }

    if (!groupSecretParams) {
      // Cannot generate token without group secret params
      return null;
    }

    // Combine all endorsements → single point
    const combined = combineEndorsements(endorsements);

    // Unblind → hash → create full token
    const clientKey = ClientDecryptionKey.forFirstPointOfAttribute(
      groupSecretParams.uidEncKeyPair.a1
    );
    const rawToken = combined.toToken(clientKey);
    const fullToken = createFullToken({ token: rawToken }, cached.expiration);
    return { token: serializeFullToken(fullToken), expiration: cached.expiration };
  }

  /**
   * Check if any group member is missing a cached endorsement.
   *
   * Used in the pre-send endorsement refresh check.
   *
   * @param groupId - Group identifier
   * @param memberUserIds - User IDs of all group members (excluding self)
   * @returns true if any member is missing, false if all present or no cache
   */
  async isMissingAnyEndorsements(groupId: string, memberUserIds: string[]): Promise<boolean> {
    if (memberUserIds.length === 0) return false;

    const cached = await this.cache.getCachedEndorsements(groupId);
    if (!cached) return true; // No cache at all — everything is missing

    for (const userId of memberUserIds) {
      if (!cached.endorsements.has(userId)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check whether endorsements should be refreshed before sending.
   *
   * Checks three conditions:
   *  1. No endorsements cached at all
   *  2. Endorsements expire within 2 hours
   *  3. Any group member is missing an endorsement
   *
   * @param groupId - Group identifier
   * @param memberUserIds - User IDs of all group members (excluding self)
   * @returns Object indicating if refresh is needed and why
   *
   */
  async shouldRefreshEndorsements(
    groupId: string,
    memberUserIds: string[]
  ): Promise<{
    needsRefresh: boolean;
    reason?: 'missing_cache' | 'expiring_soon' | 'missing_members';
  }> {
    const cached = await this.cache.getCachedEndorsements(groupId);

    // No endorsement cache exists.
    if (!cached) {
      return { needsRefresh: true, reason: 'missing_cache' };
    }

    // Endorsements expire within two hours.
    if (this.needsRefresh(cached.expiration)) {
      return { needsRefresh: true, reason: 'expiring_soon' };
    }

    // At least one current member is missing an endorsement.
    for (const userId of memberUserIds) {
      if (!cached.endorsements.has(userId)) {
        return { needsRefresh: true, reason: 'missing_members' };
      }
    }

    return { needsRefresh: false };
  }

  /**
   * Clear cached endorsements for a group.
   *
   * Call on membership changes (member added/removed) to force
   * re-issuance on next group send.
   *
   */
  async clearGroupEndorsements(groupId: string): Promise<void> {
    await this.cache.clearEndorsements(groupId);
  }

  /**
   * Get the cached endorsement expiration for a group.
   *
   * @returns Expiration in epoch seconds, or null if no cache exists
   */
  async getCachedExpiration(groupId: string): Promise<number | null> {
    const cached = await this.cache.getCachedEndorsements(groupId);
    return cached?.expiration ?? null;
  }
}
