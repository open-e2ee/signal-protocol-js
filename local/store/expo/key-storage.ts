/**
 * Key Storage using Unified SQLCipher Database
 *
 * Implements a single encrypted database for local protocol state:
 * - SQLCipher handles full-database encryption (no per-record encryption)
 * - All keys stored as base64 in direct columns
 * - Unified database for Signal Protocol data
 *
 * Architecture:
 * - Layer 1 (secret vault): Single database encryption key (DatabaseKeyManager)
 * - Layer 2 (SQLCipher): Full database encryption
 * - Storage: Direct columns for all key data
 *
 * See docs/E2EE.md for architecture details.
 */

import type {
  IdentityKeyPair,
  EcSignedPreKey,
  EcOneTimePreKey,
  KyberPreKey,
  KemOneTimePreKey,
  IdentityType,
  CompositeIdentityV1,
  ContactIdentityRecord,
} from '../../../keys';
import {
  acceptContactIdentityRotation as acceptRotation,
  createUnverifiedContactIdentityRecord,
  evaluateContactIdentityCandidate,
  verifyContactIdentityRecord,
  validateContactIdentityRecord,
} from '../../../keys/identity';
import type { PublicKey, PrivateKey, KeyPair } from '../../../keys/branded';
import type { SessionState, MessageRecord } from '../../../types';
import {
  assertCurrentSessionRecord,
  CURRENT_SESSION_RECORD_VERSION,
  SessionRecord,
} from '../../../types/session';
import { EncryptionError, EncryptionErrorCode } from '../../../types';
import { ProtocolAddress } from '../../../types/address';
import { getDatabaseKeyManager } from './database-key';
import { resolveSignalProtocolLogger, type ILogger } from '../../../logger';
import { MAX_UNACKNOWLEDGED_SESSION_AGE_MS } from '../../../types/protocol-config';

import {
  // Local identity
  getPrimaryIdentityKey,
  deletePrimaryIdentityKey,
  createPrimaryIdentityKey,
  getLocalRegistrationId as modelGetLocalRegistrationId,
  setLocalRegistrationId as modelSetLocalRegistrationId,
  // Recipient identity
  saveContactIdentity as modelSaveContactIdentity,
  getContactIdentity as modelGetContactIdentity,
  // EC Signed Prekey
  getEcSignedPreKeyByKeyId,
  getCurrentEcSignedPreKey,
  getAllEcSignedPreKeys,
  deleteEcSignedPreKeyByKeyId,
  getMaxEcSignedPreKeyId,
  storeReplacingEcSignedPreKey,
  createEcSignedPreKey,
  // EC One-Time Prekey
  getEcOneTimePreKeyByKeyId,
  getAllEcOneTimePreKeys,
  countEcOneTimePreKeys,
  deleteEcOneTimePreKeyByKeyId,
  storeBatchEcOneTimePreKeys,
  createEcOneTimePreKey,
  // Kyber Prekey
  getCurrentKyberPreKey,
  deleteKyberPreKeyByKeyId,
  getMaxKyberPreKeyId,
  createKyberPreKey,
  // Kyber One-Time Prekey
  getKyberOneTimePreKeyByKeyId,
  getAllKyberOneTimePreKeys,
  countKyberOneTimePreKeys,
  deleteKyberOneTimePreKeyByKeyId,
  storeBatchKyberOneTimePreKeys,
  createKyberOneTimePreKey,
  // Session
  getSessionById,
  getSessionsByIds,
  getSessionIdsByUserId,
  getAllSessionIds as modelGetAllSessionIds,
  sessionExists,
  countSessions,
  deleteSessionById,
  deleteAllSessions,
  createSession,
  createSessionFromRecord,
  deserializeSessionRecord,
  serializeSessionRecord,
  // Message records indexed by peer session and client timestamp
  getMessageRecord as modelGetMessageRecord,
  countMessageRecords,
  deleteMessageRecord as modelDeleteMessageRecord,
  deleteExpiredMessageRecords as modelDeleteExpiredMessageRecords,
  deleteAllMessageRecords as modelDeleteAllMessageRecords,
  deleteMessageRecordsBySessionId as modelDeleteMessageRecordsBySessionId,
  createMessageRecord,
  // Kyber Prekey Used (PQXDH replay detection)
  ReusedBaseKeyError,
  // Database access for complex queries
  getRawDatabase,
} from './models';
import { buildContactIdentityId } from './models/identity-key-id';
import type { SessionTrustCommit } from '../../../types';

/**
 * Signal Protocol Session Record Version
 *
 * Matches SessionRecord.version from types/session.ts
 * Version 4: composite identities and explicit identity types are part of the
 * authenticated session state.
 */
export {};
const SESSION_VERSION = CURRENT_SESSION_RECORD_VERSION;

// ============================================================================
// Row Types (Database schema)
// ============================================================================

/**
 * SessionRow is used by getSessionRecord() for raw SQL queries.
 * Other row types removed - queries now use Drizzle models.
 */
interface SessionRow {
  session_id: string;
  record: string; // JSON-serialized SessionRecord (future: protobuf)
  created_at: number;
  updated_at: number;
}

// ============================================================================
// KeyStorage
// ============================================================================

/**
 * KeyStorage implementation using Unified SQLCipher Database
 *
 * Provides secure storage for all Signal Protocol keys with:
 * - SQLCipher full-database encryption
 * - Database key custody through the configured local secret vault
 * - Direct SQL queries (no per-record encryption overhead)
 * - Unified storage with content tables
 */
export class KeyStorage {
  private logger: Required<ILogger>;

  constructor(providedLogger?: ILogger) {
    this.logger = resolveSignalProtocolLogger(providedLogger);
  }

  setLogger(providedLogger?: ILogger): void {
    this.logger = resolveSignalProtocolLogger(providedLogger);
  }

  // ============================================================================
  // Identity Keys
  // ============================================================================

  /**
   * Store identity key pair (only done once per device per identity type)
   *
   * IdentityKeyPair has nested structure:
   * - dhKey: { publicKey, privateKey } (X25519 for DH)
   * - signingKey: { publicKey, privateKey } (Ed25519 for signatures)
   * - registrationId: number
   *
   */
  async storeIdentityKey(
    keyPair: IdentityKeyPair,
    identityType: IdentityType = 'aci'
  ): Promise<void> {
    try {
      const identity = createPrimaryIdentityKey({
        publicKey: keyPair.dhKey.publicKey,
        dhKey: keyPair.dhKey,
        signingKey: keyPair.signingKey,
        registrationId: keyPair.registrationId,
        identityType,
      });
      await identity.save();
    } catch (error) {
      this.logger.error('[KeyStorage] storeIdentityKey failed', {
        category: 'E2EE',
        error: error instanceof Error ? error : new Error(String(error)),
      });
      throw new EncryptionError(
        'Failed to store identity key',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Retrieve identity key pair
   *
   */
  async getIdentityKey(identityType: IdentityType = 'aci'): Promise<IdentityKeyPair | null> {
    try {
      const identity = await getPrimaryIdentityKey(identityType);

      if (!identity) {
        return null;
      }

      const dhKeyRaw = identity.dhKey;
      const signingKeyRaw = identity.signingKey;
      const registrationId = identity.registrationId;

      if (!dhKeyRaw || !signingKeyRaw || registrationId === undefined) {
        return null;
      }

      // Cast strings to branded types for type safety
      const dhKey: KeyPair = {
        publicKey: dhKeyRaw.publicKey as PublicKey,
        privateKey: dhKeyRaw.privateKey as PrivateKey,
      };
      const signingKey: KeyPair = {
        publicKey: signingKeyRaw.publicKey as PublicKey,
        privateKey: signingKeyRaw.privateKey as PrivateKey,
      };

      return {
        dhKey,
        signingKey,
        registrationId,
      };
    } catch (error) {
      this.logger.error('[KeyStorage] getIdentityKey failed', {
        category: 'E2EE',
        error: error instanceof Error ? error : new Error(String(error)),
      });
      throw new EncryptionError(
        'Failed to retrieve identity key',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  async deleteIdentityKey(identityType: IdentityType = 'aci'): Promise<void> {
    try {
      await deletePrimaryIdentityKey(identityType);
    } catch (error) {
      throw new EncryptionError(
        'Failed to delete identity key',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  // ============================================================================
  // EC Signed Prekeys
  // ============================================================================

  /**
   * Store EC signed prekey.
   *
   * IMPORTANT: This DELETES all existing EC signed prekeys before inserting.
   * This matches the server-side behavior and prevents the "stale keyId" bug.
   *
   */
  async storeEcSignedPreKey(
    signedPreKey: EcSignedPreKey,
    identityType: IdentityType = 'aci'
  ): Promise<void> {
    try {
      const publicKey =
        typeof signedPreKey.publicKey === 'string'
          ? signedPreKey.publicKey
          : Buffer.from(signedPreKey.publicKey).toString('base64');
      const privateKey =
        typeof signedPreKey.privateKey === 'string'
          ? signedPreKey.privateKey
          : Buffer.from(signedPreKey.privateKey).toString('base64');
      const signature =
        typeof signedPreKey.signature === 'string'
          ? signedPreKey.signature
          : Buffer.from(signedPreKey.signature).toString('base64');

      const prekey = createEcSignedPreKey({
        keyId: signedPreKey.keyId,
        publicKey,
        privateKey,
        signature,
        timestamp: signedPreKey.timestamp,
        identityType,
      });

      // storeReplacingEcSignedPreKey handles DELETE all + INSERT in transaction
      await storeReplacingEcSignedPreKey(prekey, identityType);

      // DIAGNOSTIC: Log EC signed prekey storage for tracing
      this.logger.debug('storeEcSignedPreKey: Stored EC signed prekey', {
        category: 'E2EE',
        data: {
          keyId: signedPreKey.keyId,
          publicKeyPrefix: publicKey.substring(0, 20),
          timestamp: Date.now(),
          identityType,
        },
      });
    } catch (error) {
      throw new EncryptionError(
        'Failed to store EC signed prekey',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Retrieve EC signed prekey by ID.
   *
   * @param keyId - Optional key ID to retrieve. If not provided, returns the current (most recent) EC signed prekey.
   * @param identityType - 'aci' or 'pni' (defaults to 'aci')
   * @returns The EC signed prekey, or null if not found
   *
   */
  async getEcSignedPreKey(
    keyId?: number,
    identityType: IdentityType = 'aci'
  ): Promise<EcSignedPreKey | null> {
    try {
      let prekey;

      if (keyId !== undefined) {
        prekey = await getEcSignedPreKeyByKeyId(keyId, identityType);

        // DIAGNOSTIC: Log lookup result for debugging EC signed prekey issues
        if (!prekey) {
          const allPreKeys = await getAllEcSignedPreKeys(identityType);
          this.logger.warn('getEcSignedPreKey: Key not found by ID', {
            category: 'E2EE',
            data: {
              requestedKeyId: keyId,
              availableKeyIds: allPreKeys.map((k) => k.keyId),
              totalAvailable: allPreKeys.length,
              identityType,
            },
          });
        }
      } else {
        prekey = await getCurrentEcSignedPreKey(identityType);
      }

      if (!prekey) {
        return null;
      }

      return prekey.toEcSignedPreKey() as EcSignedPreKey;
    } catch (error) {
      throw new EncryptionError(
        'Failed to retrieve EC signed prekey',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get all stored EC signed prekeys (current + archived).
   *
   */
  async getAllEcSignedPreKeys(identityType: IdentityType = 'aci'): Promise<EcSignedPreKey[]> {
    try {
      const prekeys = await getAllEcSignedPreKeys(identityType);
      return prekeys.map((prekey) => prekey.toEcSignedPreKey() as EcSignedPreKey);
    } catch (error) {
      throw new EncryptionError(
        'Failed to retrieve all EC signed prekeys',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Mark an EC signed prekey as stale by ID.
   *
   * Called during cleanup to retire expired archived prekeys.
   * The prekey is retained for in-flight message decryption and
   * can be permanently purged later via purgeStaleEcSignedPreKeys().
   *
   */
  async removeEcSignedPreKey(keyId: number, identityType: IdentityType = 'aci'): Promise<void> {
    try {
      await deleteEcSignedPreKeyByKeyId(keyId, identityType);
    } catch (error) {
      throw new EncryptionError(
        'Failed to mark EC signed prekey as stale',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Clean up expired EC signed prekeys outside the grace period.
   *
   * Marks expired prekeys as stale. Keeps the most recent active
   * prekey and any prekeys within the grace period.
   * Stale prekeys are retained for in-flight message decryption.
   *
   */
  private async cleanupExpiredEcSignedPreKeys(identityType: IdentityType = 'aci'): Promise<void> {
    try {
      const db = getRawDatabase();
      const cutoff = Date.now() - MAX_UNACKNOWLEDGED_SESSION_AGE_MS;
      const now = Date.now();

      // Get active prekeys that will be marked replaced for logging
      const toMarkReplaced = await db.getAllAsync<{ prekey_id: number; created_at: number }>(
        `SELECT prekey_id, created_at FROM ec_signed_prekeys
         WHERE identity_type = ?
         AND created_at < ?
         AND replaced_at IS NULL
         AND prekey_id NOT IN (
           SELECT prekey_id FROM ec_signed_prekeys WHERE identity_type = ? AND replaced_at IS NULL ORDER BY created_at DESC LIMIT 1
         )`,
        [identityType, cutoff, identityType]
      );

      if (toMarkReplaced.length > 0) {
        this.logger.debug('cleanupExpiredEcSignedPreKeys: Marking expired prekeys as replaced', {
          category: 'E2EE',
          data: {
            markingReplacedKeyIds: toMarkReplaced.map((k) => k.prekey_id),
            cutoffTimestamp: cutoff,
            identityType,
          },
        });
      }

      // Mark expired prekeys as replaced, but keep the most recent active one
      await db.runAsync(
        `UPDATE ec_signed_prekeys SET replaced_at = ?
         WHERE identity_type = ?
         AND created_at < ?
         AND replaced_at IS NULL
         AND prekey_id NOT IN (
           SELECT prekey_id FROM ec_signed_prekeys WHERE identity_type = ? AND replaced_at IS NULL ORDER BY created_at DESC LIMIT 1
         )`,
        [now, identityType, cutoff, identityType]
      );
    } catch (error) {
      // Log but do not throw - cleanup is best-effort
      this.logger.warn('Failed to cleanup expired EC signed prekeys', {
        category: 'E2EE',
        data: { error, identityType },
      });
    }
  }

  // ============================================================================
  // EC One-Time Prekeys
  // ============================================================================

  /**
   * Store EC one-time prekeys (batch storage)
   *
   */
  async storeEcOneTimePreKeys(
    prekeys: EcOneTimePreKey[],
    identityType: IdentityType = 'aci'
  ): Promise<void> {
    try {
      const modelPreKeys = prekeys.map((pk) =>
        createEcOneTimePreKey({
          keyId: pk.keyId,
          publicKey: pk.publicKey,
          privateKey: pk.privateKey,
          identityType,
        })
      );

      await storeBatchEcOneTimePreKeys(modelPreKeys);
    } catch (error) {
      throw new EncryptionError(
        'Failed to store EC one-time prekeys',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Retrieve all EC one-time prekeys
   *
   */
  async getEcOneTimePreKeys(identityType: IdentityType = 'aci'): Promise<EcOneTimePreKey[]> {
    try {
      const prekeys = await getAllEcOneTimePreKeys(identityType);
      return prekeys.map((pk) => pk.toEcOneTimePreKey() as EcOneTimePreKey);
    } catch (error) {
      throw new EncryptionError(
        'Failed to retrieve EC one-time prekeys',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Remove consumed EC one-time prekey
   *
   */
  async removeEcOneTimePreKey(preKeyId: number, identityType: IdentityType = 'aci'): Promise<void> {
    try {
      await deleteEcOneTimePreKeyByKeyId(preKeyId, identityType);
    } catch (error) {
      throw new EncryptionError(
        'Failed to remove EC one-time prekey',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get EC one-time prekey count
   *
   */
  async getEcOneTimePreKeyCount(identityType: IdentityType = 'aci'): Promise<number> {
    try {
      return await countEcOneTimePreKeys(identityType);
    } catch (error) {
      throw new EncryptionError(
        'Failed to get EC one-time prekey count',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  // ============================================================================
  // Kyber Prekeys (Post-Quantum)
  // ============================================================================

  /**
   * Store Kyber prekey (post-quantum resistance)
   *
   */
  async storeKyberPreKey(
    kyberPreKey: KyberPreKey,
    identityType: IdentityType = 'aci'
  ): Promise<void> {
    try {
      const prekey = createKyberPreKey({
        keyId: kyberPreKey.keyId,
        publicKey: kyberPreKey.publicKey,
        privateKey: kyberPreKey.privateKey,
        signature: kyberPreKey.signature,
        timestamp: kyberPreKey.timestamp,
        identityType,
      });
      await prekey.save();
    } catch (error) {
      throw new EncryptionError(
        `Failed to store Kyber prekey ${kyberPreKey.keyId}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Retrieve Kyber prekey
   *
   */
  async getKyberPreKey(identityType: IdentityType = 'aci'): Promise<{
    keyId: number;
    publicKey: string;
    privateKey: string;
    signature: string;
    timestamp: number;
  } | null> {
    try {
      const prekey = await getCurrentKyberPreKey(identityType);
      if (!prekey) {
        return null;
      }
      return prekey.toKyberPreKey();
    } catch (error) {
      throw new EncryptionError(
        'Failed to retrieve Kyber prekey',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Mark Kyber prekey as used: PQXDH replay detection
   *
   * Inserts a (kyberPreKeyId, signedPreKeyIdentity, signedPreKeyId, baseKey) tuple.
   * Duplicate tuple = replay attack -> throws ReusedBaseKeyError.
   *
   */
  async markKyberPreKeyUsed(
    kyberPreKeyId: number,
    signedPreKeyId: number,
    baseKeyBytes: Uint8Array,
    identityType: IdentityType = 'aci'
  ): Promise<void> {
    try {
      const db = getRawDatabase();
      const baseKey = Buffer.from(baseKeyBytes).toString('base64');

      await db.runAsync(
        `INSERT INTO kyber_prekey_used
         (kyber_prekey_id, signed_prekey_identity, signed_prekey_id, base_key)
         VALUES (?, ?, ?, ?)`,
        [kyberPreKeyId, identityType, signedPreKeyId, baseKey]
      );
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      // Duplicate tuple = PQXDH replay attack
      if (
        errorMessage.includes('UNIQUE constraint failed') ||
        errorMessage.includes('PRIMARY KEY')
      ) {
        throw new ReusedBaseKeyError(kyberPreKeyId, signedPreKeyId);
      }
      throw new EncryptionError(
        `Failed to mark Kyber prekey ${kyberPreKeyId} as used`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Delete Kyber prekey
   *
   */
  async deleteKyberPreKey(id: number, identityType: IdentityType = 'aci'): Promise<void> {
    try {
      await deleteKyberPreKeyByKeyId(id, identityType);
    } catch (error) {
      throw new EncryptionError(
        `Failed to delete Kyber prekey ${id}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  // ============================================================================
  // Kyber One-Time Prekeys (Post-Quantum, Consumed on Use)
  // ============================================================================

  /**
   * Store one-time KEM prekeys (batch storage)
   *
   * Per PQXDH spec Section 3.2, these are signed one-time pqkem prekeys
   * that provide per-session post-quantum forward secrecy.
   *
   */
  async storeKemOneTimePreKeys(
    prekeys: KemOneTimePreKey[],
    identityType: IdentityType = 'aci'
  ): Promise<void> {
    try {
      const modelPreKeys = prekeys.map((pk) =>
        createKyberOneTimePreKey({
          keyId: pk.keyId,
          publicKey: pk.publicKey,
          privateKey: pk.privateKey,
          signature: pk.signature,
          timestamp: pk.timestamp,
          identityType,
        })
      );

      await storeBatchKyberOneTimePreKeys(modelPreKeys);
    } catch (error) {
      throw new EncryptionError(
        'Failed to store one-time Kyber prekeys',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Retrieve all one-time KEM prekeys
   *
   */
  async getKemOneTimePreKeys(identityType: IdentityType = 'aci'): Promise<KemOneTimePreKey[]> {
    try {
      const prekeys = await getAllKyberOneTimePreKeys(identityType);
      return prekeys.map((pk) => pk.toKemOneTimePreKey() as KemOneTimePreKey);
    } catch (error) {
      throw new EncryptionError(
        'Failed to retrieve one-time Kyber prekeys',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Retrieve a specific one-time KEM prekey by ID
   * Used during session establishment for decapsulation
   *
   */
  async getKemOneTimePreKey(
    keyId: number,
    identityType: IdentityType = 'aci'
  ): Promise<KemOneTimePreKey | null> {
    try {
      const prekey = await getKyberOneTimePreKeyByKeyId(keyId, identityType);
      if (!prekey) {
        return null;
      }
      return prekey.toKemOneTimePreKey() as KemOneTimePreKey;
    } catch (error) {
      throw new EncryptionError(
        `Failed to retrieve one-time Kyber prekey ${keyId}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Remove one-time KEM prekey after consumption
   *
   * CRITICAL: Must be called immediately after successful decapsulation
   * to provide per-session post-quantum forward secrecy.
   *
   */
  async removeKemOneTimePreKey(keyId: number, identityType: IdentityType = 'aci'): Promise<void> {
    try {
      await deleteKyberOneTimePreKeyByKeyId(keyId, identityType);

      this.logger.debug('Removed one-time KEM prekey after consumption', {
        category: 'KeyStorage',
        data: { keyId },
      });
    } catch (error) {
      throw new EncryptionError(
        `Failed to remove one-time Kyber prekey ${keyId}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get count of available one-time KEM prekeys
   *
   */
  async getKemOneTimePreKeyCount(identityType: IdentityType = 'aci'): Promise<number> {
    try {
      return await countKyberOneTimePreKeys(identityType);
    } catch (error) {
      throw new EncryptionError(
        'Failed to get one-time Kyber prekey count',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  // ============================================================================
  // Session Storage
  // ============================================================================

  /**
   * Store session state
   *
   * Accepts either a SessionState (wraps in SessionRecord) or a SessionRecord (stores directly).
   *
   */
  async storeSession(sessionId: string, session: SessionState | SessionRecord): Promise<void> {
    try {
      // If already a SessionRecord (has currentSession property), use createSessionFromRecord
      // Otherwise wrap the SessionState using createSession
      const sessionModel =
        'currentSession' in session
          ? createSessionFromRecord(sessionId, session)
          : createSession(sessionId, session as SessionState);

      await sessionModel.save();
    } catch (error) {
      throw new EncryptionError(
        `Failed to store session ${sessionId}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Retrieve session state
   *
   */
  async getSession(sessionId: string): Promise<SessionState | null> {
    try {
      const session = await getSessionById(sessionId);

      if (!session) {
        return null;
      }

      if (session.version !== SESSION_VERSION) {
        this.logger.warn('Session version mismatch', {
          category: 'KeyStorage',
          data: { sessionId, expected: SESSION_VERSION, actual: session.version },
        });
        return null;
      }

      return session.currentSession;
    } catch (error) {
      throw new EncryptionError(
        `Failed to retrieve session ${sessionId}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Delete session after best-effort overwrite of decoded key bytes.
   *
   * Delegates deletion to the Session model's best-effort decoded-byte overwrite.
   */
  async deleteSession(sessionId: string): Promise<void> {
    try {
      await deleteSessionById(sessionId);
    } catch (error) {
      throw new EncryptionError(
        `Failed to delete session ${sessionId}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Clear all sessions for logout or controlled local reset.
   *
   */
  async clearAllSessions(): Promise<void> {
    try {
      await deleteAllSessions();
    } catch (error) {
      throw new EncryptionError(
        'Failed to clear all sessions',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get all session IDs from the database.
   *
   * Used by SESAME session management to enumerate all users with sessions.
   * Session IDs follow Signal Protocol format: "userId:deviceId"
   *
   * @returns Array of all session IDs in the database
   * @throws {EncryptionError} If database query fails
   *
   */
  async getAllSessionIds(): Promise<string[]> {
    try {
      return await modelGetAllSessionIds();
    } catch (error) {
      throw new EncryptionError(
        'Failed to get all session IDs',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get all session IDs for a user
   * Uses Signal Protocol standard colon separator (userId:deviceId)
   *
   */
  async getSessionIdsForUser(userId: string): Promise<string[]> {
    try {
      return await getSessionIdsByUserId(userId);
    } catch (error) {
      throw new EncryptionError(
        `Failed to get session IDs for user ${userId}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get all sessions by IDs
   *
   */
  async getAllSessions(sessionIds: string[]): Promise<Record<string, SessionState>> {
    try {
      if (sessionIds.length === 0) {
        return {};
      }

      return await getSessionsByIds(sessionIds);
    } catch (error) {
      this.logger.warn('Failed to fetch sessions', {
        category: 'KeyStorage',
        error: error as Error,
      });
      return {};
    }
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  /**
   * Check if identity key exists
   */
  async hasIdentityKey(identityType: IdentityType = 'aci'): Promise<boolean> {
    try {
      const key = await this.getIdentityKey(identityType);
      return key !== null;
    } catch {
      return false;
    }
  }

  // ============================================================================
  // Metadata storage
  // ============================================================================

  async getMetadata(key: string): Promise<string | null> {
    const db = getRawDatabase();
    const row = await db.getFirstAsync<{ value: string }>(
      'SELECT value FROM metadata WHERE key = ?',
      [key]
    );
    return row?.value ?? null;
  }

  async setMetadata(key: string, value: string): Promise<void> {
    const db = getRawDatabase();
    await db.runAsync('INSERT OR REPLACE INTO metadata (key, value, updated_at) VALUES (?, ?, ?)', [
      key,
      value,
      Date.now(),
    ]);
  }

  /**
   * Clear all encryption keys
   *
   */
  async clearAllKeys(): Promise<void> {
    try {
      const db = getRawDatabase();

      // Wrap all DELETEs in one transaction, so the operation is atomic
      // If any DELETE fails, entire operation is rolled back
      await db.withTransactionAsync(async () => {
        await db.runAsync(`DELETE FROM identity_keys`);
        await db.runAsync(`DELETE FROM recipient_identities`);
        await db.runAsync(`DELETE FROM ec_signed_prekeys`);
        await db.runAsync(`DELETE FROM ec_one_time_prekeys`);
        await db.runAsync(`DELETE FROM kyber_prekeys`);
        await db.runAsync(`DELETE FROM kyber_prekey_used`);
        await db.runAsync(`DELETE FROM sessions`);
      });

      // Secret-vault deletion cannot join the SQLite transaction. A failure is
      // surfaced so the application can retry coordinated account teardown.
      const dbKeyManager = getDatabaseKeyManager(this.logger);
      await dbKeyManager.deleteKey();

      this.logger.warn('All keys cleared', { category: 'KeyStorage' });
    } catch (error) {
      throw new EncryptionError('Failed to clear all keys', EncryptionErrorCode.KEY_STORAGE_ERROR, {
        originalError: error as Error,
      });
    }
  }

  /**
   * Wipe all Signal Protocol data
   *
   */
  async wipeAllSignalProtocolData(): Promise<{
    sessions: number;
    ecSignedPreKeys: number;
    ecOneTimePreKeys: number;
    kyberPreKeys: number;
    kemOneTimePreKeys: number;
    users: number;
  }> {
    try {
      const stats = await this.getDetailedStats();

      const db = getRawDatabase();

      // Wrap all DELETEs in one transaction, so the operation is atomic
      // If any DELETE fails, entire operation is rolled back
      await db.withTransactionAsync(async () => {
        await db.runAsync(`DELETE FROM identity_keys`);
        await db.runAsync(`DELETE FROM recipient_identities`);
        await db.runAsync(`DELETE FROM ec_signed_prekeys`);
        await db.runAsync(`DELETE FROM ec_one_time_prekeys`);
        await db.runAsync(`DELETE FROM kyber_prekeys`);
        await db.runAsync(`DELETE FROM kyber_prekey_used`);
        await db.runAsync(`DELETE FROM kyber_one_time_prekeys`);
        await db.runAsync(`DELETE FROM sessions`);
        await db.runAsync(`DELETE FROM sesame_device_records`);
      });

      this.logger.info('All Signal Protocol data wiped', {
        category: 'KeyStorage',
        data: stats,
      });

      return stats;
    } catch (error) {
      throw new EncryptionError(
        'Failed to wipe Signal Protocol data',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get storage statistics
   */
  async getStorageStats(): Promise<{
    hasIdentityKey: boolean;
    hasEcSignedPreKey: boolean;
    ecOneTimePreKeysCount: number;
  }> {
    try {
      const hasIdentityKey = await this.hasIdentityKey();
      const ecSignedPreKey = await this.getEcSignedPreKey();
      const ecOneTimePreKeysCount = await this.getEcOneTimePreKeyCount();

      return {
        hasIdentityKey,
        hasEcSignedPreKey: ecSignedPreKey !== null,
        ecOneTimePreKeysCount,
      };
    } catch (error) {
      throw new EncryptionError(
        'Failed to get storage stats',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get detailed statistics
   *
   */
  async getDetailedStats(): Promise<{
    sessions: number;
    ecSignedPreKeys: number;
    ecOneTimePreKeys: number;
    kyberPreKeys: number;
    kemOneTimePreKeys: number;
    users: number;
  }> {
    try {
      const db = getRawDatabase();

      const [ecSigned, ecOneTime, kyber, kemOneTime, sessions, users] = await Promise.all([
        db.getFirstAsync<{ count: number }>(`SELECT COUNT(*) as count FROM ec_signed_prekeys`),
        db.getFirstAsync<{ count: number }>(`SELECT COUNT(*) as count FROM ec_one_time_prekeys`),
        db.getFirstAsync<{ count: number }>(`SELECT COUNT(*) as count FROM kyber_prekeys`),
        db.getFirstAsync<{ count: number }>(`SELECT COUNT(*) as count FROM kyber_one_time_prekeys`),
        db.getFirstAsync<{ count: number }>(`SELECT COUNT(*) as count FROM sessions`),
        db.getFirstAsync<{ count: number }>(
          `SELECT COUNT(DISTINCT user_id) as count FROM sesame_device_records`
        ),
      ]);

      return {
        sessions: sessions?.count ?? 0,
        ecSignedPreKeys: ecSigned?.count ?? 0,
        ecOneTimePreKeys: ecOneTime?.count ?? 0,
        kyberPreKeys: kyber?.count ?? 0,
        kemOneTimePreKeys: kemOneTime?.count ?? 0,
        users: users?.count ?? 0,
      };
    } catch (error) {
      throw new EncryptionError(
        'Failed to get detailed stats',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Validate session integrity
   *
   */
  async validateSession(sessionId: string): Promise<boolean> {
    try {
      const session = await getSessionById(sessionId);
      if (!session) {
        return false;
      }

      return await session.validate();
    } catch (error) {
      this.logger.error('Session validation error', {
        category: 'KeyStorage',
        error: error as Error,
      });
      return false;
    }
  }

  // ============================================================================
  // Registration ID Management
  // ============================================================================

  /**
   */
  async getLocalRegistrationId(identityType: IdentityType = 'aci'): Promise<number> {
    const registrationId = await modelGetLocalRegistrationId(identityType);
    return registrationId ?? 0;
  }

  /**
   */
  async setLocalRegistrationId(id: number, identityType: IdentityType = 'aci'): Promise<void> {
    await modelSetLocalRegistrationId(id, identityType);
  }

  // ============================================================================
  // Contact Identity Management
  // ============================================================================

  /**
   */
  async saveContactIdentity(
    address: { userId: string; deviceId: number },
    identity: CompositeIdentityV1,
    identityType: IdentityType = 'aci',
    suppliedCommitment?: Uint8Array
  ): Promise<import('../../../types/trust').IdentityKeyChange> {
    try {
      const { IdentityKeyChange } = await import('../../../types/trust');
      const existing = await modelGetContactIdentity(address.userId, identityType);
      const status = evaluateContactIdentityCandidate(existing, identity, suppliedCommitment);
      if (status === 'NEW') {
        await modelSaveContactIdentity(
          address.userId,
          createUnverifiedContactIdentityRecord(identity, Date.now()),
          identityType
        );
        return IdentityKeyChange.NEW_IDENTITY;
      }
      if (status === 'MATCH') return IdentityKeyChange.UNCHANGED;
      if (status === 'ROLLBACK') return IdentityKeyChange.ROLLBACK;
      return IdentityKeyChange.CHANGED;
    } catch (error) {
      throw new EncryptionError(
        'Failed to save contact identity',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   */
  async getContactIdentity(
    address: { userId: string; deviceId: number },
    identityType: IdentityType = 'aci'
  ): Promise<ContactIdentityRecord | null> {
    try {
      return await modelGetContactIdentity(address.userId, identityType);
    } catch (error) {
      throw new EncryptionError(
        'Failed to get contact identity',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  async acceptContactIdentityRotation(
    address: { userId: string; deviceId: number },
    identity: CompositeIdentityV1,
    identityType: IdentityType = 'aci',
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord> {
    return await this.acceptContactIdentityRotationAndDeleteSessions(
      ProtocolAddress.create(address.userId, address.deviceId),
      identity,
      identityType,
      suppliedCommitment
    );
  }

  async acceptContactIdentityRotationAndDeleteSessions(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType: IdentityType = 'aci',
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord> {
    const db = getRawDatabase();
    let replacement: ContactIdentityRecord | undefined;
    await db.withTransactionAsync(async () => {
      const recipientId = buildContactIdentityId(address.userId, identityType);
      const row = await db.getFirstAsync<{ recordJson: string }>(
        `SELECT record_json AS recordJson FROM recipient_identities WHERE recipient_id = ?`,
        [recipientId]
      );
      if (!row) throw new Error('Cannot rotate an unseen identity');
      const existing = JSON.parse(row.recordJson) as ContactIdentityRecord;
      validateContactIdentityRecord(existing);
      replacement = acceptRotation(existing, identity, Date.now(), suppliedCommitment);
      validateContactIdentityRecord(replacement);
      await db.runAsync(
        `INSERT OR REPLACE INTO recipient_identities
           (recipient_id, identity_type, record_json, updated_at) VALUES (?, ?, ?, ?)`,
        [recipientId, identityType, JSON.stringify(replacement), Date.now()]
      );

      const sessions = await db.getAllAsync<{ sessionId: string }>(
        `SELECT session_id AS sessionId FROM sessions`
      );
      for (const session of sessions) {
        let parsed: ProtocolAddress;
        try {
          parsed = ProtocolAddress.parse(session.sessionId);
        } catch {
          continue;
        }
        if (parsed.userId === address.userId) {
          await db.runAsync(`DELETE FROM sessions WHERE session_id = ?`, [session.sessionId]);
        }
      }
    });
    if (!replacement) throw new Error('Identity rotation transaction produced no replacement');
    return replacement;
  }

  async verifyContactIdentity(
    address: { userId: string; deviceId: number },
    identity: CompositeIdentityV1,
    identityType: IdentityType = 'aci',
    suppliedCommitment?: Uint8Array
  ): Promise<ContactIdentityRecord> {
    const db = getRawDatabase();
    let verified: ContactIdentityRecord | undefined;
    await db.withTransactionAsync(async () => {
      const recipientId = buildContactIdentityId(address.userId, identityType);
      const row = await db.getFirstAsync<{ recordJson: string }>(
        `SELECT record_json AS recordJson FROM recipient_identities WHERE recipient_id = ?`,
        [recipientId]
      );
      if (!row) throw new Error('Cannot verify an unseen identity');
      const existing = JSON.parse(row.recordJson) as ContactIdentityRecord;
      validateContactIdentityRecord(existing);
      verified = verifyContactIdentityRecord(existing, identity, Date.now(), suppliedCommitment);
      validateContactIdentityRecord(verified);
      await db.runAsync(
        `INSERT OR REPLACE INTO recipient_identities
           (recipient_id, identity_type, record_json, updated_at) VALUES (?, ?, ?, ?)`,
        [recipientId, identityType, JSON.stringify(verified), Date.now()]
      );
    });
    if (!verified) throw new Error('Identity verification transaction produced no result');
    return verified;
  }

  /**
   */
  async isTrustedIdentity(
    address: { userId: string; deviceId: number },
    identity: CompositeIdentityV1,
    _direction: number,
    identityType: IdentityType = 'aci'
  ): Promise<boolean> {
    const status = evaluateContactIdentityCandidate(
      await modelGetContactIdentity(address.userId, identityType),
      identity
    );
    return status === 'NEW' || status === 'MATCH';
  }

  // ============================================================================
  // Session record management
  // ============================================================================

  async storeSessionRecord(
    address: { userId: string; deviceId: number },
    record: SessionRecord
  ): Promise<void> {
    // Use colon separator to match ProtocolAddress.toString() format
    const sessionId = `${address.userId}:${address.deviceId}`;
    assertCurrentSessionRecord(record);
    await createSessionFromRecord(sessionId, record).save();
  }

  async commitSessionTrust(commit: SessionTrustCommit): Promise<void> {
    assertCurrentSessionRecord(commit.record);
    const db = getRawDatabase();
    const sessionId = ProtocolAddress.toString(commit.address);
    const serialized = serializeSessionRecord(commit.record);
    const now = Date.now();
    await db.withTransactionAsync(async () => {
      const existingContact = await modelGetContactIdentity(
        commit.address.userId,
        commit.contactIdentityType
      );
      const contactStatus = evaluateContactIdentityCandidate(
        existingContact,
        commit.contactIdentity
      );
      if (contactStatus !== 'NEW' && contactStatus !== 'MATCH') {
        throw new Error(`Atomic session/trust commit rejected contact identity status ${contactStatus}`);
      }
      if (
        commit.oneTimePreKeyId !== undefined &&
        !(await getEcOneTimePreKeyByKeyId(
          commit.oneTimePreKeyId,
          commit.localIdentityType
        ))
      ) {
        throw new Error('Atomic session/trust commit cannot consume a missing EC one-time prekey');
      }
      if (
        commit.kemOneTimePreKeyId !== undefined &&
        !(await getKyberOneTimePreKeyByKeyId(
          commit.kemOneTimePreKeyId,
          commit.localIdentityType
        ))
      ) {
        throw new Error('Atomic session/trust commit cannot consume a missing KEM one-time prekey');
      }
      if (contactStatus === 'NEW') {
        await modelSaveContactIdentity(
          commit.address.userId,
          createUnverifiedContactIdentityRecord(commit.contactIdentity, now),
          commit.contactIdentityType
        );
      }
      await db.runAsync(
        `INSERT INTO sessions (session_id, identity_type, record, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(session_id) DO UPDATE SET
             identity_type = excluded.identity_type,
             record = excluded.record,
             updated_at = excluded.updated_at`,
        [sessionId, commit.contactIdentityType, serialized, now, now]
      );
      if (commit.oneTimePreKeyId !== undefined) {
        await db.runAsync(
          `DELETE FROM ec_one_time_prekeys WHERE identity_type = ? AND prekey_id = ?`,
          [commit.localIdentityType, commit.oneTimePreKeyId]
        );
      }
      if (commit.kemOneTimePreKeyId !== undefined) {
        await db.runAsync(
          `DELETE FROM kyber_one_time_prekeys WHERE identity_type = ? AND prekey_id = ?`,
          [commit.localIdentityType, commit.kemOneTimePreKeyId]
        );
      }
    });
  }

  /**
   * Get session record by address
   *
   */
  async getSessionRecord(
    address: { userId: string; deviceId: number }
  ): Promise<SessionRecord | null> {
    try {
      // Use colon separator to match ProtocolAddress.toString() format
      const sessionId = `${address.userId}:${address.deviceId}`;
      const db = getRawDatabase();

      const row = await db.getFirstAsync<SessionRow>(
        `SELECT record FROM sessions WHERE session_id = ?`,
        [sessionId]
      );

      if (!row) {
        return null;
      }

      let record: SessionRecord;
      try {
        record = deserializeSessionRecord(row.record);
        assertCurrentSessionRecord(record);
      } catch {
        await db.runAsync(`DELETE FROM sessions WHERE session_id = ?`, [sessionId]);
        return null;
      }

      return {
        currentSession: record.currentSession,
        archivedSessions: record.archivedSessions,
        version: record.version,
        metadata: record.metadata,
      };
    } catch (error) {
      throw new EncryptionError(
        `Failed to retrieve session record for ${address.userId}:${address.deviceId}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  async deleteSessionRecord(address: ProtocolAddress): Promise<void> {
    // Use colon separator to match ProtocolAddress.toString() format
    const sessionId = `${address.userId}:${address.deviceId}`;
    await this.deleteSession(sessionId);
  }

  async archiveCurrentSession(address: ProtocolAddress, newSession?: SessionState): Promise<void> {
    const sessionId = ProtocolAddress.toString(address);
    if (newSession) {
      const existing = await this.getSessionRecord(address);
      const record = existing ?? SessionRecord.create(newSession);
      if (existing) {
        SessionRecord.archiveCurrent(record, newSession);
      }
      await createSessionFromRecord(sessionId, record).save();
    } else {
      await this.deleteSession(sessionId);
    }
  }

  async getSessionsForUser(userId: string): Promise<SessionRecord[]> {
    try {
      const sessionIds = await this.getSessionIdsForUser(userId);
      if (sessionIds.length === 0) return [];

      const records: SessionRecord[] = [];

      for (const sessionId of sessionIds) {
        const session = await getSessionById(sessionId);
        if (!session || session.version !== SESSION_VERSION) continue;

        records.push(session.record);
      }

      return records;
    } catch (error) {
      throw new EncryptionError(
        `Failed to get sessions for user ${userId}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   */
  async hasSession(address: { userId: string; deviceId: number }): Promise<boolean> {
    // Use Signal Protocol standard colon separator
    const sessionId = `${address.userId}:${address.deviceId}`;
    return await sessionExists(sessionId);
  }

  /**
   */
  async getSessionCount(): Promise<number> {
    return await countSessions();
  }

  // ============================================================================
  // MessageRecord Storage (SESAME Retry Request Support)
  // Per SESAME Specification Section 6.2
  //
  // Retry records are indexed by the client timestamp assigned before encryption.
  // The primary lookup method is getMessageRecord().
  // ============================================================================

  /**
   * Store a message record for potential retry resending
   *
   * Called after successful encryption to store the plaintext.
   * Record is deleted after confirmed delivery or expiration.
   *
   */
  async storeMessageRecord(record: MessageRecord): Promise<void> {
    try {
      const messageRecordModel = createMessageRecord({
        sessionId: record.sessionId,
        timestamp: record.timestamp,
        recipientUserId: record.recipientUserId,
        recipientDeviceId: record.recipientDeviceId,
        plaintext: record.plaintext,
        sessionStateId: record.sessionStateId,
        createdAt: record.createdAt,
      });
      await messageRecordModel.save();

      this.logger.debug('Stored message record for retry support', {
        category: 'KeyStorage',
        data: {
          sessionId: record.sessionId,
          timestamp: record.timestamp,
          recipient: `${record.recipientUserId}:${record.recipientDeviceId}`,
        },
      });
    } catch (error) {
      throw new EncryptionError(
        `Failed to store message record ${record.sessionId}:${record.timestamp}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get a message record by session and timestamp
   *
   */
  async getMessageRecord(sessionId: string, timestamp: number): Promise<MessageRecord | null> {
    try {
      const record = await modelGetMessageRecord(sessionId, timestamp);
      return record?.toStoredMessageRecord() ?? null;
    } catch (error) {
      throw new EncryptionError(
        `Failed to get message record ${sessionId}:${timestamp}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Delete all expired message records older than maxAgeMs
   *
   * Called periodically to clean up old records.
   * Per SESAME spec: "The maxLatency setting serves as an upper bound on message age"
   *
   */
  async deleteExpiredMessageRecords(maxAgeMs: number): Promise<number> {
    try {
      const deleted = await modelDeleteExpiredMessageRecords(maxAgeMs);

      if (deleted > 0) {
        this.logger.info('Deleted expired message records', {
          category: 'KeyStorage',
          data: { deleted, maxAgeMs },
        });
      }

      return deleted;
    } catch (error) {
      throw new EncryptionError(
        'Failed to delete expired message records',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Clear all message records
   *
   * Called when device re-registers and all local sessions are cleared.
   * All stored message records become orphaned and should be deleted.
   *
   */
  async clearAllMessageRecords(): Promise<number> {
    try {
      const deleted = await modelDeleteAllMessageRecords();

      if (deleted > 0) {
        this.logger.info('Cleared all message records', {
          category: 'KeyStorage',
          data: { deleted },
        });
      }

      return deleted;
    } catch (error) {
      throw new EncryptionError(
        'Failed to clear message records',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Delete all message records for a session
   *
   * Called when a session is archived or deleted.
   *
   */
  async deleteMessageRecordsForSession(sessionId: string): Promise<number> {
    try {
      const deleted = await modelDeleteMessageRecordsBySessionId(sessionId);

      if (deleted > 0) {
        this.logger.debug('Deleted message records for session', {
          category: 'KeyStorage',
          data: { sessionId, deleted },
        });
      }

      return deleted;
    } catch (error) {
      throw new EncryptionError(
        `Failed to delete message records for session ${sessionId}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get count of message records (for statistics)
   *
   */
  async getMessageRecordCount(): Promise<number> {
    try {
      return await countMessageRecords();
    } catch (error) {
      throw new EncryptionError(
        'Failed to get message record count',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Delete a message record by session and timestamp.
   *
   * Called when processing delivery receipts to clean up confirmed messages.
   * Per Signal Protocol, messages are identified by client timestamp.
   *
   * @param sessionId - Session identifier (userId:deviceId)
   * @param timestamp - Client timestamp (set before encryption)
   */
  async deleteMessageRecord(sessionId: string, timestamp: number): Promise<void> {
    try {
      await modelDeleteMessageRecord(sessionId, timestamp);

      this.logger.debug('Deleted message record after delivery receipt', {
        category: 'KeyStorage',
        data: { sessionId, timestamp },
      });
    } catch (error) {
      throw new EncryptionError(
        `Failed to delete message record ${sessionId}:${timestamp}`,
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  // ============================================================================
  // Key Recovery Support (Bug #7 - PQXDH §4.13 Identifier Collision Recovery)
  // ============================================================================

  /**
   * Get the maximum signed prekey ID in storage.
   *
   * Used during key recovery to generate new prekeys with fresh IDs
   * that avoid identifier collisions (PQXDH §4.13).
   *
   * @returns The highest prekey_id, or 0 if no signed prekeys exist
   */
  /**
   */
  async getEcSignedPreKeyMaxId(identityType: IdentityType = 'aci'): Promise<number> {
    try {
      return await getMaxEcSignedPreKeyId(identityType);
    } catch (error) {
      throw new EncryptionError(
        'Failed to get max signed prekey ID',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Get the maximum Kyber prekey ID in storage.
   *
   * Used during key recovery to generate new prekeys with fresh IDs
   * that avoid identifier collisions (PQXDH §4.13).
   *
   * @returns The highest prekey_id, or 0 if no Kyber prekeys exist
   *
   */
  async getKyberPreKeyMaxId(identityType: IdentityType = 'aci'): Promise<number> {
    try {
      return await getMaxKyberPreKeyId(identityType);
    } catch (error) {
      throw new EncryptionError(
        'Failed to get max Kyber prekey ID',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }

  /**
   * Delete all prekeys (signed, one-time, Kyber, KEM one-time).
   *
   * Used during key recovery when persistent MAC failures indicate
   * identifier collision (same keyId, different publicKey).
   * Per PQXDH §4.13, this forces fresh key generation with new IDs.
   *
   * NOTE: This preserves identity keys and sessions.
   *
   */
  async deleteAllPreKeys(identityType: IdentityType = 'aci'): Promise<{
    ecSignedPreKeys: number;
    ecOneTimePreKeys: number;
    kyberPreKeys: number;
    kemOneTimePreKeys: number;
  }> {
    try {
      const db = getRawDatabase();

      // Get counts before deletion for logging
      const [ecSigned, ecOneTime, kyber, kemOneTime] = await Promise.all([
        db.getFirstAsync<{ count: number }>(
          `SELECT COUNT(*) as count FROM ec_signed_prekeys WHERE identity_type = ?`,
          [identityType]
        ),
        db.getFirstAsync<{ count: number }>(
          `SELECT COUNT(*) as count FROM ec_one_time_prekeys WHERE identity_type = ?`,
          [identityType]
        ),
        db.getFirstAsync<{ count: number }>(
          `SELECT COUNT(*) as count FROM kyber_prekeys WHERE identity_type = ?`,
          [identityType]
        ),
        db.getFirstAsync<{ count: number }>(
          `SELECT COUNT(*) as count FROM kyber_one_time_prekeys WHERE identity_type = ?`,
          [identityType]
        ),
      ]);

      const stats = {
        ecSignedPreKeys: ecSigned?.count ?? 0,
        ecOneTimePreKeys: ecOneTime?.count ?? 0,
        kyberPreKeys: kyber?.count ?? 0,
        kemOneTimePreKeys: kemOneTime?.count ?? 0,
      };

      // Delete prekeys for the specified identity type
      await db.runAsync(`DELETE FROM ec_signed_prekeys WHERE identity_type = ?`, [identityType]);
      await db.runAsync(`DELETE FROM ec_one_time_prekeys WHERE identity_type = ?`, [identityType]);
      await db.runAsync(`DELETE FROM kyber_prekeys WHERE identity_type = ?`, [identityType]);
      await db.runAsync(`DELETE FROM kyber_prekey_used WHERE signed_prekey_identity = ?`, [
        identityType,
      ]);
      await db.runAsync(`DELETE FROM kyber_one_time_prekeys WHERE identity_type = ?`, [
        identityType,
      ]);

      this.logger.warn('Deleted all prekeys for key recovery', {
        category: 'KeyStorage',
        data: { ...stats, identityType },
      });

      return stats;
    } catch (error) {
      throw new EncryptionError(
        'Failed to delete all prekeys',
        EncryptionErrorCode.KEY_STORAGE_ERROR,
        { originalError: error as Error }
      );
    }
  }
}

// ============================================================================
// Singleton
// ============================================================================

let keyStorageInstance: KeyStorage | null = null;

export function getKeyStorage(providedLogger?: ILogger): KeyStorage {
  if (!keyStorageInstance) {
    keyStorageInstance = new KeyStorage(providedLogger);
  } else if (providedLogger) {
    keyStorageInstance.setLogger(providedLogger);
  }
  return keyStorageInstance;
}

export async function resetKeyStorage(): Promise<void> {
  keyStorageInstance = null;
}
