/**
 * Session Model
 *
 * Domain model for Signal Protocol sessions using Drizzle ORM.
 * Sessions contain Double Ratchet state for secure message exchange.
 *
 * Session ID format: 'userId:deviceId' (ProtocolAddress.toString())
 *
 *
 * @see https://signal.org/docs/specifications/doubleratchet/
 */

import {
  getDrizzle,
  getRawDatabase,
  sessions,
  type NewSession,
  eq,
  count,
  sql,
  inArray,
} from '../db';

// Row type from Drizzle schema (internal)
export {};
type SessionRow = typeof sessions.$inferSelect;
import {
  assertCurrentSessionRecord,
  CURRENT_SESSION_RECORD_VERSION,
  type SessionState,
  type SessionRecord,
  type SessionRecordMetadata,
} from '../../../../types/session';
import { secureZero } from '../../../../internal/crypto';
import type { IdentityType } from '../../../../keys/types';
export { serializeSessionRecord, deserializeSessionRecord } from '../../session-codec';
import { serializeSessionRecord, deserializeSessionRecord } from '../../session-codec';

// ============================================================================
// Constants
// ============================================================================

/**
 * Signal Protocol Session Record Version
 * Version 3: composite identities are part of the authenticated session state.
 */
const SESSION_VERSION = CURRENT_SESSION_RECORD_VERSION;
// ============================================================================
// Secure Key Zeroing Helper
// ============================================================================

/**
 * Best-effort overwrite decoded sensitive byte arrays in a session state.
 * JavaScript strings, engine copies, and physical memory cannot be guaranteed erased.
 *
 * @param state - Session state containing sensitive key material
 */
function secureZeroSessionState(state: SessionState): void {
  if (state.RK) secureZero(state.RK);
  if (state.CKs) secureZero(state.CKs);
  if (state.CKr) secureZero(state.CKr);
  if (state.DHs?.privateKey) secureZero(state.DHs.privateKey);

  // Zero receiverChains (skipped message keys storage)
  if (state.receiverChains) {
    for (const chain of state.receiverChains) {
      if (chain.chainKey) secureZero(chain.chainKey);
      for (const key of chain.messageKeys) {
        if (key?.seed) secureZero(key.seed);
      }
    }
  }
}

// ============================================================================
// Query Functions
// ============================================================================

/**
 * Get session by ID.
 *
 * @param sessionId - Session ID (format: userId:deviceId)
 * @returns Session instance or null if not found/corrupted
 */
export async function getSessionById(sessionId: string): Promise<Session | null> {
  const db = await getDrizzle();
  const results = await db
    .select()
    .from(sessions)
    .where(eq(sessions.sessionId, sessionId))
    .limit(1);

  if (results.length === 0) return null;

  const session = Session.fromRow(results[0]);
  if (!session) {
    await db.delete(sessions).where(eq(sessions.sessionId, sessionId));
    return null;
  }

  // Validate version
  if (session.version !== SESSION_VERSION) {
    return null;
  }

  return session;
}

/**
 * Get multiple sessions by IDs.
 * Uses a single IN query for efficiency (O(1) vs O(n) queries).
 *
 * @param sessionIds - Array of session IDs
 * @returns Record mapping session ID to session state
 */
export async function getSessionsByIds(
  sessionIds: string[]
): Promise<Record<string, SessionState>> {
  if (sessionIds.length === 0) return {};

  const db = await getDrizzle();
  const results = await db.select().from(sessions).where(inArray(sessions.sessionId, sessionIds));

  const output: Record<string, SessionState> = {};
  const corruptedSessionIds: string[] = [];
  for (const row of results) {
    const session = Session.fromRow(row);
    if (session?.version === SESSION_VERSION && session.currentSession) {
      output[session.id] = session.currentSession;
    } else if (!session || session.version !== SESSION_VERSION) {
      corruptedSessionIds.push(row.sessionId);
    }
  }
  if (corruptedSessionIds.length > 0) {
    await db.delete(sessions).where(inArray(sessions.sessionId, corruptedSessionIds));
  }
  return output;
}

/**
 * Get session IDs for a specific user.
 * Uses the userId:deviceId format to filter by user prefix.
 *
 * @param userId - User ID to filter by
 * @returns Array of session IDs for the user
 */
export async function getSessionIdsByUserId(userId: string): Promise<string[]> {
  const db = await getDrizzle();
  const results = await db
    .select({ sessionId: sessions.sessionId })
    .from(sessions)
    .where(sql`${sessions.sessionId} LIKE ${userId + ':%'}`);
  return results.map((r) => r.sessionId);
}

/**
 * Get all session IDs.
 *
 * @returns Array of all session IDs
 */
export async function getAllSessionIds(): Promise<string[]> {
  const db = await getDrizzle();
  const results = await db.select({ sessionId: sessions.sessionId }).from(sessions);
  return results.map((r) => r.sessionId);
}

/**
 * Check if session exists.
 *
 * @param sessionId - Session ID to check
 * @returns True if session exists
 */
export async function sessionExists(sessionId: string): Promise<boolean> {
  const session = await getSessionById(sessionId);
  return session !== null;
}

/**
 * Count sessions.
 *
 * @returns Number of sessions in database
 */
export async function countSessions(): Promise<number> {
  const db = await getDrizzle();
  const results = await db.select({ count: count() }).from(sessions);
  return results[0]?.count ?? 0;
}

/**
 * Delete session by ID.
 * Best-effort overwrites decoded key bytes before deleting the record.
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 *
 * @param sessionId - Session ID to delete
 */
export async function deleteSessionById(sessionId: string): Promise<void> {
  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    // Retrieve the session to overwrite decoded key bytes where possible.
    const session = await getSessionById(sessionId);
    if (session) {
      // Best-effort overwrite current decoded session state.
      if (session.currentSession) {
        secureZeroSessionState(session.currentSession);
      }

      // Best-effort overwrite archived decoded session states.
      for (const archived of Object.values(session.archivedSessions)) {
        secureZeroSessionState(archived);
      }
    }

    const db = await getDrizzle();
    await db.delete(sessions).where(eq(sessions.sessionId, sessionId));
  });
}

/**
 * Delete all sessions.
 * Best-effort overwrites decoded key bytes before deleting records.
 *
 * NOTE: Due to JavaScript string immutability, secureZero() only zeros the
 * decoded bytes, not the original base64 string. The base64 string remains
 * in memory until garbage collected. This is a fundamental JS limitation.
 * Defense in depth: We zero decoded bytes + rely on timely GC + database deletion.
 */
export async function deleteAllSessions(): Promise<void> {
  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    const db = await getDrizzle();

    // Fetch sessions to overwrite decoded key bytes where possible.
    const allRows = await db.select().from(sessions);

    for (const row of allRows) {
      const session = Session.fromRow(row);
      if (session) {
        if (session.currentSession) {
          secureZeroSessionState(session.currentSession);
        }
        for (const archived of Object.values(session.archivedSessions)) {
          secureZeroSessionState(archived);
        }
      }
    }

    await db.delete(sessions);
  });
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a new session with a session state.
 *
 * @param sessionId - Session ID (format: userId:deviceId)
 * @param state - Initial session state
 * @param identityType - 'aci' or 'pni' (defaults to 'aci')
 * @returns New Session instance (not yet persisted)
 */
export function createSession(
  sessionId: string,
  state: SessionState,
  identityType: IdentityType = 'aci'
): Session {
  const now = Date.now();
  const record: SessionRecord = {
    currentSession: state,
    archivedSessions: {},
    version: SESSION_VERSION,
  };
  assertCurrentSessionRecord(record);

  return new Session({
    sessionId,
    identityType,
    record: serializeSessionRecord(record),
    createdAt: now,
    updatedAt: now,
  });
}

/**
 * Create a session from a full SessionRecord.
 *
 * @param sessionId - Session ID (format: userId:deviceId)
 * @param record - Full session record with archived sessions
 * @param identityType - 'aci' or 'pni' (defaults to 'aci')
 * @returns New Session instance (not yet persisted)
 */
export function createSessionFromRecord(
  sessionId: string,
  record: SessionRecord,
  identityType: IdentityType = 'aci'
): Session {
  const now = Date.now();
  assertCurrentSessionRecord(record);

  return new Session({
    sessionId,
    identityType,
    record: serializeSessionRecord(record),
    createdAt: now,
    updatedAt: now,
  });
}

// ============================================================================
// Session Class
// ============================================================================

/**
 * Session domain model with business logic methods.
 *
 * Uses Drizzle ORM directly for type-safe database operations.
 *
 * @example
 * ```typescript
 * // Create and store a session
 * const session = createSession(sessionId, sessionState);
 * await session.save();
 *
 * // Get session by ID
 * const session = await getSessionById(sessionId);
 * const state = session?.currentSession;
 *
 * // Delete session after best-effort overwrite of decoded key bytes
 * await deleteSessionById(sessionId);
 * ```
 */
export class Session {
  private data: SessionRow;
  private _record: SessionRecord;

  constructor(data: SessionRow) {
    this.data = { ...data };
    this._record = deserializeSessionRecord(data.record);
    assertCurrentSessionRecord(this._record);
  }

  /**
   * Create Session from database row.
   * Returns null if session data is corrupted.
   * @internal Used by query functions
   */
  static fromRow(row: SessionRow): Session | null {
    try {
      return new Session(row);
    } catch {
      // Corrupted session data - return null
      return null;
    }
  }

  // ============================================================================
  // Accessors
  // ============================================================================

  /** Session ID (format: userId:deviceId) */
  get id(): string {
    return this.data.sessionId;
  }

  /** Current session state (may be null if all sessions archived) */
  get currentSession(): SessionState | null {
    return this._record.currentSession;
  }

  /** Archived sessions indexed by baseKey */
  get archivedSessions(): Record<string, SessionState> {
    return this._record.archivedSessions;
  }

  /** Session record version */
  get version(): number {
    return this._record.version;
  }

  /** Session record metadata */
  get metadata(): SessionRecordMetadata | undefined {
    return this._record.metadata;
  }

  /** Full session record */
  get record(): SessionRecord {
    return { ...this._record };
  }

  get createdAt(): number {
    return this.data.createdAt;
  }

  get updatedAt(): number {
    return this.data.updatedAt;
  }

  // ============================================================================
  // Domain Methods
  // ============================================================================

  /**
   * Validate session state has required Double Ratchet fields.
   *
   * @returns True if session is valid
   */
  async validate(): Promise<boolean> {
    const state = this.currentSession;
    if (!state) return false;

    // Section 3 variant (plaintext headers + MAC) - no header keys required
    const required = [
      'baseKey',
      'remoteAddress',
      'RK',
      'Ns',
      'Nr',
      'PN',
      'identityKeyPair',
      'localIdentity',
      'remoteIdentity',
      'createdAt',
      'lastUsedAt',
    ];

    for (const field of required) {
      if (!(field in state)) {
        return false;
      }
    }

    // receiverChains is required for skipped message keys storage
    if (!('receiverChains' in state)) {
      return false;
    }

    // Validate root key (chain keys can be undefined in lazy init)
    if (!state.RK?.trim()) {
      return false;
    }

    // Validate counters
    if (
      typeof state.Ns !== 'number' ||
      state.Ns < 0 ||
      typeof state.Nr !== 'number' ||
      state.Nr < 0 ||
      typeof state.PN !== 'number' ||
      state.PN < 0
    ) {
      return false;
    }

    return true;
  }

  // ============================================================================
  // Immutable Updates
  // ============================================================================

  /**
   * Create a new instance with updated current session.
   *
   * @param state - New current session state (or null to clear)
   * @returns New Session instance with updated state
   */
  withCurrentSession(state: SessionState | null): Session {
    const now = Date.now();
    const newRecord: SessionRecord = {
      ...this._record,
      currentSession: state,
    };
    return new Session({
      ...this.data,
      record: serializeSessionRecord(newRecord),
      updatedAt: now,
    });
  }

  /**
   * Create a new instance with an archived session.
   *
   * @param baseKey - Base key identifying the archived session
   * @param state - Session state to archive
   * @returns New Session instance with archived session added
   */
  withArchivedSession(baseKey: string, state: SessionState): Session {
    const now = Date.now();
    const newRecord: SessionRecord = {
      ...this._record,
      archivedSessions: {
        ...this._record.archivedSessions,
        [baseKey]: state,
      },
    };
    return new Session({
      ...this.data,
      record: serializeSessionRecord(newRecord),
      updatedAt: now,
    });
  }

  /**
   * Create a new instance with metadata.
   *
   * @param metadata - Session record metadata
   * @returns New Session instance with metadata
   */
  withMetadata(metadata: SessionRecordMetadata): Session {
    const now = Date.now();
    const newRecord: SessionRecord = {
      ...this._record,
      metadata,
    };
    return new Session({
      ...this.data,
      record: serializeSessionRecord(newRecord),
      updatedAt: now,
    });
  }

  // ============================================================================
  // Persistence
  // ============================================================================

  /**
   * Save session to database.
   */
  async save(): Promise<void> {
    assertCurrentSessionRecord(this._record);
    const db = await getDrizzle();
    const now = Date.now();

    const insertData: NewSession = {
      sessionId: this.data.sessionId,
      identityType: this.data.identityType,
      record: this.data.record,
      createdAt: this.data.createdAt,
      updatedAt: now,
    };

    await db
      .insert(sessions)
      .values(insertData)
      .onConflictDoUpdate({
        target: sessions.sessionId,
        set: {
          identityType: insertData.identityType,
          record: insertData.record,
          updatedAt: now,
        },
      });
  }

  /**
   * Delete session from database.
   * Best-effort overwrites decoded key bytes before deletion.
   */
  async delete(): Promise<void> {
    // Best-effort overwrite current decoded session state.
    if (this._record.currentSession) {
      secureZeroSessionState(this._record.currentSession);
    }

    // Best-effort overwrite archived decoded session states.
    for (const archived of Object.values(this._record.archivedSessions)) {
      secureZeroSessionState(archived);
    }

    const db = await getDrizzle();
    await db.delete(sessions).where(eq(sessions.sessionId, this.data.sessionId));
  }
}
