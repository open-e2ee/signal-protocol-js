/** Double Ratchet session records, one per peer address. */

import type { SessionState } from '../../../../types';
import { ProtocolAddress } from '../../../../types/address';
import {
  assertCurrentSessionRecord,
  CURRENT_SESSION_RECORD_VERSION,
  SessionRecord,
} from '../../../../types/session';
import {
  clearSesameState,
  countSessions,
  createSession,
  createSessionFromRecord,
  deleteSessionById,
  deserializeSessionRecord,
  getAllSessionIds as modelGetAllSessionIds,
  getSessionById,
  getSessionIdsByUserId,
  getSessionsByIds,
  sessionExists,
} from '../models';
import { keyStorageError, type KeyStorageContext } from './context';

/**
 * Version 4: composite identities and explicit identity types are part of the
 * authenticated session state.
 */
const SESSION_VERSION = CURRENT_SESSION_RECORD_VERSION;

type PeerAddress = { userId: string; deviceId: number };

// Use colon separator to match ProtocolAddress.toString() format
function sessionIdOf(address: PeerAddress): string {
  return `${address.userId}:${address.deviceId}`;
}

/**
 * Store session state
 *
 * Accepts either a SessionState (wraps in SessionRecord) or a SessionRecord (stores directly).
 */
export async function storeSession(
  ctx: KeyStorageContext,
  sessionId: string,
  session: SessionState | SessionRecord
): Promise<void> {
  try {
    // If already a SessionRecord (has currentSession property), use createSessionFromRecord
    // Otherwise wrap the SessionState using createSession
    const sessionModel =
      'currentSession' in session
        ? createSessionFromRecord(sessionId, session)
        : createSession(sessionId, session as SessionState);

    await sessionModel.save(ctx.db);
  } catch (error) {
    throw keyStorageError(`Failed to store session ${sessionId}`, error);
  }
}

export async function getSession(
  ctx: KeyStorageContext,
  sessionId: string
): Promise<SessionState | null> {
  try {
    const session = await getSessionById(ctx.db, sessionId);

    if (!session) {
      return null;
    }

    if (session.version !== SESSION_VERSION) {
      ctx.logger.warn('Session version mismatch', {
        category: 'KeyStorage',
        data: { sessionId, expected: SESSION_VERSION, actual: session.version },
      });
      return null;
    }

    return session.currentSession;
  } catch (error) {
    throw keyStorageError(`Failed to retrieve session ${sessionId}`, error);
  }
}

/**
 * Delete session after best-effort overwrite of decoded key bytes.
 *
 * Delegates deletion to the Session model's best-effort decoded-byte overwrite.
 */
export async function deleteSession(ctx: KeyStorageContext, sessionId: string): Promise<void> {
  try {
    await deleteSessionById(ctx.db, sessionId);
  } catch (error) {
    throw keyStorageError(`Failed to delete session ${sessionId}`, error);
  }
}

/**
 * Clear all sessions, and the SESAME user records with them, for logout or
 * controlled local reset.
 */
export async function clearAllSessions(ctx: KeyStorageContext): Promise<void> {
  try {
    await clearSesameState(ctx.db);
  } catch (error) {
    throw keyStorageError('Failed to clear all sessions', error);
  }
}

/**
 * Get all session IDs from the database.
 *
 * Used by SESAME session management to enumerate all users with sessions.
 * Session IDs follow Signal Protocol format: "userId:deviceId"
 */
export async function getAllSessionIds(ctx: KeyStorageContext): Promise<string[]> {
  try {
    return await modelGetAllSessionIds(ctx.db);
  } catch (error) {
    throw keyStorageError('Failed to get all session IDs', error);
  }
}

/**
 * Get all session IDs for a user
 * Uses Signal Protocol standard colon separator (userId:deviceId)
 */
export async function getSessionIdsForUser(
  ctx: KeyStorageContext,
  userId: string
): Promise<string[]> {
  try {
    return await getSessionIdsByUserId(ctx.db, userId);
  } catch (error) {
    throw keyStorageError(`Failed to get session IDs for user ${userId}`, error);
  }
}

export async function getAllSessions(
  ctx: KeyStorageContext,
  sessionIds: string[]
): Promise<Record<string, SessionState>> {
  try {
    if (sessionIds.length === 0) {
      return {};
    }

    return await getSessionsByIds(ctx.db, sessionIds);
  } catch (error) {
    ctx.logger.warn('Failed to fetch sessions', {
      category: 'KeyStorage',
      error: error as Error,
    });
    return {};
  }
}

export async function validateSession(
  ctx: KeyStorageContext,
  sessionId: string
): Promise<boolean> {
  try {
    const session = await getSessionById(ctx.db, sessionId);
    if (!session) {
      return false;
    }

    return await session.validate();
  } catch (error) {
    ctx.logger.error('Session validation error', {
      category: 'KeyStorage',
      error: error as Error,
    });
    return false;
  }
}

// ============================================================================
// Session record management
// ============================================================================

export async function storeSessionRecord(
  ctx: KeyStorageContext,
  address: PeerAddress,
  record: SessionRecord
): Promise<void> {
  assertCurrentSessionRecord(record);
  await createSessionFromRecord(sessionIdOf(address), record).save(ctx.db);
}

export async function getSessionRecord(
  ctx: KeyStorageContext,
  address: PeerAddress
): Promise<SessionRecord | null> {
  try {
    const sessionId = sessionIdOf(address);

    const row = await ctx.db.first<{ record: string }>(
      'SELECT record FROM sessions WHERE session_id = ?',
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
      await ctx.db.run('DELETE FROM sessions WHERE session_id = ?', [sessionId]);
      return null;
    }

    return {
      currentSession: record.currentSession,
      archivedSessions: record.archivedSessions,
      version: record.version,
      metadata: record.metadata,
    };
  } catch (error) {
    throw keyStorageError(
      `Failed to retrieve session record for ${address.userId}:${address.deviceId}`,
      error
    );
  }
}

export async function deleteSessionRecord(
  ctx: KeyStorageContext,
  address: ProtocolAddress
): Promise<void> {
  await deleteSession(ctx, sessionIdOf(address));
}

export async function archiveCurrentSession(
  ctx: KeyStorageContext,
  address: ProtocolAddress,
  newSession?: SessionState
): Promise<void> {
  const sessionId = ProtocolAddress.toString(address);
  if (newSession) {
    const existing = await getSessionRecord(ctx, address);
    const record = existing ?? SessionRecord.create(newSession);
    if (existing) {
      SessionRecord.archiveCurrent(record, newSession);
    }
    await createSessionFromRecord(sessionId, record).save(ctx.db);
  } else {
    await deleteSession(ctx, sessionId);
  }
}

export async function getSessionsForUser(
  ctx: KeyStorageContext,
  userId: string
): Promise<SessionRecord[]> {
  try {
    const sessionIds = await getSessionIdsForUser(ctx, userId);
    if (sessionIds.length === 0) return [];

    const records: SessionRecord[] = [];

    for (const sessionId of sessionIds) {
      const session = await getSessionById(ctx.db, sessionId);
      if (!session || session.version !== SESSION_VERSION) continue;

      records.push(session.record);
    }

    return records;
  } catch (error) {
    throw keyStorageError(`Failed to get sessions for user ${userId}`, error);
  }
}

export async function hasSession(ctx: KeyStorageContext, address: PeerAddress): Promise<boolean> {
  return await sessionExists(ctx.db, sessionIdOf(address));
}

export async function getSessionCount(ctx: KeyStorageContext): Promise<number> {
  return await countSessions(ctx.db);
}
