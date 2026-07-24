/**
 * SessionResolver - Session Record Resolution Logic
 *
 * @layer 3 - Domain/Session
 *
 * Handles the active/inactive session logic per SESAME spec:
 * - Inserting new sessions (demoting current to archived)
 * - Finding sessions that can decrypt a message
 * - Promoting archived sessions on successful decryption (convergence)
 *
 * This class provides pure functions that wrap the SessionRecord namespace
 * functions with active/archive record handling shared by SESAME orchestration
 * and the lower-level session cipher.
 *
 * @see https://signal.org/docs/specifications/sesame/
 */

import type { SessionState, SessionRecord } from '../../types/session';
import {
  CURRENT_SESSION_RECORD_VERSION,
  SessionRecord as SessionRecordNS,
} from '../../types/session';
import type { Base64 } from '../../types/utils';

/**
 * Candidate session for decryption attempt.
 *
 * When receiving a message, we try decryption on multiple sessions
 * in order: current session first, then archived sessions.
 */
export {};
export interface DecryptionCandidate {
  /** The session state to try */
  session: SessionState;
  /** Base key identifying this session (null for current) */
  baseKey: Base64 | null;
  /** Whether this is the current (active) session */
  isActive: boolean;
}

/**
 * SessionResolver handles the active/inactive session logic per SESAME spec.
 *
 * This class provides pure, static functions for session management:
 *
 * **insertSession**: When establishing a new session, the current session
 * is archived and the new session becomes active. This handles the case
 * where we initiate a session while the other party also initiates one.
 *
 * **findDecryptingSessions**: Returns an ordered list of sessions to try
 * for decryption. Current session is tried first, then archived sessions.
 *
 * **promoteSession**: When we successfully decrypt on an archived session,
 * that session becomes the new active session (session convergence).
 * This ensures both parties eventually converge to the same session.
 *
 * **archiveCurrentSession**: Moves the current session to archived without
 * replacing it. Used when handling retry requests.
 *
 * @example
 * ```typescript
 * // Insert a new session
 * const record = SessionResolver.insertSession(existingRecord, newSession, true, 5);
 *
 * // Find sessions for decryption
 * const candidates = SessionResolver.findDecryptingSessions(record);
 * for (const candidate of candidates) {
 *   try {
 *     const plaintext = decrypt(ciphertext, candidate.session);
 *     if (!candidate.isActive) {
 *       // Promote the archived session (convergence)
 *       const updated = SessionResolver.promoteSession(record, candidate.baseKey!);
 *     }
 *     break;
 *   } catch {
 *     continue;
 *   }
 * }
 * ```
 *
 * @see https://signal.org/docs/specifications/sesame/
 */
export class SessionResolver {
  /**
   * Insert a new session, archiving the current one if present.
   *
   * This is called when establishing a new session via X3DH/PQXDH.
   * If there's an existing session, it's moved to the archived list
   * to handle race conditions (both parties initiating simultaneously).
   *
   * @param sessionRecord - Current SessionRecord (or null for first session)
   * @param newSession - The new SessionState to make active
   * @param isInitiator - Whether we initiated this session
   * @param maxArchived - Maximum archived sessions to retain
   * @returns Updated SessionRecord with new session as current
   */
  static insertSession(
    sessionRecord: SessionRecord | null,
    newSession: SessionState,
    isInitiator: boolean,
    maxArchived: number
  ): SessionRecord {
    const now = Date.now();

    if (!sessionRecord) {
      // First session - create new record with SESAME metadata
      return {
        currentSession: newSession,
        archivedSessions: {},
        version: CURRENT_SESSION_RECORD_VERSION,
        metadata: {
          createdAt: now,
          lastSentAt: null,
          lastReceivedAt: null,
          isInitiator,
          isActive: true,
        },
      };
    }

    // Archive current and set new
    const updated = SessionRecordNS.archiveCurrent(sessionRecord, newSession, maxArchived);
    updated.metadata = {
      ...(sessionRecord.metadata ?? {}),
      createdAt: sessionRecord.metadata?.createdAt ?? now, // Preserve original createdAt
      isInitiator,
      lastUsedAt: now,
    };

    return updated;
  }

  /**
   * Get ordered list of sessions to try for decryption.
   *
   * Returns current session first (most likely to succeed), then
   * archived sessions. The caller should try each session in order
   * until decryption succeeds.
   *
   * Note: Archived sessions are returned in object iteration order, which
   * is insertion order in modern JS engines. Ideally they would be sorted
   * by recency, but archived sessions don't have individual timestamps.
   * In practice, this is acceptable because:
   * 1. The current session handles 99%+ of decryptions
   * 2. Archived sessions are only tried for race condition edge cases
   * 3. The number of archived sessions is bounded by maxInactiveSessions
   *
   * @param sessionRecord - The SessionRecord to search
   * @returns Array of DecryptionCandidate to try in order
   */
  static findDecryptingSessions(sessionRecord: SessionRecord | null): DecryptionCandidate[] {
    if (!sessionRecord) return [];

    const candidates: DecryptionCandidate[] = [];

    // Current session first (most likely to succeed)
    if (sessionRecord.currentSession) {
      candidates.push({
        session: sessionRecord.currentSession,
        baseKey: null,
        isActive: true,
      });
    }

    // Archived sessions (for race condition handling)
    // Iteration order follows insertion order in modern JS engines
    for (const [baseKey, session] of Object.entries(sessionRecord.archivedSessions)) {
      if (session) {
        candidates.push({
          session,
          baseKey: baseKey as Base64,
          isActive: false,
        });
      }
    }

    return candidates;
  }

  /**
   * Promote an archived session to current (session convergence).
   *
   * When we successfully decrypt a message using an archived session,
   * that session should become the new active session. This is the
   * SESAME "convergence" mechanism that ensures both parties end up
   * using the same session.
   *
   * The current session is moved to archived, and the specified
   * archived session becomes current.
   *
   * @param sessionRecord - The SessionRecord to update
   * @param baseKey - Base key of the archived session to promote
   * @returns Updated SessionRecord, or null if baseKey not found
   */
  static promoteSession(sessionRecord: SessionRecord, baseKey: Base64): SessionRecord | null {
    // Create a shallow copy to avoid mutating the original
    const copy: SessionRecord = {
      ...sessionRecord,
      archivedSessions: { ...sessionRecord.archivedSessions },
    };

    // promoteSession mutates in place
    const success = SessionRecordNS.promoteSession(copy, baseKey);

    if (!success) return null;

    // Update metadata (with explicit null check)
    copy.metadata = {
      ...(copy.metadata ?? {}),
      lastUsedAt: Date.now(),
    };

    return copy;
  }

  /**
   * Archive the current session without replacing it.
   *
   * Used when handling retry requests - the sender archives their
   * current session so they'll create a new one on the next send.
   *
   * @param sessionRecord - The SessionRecord to update
   * @param maxArchived - Maximum archived sessions to retain
   * @returns Updated SessionRecord with current session archived
   */
  static archiveCurrentSession(sessionRecord: SessionRecord, maxArchived: number): SessionRecord {
    return SessionRecordNS.archiveCurrent(sessionRecord, null, maxArchived);
  }
}
