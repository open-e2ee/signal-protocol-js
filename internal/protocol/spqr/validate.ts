/**
 * SPQR State Validation
 *
 * @module spqr/validate
 *
 * Provides validation and skipped-key trimming for SPQR state.
 * Extracted from spqr.ts for modularity (target: 150 LOC).
 */

import { EncryptionError, EncryptionErrorCode } from '../../../types/errors';

// Type-only imports to avoid circular dependency
import type { SPQRState } from './spqr';

import { SPQR_LIMITS_DEFAULTS } from '../../../types/protocol-config';

// ============================================================================
// SPQR State Validation
// ============================================================================

/**
 * Validate SPQR state before operations.
 *
 * Checks that the state is internally consistent and safe to use.
 * Called at the start of SPQR operations for defense-in-depth.
 *
 * @param spqrState - Current SPQR state
 * @param operation - Name of the operation being performed (for error messages)
 * @throws EncryptionError if state is invalid
 */
export {};
export function validateSPQRState(spqrState: SPQRState, operation: string): void {
  // Validate direction
  if (spqrState.direction !== 'A2B' && spqrState.direction !== 'B2A') {
    throw new EncryptionError(
      `Invalid SPQR direction: ${spqrState.direction}`,
      EncryptionErrorCode.INVALID_STATE,
      { operation, direction: spqrState.direction }
    );
  }

  // Validate epoch is non-negative integer
  if (spqrState.epoch < 0 || !Number.isInteger(spqrState.epoch)) {
    throw new EncryptionError(
      `Invalid SPQR epoch: ${spqrState.epoch}`,
      EncryptionErrorCode.SPQR_EPOCH_OUT_OF_RANGE,
      { operation, epoch: spqrState.epoch }
    );
  }

  // Validate root key exists
  if (!spqrState.RK) {
    throw new EncryptionError('Missing SPQR root key', EncryptionErrorCode.INVALID_STATE, {
      operation,
    });
  }
}

// ============================================================================
// SPQR Skipped-Key Trimming
// ============================================================================

/**
 * The count of held skipped keys in one epoch at which a receive trims the
 * old keys of that epoch: `maxOutOfOrderKeys * 11 / 10 + 1`, 2201 by
 * default, as `trim_size` in the reference chain. A stored epoch therefore
 * holds at most one key less than this count.
 */
export function skippedKeyTrimSize(maxOutOfOrderKeys: number): number {
  return Math.floor((maxOutOfOrderKeys * 11) / 10) + 1;
}

/** The epoch and index of a held skipped key name, `"epoch:index"`. */
export function parseSkippedKeyName(name: string): { epoch: number; index: number } | null {
  const match = /^(\d+):(\d+)$/.exec(name);
  if (!match) return null;
  return { epoch: Number(match[1]), index: Number(match[2]) };
}

/**
 * Trim the held skipped keys of one epoch by index, as the reference chain
 * collects its key history. When the epoch holds
 * `skippedKeyTrimSize` keys or more, each key whose index is below the
 * receive counter minus `maxOutOfOrderKeys` leaves, so at most
 * `maxOutOfOrderKeys` keys stay. A key below that horizon is refused at
 * receive, so a trimmed key is never one that could still decrypt. The
 * clock is not read.
 *
 * The reference collects before it steps its counter to the received index,
 * so its horizon is one lower and it keeps one key that its refusal rule
 * already refuses. This trim uses the stepped counter, so the kept set is the
 * set that the refusal rule accepts.
 *
 * Uses limits from state if available, otherwise falls back to SPQR_LIMITS_DEFAULTS.
 *
 * @param spqrState - Current SPQR state to trim
 * @param epoch - The epoch whose receive chain holds the keys
 * @returns Number of keys removed
 */
export function trimEpochSkippedKeys(spqrState: SPQRState, epoch: number): number {
  const chains = spqrState.kdfChains[epoch];
  if (!chains) return 0;
  const maxOOOKeys = spqrState.limits?.maxOutOfOrderKeys ?? SPQR_LIMITS_DEFAULTS.maxOutOfOrderKeys;

  const held: Array<[string, number]> = [];
  for (const name of Object.keys(spqrState.MKSKIPPED)) {
    const parsed = parseSkippedKeyName(name);
    if (parsed && parsed.epoch === epoch) held.push([name, parsed.index]);
  }
  if (held.length < skippedKeyTrimSize(maxOOOKeys)) {
    return 0;
  }

  const horizon = chains.receive.N - maxOOOKeys;
  let removed = 0;
  for (const [name, index] of held) {
    if (index < horizon) {
      delete spqrState.MKSKIPPED[name];
      removed++;
    }
  }
  return removed;
}
