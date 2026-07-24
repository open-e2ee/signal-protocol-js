/**
 * SPQR State Validation
 *
 * @module spqr/validate
 *
 * Provides validation and cleanup functions for SPQR state.
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
 * Ensures state is internally consistent and safe to use.
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
// SPQR Automatic Trimming
// ============================================================================

/**
 * Trim oldest skipped keys when approaching limit.
 *
 * Automatically trim when reaching threshold of max_ooo_keys.
 * This prevents memory exhaustion while preserving recent keys for
 * out-of-order message delivery.
 *
 * Uses limits from state if available, otherwise falls back to SPQR_LIMITS_DEFAULTS.
 *
 * @param spqrState - Current SPQR state to trim
 * @returns Number of keys removed
 */
export function trimSkippedKeys(spqrState: SPQRState): number {
  const skippedEntries = Object.entries(spqrState.MKSKIPPED);
  const currentCount = skippedEntries.length;

  // Use state limits if available, otherwise fall back to defaults
  const maxOOOKeys = spqrState.limits?.maxOutOfOrderKeys ?? SPQR_LIMITS_DEFAULTS.maxOutOfOrderKeys;

  // No trimming needed if under limit
  if (currentCount <= maxOOOKeys) {
    return 0;
  }

  // Sort by timestamp (oldest first)
  const sorted = skippedEntries.sort((a, b) => a[1].timestamp - b[1].timestamp);

  // Trim to 90% of max to create headroom for new keys
  const targetCount = Math.floor(maxOOOKeys * 0.9);
  const toRemove = currentCount - targetCount;

  for (let i = 0; i < toRemove; i++) {
    const [key] = sorted[i];
    delete spqrState.MKSKIPPED[key];
  }

  return toRemove;
}
