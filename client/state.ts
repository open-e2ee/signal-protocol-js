/**
 * SignalProtocolClientState - Centralized State Management for SignalProtocolClient
 *
 * Consolidates all tracking state that was previously scattered across
 * the SignalProtocolClient class. Provides typed views for operation modules
 * and centralized mutation methods.
 *
 * State categories:
 * - Retry deduplication: Prevents duplicate retry request processing
 * - Rate limiting: Prevents retry storms
 * - Prekey rotation debouncing: Rate-limits forced prekey rotations
 */

import type { RetryDedupState, RetryRateLimitState } from './retry';
import type { RelaySubscriptionState } from './relay-subscription';

/**
 * Configuration for state management
 */
export {};
export interface SignalProtocolClientStateConfig {
  /** Deduplication window for retry requests in ms */
  retryDedupWindowMs: number;
  /** Cleanup interval for retry dedup entries in ms */
  retryCleanupIntervalMs: number;
}

/**
 * Default configuration values
 */
export const DEFAULT_STATE_CONFIG: SignalProtocolClientStateConfig = {
  retryDedupWindowMs: 5000,
  retryCleanupIntervalMs: 60_000,
};

/**
 * Consolidated constants for SignalProtocolClient
 * Single source of truth for timing and retry configuration
 */
export const SIGNAL_PROTOCOL_CLIENT_CONSTANTS = {
  /** Debounce interval for forced prekey rotations (1 hour). */
  KEY_ROTATION_DEBOUNCE_MS: 3_600_000,
  /** Retry request deduplication window in milliseconds */
  RETRY_DEDUP_WINDOW_MS: DEFAULT_STATE_CONFIG.retryDedupWindowMs,
  /** Cleanup interval for expired retry dedup entries */
  RETRY_CLEANUP_INTERVAL_MS: DEFAULT_STATE_CONFIG.retryCleanupIntervalMs,
} as const;

/**
 * Centralized state management for SignalProtocolClient tracking maps
 *
 * This class consolidates all the per-session and per-message tracking
 * that SignalProtocolClient needs for:
 * - Retry request deduplication (prevents processing same retry twice)
 * - Rate limiting (prevents retry storms per sender)
 * - Prekey rotation debouncing (rate-limits forced prekey rotations)
 */
export class SignalProtocolClientState {
  private readonly config: SignalProtocolClientStateConfig;

  // ============================================================================
  // Retry Deduplication State
  // ============================================================================

  /**
   * Tracks recent retry requests to prevent duplicate processing
   * Key: `${sessionId}:${failedTimestamp}` (sessionId = userId:deviceId)
   * Value: timestamp when last processed
   */
  private readonly recentRetryRequests = new Map<string, number>();

  /**
   * Timestamp of last cleanup of recentRetryRequests map
   * Used for time-based cleanup instead of modulo-based
   */
  private lastRetryCleanupTime = 0;

  /**
   * Timestamp of last forced prekey rotation.
   * Used for debouncing rotations.
   */
  private lastPreKeyRotationTime = 0;

  // ============================================================================
  // Retry Response Counting State
  // ============================================================================

  /**
   * Tracks how many times we have responded to retry requests per message.
   * Key: `${sessionId}:${failedTimestamp}` (same as dedup key)
   * Value: number of retry responses sent
   * Prevents infinite retry loops
   */
  private readonly retryResponseCounts = new Map<string, number>();

  // ============================================================================
  // Retry Rate Limiting State
  // ============================================================================

  /**
   * Tracks retry request counts per sender for receiver-side rate limiting.
   * Key: senderId, Value: {count, lastReceivedTime}
   * Prevents retry storms.
   */
  private readonly retryRateLimitCounts = new Map<
    string,
    { count: number; lastReceivedTime: number }
  >();

  // ============================================================================
  // Receipt Batching State
  // ============================================================================

  /** Pending delivery receipt timestamps per sender */
  private readonly receiptAccumulatorPending = new Map<string, number[]>();
  /** Flush timers per sender for batched delivery receipts */
  private readonly receiptAccumulatorTimers = new Map<string, ReturnType<typeof setTimeout>>();

  constructor(config: Partial<SignalProtocolClientStateConfig> = {}) {
    this.config = { ...DEFAULT_STATE_CONFIG, ...config };
  }

  // ============================================================================
  // State Views (for operation modules)
  // ============================================================================

  /**
   * Get retry dedup state for retry operations
   */
  getRetryDedupState(): RetryDedupState {
    return {
      recentRetryRequests: this.recentRetryRequests,
      lastRetryCleanupTime: this.lastRetryCleanupTime,
      retryResponseCounts: this.retryResponseCounts,
    };
  }

  /**
   * Get rate limiting state for retry operations
   */
  getRateLimitState(): RetryRateLimitState {
    return {
      retryRateLimitCounts: this.retryRateLimitCounts,
      lastPreKeyRotationTime: this.lastPreKeyRotationTime,
    };
  }

  /**
   * Get combined state for relay subscription operations
   */
  getRelaySubscriptionState(): RelaySubscriptionState {
    return {
      lastPreKeyRotationTime: this.lastPreKeyRotationTime,
      retryRateLimitCounts: this.retryRateLimitCounts,
      receiptAccumulator: {
        pending: this.receiptAccumulatorPending,
        timers: this.receiptAccumulatorTimers,
      },
    };
  }

  // ============================================================================
  // State Mutation Methods
  // ============================================================================

  /**
   * Update lastRetryCleanupTime after cleanup operation
   */
  setLastRetryCleanupTime(time: number): void {
    this.lastRetryCleanupTime = time;
  }

  /**
   * Update lastPreKeyRotationTime after forced rotation
   */
  setLastPreKeyRotationTime(time: number): void {
    this.lastPreKeyRotationTime = time;
  }

  /**
   * Get the last prekey rotation timestamp
   */
  getLastPreKeyRotationTime(): number {
    return this.lastPreKeyRotationTime;
  }

  /**
   * Clear all state (called on stop())
   * Resets all tracking to initial state for clean shutdown
   */
  clearAll(): void {
    this.recentRetryRequests.clear();
    this.retryResponseCounts.clear();
    this.lastRetryCleanupTime = 0;

    this.lastPreKeyRotationTime = 0;

    this.retryRateLimitCounts.clear();
  }

  /**
   * Clear stop-relevant state (subset for stop() without full reset)
   * Preserves timing state but clears tracking maps
   */
  clearForStop(): void {
    this.lastPreKeyRotationTime = 0;
    this.recentRetryRequests.clear();
    this.retryResponseCounts.clear();
    this.retryRateLimitCounts.clear();

    // Flush pending receipt timers
    for (const timer of this.receiptAccumulatorTimers.values()) {
      clearTimeout(timer);
    }
    this.receiptAccumulatorTimers.clear();
    this.receiptAccumulatorPending.clear();
  }

  // ============================================================================
  // Cleanup Operations
  // ============================================================================

  /**
   * Run all periodic cleanups.
   * Safe to call frequently - internally throttled.
   *
   * @param now - Current timestamp (defaults to Date.now())
   * @returns Object with count of entries cleaned
   */
  runPeriodicCleanup(now: number = Date.now()): { cleaned: number } {
    let cleaned = 0;
    cleaned += this.cleanupExpiredRetryEntries(now);
    return { cleaned };
  }

  /**
   * Cleanup expired retry dedup entries.
   * Returns number of entries removed.
   *
   * @param now - Current timestamp (defaults to Date.now())
   * @returns Number of entries removed
   */
  cleanupExpiredRetryEntries(now: number = Date.now()): number {
    if (now - this.lastRetryCleanupTime < this.config.retryCleanupIntervalMs) {
      return 0; // Not time yet
    }

    this.lastRetryCleanupTime = now;
    let removed = 0;

    for (const [key, timestamp] of this.recentRetryRequests) {
      // Clean entries older than 2x the dedup window
      if (now - timestamp > this.config.retryDedupWindowMs * 2) {
        this.recentRetryRequests.delete(key);
        this.retryResponseCounts.delete(key);
        removed++;
      }
    }

    return removed;
  }

  // ============================================================================
  // Diagnostics
  // ============================================================================

  /**
   * Get state sizes for debugging
   */
  getDebugInfo(): {
    retryRequestsCount: number;
    lastRetryCleanupTime: number;
    lastPreKeyRotationTime: number;
  } {
    return {
      retryRequestsCount: this.recentRetryRequests.size,
      lastRetryCleanupTime: this.lastRetryCleanupTime,
      lastPreKeyRotationTime: this.lastPreKeyRotationTime,
    };
  }
}
