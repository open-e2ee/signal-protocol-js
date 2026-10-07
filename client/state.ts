/**
 * SignalProtocolClientState - Centralized State Management for SignalProtocolClient
 *
 * Consolidates all tracking state that was previously scattered across
 * the DefaultSignalProtocolClient class. Provides typed views for operation modules
 * and centralized mutation methods.
 *
 * State categories:
 * - Retry response counting: Caps the resends of one message
 * - Rate limiting: Prevents retry storms
 * - Prekey rotation debouncing: Rate-limits forced prekey rotations
 * - Relay work: Deliveries, retry requests, and receipt sends in progress, which stop() settles
 */

import type { RetryResponseState, RetryRateLimitState } from './retry';
import type { ReceiptAccumulator, RelaySubscriptionState } from './relay-subscription';
import { RelayWorkTracker } from './relay-work';

export {};

/**
 * Consolidated constants for SignalProtocolClient
 * Single source of truth for timing and retry configuration
 */
export const SIGNAL_PROTOCOL_CLIENT_CONSTANTS = {
  /** Debounce interval for forced prekey rotations (1 hour). */
  KEY_ROTATION_DEBOUNCE_MS: 3_600_000,
} as const;

/**
 * Centralized state management for SignalProtocolClient tracking maps
 *
 * This class consolidates all the per-session and per-message tracking
 * that SignalProtocolClient needs for:
 * - Retry response counting (caps the resends of one message)
 * - Rate limiting (prevents retry storms per sender)
 * - Prekey rotation debouncing (rate-limits forced prekey rotations)
 */
export class SignalProtocolClientState {
  // ============================================================================
  // Prekey Rotation State
  // ============================================================================

  /**
   * Timestamp of last forced prekey rotation.
   * Used for debouncing rotations.
   */
  private lastPreKeyRotationTime = 0;

  // ============================================================================
  // Relay Work State
  // ============================================================================

  /**
   * Relay deliveries, retry requests, and receipt sends in progress. The
   * relay calls its handlers without waiting for them, so stop() settles
   * them here before the app can close the store.
   */
  readonly relayWork = new RelayWorkTracker();

  // ============================================================================
  // Retry Response Counting State
  // ============================================================================

  /**
   * Tracks how many times we have responded to retry requests per message.
   * Key: `${sessionId}:${failedTimestamp}` (sessionId = userId:deviceId)
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

  /**
   * Pending delivery receipt timestamps per sender, with the first arrival
   * time, their flush timers, and whether stop() holds the batches
   */
  private readonly receiptAccumulator: ReceiptAccumulator = {
    pending: new Map(),
    timers: new Map(),
    held: false,
  };

  // ============================================================================
  // State Views (for operation modules)
  // ============================================================================

  /**
   * Get retry response state for retry operations
   */
  getRetryResponseState(): RetryResponseState {
    return { retryResponseCounts: this.retryResponseCounts };
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
      receiptAccumulator: this.receiptAccumulator,
    };
  }

  // ============================================================================
  // State Mutation Methods
  // ============================================================================

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
    this.retryResponseCounts.clear();

    this.lastPreKeyRotationTime = 0;

    this.retryRateLimitCounts.clear();
  }

  /**
   * Clear stop-relevant state (subset for stop() without full reset)
   * Preserves timing state but clears tracking maps
   */
  clearForStop(): void {
    this.lastPreKeyRotationTime = 0;
    this.retryResponseCounts.clear();
    this.retryRateLimitCounts.clear();

    // Drop the pending receipt batches and their timers
    for (const timer of this.receiptAccumulator.timers.values()) {
      clearTimeout(timer);
    }
    this.receiptAccumulator.timers.clear();
    this.receiptAccumulator.pending.clear();
  }

  // ============================================================================
  // Diagnostics
  // ============================================================================

  /**
   * Get state sizes for debugging
   */
  getDebugInfo(): {
    retryResponseCount: number;
    lastPreKeyRotationTime: number;
  } {
    return {
      retryResponseCount: this.retryResponseCounts.size,
      lastPreKeyRotationTime: this.lastPreKeyRotationTime,
    };
  }
}
