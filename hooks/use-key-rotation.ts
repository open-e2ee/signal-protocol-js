/**
 * useKeyRotation Hook
 *
 * React hook for automatic foreground key rotation.
 * Rotates BOTH signed and Kyber prekeys when the app comes to foreground.
 *
 * Per PQXDH spec Section 3.2, both key types must rotate together on the same
 * schedule to maintain synchronized post-quantum security.
 *
 * Features:
 * - AppState-based trigger (inactive/background → active)
 * - Rate limiting (max once per hour)
 * - Uses SignalProtocolClient rotation methods
 * - Error handling with logging
 *
 * @example
 * ```typescript
 * function App() {
 *   useKeyRotation(); // Sets up foreground rotation
 *   return <Children />;
 * }
 * ```
 *
 * @example With a custom Signal Protocol client
 * ```typescript
 * function App() {
 *   const signal = useSignalProtocolClient();
 *   useKeyRotation({ signal });
 *   return <Children />;
 * }
 * ```
 *
 * @see https://signal.org/docs/specifications/pqxdh/#publishing-keys
 */

import type React from 'react';
import { useRef, useEffect, useCallback } from 'react';
import { AppState, type AppStateStatus } from 'react-native';
import { defaultSignalProtocolLogger } from '../logger';
import type { ISignalProtocolClient } from '../types';

/**
 * Rate limiting interval (1 hour in milliseconds)
 */
export {};
const MIN_ROTATION_CHECK_INTERVAL_MS = 60 * 60 * 1000;

/**
 * Options for useKeyRotation hook
 */
export interface UseKeyRotationOptions {
  /**
   * SignalProtocolClient instance to use for rotation.
   * If not provided, will be retrieved from context.
   */
  signal?: ISignalProtocolClient;

  /**
   * Custom rate limit interval in milliseconds.
   * Default: 1 hour (3600000ms)
   */
  rateLimitMs?: number;

  /**
   * Whether to enable the hook.
   * Useful for conditional rotation.
   * Default: true
   */
  enabled?: boolean;

  /**
   * Callback when rotation completes
   */
  onRotationComplete?: (result: { signedRotated: boolean; kyberRotated: boolean }) => void;

  /**
   * Callback when rotation fails
   */
  onRotationError?: (error: Error) => void;
}

// ============================================================================
// Internal shared hook
// ============================================================================

interface UseKeyRotationInternal {
  triggerRotation: () => Promise<void>;
  lastRotationCheckRef: React.MutableRefObject<number>;
  isRotatingRef: React.MutableRefObject<boolean>;
}

/**
 * Internal hook that contains the shared rotation logic.
 * Used by both useKeyRotation and useKeyRotationWithControls.
 */
function useKeyRotationInternal(options: UseKeyRotationOptions): UseKeyRotationInternal {
  const {
    signal,
    rateLimitMs = MIN_ROTATION_CHECK_INTERVAL_MS,
    enabled = true,
    onRotationComplete,
    onRotationError,
  } = options;

  const appStateRef = useRef<AppStateStatus>(AppState.currentState);
  const lastRotationCheckRef = useRef<number>(0);
  const isRotatingRef = useRef<boolean>(false);
  const isMountedRef = useRef<boolean>(true);
  const logger = signal?.logger ?? defaultSignalProtocolLogger;

  const triggerRotation = useCallback(async () => {
    if (!signal) {
      logger.warn('useKeyRotation: No Signal Protocol client provided, skipping rotation', {
        category: 'E2EE',
      });
      return;
    }

    if (isRotatingRef.current) {
      logger.breadcrumb('Key rotation already in progress, skipping', {
        category: 'E2EE',
        level: 'debug',
      });
      return;
    }

    isRotatingRef.current = true;
    lastRotationCheckRef.current = Date.now();

    try {
      const signedRotated = await signal.rotateEcSignedPreKey();
      const kyberRotated = await signal.rotateKyberPreKey();

      // Do not invoke callbacks if unmounted during async operation
      if (!isMountedRef.current) {
        return;
      }

      if (signedRotated || kyberRotated) {
        logger.info('Foreground key rotation completed', {
          category: 'E2EE',
          data: { signedRotated, kyberRotated },
        });
      }

      onRotationComplete?.({ signedRotated, kyberRotated });
    } catch (error) {
      // Do not invoke error callback if unmounted during async operation
      if (!isMountedRef.current) {
        return;
      }

      logger.error('Foreground key rotation failed', {
        category: 'E2EE',
        error: error as Error,
      });
      onRotationError?.(error as Error);
    } finally {
      isRotatingRef.current = false;
    }
  }, [logger, signal, onRotationComplete, onRotationError]);

  // Track mounted state for cleanup safety
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  // Set up AppState listener for foreground triggers
  useEffect(() => {
    if (!enabled || !signal) {
      return;
    }

    const handleAppStateChange = async (nextState: AppStateStatus) => {
      // Do not rotate if unmounted (ServicesProvider cleanup race)
      if (!isMountedRef.current) {
        return;
      }

      const previousState = appStateRef.current;
      appStateRef.current = nextState;

      // Only trigger on foreground transition
      const isComingToForeground =
        previousState.match(/inactive|background/) && nextState === 'active';

      if (!isComingToForeground) {
        return;
      }

      // Rate limiting
      const now = Date.now();
      const timeSinceLastCheck = now - lastRotationCheckRef.current;

      if (timeSinceLastCheck < rateLimitMs) {
        const minutesRemaining = Math.ceil((rateLimitMs - timeSinceLastCheck) / (60 * 1000));
        logger.breadcrumb('Key rotation check skipped (rate-limited)', {
          category: 'E2EE',
          level: 'debug',
          data: { minutesRemaining },
        });
        return;
      }

      logger.breadcrumb('App foregrounded, checking key rotation', {
        category: 'E2EE',
        level: 'info',
      });

      await triggerRotation();
    };

    const subscription = AppState.addEventListener('change', handleAppStateChange);

    return () => {
      subscription.remove();
    };
  }, [enabled, logger, signal, rateLimitMs, triggerRotation]);

  return { triggerRotation, lastRotationCheckRef, isRotatingRef };
}

// ============================================================================
// Public hooks
// ============================================================================

/**
 * Hook for automatic foreground key rotation
 *
 * Rotates signed and Kyber prekeys when app comes to foreground.
 * Uses rate limiting to prevent excessive rotation checks.
 *
 * @param options - Hook options
 *
 * @example Basic usage (with context)
 * ```typescript
 * // Requires ServicesProvider to be in the tree
 * function App() {
 *   useKeyRotation();
 *   return <Children />;
 * }
 * ```
 *
 * @example With an explicit Signal Protocol client
 * ```typescript
 * function App() {
 *   const signal = useSignalProtocolClient();
 *   useKeyRotation({ signal });
 *   return <Children />;
 * }
 * ```
 */
export function useKeyRotation(options: UseKeyRotationOptions = {}): void {
  // Delegate to internal hook, discard return value
  useKeyRotationInternal(options);
}

/**
 * Hook result type
 */
export interface UseKeyRotationResult {
  /** Trigger rotation manually */
  triggerRotation: () => Promise<void>;
  /** Last rotation check timestamp */
  lastRotationCheck: number;
  /** Whether rotation is currently in progress */
  isRotating: boolean;
}

/**
 * Extended hook that returns control functions
 *
 * Useful for controlled or manual rotation triggers.
 *
 * @param options - Hook options
 * @returns Control functions and state
 */
export function useKeyRotationWithControls(
  options: UseKeyRotationOptions = {}
): UseKeyRotationResult {
  const { triggerRotation, lastRotationCheckRef, isRotatingRef } = useKeyRotationInternal(options);

  return {
    triggerRotation,
    get lastRotationCheck() {
      return lastRotationCheckRef.current;
    },
    get isRotating() {
      return isRotatingRef.current;
    },
  };
}
