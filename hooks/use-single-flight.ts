/**
 * Single-Flight Hook
 *
 * Wraps an async function so only one call runs at a time.
 * If called while in-flight, queues the latest call (drops intermediate ones).
 *
 * This prevents request spam during rapid state changes like network reconnects,
 * where the WebSocket might connect/disconnect multiple times in quick succession.
 *
 * @example
 * ```typescript
 * const markConnected = useSingleFlight(useMutation(api.signal.devices.markDeviceConnected));
 *
 * // Even if called rapidly, only one request is in-flight at a time
 * markConnected({ deviceId: 1 });
 * markConnected({ deviceId: 1 }); // Queued, replaces any previous queued call
 * markConnected({ deviceId: 1 }); // Replaces the previous queued call
 * ```
 */

import { useCallback, useRef } from 'react';

/**
 * Wraps an async function so only one call runs at a time.
 * If called while in-flight, queues the latest call (drops intermediate ones).
 *
 * @param fn - Async function to wrap
 * @returns Wrapped function with single-flight behavior
 */
export {};
export function useSingleFlight<Args extends unknown[], Result>(
  fn: (...args: Args) => Promise<Result>
): (...args: Args) => Promise<Result> {
  const flightStatus = useRef({
    inFlight: false,
    upNext: null as null | {
      resolve: (value: Result) => void;
      reject: (error: unknown) => void;
      args: Args;
    },
  });

  return useCallback(
    (...args: Args): Promise<Result> => {
      if (flightStatus.current.inFlight) {
        // Already in-flight: queue this call (replacing any previous queued call)
        return new Promise((resolve, reject) => {
          flightStatus.current.upNext = { resolve, reject, args };
        });
      }

      flightStatus.current.inFlight = true;
      const firstReq = fn(...args);

      void (async () => {
        try {
          await firstReq;
        } catch {
          // If it failed, continue to next request
        }

        // Process queued request (if any)
        while (flightStatus.current.upNext) {
          const cur = flightStatus.current.upNext;
          flightStatus.current.upNext = null;
          try {
            const result = await fn(...cur.args);
            cur.resolve(result);
          } catch (error) {
            cur.reject(error);
          }
        }

        flightStatus.current.inFlight = false;
      })();

      return firstReq;
    },
    [fn]
  );
}
