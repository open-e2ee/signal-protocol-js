/**
 * useSessionHealth Hook
 *
 * React hook for checking Signal Protocol session health.
 * Provides client-side health checking for encryption sessions.
 *
 * @example
 * ```typescript
 * function EncryptionStatus({ userId }: { userId: string }) {
 *   const signal = useSignalProtocolClient();
 *   const { health, isLoading, error, refresh } = useSessionHealth({ signal, userId });
 *
 *   if (isLoading) return <Text>Checking...</Text>;
 *   if (error) return <Text>Error: {error.message}</Text>;
 *
 *   return (
 *     <Text>Status: {health?.status}</Text>
 *   );
 * }
 * ```
 */

import { useCallback, useEffect, useState } from 'react';
import type { SessionHealthResult } from '../client/types';
import type { ISignalProtocolClient } from '../types/api';

/**
 * Hook result type
 */
export {};
export interface UseSessionHealthResult {
  /** Health check result */
  health: SessionHealthResult | null;
  /** Whether check is in progress */
  isLoading: boolean;
  /** Error if check failed */
  error: Error | null;
  /** Manually trigger a health check */
  refresh: () => Promise<void>;
}

export interface UseSessionHealthOptions {
  /** Signal Protocol client used to run the health check */
  signal: Pick<ISignalProtocolClient, 'getSessionHealth'>;
  /** User ID to check session health for (undefined to skip) */
  userId: string | undefined;
}

/**
 * Hook for checking session health with a user
 *
 * @param options - Health-check dependencies and target user
 * @returns Health check result with loading/error states
 */
export function useSessionHealth({
  signal,
  userId,
}: UseSessionHealthOptions): UseSessionHealthResult {
  const [health, setHealth] = useState<SessionHealthResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const refresh = useCallback(async () => {
    if (!userId) {
      setError(null);
      setHealth(null);
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const result = await signal.getSessionHealth(userId);
      setHealth(result);
    } catch (e) {
      setError(e as Error);
      setHealth(null);
    } finally {
      setIsLoading(false);
    }
  }, [signal, userId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { health, isLoading, error, refresh };
}
