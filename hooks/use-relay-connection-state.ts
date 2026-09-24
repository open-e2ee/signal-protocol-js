/**
 * useRelayConnectionState Hook
 *
 * React hook for the connection state of the relay subscription on this
 * device. Use it for a local indicator, such as a dot on the user's own avatar.
 *
 * @example
 * ```typescript
 * function OwnConnectionDot() {
 *   const signal = useSignalProtocolClient();
 *   const { state } = useRelayConnectionState({ signal });
 *   return <Dot online={state === 'connected'} />;
 * }
 * ```
 */

import { useCallback, useSyncExternalStore } from 'react';
import type { RelayConnectionState } from '../remote/relay/types';
import type { SignalProtocolClient } from '../types/api';

export interface UseRelayConnectionStateOptions {
  /** Signal Protocol client that owns the relay subscription */
  signal: Pick<SignalProtocolClient, 'relayConnectionState' | 'subscribeRelayConnectionState'>;
}

/**
 * Hook for the relay connection state
 *
 * The component renders again on each transition. The hook unsubscribes when
 * the component unmounts.
 *
 * @param options - The client to read
 * @returns The current relay connection state
 */
export function useRelayConnectionState({
  signal,
}: UseRelayConnectionStateOptions): RelayConnectionState {
  const subscribe = useCallback(
    (onChange: () => void) => signal.subscribeRelayConnectionState(onChange),
    [signal]
  );
  const read = useCallback(() => signal.relayConnectionState, [signal]);
  return useSyncExternalStore(subscribe, read, read);
}
