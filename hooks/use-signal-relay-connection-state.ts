/**
 * useSignalProtocolRelayConnectionState Hook
 *
 * React hook for the connection state of the relay subscription on this
 * device. Use it for a local indicator, such as a dot on the user's own avatar.
 *
 * @example
 * ```typescript
 * function OwnConnectionDot() {
 *   const signal = useSignalProtocolClient();
 *   const { state } = useSignalProtocolRelayConnectionState({ signal });
 *   return <Dot online={state === 'connected'} />;
 * }
 * ```
 */

import { useCallback, useSyncExternalStore } from 'react';
import type { SignalProtocolRelayConnectionState } from '../remote/signal-relay/types';
import type { SignalProtocolClient } from '../types/api';
import { readRenamedImplementation } from '../types/renamed-member';

export interface UseSignalProtocolRelayConnectionStateOptions {
  /**
   * Signal Protocol client that owns the relay subscription. An object with
   * only the deprecated member names also works. The hook reads each new name
   * first.
   */
  signal:
    | Pick<
        SignalProtocolClient,
        'signalProtocolRelayConnectionState' | 'subscribeSignalProtocolRelayConnectionState'
      >
    | Pick<SignalProtocolClient, 'relayConnectionState' | 'subscribeRelayConnectionState'>;
}

type ConnectionStateSource = Partial<
  Pick<
    SignalProtocolClient,
    | 'signalProtocolRelayConnectionState'
    | 'subscribeSignalProtocolRelayConnectionState'
    | 'relayConnectionState'
    | 'subscribeRelayConnectionState'
  >
>;

/**
 * Hook for the relay connection state
 *
 * The component renders again on each transition. The hook unsubscribes when
 * the component unmounts.
 *
 * @param options - The client to read
 * @returns The current relay connection state
 */
export function useSignalProtocolRelayConnectionState({
  signal,
}: UseSignalProtocolRelayConnectionStateOptions): SignalProtocolRelayConnectionState {
  const subscribe = useCallback((onChange: () => void) => {
    const subscribeState = readRenamedImplementation(
      signal as ConnectionStateSource,
      'subscribeSignalProtocolRelayConnectionState',
      'subscribeRelayConnectionState'
    );
    if (!subscribeState) throw new TypeError('signal has no relay connection state');
    return subscribeState(onChange);
  }, [signal]);
  const read = useCallback(() => {
    const state = readRenamedImplementation(
      signal as ConnectionStateSource,
      'signalProtocolRelayConnectionState',
      'relayConnectionState'
    );
    if (!state) throw new TypeError('signal has no relay connection state');
    return state;
  }, [signal]);
  return useSyncExternalStore(subscribe, read, read);
}

// Names before the Signal Protocol Relay rename. SDK 15.0.0 removes them.
/** @deprecated Use `useSignalProtocolRelayConnectionState`. SDK 15.0.0 removes this name. */
export const useRelayConnectionState = useSignalProtocolRelayConnectionState;
/** @deprecated Use `UseSignalProtocolRelayConnectionStateOptions`. SDK 15.0.0 removes this name. */
export type UseRelayConnectionStateOptions = UseSignalProtocolRelayConnectionStateOptions;
