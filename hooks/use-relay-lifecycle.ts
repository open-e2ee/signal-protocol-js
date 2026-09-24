/**
 * useRelayLifecycle Hook
 *
 * React Native hook that stops the relay subscription when the app goes to the
 * background and starts it again when the app becomes active. It binds
 * `bindRelayLifecycle` to React Native's `AppState`. On web it does nothing.
 *
 * @example
 * ```typescript
 * function SignalLifecycle() {
 *   const signal = useSignalProtocolClient();
 *   useRelayLifecycle({ signal });
 *   return null;
 * }
 * ```
 */

import { useEffect } from 'react';
import { AppState, Platform } from 'react-native';
import { bindRelayLifecycle } from '../client/relay-lifecycle';
import type { SignalProtocolClient } from '../types/api';

export interface UseRelayLifecycleOptions {
  /** Signal Protocol client that owns the relay subscription */
  signal: Pick<
    SignalProtocolClient,
    'relayConnectionState' | 'startRelaySubscription' | 'stopRelaySubscription'
  >;
  /**
   * Keep the relay socket open in the background, for example while an Android
   * foreground service runs. Default: `false`.
   */
  keepOpenInBackground?: boolean;
}

/**
 * Hook that binds the relay subscription to the app state
 *
 * The binding follows `bindRelayLifecycle`. The hook removes it when the
 * component unmounts.
 *
 * @param options - The client and the background policy
 */
export function useRelayLifecycle({
  signal,
  keepOpenInBackground = false,
}: UseRelayLifecycleOptions): void {
  useEffect(() => {
    if (Platform.OS === 'web') return undefined;
    return bindRelayLifecycle(signal, AppState, { keepOpenInBackground });
  }, [signal, keepOpenInBackground]);
}
