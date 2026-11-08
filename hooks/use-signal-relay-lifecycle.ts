/**
 * useSignalProtocolRelayLifecycle Hook
 *
 * React Native hook that stops the relay subscription when the app goes to the
 * background and starts it again when the app becomes active. It binds
 * `bindSignalProtocolRelayLifecycle` to React Native's `AppState`. On web it does nothing.
 *
 * @example
 * ```typescript
 * function SignalLifecycle() {
 *   const signal = useSignalProtocolClient();
 *   useSignalProtocolRelayLifecycle({ signal });
 *   return null;
 * }
 * ```
 */

import { useEffect } from 'react';
import { AppState, Platform } from 'react-native';
import { bindSignalProtocolRelayLifecycle } from '../client/signal-relay-lifecycle';

export interface UseSignalProtocolRelayLifecycleOptions {
  /**
   * Signal Protocol client that owns the relay subscription. An object with
   * only the deprecated member names also works.
   */
  signal: Parameters<typeof bindSignalProtocolRelayLifecycle>[0];
  /**
   * Keep the relay socket open in the background, for example while an Android
   * foreground service runs. Default: `false`.
   */
  keepOpenInBackground?: boolean;
}

/**
 * Hook that binds the relay subscription to the app state
 *
 * The binding follows `bindSignalProtocolRelayLifecycle`. The hook removes it when the
 * component unmounts.
 *
 * @param options - The client and the background policy
 */
export function useSignalProtocolRelayLifecycle({
  signal,
  keepOpenInBackground = false,
}: UseSignalProtocolRelayLifecycleOptions): void {
  useEffect(() => {
    if (Platform.OS === 'web') return undefined;
    return bindSignalProtocolRelayLifecycle(signal, AppState, { keepOpenInBackground });
  }, [signal, keepOpenInBackground]);
}

// Names before the Signal Protocol Relay rename. SDK 15.0.0 removes them.
/** @deprecated Use `useSignalProtocolRelayLifecycle`. SDK 15.0.0 removes this name. */
export const useRelayLifecycle = useSignalProtocolRelayLifecycle;
/** @deprecated Use `UseSignalProtocolRelayLifecycleOptions`. SDK 15.0.0 removes this name. */
export type UseRelayLifecycleOptions = UseSignalProtocolRelayLifecycleOptions;
