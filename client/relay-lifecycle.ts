import type { Unsubscribe } from '../remote/relay/types';
import type { SignalProtocolClient } from '../types/api';

/**
 * The part of an app state source that `bindRelayLifecycle` reads.
 *
 * React Native's `AppState` satisfies it. The client entry does not import
 * react-native, so any source with this shape can drive the binding.
 */
export interface RelayLifecycleAppState {
  /** The state at bind time, for example `active` or `background`. */
  readonly currentState: string;
  /** Returns a subscription with `remove()`, or a function that removes the listener. */
  addEventListener(
    type: 'change',
    listener: (state: string) => void
  ): { remove(): void } | (() => void);
}

/** Options for `bindRelayLifecycle`. */
export interface RelayLifecycleOptions {
  /**
   * Keep the relay socket open in the background, for example while an Android
   * foreground service runs. The binding then does nothing. Default: `false`.
   */
  readonly keepOpenInBackground?: boolean;
}

/**
 * Stops the relay subscription when the app goes to the background and starts
 * it again when the app becomes active.
 *
 * - `background` calls `stopRelaySubscription()`, which closes the socket with
 *   code 1000. The Relay records a client close.
 * - `active` calls `startRelaySubscription()`, but only after a stop that this
 *   binding made. The Relay replays retained messages over the new socket.
 * - `inactive` and other states change nothing. There is no grace delay.
 * - A subscription that is `stopped` stays stopped, so an app stop is kept.
 *
 * If the app is in the background at bind time, the binding stops at once.
 * Call the returned function before `stop()` on the client. It removes the
 * listener and does not start or stop the subscription.
 *
 * @param signal - The Signal Protocol client
 * @param appState - React Native's `AppState`, or an object of the same shape
 * @param options - Binding options
 * @returns A function that removes the binding
 *
 * @example
 * ```typescript
 * import { AppState } from 'react-native';
 * import { bindRelayLifecycle } from '@open-e2ee/signal-protocol-sdk/client';
 *
 * const unbind = bindRelayLifecycle(signal, AppState);
 * // At sign-out:
 * unbind();
 * await signal.stop();
 * ```
 */
export function bindRelayLifecycle(
  signal: Pick<
    SignalProtocolClient,
    'relayConnectionState' | 'startRelaySubscription' | 'stopRelaySubscription'
  >,
  appState: RelayLifecycleAppState,
  { keepOpenInBackground = false }: RelayLifecycleOptions = {}
): Unsubscribe {
  if (keepOpenInBackground) return () => undefined;
  let stoppedByBinding = false;
  const apply = (state: string) => {
    if (state === 'background') {
      if (stoppedByBinding || signal.relayConnectionState.state === 'stopped') return;
      stoppedByBinding = true;
      signal.stopRelaySubscription();
    } else if (state === 'active' && stoppedByBinding) {
      stoppedByBinding = false;
      signal.startRelaySubscription();
    }
  };
  const subscription = appState.addEventListener('change', apply);
  apply(appState.currentState);
  let bound = true;
  return () => {
    if (!bound) return;
    bound = false;
    if (typeof subscription === 'function') subscription();
    else subscription.remove();
  };
}
