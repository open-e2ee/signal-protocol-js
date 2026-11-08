import type { Unsubscribe } from '../remote/signal-relay/types';
import type { SignalProtocolClient } from '../types/api';
import { readRenamedImplementation } from '../types/renamed-member';

/**
 * The part of an app state source that `bindSignalProtocolRelayLifecycle` reads.
 *
 * React Native's `AppState` satisfies it. The client entry does not import
 * react-native, so any source with this shape can drive the binding.
 */
export interface SignalProtocolRelayLifecycleAppState {
  /**
   * The state at bind time, for example `active` or `background`. React
   * Native reports `null` when its native AppState module is not available.
   * The binding then acts only on a change.
   */
  readonly currentState: string | null | undefined;
  /** Returns a subscription with `remove()`, or a function that removes the listener. */
  addEventListener(
    type: 'change',
    listener: (state: string) => void
  ): { remove(): void } | (() => void);
}

/** Options for `bindSignalProtocolRelayLifecycle`. */
export interface SignalProtocolRelayLifecycleOptions {
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
 * - `background` calls `stopSignalProtocolRelaySubscription()`, which closes the socket with
 *   code 1000. The Relay records a client close.
 * - `active` calls `startSignalProtocolRelaySubscription()`, but only after a stop that this
 *   binding made. The Relay replays retained messages over the new socket.
 * - `inactive` and other states change nothing. There is no grace delay.
 * - A subscription that is `stopped` stays stopped, so an app stop is kept.
 *
 * If the app is in the background at bind time, the binding stops at once.
 * Call the returned function before `stop()` on the client. It removes the
 * listener and does not start or stop the subscription.
 *
 * An object that has only the deprecated member names, such as
 * `stopRelaySubscription()`, also drives the binding. The binding reads each
 * new name first.
 *
 * @param signal - The Signal Protocol client
 * @param appState - React Native's `AppState`, or an object of the same shape
 * @param options - Binding options
 * @returns A function that removes the binding
 *
 * @example
 * ```typescript
 * import { AppState } from 'react-native';
 * import { bindSignalProtocolRelayLifecycle } from '@open-e2ee/signal-protocol-sdk/client';
 *
 * const unbind = bindSignalProtocolRelayLifecycle(signal, AppState);
 * // At sign-out:
 * unbind();
 * await signal.stop();
 * ```
 */
export function bindSignalProtocolRelayLifecycle(
  signal:
    | Pick<
        SignalProtocolClient,
        | 'signalProtocolRelayConnectionState'
        | 'startSignalProtocolRelaySubscription'
        | 'stopSignalProtocolRelaySubscription'
      >
    | Pick<
        SignalProtocolClient,
        'relayConnectionState' | 'startRelaySubscription' | 'stopRelaySubscription'
      >,
  appState: SignalProtocolRelayLifecycleAppState,
  { keepOpenInBackground = false }: SignalProtocolRelayLifecycleOptions = {}
): Unsubscribe {
  if (keepOpenInBackground) return () => undefined;
  const client = signal as Partial<
    Pick<
      SignalProtocolClient,
      | 'signalProtocolRelayConnectionState'
      | 'startSignalProtocolRelaySubscription'
      | 'stopSignalProtocolRelaySubscription'
      | 'relayConnectionState'
      | 'startRelaySubscription'
      | 'stopRelaySubscription'
    >
  >;
  let stoppedByBinding = false;
  const apply = (state: string | null | undefined) => {
    if (state === 'background') {
      const connectionState = readRenamedImplementation(
        client,
        'signalProtocolRelayConnectionState',
        'relayConnectionState'
      );
      if (stoppedByBinding || connectionState?.state === 'stopped') return;
      stoppedByBinding = true;
      readRenamedImplementation(
        client,
        'stopSignalProtocolRelaySubscription',
        'stopRelaySubscription'
      )?.();
    } else if (state === 'active' && stoppedByBinding) {
      stoppedByBinding = false;
      readRenamedImplementation(
        client,
        'startSignalProtocolRelaySubscription',
        'startRelaySubscription'
      )?.();
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

// Names before the Signal Protocol Relay rename. SDK 15.0.0 removes them.
/** @deprecated Use `bindSignalProtocolRelayLifecycle`. SDK 15.0.0 removes this name. */
export const bindRelayLifecycle = bindSignalProtocolRelayLifecycle;
/** @deprecated Use `SignalProtocolRelayLifecycleAppState`. SDK 15.0.0 removes this name. */
export type RelayLifecycleAppState = SignalProtocolRelayLifecycleAppState;
/** @deprecated Use `SignalProtocolRelayLifecycleOptions`. SDK 15.0.0 removes this name. */
export type RelayLifecycleOptions = SignalProtocolRelayLifecycleOptions;
