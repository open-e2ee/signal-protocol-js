import type {
  SignalProtocolRelayConnectionReason,
  SignalProtocolRelayConnectionState,
  Unsubscribe,
} from "./types";

/**
 * Owns one relay connection state and its listeners.
 *
 * A move to the same state and reason emits nothing, so a listener never
 * receives the same value twice. A listener that throws does not stop the
 * other listeners or the connection. Its error is thrown again in a microtask.
 */
export class SignalProtocolRelayConnectionStateOwner {
  private value: SignalProtocolRelayConnectionState = { state: "stopped", since: Date.now() };
  private readonly listeners = new Set<(state: SignalProtocolRelayConnectionState) => void>();

  public get current(): SignalProtocolRelayConnectionState {
    return this.value;
  }

  public move(
    state: SignalProtocolRelayConnectionState["state"],
    reason?: SignalProtocolRelayConnectionReason,
  ): void {
    if (this.value.state === state && this.value.reason === reason) return;
    const next: SignalProtocolRelayConnectionState =
      reason === undefined
        ? { state, since: Date.now() }
        : { state, reason, since: Date.now() };
    this.value = next;
    for (const listener of [...this.listeners]) {
      try {
        listener(next);
      } catch (error) {
        queueMicrotask(() => {
          throw error;
        });
      }
    }
  }

  public subscribe(
    listener: (state: SignalProtocolRelayConnectionState) => void,
  ): Unsubscribe {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
}
