import type {
  RelayConnectionReason,
  RelayConnectionState,
  Unsubscribe,
} from "./types";

/**
 * Owns one relay connection state and its listeners.
 *
 * A move to the same state and reason emits nothing, so a listener never
 * receives the same value twice. A listener that throws does not stop the
 * other listeners or the connection. Its error is thrown again in a microtask.
 */
export class RelayConnectionStateOwner {
  private value: RelayConnectionState = { state: "stopped", since: Date.now() };
  private readonly listeners = new Set<(state: RelayConnectionState) => void>();

  public get current(): RelayConnectionState {
    return this.value;
  }

  public move(
    state: RelayConnectionState["state"],
    reason?: RelayConnectionReason,
  ): void {
    if (this.value.state === state && this.value.reason === reason) return;
    const next: RelayConnectionState =
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
    listener: (state: RelayConnectionState) => void,
  ): Unsubscribe {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
}
