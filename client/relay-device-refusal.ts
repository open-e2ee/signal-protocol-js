/**
 * Relay device refusal: a relay's refusal of one direct post because of the
 * destination device, and the relays whose refusals a send can rely on.
 *
 * A relay that refuses every post to a removed device's mailbox, before its
 * device list shows the removal, declares itself here. A direct send through
 * such a relay can post to the known devices before it reads the recipient's
 * device list: a post to a removed device is refused, not delivered. The
 * relay marks each refusal with the device it names and the relay code, so
 * the cipher can tell a refused device from any other failure.
 *
 * No package entry exports this module. The declaration and the mark are
 * internal to the SDK, so no public type carries them.
 *
 * @internal
 */

/** The relay code of a refused direct post. */
export type RelayDeviceRefusalCode = 'NOT_FOUND' | 'STALE_DEVICE';

/** The device that a relay refused, and why. */
export interface RelayDeviceRefusal {
  /** NOT_FOUND: the device's mailbox is gone. STALE_DEVICE: its registration changed. */
  readonly code: RelayDeviceRefusalCode;
  readonly userId: string;
  readonly deviceId: number;
}

const refusingRelays = new WeakSet<object>();
const refusals = new WeakMap<object, RelayDeviceRefusal>();

/** Declare that this relay refuses every post to a removed device's mailbox. */
export function declareRefusesRemovedDevices(relay: object): void {
  refusingRelays.add(relay);
}

/** True only for the relay object that declared itself. A wrapper is not declared. */
export function refusesRemovedDevices(relay: object): boolean {
  return refusingRelays.has(relay);
}

/** Mark an error as the relay's refusal of one device. Returns the same error. */
export function markRelayDeviceRefusal<T extends Error>(error: T, refusal: RelayDeviceRefusal): T {
  refusals.set(error, { ...refusal });
  return error;
}

/** The refusal that a relay marked on this error, if any. */
export function relayDeviceRefusal(error: unknown): RelayDeviceRefusal | undefined {
  return error !== null && typeof error === 'object' ? refusals.get(error) : undefined;
}
