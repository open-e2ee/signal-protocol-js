/**
 * Relay receipt intake: the Relay delivery receipts that reach this device as
 * the sender of the messages that they name.
 *
 * A Relay delivery receipt tells that a recipient device acknowledged the
 * named messages to the Relay. It never tells that the device decrypted them.
 * The hosted mailbox hands each receipt off in mailbox order, behind the
 * messages that came before it, and acknowledges it to the Relay after the
 * hand-off. A replay carries the same `receiptId`, so the intake hands each
 * receipt off once and the replay is only acknowledged again.
 *
 * A relay that delivers Relay receipts declares its intake here. The client
 * binds its listener to the intake of its relay.
 *
 * No package entry exports this module. The receipt and the declaration are
 * internal to the SDK, so no public type carries them.
 *
 * @internal
 */

import type { Unsubscribe } from '../remote/relay/types';

/** One Relay delivery receipt, as the Relay sends it to the sender. */
export interface RelayDeliveryReceipt {
  /** The stable identity of the receipt. A replay carries the same value. */
  readonly receiptId: string;
  /** The recipient device that acknowledged the messages. */
  readonly recipient: { readonly accountId: string; readonly deviceId: number };
  /** The Relay message IDs, which are the client message IDs of the sends. */
  readonly messageIds: readonly string[];
  /** The time, in epoch milliseconds, at which the Relay removed the messages. */
  readonly deliveredAt: number;
}

/**
 * Receives one Relay delivery receipt. The intake awaits each listener in
 * order. A listener that throws fails the hand-off, so the receipt is not
 * acknowledged and the Relay replays it.
 */
export type RelayDeliveryReceiptListener = (receipt: RelayDeliveryReceipt) => void | Promise<void>;

/** The intake that a client binds to. */
export interface RelayReceiptIntake {
  subscribe(listener: RelayDeliveryReceiptListener): Unsubscribe;
}

/** A `delivery-receipt` frame holds no more receipts than this. */
export const MAXIMUM_RECEIPTS_PER_FRAME = 32;
/** A receipt names no more messages than one acknowledgment holds. */
const MAXIMUM_RECEIPT_MESSAGE_IDS = 100;
const MAXIMUM_ID_CHARACTERS = 128;
/** A `receiptId` is 32 bytes in unpadded base64url. */
const RECEIPT_ID = /^[A-Za-z0-9_-]{43}$/u;
/** The intake remembers this many handed-off receipt IDs, oldest out first. */
const REMEMBERED_RECEIPT_IDS = 4_096;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAXIMUM_ID_CHARACTERS;
}

function invalid(): Error {
  return new Error('Signal Protocol Relay delivery receipt is invalid');
}

/** Decodes one receipt of a `delivery-receipt` frame or a pull page. Throws when it is invalid. */
export function decodeRelayDeliveryReceipt(value: unknown): RelayDeliveryReceipt {
  if (
    !isRecord(value) ||
    typeof value.receiptId !== 'string' ||
    !RECEIPT_ID.test(value.receiptId) ||
    !isRecord(value.recipient) ||
    !isId(value.recipient.accountId) ||
    !Number.isSafeInteger(value.recipient.deviceId) ||
    (value.recipient.deviceId as number) < 1 ||
    !Array.isArray(value.messageIds) ||
    value.messageIds.length < 1 ||
    value.messageIds.length > MAXIMUM_RECEIPT_MESSAGE_IDS ||
    !value.messageIds.every(isId) ||
    !Number.isSafeInteger(value.deliveredAt) ||
    (value.deliveredAt as number) < 1
  )
    throw invalid();
  return {
    receiptId: value.receiptId,
    recipient: {
      accountId: value.recipient.accountId,
      deviceId: value.recipient.deviceId as number,
    },
    messageIds: [...(value.messageIds as string[])],
    deliveredAt: value.deliveredAt as number,
  };
}

/** Decodes the receipt list of a frame or a pull page. Throws when any receipt is invalid. */
export function decodeRelayDeliveryReceipts(
  value: unknown,
  maximum = Number.POSITIVE_INFINITY
): readonly RelayDeliveryReceipt[] {
  if (!Array.isArray(value) || value.length > maximum) throw invalid();
  return value.map(decodeRelayDeliveryReceipt);
}

/**
 * The receipt inbox of one relay. It hands each receipt off to the bound
 * listeners once, by `receiptId`.
 */
export class RelayReceiptInbox implements RelayReceiptIntake {
  private readonly listeners = new Set<RelayDeliveryReceiptListener>();
  private readonly handedOff = new Set<string>();

  public subscribe(listener: RelayDeliveryReceiptListener): Unsubscribe {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /**
   * Hands one receipt off to each listener in order, unless an earlier
   * hand-off of its `receiptId` completed. Resolves when the receipt may be
   * acknowledged. Rejects when a listener throws; the next replay then hands
   * the receipt off again.
   */
  public async handOff(receipt: RelayDeliveryReceipt): Promise<void> {
    if (this.handedOff.has(receipt.receiptId)) return;
    for (const listener of [...this.listeners]) await listener(receipt);
    this.handedOff.add(receipt.receiptId);
    if (this.handedOff.size > REMEMBERED_RECEIPT_IDS) {
      const oldest = this.handedOff.values().next().value;
      if (oldest !== undefined) this.handedOff.delete(oldest);
    }
  }
}

const intakes = new WeakMap<object, RelayReceiptIntake>();

/** Declare the receipt intake of this relay. */
export function declareRelayReceiptIntake(relay: object, intake: RelayReceiptIntake): void {
  intakes.set(relay, intake);
}

/** The receipt intake that this relay object declared. A wrapper declares none. */
export function relayReceiptIntakeOf(relay: object): RelayReceiptIntake | undefined {
  return intakes.get(relay);
}
