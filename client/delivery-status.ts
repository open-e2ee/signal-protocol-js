/**
 * Delivery status: the per-device delivery of each outgoing message, from
 * the Relay delivery receipts and the E2EE delivery receipts that name it.
 *
 * The status of one message to one recipient device is monotonic: accepted
 * when the send resolves, then delivered. A delivered device carries each
 * source that reported it, once, in the order of arrival. A `'relay'` source
 * tells that the Relay handed the message to the device. An `'e2ee'` source
 * tells that the device decrypted it. A second report of the same source
 * changes nothing.
 *
 * The status is durable. Each change is written before the client announces
 * it, and the write marks it announced, so a replayed receipt announces
 * nothing again. A receipt for a send that has not resolved is kept and
 * announced when the send resolves.
 *
 * A receipt names no message that has no outbox intent, such as a sync copy
 * or a retry resend. Such a receipt changes nothing.
 *
 * @internal
 */

import type { SignalProtocolLocalStore } from '../types';
import {
  getSentClientMessageIds,
  updateDeliveryStatus,
  type StoredDeliveryStatus,
  type StoredOutgoingMessageIntent,
} from '../local/store/reliability';
import type { DeliveredEvent, DeliverySource } from './event-hooks';
import type { RelayDeliveryReceipt } from './relay-receipt-intake';

type DeliveryStatusStore = Pick<SignalProtocolLocalStore, 'getMetadata' | 'setMetadata' | 'deleteMetadata'>;

function addresses(intent: StoredOutgoingMessageIntent, recipientId: string): boolean {
  return intent.kind === 'group'
    ? (intent.groupMemberUserIds ?? []).includes(recipientId)
    : intent.recipientId === recipientId;
}

/** Mark each unannounced source of each device announced, and return one event for each. */
function announce(
  status: StoredDeliveryStatus,
  intent: StoredOutgoingMessageIntent
): DeliveredEvent[] {
  const events: DeliveredEvent[] = [];
  for (const [recipientId, devices] of Object.entries(status.devices)) {
    for (const [deviceId, delivery] of Object.entries(devices)) {
      for (let index = delivery.announced; index < delivery.sources.length; index++) {
        const sources = delivery.sources.slice(0, index + 1);
        events.push({
          clientMessageId: status.clientMessageId,
          recipientId,
          recipientDeviceId: Number(deviceId),
          source: sources[index],
          sources,
          decryptionConfirmed: sources.includes('e2ee'),
          deliveredAt: delivery.deliveredAt,
          clientTimestamp: intent.clientTimestamp,
          ...(intent.kind === 'group' && { groupId: intent.recipientId }),
        });
      }
      delivery.announced = delivery.sources.length;
    }
  }
  return events;
}

export class DeliveryStatusTracker {
  /** The client message IDs that a send of this client is posting, with a count of the sends. */
  private readonly sending = new Map<string, number>();

  constructor(private readonly store: DeliveryStatusStore) {}

  /** A send of this client message ID starts. Its deliveries wait for `release`. */
  public beginSend(clientMessageId: string): void {
    this.sending.set(clientMessageId, (this.sending.get(clientMessageId) ?? 0) + 1);
  }

  /** A send of this client message ID resolved or failed. */
  public endSend(clientMessageId: string): void {
    const count = (this.sending.get(clientMessageId) ?? 0) - 1;
    if (count > 0) this.sending.set(clientMessageId, count);
    else this.sending.delete(clientMessageId);
  }

  /** Apply one Relay delivery receipt. Resolves to the events to announce. */
  public async applyRelayReceipt(receipt: RelayDeliveryReceipt): Promise<DeliveredEvent[]> {
    const events: DeliveredEvent[] = [];
    for (const clientMessageId of new Set(receipt.messageIds)) {
      events.push(
        ...(await this.apply(
          clientMessageId,
          'relay',
          receipt.recipient.accountId,
          receipt.recipient.deviceId,
          receipt.deliveredAt
        ))
      );
    }
    return events;
  }

  /**
   * Apply one E2EE delivery receipt from a recipient device. The receipt
   * names each message by its client timestamp. Resolves to the events to
   * announce.
   */
  public async applyE2eeReceipt(
    recipientId: string,
    recipientDeviceId: number,
    timestamps: readonly number[],
    deliveredAt: number
  ): Promise<DeliveredEvent[]> {
    const events: DeliveredEvent[] = [];
    for (const timestamp of new Set(timestamps)) {
      for (const clientMessageId of await getSentClientMessageIds(this.store, timestamp)) {
        events.push(
          ...(await this.apply(clientMessageId, 'e2ee', recipientId, recipientDeviceId, deliveredAt))
        );
      }
    }
    return events;
  }

  /**
   * Announce the deliveries that waited for the send of this client message
   * ID. Resolves to the events to announce.
   */
  public async release(clientMessageId: string): Promise<DeliveredEvent[]> {
    if (this.sending.has(clientMessageId)) return [];
    return (
      (await updateDeliveryStatus(this.store, clientMessageId, (status, intent) =>
        intent.result && !this.sending.has(clientMessageId) ? announce(status, intent) : []
      )) ?? []
    );
  }

  private async apply(
    clientMessageId: string,
    source: DeliverySource,
    recipientId: string,
    recipientDeviceId: number,
    deliveredAt: number
  ): Promise<DeliveredEvent[]> {
    return (
      (await updateDeliveryStatus(this.store, clientMessageId, (status, intent) => {
        if (!addresses(intent, recipientId)) return [];
        const devices = (status.devices[recipientId] ??= {});
        const delivery = (devices[String(recipientDeviceId)] ??= {
          sources: [],
          deliveredAt,
          announced: 0,
        });
        if (delivery.sources.includes(source)) return [];
        delivery.sources.push(source);
        if (!intent.result || this.sending.has(clientMessageId)) return [];
        return announce(status, intent);
      })) ?? []
    );
  }
}
