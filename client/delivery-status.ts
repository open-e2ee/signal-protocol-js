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
 * The status is durable. A receipt writes its source before the client
 * announces it. The client marks a source announced only after the
 * `onDelivered` hook returns for it. A hook that throws, a stop during the
 * hook, or a crash leaves the source unannounced, and the next receipt for
 * the message announces it again: a replay of the same receipt, or a receipt
 * of another source or device. So the announcement is at least once, and a
 * replayed receipt announces nothing again only after the hook returned. A
 * receipt for a send that has not resolved is kept and announced when the
 * send resolves.
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
import type { DeliveredEvent, DeliverySource, SignalProtocolClientHooks } from './event-hooks';
import type { RelayDeliveryReceipt } from './relay-receipt-intake';

type DeliveryStatusStore = Pick<
  SignalProtocolLocalStore,
  'getMetadata' | 'setMetadata' | 'deleteMetadata' | 'deleteSendLogRecipientsByTimestamp'
>;

function addresses(intent: StoredOutgoingMessageIntent, recipientId: string): boolean {
  return intent.kind === 'group'
    ? (intent.groupMemberUserIds ?? []).includes(recipientId)
    : intent.recipientId === recipientId;
}

/**
 * One event for each source of each device that the client has not
 * announced, in the order of arrival. It changes nothing: `announce` marks
 * an event announced after its hook returns.
 */
function unannounced(
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
   *
   * The device decrypted each message, so the receipt first deletes the send
   * log row of that device at each timestamp. A Relay receipt deletes no
   * row: a device also acknowledges a copy that it could not decrypt, and
   * the row authorizes the resend of the content to it.
   */
  public async applyE2eeReceipt(
    recipientId: string,
    recipientDeviceId: number,
    timestamps: readonly number[],
    deliveredAt: number
  ): Promise<DeliveredEvent[]> {
    const unique = [...new Set(timestamps)];
    await this.store.deleteSendLogRecipientsByTimestamp(
      { userId: recipientId, deviceId: recipientDeviceId },
      unique
    );
    const events: DeliveredEvent[] = [];
    for (const timestamp of unique) {
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
        intent.result && !this.sending.has(clientMessageId) ? unannounced(status, intent) : []
      )) ?? []
    );
  }

  /**
   * Run the `onDelivered` hook for each event in order, and mark each event
   * announced after its hook returns. The hook is called directly, not
   * through `callHook`, so an error from the hook, or the RelayWorkStopped of
   * a stop, rejects the call. That event and each later event then stay
   * unannounced, and the next receipt for the message announces them again.
   * The caller lets the rejection fail the hand-off of the receipt, so the
   * relay replays it.
   */
  public async announce(
    hooks: SignalProtocolClientHooks | undefined,
    events: readonly DeliveredEvent[]
  ): Promise<void> {
    const deliver = hooks?.onDelivered;
    for (const event of events) {
      if (deliver) await deliver(event);
      await this.markAnnounced(event);
    }
  }

  /**
   * Mark the sources of this event announced. The announced count of a
   * device only moves forward, so a late or repeated mark never announces a
   * source again.
   */
  private async markAnnounced(event: DeliveredEvent): Promise<void> {
    await updateDeliveryStatus(this.store, event.clientMessageId, (status) => {
      const delivery = status.devices[event.recipientId]?.[String(event.recipientDeviceId)];
      if (!delivery) return;
      const announced = Math.min(event.sources.length, delivery.sources.length);
      if (announced > delivery.announced) delivery.announced = announced;
    });
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
        // A replay of a source adds nothing. It still announces each source
        // whose hook did not return.
        if (!delivery.sources.includes(source)) delivery.sources.push(source);
        if (!intent.result || this.sending.has(clientMessageId)) return [];
        return unannounced(status, intent);
      })) ?? []
    );
  }
}
