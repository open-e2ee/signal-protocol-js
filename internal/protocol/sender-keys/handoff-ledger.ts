/**
 * The sender-key handoff ledger: which recipient devices already got the
 * local device's current sender key for a group.
 *
 * A row records that the Relay accepted a distribution of the key for one
 * recipient device. A row is a handoff, never proof of install. The ledger
 * owns the policy: which devices need the key, when a row is written, and
 * which rows an event or the sweep removes. The store owns the rows and the
 * deletes that happen in the same transaction as a session, device, identity,
 * or sender-key write.
 *
 * The ledger has the role of the sender-key shared-with record of the Signal
 * clients: the devices that got the current sender key of a group. These
 * events delete rows, as in one Signal client:
 * - a session archive or a new PreKey session deletes the rows of the device
 *   in every group, as the session archive and the PreKey decrypt of that
 *   client do
 * - an identity change deletes the rows of the account
 * - a retry request for a group message deletes the rows of the device in the
 *   group of the message only, as the sender-key retry receipt does
 * - a rotation, a new own key, or a delete of the own key deletes the rows of
 *   the group in the same write as the key
 *
 * The SDK has no handler for a device-set mismatch from the Relay. Signal
 * clears the rows of the devices in a 409 or a 410 answer. Here a session
 * archive and the listed devices of each send do that work.
 */

import type { SenderKeyHandoffDevice, SenderKeyHandoffStore } from '../../../types/api';

/** The own sender key that a distribution carries. */
export interface SenderKeyHandoffKey {
  readonly senderKeyId: string;
  readonly generation: number;
}

/**
 * One listed recipient device of another member. The registration ID is
 * the `remoteRegistrationId` of the current session with the device, or
 * undefined when there is no current session.
 */
export interface SenderKeyHandoffTarget extends SenderKeyHandoffDevice {
  readonly registrationId: number | undefined;
}

/** What the sweep reads and locks for each group that holds rows. */
export interface SenderKeyHandoffSweepGroups {
  /** The senderKeyId of the own sender key of the group, or null when there is none. */
  currentSenderKeyId(groupId: string): Promise<string | null>;
  /** Run the task in the sender-key turn of the group. */
  inTurn(groupId: string, task: () => Promise<number>): Promise<number>;
}

function targetKey(userId: string, deviceId: number, registrationId: number): string {
  return JSON.stringify([userId, deviceId, registrationId]);
}

export class SenderKeyHandoffLedger {
  constructor(
    private readonly store: SenderKeyHandoffStore,
    private readonly now: () => number = Date.now
  ) {}

  /**
   * The targets that need the key, in input order. A target needs the key
   * when no row of the group matches the key's generation and senderKeyId,
   * the user, the device, and the registration ID of the current session.
   * A target with no current session always needs the key, as in one Signal
   * client.
   *
   * Two parts of the match are not in the shared-with table of that client,
   * which keys a row by distribution and device only:
   * - The senderKeyId. A delete and then a create of the own key start again
   *   at generation 1 with a new senderKeyId, so a row of the earlier key
   *   has the same generation. The built-in stores delete the rows in the
   *   rotation write. A custom store can write the key and delete the rows
   *   in two writes, and a crash between them leaves a row.
   *   The own key rotation of that client has the same crash window between its
   *   key delete and its row delete. With the senderKeyId in
   *   the match, such a row never stops a device from getting the current
   *   key.
   * - The registration ID. Another Signal client compares the registration
   *   IDs of the member devices of a group before a send. A new install of a
   *   device with the same device ID gets the key from this match. A peer
   *   that holds the earlier key installs the new key, because the receiver
   *   matches a sender key by its ID and not by its generation.
   */
  async devicesNeedingKey<T extends SenderKeyHandoffTarget>(
    groupId: string,
    key: SenderKeyHandoffKey,
    targets: readonly T[]
  ): Promise<T[]> {
    if (targets.length === 0) return [];
    const rows = await this.store.listSenderKeyHandoffs(groupId, key.generation);
    const handedOff = new Set(
      rows
        .filter((row) => row.senderKeyId === key.senderKeyId && row.generation === key.generation)
        .map((row) =>
          targetKey(row.recipientUserId, row.recipientDeviceId, row.recipientRegistrationId)
        )
    );
    return targets.filter(
      (target) =>
        target.registrationId === undefined ||
        !handedOff.has(targetKey(target.userId, target.deviceId, target.registrationId))
    );
  }

  /**
   * Record that the Relay accepted a distribution of the key for one device.
   * The caller records only after the acceptance, and before it confirms the
   * pre-message in its intent.
   */
  async record(
    groupId: string,
    key: SenderKeyHandoffKey,
    device: SenderKeyHandoffDevice,
    registrationId: number
  ): Promise<void> {
    await this.store.recordSenderKeyHandoff({
      groupId,
      senderKeyId: key.senderKeyId,
      generation: key.generation,
      recipientUserId: device.userId,
      recipientDeviceId: device.deviceId,
      recipientRegistrationId: registrationId,
      acceptedAt: this.now(),
    });
  }

  /**
   * Delete the rows of one device in one group, so the next send gives the
   * current key to that device. True when a row was deleted.
   */
  invalidate(groupId: string, device: SenderKeyHandoffDevice): Promise<boolean> {
    return this.store.invalidateSenderKeyHandoff(groupId, device);
  }

  /**
   * Delete the rows of every device of one account in every group, as one
   * Signal client does at an automatic session reset. The store deletes them as it does at
   * an identity rotation of the account. True when a row
   * was deleted.
   */
  invalidateAccount(userId: string): Promise<boolean> {
    return this.store.invalidateAccountSenderKeyHandoffs(userId);
  }

  /**
   * Delete the rows that no current own key covers: every row of a group
   * with no own sender key, and each row whose senderKeyId is not the
   * current one. Each group runs in its own sender-key turn, so no send or
   * rotation of the group runs between the key read and the delete.
   *
   * Signal has no sweep, because its row delete and its key delete share one
   * lock. The match above already ignores such rows, so the sweep only
   * removes storage that a crash or a custom store left.
   *
   * @returns The count of deleted rows.
   */
  async sweep(groups: SenderKeyHandoffSweepGroups): Promise<number> {
    let deleted = 0;
    for (const groupId of await this.store.listSenderKeyHandoffGroupIds()) {
      deleted += await groups.inTurn(groupId, async () =>
        this.store.retainSenderKeyHandoffs(groupId, await groups.currentSenderKeyId(groupId))
      );
    }
    return deleted;
  }
}
