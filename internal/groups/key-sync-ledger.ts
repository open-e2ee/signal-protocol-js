/**
 * The own-device group key sync ledger.
 *
 * The ledger marks, for each group, the own devices whose `GroupKeySync`
 * copy with the group master key the relay accepted, and the own device
 * that sent this device the key. A pair of a group and an own device that
 * the ledger does not mark gets a `GroupKeySync` at the next start, so a
 * fault between the send and the mark causes one more send, not a lost key.
 *
 * The ledger is one versioned metadata value for each group in the
 * `SignalProtocolLocalStore`. It is not part of the group-state record. A
 * custom local store must keep the metadata contract: `compareAndSetMetadata`
 * compares and sets one key atomically, and each metadata value survives a
 * close and a reopen of the store. A store that loses a value causes one
 * more `GroupKeySync` for each pair that the value marked.
 */

import type { SignalProtocolLocalStore } from '../../types/api';

export {};

const LEDGER_VERSION = 1;
const LEDGER_PREFIX = 'open-e2ee:group-key-sync:v1:';

/** An own device that the ledger marks for a group. */
export interface GroupKeySyncDevice {
  readonly deviceId: number;
  readonly registrationId: number;
}

const acceptedBeforeFailure = new WeakMap<object, readonly GroupKeySyncDevice[]>();

/**
 * Record on the error of a failed `GroupKeySync` send the own devices whose
 * copy the relay accepted before the failure, and return the error. A
 * caller that catches the error marks those devices. Only the outermost
 * frame of a `GroupKeySync` send records, and it records each error that
 * the send throws, an empty list included. Other sync sends record nothing.
 * So an error object that a relay adapter reuses carries only the devices
 * of the latest `GroupKeySync` send.
 */
export function withAcceptedSyncDevices(
  error: unknown,
  devices: readonly GroupKeySyncDevice[]
): unknown {
  if (typeof error === 'object' && error !== null) {
    acceptedBeforeFailure.set(error, devices);
  }
  return error;
}

/**
 * The own devices whose copy the relay accepted before a sync send failed.
 * The read deletes the record, so a second read of the same error gives no
 * devices.
 */
export function syncDevicesAcceptedBefore(error: unknown): readonly GroupKeySyncDevice[] {
  if (typeof error !== 'object' || error === null) return [];
  const devices = acceptedBeforeFailure.get(error) ?? [];
  acceptedBeforeFailure.delete(error);
  return devices;
}

/** The ledger value of one group. */
export interface GroupKeySyncRecord {
  readonly version: typeof LEDGER_VERSION;
  /** The marked own devices, keyed by device ID. */
  readonly devices: Readonly<Record<string, { readonly registrationId: number }>>;
}

function ledgerKey(groupId: string): string {
  return `${LEDGER_PREFIX}${groupId}`;
}

function decodeLedger(encoded: string): GroupKeySyncRecord {
  const decoded = JSON.parse(encoded) as { version?: unknown; devices?: unknown };
  if (decoded.version !== LEDGER_VERSION) {
    throw new Error(
      `Unsupported SDK group key sync record version ${String(decoded.version)}`
    );
  }
  if (typeof decoded.devices !== 'object' || decoded.devices === null) {
    throw new Error('The SDK group key sync record is malformed');
  }
  return decoded as GroupKeySyncRecord;
}

/** The ledger value of a group, or `null` when no own device is marked. */
export async function readGroupKeySync(
  storage: SignalProtocolLocalStore,
  groupId: string
): Promise<GroupKeySyncRecord | null> {
  const encoded = await storage.getMetadata(ledgerKey(groupId));
  return encoded === null ? null : decodeLedger(encoded);
}

/**
 * Mark the given own devices as synced for a group. Call it only after the
 * relay accepted the send to these devices. The mark replaces the entry of a
 * device, so a repeat mark keeps one entry for each device.
 */
export async function markGroupKeySynced(
  storage: SignalProtocolLocalStore,
  groupId: string,
  accepted: readonly GroupKeySyncDevice[]
): Promise<void> {
  if (accepted.length === 0) return;
  const key = ledgerKey(groupId);
  for (;;) {
    const encoded = await storage.getMetadata(key);
    const devices: Record<string, { registrationId: number }> = {
      ...(encoded === null ? {} : decodeLedger(encoded).devices),
    };
    for (const device of accepted) {
      devices[String(device.deviceId)] = {
        registrationId: device.registrationId,
      };
    }
    const next: GroupKeySyncRecord = { version: LEDGER_VERSION, devices };
    if (await storage.compareAndSetMetadata(key, encoded, JSON.stringify(next))) {
      return;
    }
  }
}

/**
 * Whether the ledger marks an own device as synced for a group. An entry with
 * a different registration ID belongs to an earlier install of the device ID,
 * so it reads as unsent.
 */
export async function isGroupKeySynced(
  storage: SignalProtocolLocalStore,
  groupId: string,
  device: GroupKeySyncDevice
): Promise<boolean> {
  const record = await readGroupKeySync(storage, groupId);
  const entry = record?.devices[String(device.deviceId)];
  return entry !== undefined && entry.registrationId === device.registrationId;
}

/** Delete the ledger value of a group. */
export async function deleteGroupKeySync(
  storage: SignalProtocolLocalStore,
  groupId: string
): Promise<void> {
  await storage.deleteMetadata(ledgerKey(groupId));
}
