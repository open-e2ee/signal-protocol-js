/**
 * How IndexedDbSignalProtocolStore keeps a SESAME user record.
 *
 * The stored user record holds each device's identity pin and lifecycle
 * fields, and no session. A device's session lives only in the `sessions`
 * object store, the record the protocol layer reads and writes. A read joins
 * the two, so the SESAME layer sees the session that the protocol layer
 * established, and a write of a user record that was read earlier never
 * replaces a newer session. The identity pin is stored as a JSON number
 * array, so its bytes come back as an owned `Uint8Array`.
 */

import type { DeviceID, DeviceRecord, UserRecord } from '../../../types';

type StoredDeviceRecord = Omit<DeviceRecord, 'identityKey' | 'session'> & {
  identityKey: number[];
};

export type StoredUserRecord = Omit<UserRecord, 'devices'> & {
  devices: Array<[DeviceID, StoredDeviceRecord]>;
};

export function encodeUserRecord(record: UserRecord): StoredUserRecord {
  return {
    ...record,
    devices: Array.from(record.devices.entries(), ([deviceId, device]) => {
      const { session: _session, ...rest } = device;
      return [deviceId, { ...rest, identityKey: Array.from(device.identityKey) }];
    }),
  };
}

/** The stored devices, each with a null session until `withSession` joins it. */
export function decodeUserRecord(data: StoredUserRecord): UserRecord {
  return {
    ...data,
    devices: new Map(
      data.devices.map(([deviceId, device]) => [
        deviceId,
        { ...device, identityKey: new Uint8Array(device.identityKey), session: null },
      ])
    ),
  };
}
