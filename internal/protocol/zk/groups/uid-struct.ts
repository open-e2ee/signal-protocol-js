/**
 * UidStruct: UUID-based user identifier as two Ristretto points
 *
 *
 * Converts a ServiceId (ACI or PNI) into a pair of Ristretto points (M1, M2)
 * suitable for use as a credential attribute:
 *  - M1 = SHO(label || service_id_binary).getPoint()
 *  - M2 = lizardEncode(raw_uuid_bytes)
 *
 * @see https://eprint.iacr.org/2019/1416.pdf (Signal Private Group System)
 */

import { ShoHmacSha256, RistrettoPoint } from '../proofs/sho';
import { lizardEncode } from './lizard';
import type { Attribute } from '../credentials/attributes';
export {};
const enc = new TextEncoder();

// ---------------------------------------------------------------------------
// ServiceId: ACI/PNI identifier
// ---------------------------------------------------------------------------

export const SERVICE_ID_ACI = 0x00 as const;
export const SERVICE_ID_PNI = 0x01 as const;
export type ServiceIdKind = typeof SERVICE_ID_ACI | typeof SERVICE_ID_PNI;

export interface ServiceId {
  kind: ServiceIdKind;
  uuid: Uint8Array; // 16 bytes
}

/** Return whether a UUID is the reserved all-zero value. */
export function isNilUuid(uuid: Uint8Array): boolean {
  return uuid.length === 16 && uuid.every((byte) => byte === 0);
}

/**
 * Serialize a ServiceId to 17-byte binary form: [kind_byte, ...uuid_bytes].
 */
export function serviceIdBinary(sid: ServiceId): Uint8Array {
  if (sid.uuid.length !== 16) {
    throw new Error(`ServiceId uuid must be 16 bytes, got ${sid.uuid.length}`);
  }
  const result = new Uint8Array(17);
  result[0] = sid.kind;
  result.set(sid.uuid, 1);
  return result;
}

// ---------------------------------------------------------------------------
// UidStruct
// ---------------------------------------------------------------------------

export interface UidStruct extends Attribute {
  readonly rawUuidBytes: Uint8Array; // 16 bytes
  readonly M1: RistrettoPoint;
  readonly M2: RistrettoPoint;
}

/**
 * Create the seed SHO for M1 calculation.
 */
export function seedM1(): ShoHmacSha256 {
  return new ShoHmacSha256(enc.encode('Signal_ZKGroup_20200424_UID_CalcM1'));
}

/**
 * Calculate the M1 point from a seed SHO and a ServiceId.
 *
 * NOTE: This consumes the SHO state (absorb + get_point both ratchet).
 * Clone the seed first if you need to reuse it.
 */
export function calcM1(seed: ShoHmacSha256, serviceId: ServiceId): RistrettoPoint {
  seed.absorbAndRatchet(serviceIdBinary(serviceId));
  return seed.getPoint();
}

/**
 * Create a UidStruct from a ServiceId.
 */
/** Parse a UUID string to 16-byte Uint8Array. */
export function uuidToBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, '');
  if (hex.length !== 32) throw new Error(`Invalid UUID: ${uuid}`);
  if (!/^[0-9a-f]{32}$/i.test(hex)) throw new Error(`Invalid UUID (non-hex chars): ${uuid}`);
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function uidStructFromServiceId(serviceId: ServiceId): UidStruct {
  const M1 = calcM1(seedM1(), serviceId);
  const rawUuidBytes = new Uint8Array(serviceId.uuid);
  const M2 = lizardEncode(rawUuidBytes);

  return {
    rawUuidBytes,
    M1,
    M2,
    asPoints(): [RistrettoPoint, RistrettoPoint] {
      return [this.M1, this.M2];
    },
  };
}
