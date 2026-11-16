import {
  base64ToBytes,
  bytesToBase64,
  bytesToUrlSafeBase64,
  concatBytes,
  sha256,
  stringToBytes,
  urlSafeToBase64,
} from "../internal/crypto";
import { encodeCompositeIdentityV1 } from "../keys/identity";
import type { CompositeIdentityV1 } from "../keys/types";
import type { Base64 } from "../types";
import type { HostedSignalProtocolRelayConnection } from "./hosted-connection";
import type {
  HostedSignalProtocolRelayRegistrationPreKey,
  HostedSignalProtocolRelayRegistrationPreKeys,
} from "./hosted";
import type { JsonRecord } from "./signal-relay-http";

/**
 * The registration material label. Every protocol version frames the
 * material fingerprint with these bytes, and the Relay stores the
 * fingerprint, so the label never changes.
 */
const REGISTRATION_MATERIAL_LABEL = stringToBytes(
  "OpenE2EE Relay registration material v1\0",
);

export function uint32be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("Signal Protocol Relay unsigned integer is invalid");
  }
  return new Uint8Array([value >>> 24, value >>> 16, value >>> 8, value]);
}

export function lengthPrefixed(value: Uint8Array): Uint8Array {
  return concatBytes(uint32be(value.length), value);
}

export function text(value: string): Uint8Array {
  return lengthPrefixed(stringToBytes(value));
}

/** Compares two byte strings in a time that depends only on their lengths. */
export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

export function canonicalBase64(value: Uint8Array): string {
  return bytesToBase64(value);
}

export function decodeCanonicalBase64(value: unknown, label: string): Uint8Array {
  if (typeof value !== "string") throw new Error(`${label} is invalid`);
  const decoded = base64ToBytes(value as Base64);
  if (bytesToBase64(decoded) !== value) throw new Error(`${label} is invalid`);
  return decoded;
}

export function decodeBase64Url(value: string, label: string): Uint8Array {
  try {
    const decoded = base64ToBytes(urlSafeToBase64(value) as Base64);
    if (bytesToUrlSafeBase64(decoded) !== value) throw new Error();
    return decoded;
  } catch {
    throw new Error(`${label} is invalid`);
  }
}

export function signalProtocolRelayScopeId(connection: HostedSignalProtocolRelayConnection): string {
  return bytesToUrlSafeBase64(connection.relayScopeId);
}

function serializedPreKey(prekey: HostedSignalProtocolRelayRegistrationPreKey): JsonRecord {
  return {
    algorithm: prekey.algorithm,
    keyId: prekey.keyId,
    publicKey: canonicalBase64(prekey.publicKey),
    ...(prekey.signature === undefined
      ? {}
      : { signature: canonicalBase64(prekey.signature) }),
  };
}

export function signalRegistration(
  identity: CompositeIdentityV1,
  registrationId: number,
  prekeys: HostedSignalProtocolRelayRegistrationPreKeys,
): JsonRecord {
  return {
    identity,
    oneTimePreKeys: prekeys.oneTimePreKeys.map(serializedPreKey),
    registrationId,
    signedPreKeys: prekeys.signedPreKeys.map(serializedPreKey),
  };
}

export async function registrationMaterialFingerprint(
  identity: CompositeIdentityV1,
  registrationId: number,
  prekeys: HostedSignalProtocolRelayRegistrationPreKeys,
): Promise<string> {
  const entries = [
    ...prekeys.signedPreKeys.map((prekey) => ({
      ...prekey,
      kind: "signed" as const,
    })),
    ...prekeys.oneTimePreKeys.map((prekey) => ({
      ...prekey,
      kind: "one-time" as const,
    })),
  ].sort((left, right) =>
    `${left.kind}:${left.algorithm}:${String(left.keyId)}`.localeCompare(
      `${right.kind}:${right.algorithm}:${String(right.keyId)}`,
    ),
  );
  return bytesToUrlSafeBase64(
    await sha256(
      concatBytes(
        REGISTRATION_MATERIAL_LABEL,
        text("aci"),
        text("signal-composite-v1"),
        uint32be(registrationId),
        lengthPrefixed(encodeCompositeIdentityV1(identity)),
        ...entries.flatMap((prekey) => [
          text(prekey.kind),
          text(prekey.algorithm),
          uint32be(prekey.keyId),
          lengthPrefixed(prekey.publicKey),
          lengthPrefixed(prekey.signature ?? new Uint8Array()),
        ]),
      ),
    ),
  );
}
