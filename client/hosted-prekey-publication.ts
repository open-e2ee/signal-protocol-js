import type { PreKeyUpload } from '../remote/relay/types';
import type {
  HostedRelayRegistrationPreKey,
  HostedRelayRegistrationPreKeys,
} from './hosted';
import { base64ToBytes, bytesToBase64 } from '../internal/crypto';
import type { Base64 } from '../types';

type JsonRecord = Record<string, unknown>;

export interface StoredHostedPreKey {
  algorithm: 'ec-x25519' | 'kem-ml-kem-1024';
  keyId: number;
  publicKey: string;
  signature?: string;
}

export interface StoredHostedPreKeyPublication {
  authorityGeneration: number;
  materialFingerprint: string;
  oneTimePreKeys: readonly StoredHostedPreKey[];
  operationId: string;
  revision: number;
  signedPreKeys: readonly StoredHostedPreKey[];
}

export interface StoredHostedPendingPreKeyPublication {
  materialFingerprint: string;
  oneTimePreKeys: readonly StoredHostedPreKey[];
  operationId: string;
  predecessorRevision: number;
  signedPreKeys: readonly StoredHostedPreKey[];
}

export interface HostedPreKeyStatus {
  authorityGeneration: number;
  currentOperationId: string;
  identityPublicMaterial: Uint8Array;
  materialFingerprint: string;
  oneTimePreKeys: readonly HostedRelayRegistrationPreKey[];
  oneTimePreKeyCounts: Readonly<Record<string, number>>;
  publicationRevision: number;
  profile: string;
  registrationId: number;
  signedPreKeys: readonly {
    acceptedAtMilliseconds: number;
    algorithm: HostedRelayRegistrationPreKey['algorithm'];
    keyId: number;
    publicKey: Uint8Array;
    signature: Uint8Array;
  }[];
}

function record(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function decodeCanonicalBase64(value: unknown, label: string): Uint8Array {
  if (typeof value !== 'string') throw new Error(`${label} is invalid`);
  const decoded = base64ToBytes(value as Base64);
  if (bytesToBase64(decoded) !== value) throw new Error(`${label} is invalid`);
  return decoded;
}

function requiredNumber(object: JsonRecord, key: string): number {
  const value = object[key];
  if (!Number.isSafeInteger(value))
    throw new Error('Managed Relay returned invalid data');
  return value as number;
}

function requiredString(object: JsonRecord, key: string): string {
  const value = object[key];
  if (typeof value !== 'string' || !value)
    throw new Error('Managed Relay returned invalid data');
  return value;
}

export function storedPreKey(
  prekey: HostedRelayRegistrationPreKey,
): StoredHostedPreKey {
  return {
    algorithm: prekey.algorithm,
    keyId: prekey.keyId,
    publicKey: bytesToBase64(prekey.publicKey),
    ...(prekey.signature === undefined
      ? {}
      : { signature: bytesToBase64(prekey.signature) }),
  };
}

function parseStoredPreKey(value: unknown): StoredHostedPreKey {
  if (
    !record(value) ||
    (value.algorithm !== 'ec-x25519' &&
      value.algorithm !== 'kem-ml-kem-1024') ||
    !Number.isSafeInteger(value.keyId) ||
    (value.keyId as number) < 0 ||
    typeof value.publicKey !== 'string' ||
    (value.signature !== undefined && typeof value.signature !== 'string')
  ) {
    throw new Error('Stored hosted Relay session is invalid');
  }
  decodeCanonicalBase64(value.publicKey, 'Stored prekey public key');
  if (value.signature !== undefined)
    decodeCanonicalBase64(value.signature, 'Stored prekey signature');
  return value as unknown as StoredHostedPreKey;
}

function parseStoredPreKeys(value: unknown): readonly StoredHostedPreKey[] {
  if (!Array.isArray(value))
    throw new Error('Stored hosted Relay session is invalid');
  return value.map(parseStoredPreKey);
}

export function registrationPreKey(
  prekey: StoredHostedPreKey,
): HostedRelayRegistrationPreKey {
  return {
    algorithm: prekey.algorithm,
    keyId: prekey.keyId,
    publicKey: decodeCanonicalBase64(
      prekey.publicKey,
      'Stored prekey public key',
    ),
    ...(prekey.signature === undefined
      ? {}
      : {
          signature: decodeCanonicalBase64(
            prekey.signature,
            'Stored prekey signature',
          ),
        }),
  };
}

export function storedPublication(
  authorityGeneration: number,
  materialFingerprint: string,
  operationId: string,
  revision: number,
  prekeys: HostedRelayRegistrationPreKeys,
): StoredHostedPreKeyPublication {
  return {
    authorityGeneration,
    materialFingerprint,
    oneTimePreKeys: prekeys.oneTimePreKeys.map(storedPreKey),
    operationId,
    revision,
    signedPreKeys: prekeys.signedPreKeys.map(storedPreKey),
  };
}

export function parseStoredPublication(
  value: unknown,
): StoredHostedPreKeyPublication {
  if (
    !record(value) ||
    Object.keys(value).sort().join(',') !==
      'authorityGeneration,materialFingerprint,oneTimePreKeys,operationId,revision,signedPreKeys' ||
    !Number.isSafeInteger(value.authorityGeneration) ||
    (value.authorityGeneration as number) < 0 ||
    typeof value.materialFingerprint !== 'string' ||
    !value.materialFingerprint ||
    typeof value.operationId !== 'string' ||
    !value.operationId ||
    !Number.isSafeInteger(value.revision) ||
    (value.revision as number) < 0
  ) {
    throw new Error('Stored hosted Relay session is invalid');
  }
  return {
    authorityGeneration: value.authorityGeneration as number,
    materialFingerprint: value.materialFingerprint,
    oneTimePreKeys: parseStoredPreKeys(value.oneTimePreKeys),
    operationId: value.operationId,
    revision: value.revision as number,
    signedPreKeys: parseStoredPreKeys(value.signedPreKeys),
  };
}

export function parseStoredPendingPublication(
  value: unknown,
): StoredHostedPendingPreKeyPublication | null {
  if (value === null) return null;
  if (
    !record(value) ||
    Object.keys(value).sort().join(',') !==
      'materialFingerprint,oneTimePreKeys,operationId,predecessorRevision,signedPreKeys' ||
    typeof value.materialFingerprint !== 'string' ||
    !value.materialFingerprint ||
    typeof value.operationId !== 'string' ||
    !value.operationId ||
    !Number.isSafeInteger(value.predecessorRevision) ||
    (value.predecessorRevision as number) < 0
  ) {
    throw new Error('Stored hosted Relay session is invalid');
  }
  return {
    materialFingerprint: value.materialFingerprint,
    oneTimePreKeys: parseStoredPreKeys(value.oneTimePreKeys),
    operationId: value.operationId,
    predecessorRevision: value.predecessorRevision as number,
    signedPreKeys: parseStoredPreKeys(value.signedPreKeys),
  };
}

export function parseHostedPreKeyStatus(value: unknown): HostedPreKeyStatus {
  if (
    !record(value) ||
    typeof value.identityPublicMaterial !== 'string' ||
    !Array.isArray(value.oneTimePreKeys) ||
    !record(value.oneTimePreKeyCounts) ||
    typeof value.profile !== 'string' ||
    !Array.isArray(value.signedPreKeys)
  ) {
    throw new Error('Managed Relay returned invalid prekey status');
  }
  const parsePreKey = (
    candidate: unknown,
    kind: 'one-time' | 'signed',
  ): HostedRelayRegistrationPreKey => {
    if (!record(candidate))
      throw new Error('Managed Relay returned invalid prekey status');
    const algorithm = requiredString(candidate, 'algorithm');
    if (algorithm !== 'ec-x25519' && algorithm !== 'kem-ml-kem-1024')
      throw new Error('Managed Relay returned invalid prekey status');
    const signature =
      candidate.signature === undefined
        ? undefined
        : decodeCanonicalBase64(candidate.signature, 'Prekey signature');
    const signatureRequired =
      kind === 'signed' || algorithm === 'kem-ml-kem-1024';
    if (signatureRequired !== (signature !== undefined))
      throw new Error('Managed Relay returned invalid prekey status');
    return {
      algorithm,
      keyId: requiredNumber(candidate, 'keyId'),
      publicKey: decodeCanonicalBase64(
        candidate.publicKey,
        'Prekey public key',
      ),
      ...(signature === undefined ? {} : { signature }),
    };
  };
  const counts: Record<string, number> = {};
  for (const [algorithm, count] of Object.entries(value.oneTimePreKeyCounts)) {
    if (!Number.isSafeInteger(count) || (count as number) < 0)
      throw new Error('Managed Relay returned invalid prekey status');
    counts[algorithm] = count as number;
  }
  return {
    authorityGeneration: requiredNumber(value, 'authorityGeneration'),
    currentOperationId: requiredString(value, 'currentOperationId'),
    identityPublicMaterial: decodeCanonicalBase64(
      value.identityPublicMaterial,
      'Signal identity',
    ),
    materialFingerprint: requiredString(value, 'materialFingerprint'),
    oneTimePreKeys: value.oneTimePreKeys.map((candidate) =>
      parsePreKey(candidate, 'one-time'),
    ),
    oneTimePreKeyCounts: counts,
    profile: value.profile,
    publicationRevision: requiredNumber(value, 'publicationRevision'),
    registrationId: requiredNumber(value, 'registrationId'),
    signedPreKeys: value.signedPreKeys.map((candidate) => ({
      ...parsePreKey(candidate, 'signed'),
      acceptedAtMilliseconds: requiredNumber(
        candidate as JsonRecord,
        'acceptedAtMilliseconds',
      ),
      signature: decodeCanonicalBase64(
        (candidate as JsonRecord).signature,
        'Prekey signature',
      ),
    })),
  };
}

export function statusPreKeys(
  status: HostedPreKeyStatus,
): HostedRelayRegistrationPreKeys {
  return {
    oneTimePreKeys: status.oneTimePreKeys,
    signedPreKeys: status.signedPreKeys.map((prekey) => ({
      algorithm: prekey.algorithm,
      keyId: prekey.keyId,
      publicKey: prekey.publicKey,
      signature: prekey.signature,
    })),
  };
}

export function publicationMatchesStatus(
  publication: StoredHostedPreKeyPublication,
  status: HostedPreKeyStatus,
): boolean {
  return (
    status.authorityGeneration === publication.authorityGeneration &&
    status.currentOperationId === publication.operationId &&
    status.materialFingerprint === publication.materialFingerprint &&
    status.publicationRevision === publication.revision
  );
}

function registrationPreKeyUpload(
  upload: PreKeyUpload,
): HostedRelayRegistrationPreKey {
  if (!Number.isSafeInteger(upload.keyId) || upload.keyId < 0)
    throw new Error('Hosted Relay prekey upload is invalid');
  const signature =
    upload.signature === undefined
      ? undefined
      : decodeCanonicalBase64(upload.signature, 'Prekey signature');
  if (
    (upload.type === 'ecPreKey' && signature !== undefined) ||
    (upload.type !== 'ecPreKey' && signature === undefined)
  ) {
    throw new Error('Hosted Relay prekey upload is invalid');
  }
  return {
    algorithm:
      upload.type === 'ecPreKey' || upload.type === 'ecSignedPreKey'
        ? 'ec-x25519'
        : 'kem-ml-kem-1024',
    keyId: upload.keyId,
    publicKey: decodeCanonicalBase64(upload.publicKey, 'Prekey public key'),
    ...(signature === undefined ? {} : { signature }),
  };
}

export function applyPreKeyUploads(
  current: HostedRelayRegistrationPreKeys,
  uploads: readonly PreKeyUpload[],
): HostedRelayRegistrationPreKeys {
  const oneTimePreKeys = [...current.oneTimePreKeys];
  const signedPreKeys = [...current.signedPreKeys];
  for (const type of [
    'ecPreKey',
    'kemOneTimePreKey',
    'ecSignedPreKey',
    'kemLastResortPreKey',
  ] as const) {
    const replacements = uploads
      .filter((upload) => upload.type === type)
      .map(registrationPreKeyUpload);
    if (replacements.length === 0) continue;
    const algorithm =
      type === 'ecPreKey' || type === 'ecSignedPreKey'
        ? 'ec-x25519'
        : 'kem-ml-kem-1024';
    const target =
      type === 'ecPreKey' || type === 'kemOneTimePreKey'
        ? oneTimePreKeys
        : signedPreKeys;
    for (let index = target.length - 1; index >= 0; index -= 1) {
      if (target[index]?.algorithm === algorithm) target.splice(index, 1);
    }
    target.push(...replacements);
  }
  for (const [kind, prekeys] of [
    ['one-time', oneTimePreKeys],
    ['signed', signedPreKeys],
  ] as const) {
    const identifiers = new Set<string>();
    for (const prekey of prekeys) {
      const identifier = `${prekey.algorithm}:${String(prekey.keyId)}`;
      if (identifiers.has(identifier))
        throw new Error(
          `Hosted Relay ${kind} prekey upload repeats an identifier`,
        );
      identifiers.add(identifier);
    }
  }
  return { oneTimePreKeys, signedPreKeys };
}
