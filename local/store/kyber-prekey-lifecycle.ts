import type { IdentityType, KyberPreKey } from '../../keys';
import { bytesToBase64 } from '../../internal/crypto/utils';
import { generateRandomBytes } from '../../internal/crypto/random';

export interface StoredKyberPreKeyInstance {
  instanceId: string;
  key: KyberPreKey;
  replacedAt: number | null;
  uses: Record<string, true>;
}

/** One identity's retained reusable-key generations and their replay records. */
export interface StoredKyberPreKeyState {
  currentKeyId: number | null;
  instances: Record<string, StoredKyberPreKeyInstance>;
}

export interface KyberPreKeyUse {
  kyberPreKeyId: number;
  kyberPreKeyInstanceId: string;
  signedPreKeyId: number;
  baseKeyBytes: Uint8Array;
}

export interface RetainedKyberPreKey {
  preKey: KyberPreKey;
  instanceId: string;
}

type UnboundKyberPreKeyUse = Omit<KyberPreKeyUse, 'kyberPreKeyInstanceId'>;

export class ReusedBaseKeyError extends Error {
  constructor(kyberPreKeyId: number, signedPreKeyId: number) {
    super(
      `Reused base key detected for Kyber prekey ${kyberPreKeyId} with signed prekey ${signedPreKeyId}`
    );
    this.name = 'ReusedBaseKeyError';
  }
}

export function sameKyberPreKeyInstance(left: KyberPreKey, right: KyberPreKey): boolean {
  return (
    left.keyId === right.keyId &&
    left.publicKey === right.publicKey &&
    left.privateKey === right.privateKey &&
    left.signature === right.signature
  );
}

export function assertUnambiguousKyberPreKeyStore(
  existing: KyberPreKey | null | undefined,
  candidate: KyberPreKey,
  identityType: IdentityType
): void {
  if (existing && !sameKyberPreKeyInstance(existing, candidate)) {
    throw new Error(
      `Kyber prekey key ID ${candidate.keyId} already identifies different retained material for ${identityType}`
    );
  }
}

export function kyberPreKeyUseKey(identityType: IdentityType, use: KyberPreKeyUse): string {
  const baseKey = bytesToBase64(use.baseKeyBytes);
  return `${identityType}:${use.kyberPreKeyId}:${use.signedPreKeyId}:${baseKey}`;
}

export function createKyberPreKeyState(): StoredKyberPreKeyState {
  return { currentKeyId: null, instances: Object.create(null) };
}

export async function createKyberPreKeyInstanceId(): Promise<string> {
  return bytesToBase64(await generateRandomBytes(32));
}

export function getCurrentKyberPreKey(
  state: StoredKyberPreKeyState | null | undefined
): KyberPreKey | null {
  if (!state || state.currentKeyId === null) return null;
  return state.instances[String(state.currentKeyId)]?.key ?? null;
}

export function getRetainedKyberPreKey(
  state: StoredKyberPreKeyState | null | undefined,
  keyId: number
): RetainedKyberPreKey | null {
  const instance = state?.instances[String(keyId)];
  return instance ? { preKey: instance.key, instanceId: instance.instanceId } : null;
}

/**
 * Retain a new immutable instance and make it current.
 *
 * A retry with identical material is idempotent. Reusing a still-retained
 * logical ID for different material is ambiguous and is refused.
 */
export function retainKyberPreKey(
  state: StoredKyberPreKeyState,
  candidate: KyberPreKey,
  identityType: IdentityType,
  now: number,
  instanceId: string
): boolean {
  const key = String(candidate.keyId);
  const existing = state.instances[key];
  assertUnambiguousKyberPreKeyStore(existing?.key, candidate, identityType);
  if (existing) return false;

  if (state.currentKeyId !== null) {
    const current = state.instances[String(state.currentKeyId)];
    if (current && current.replacedAt === null) current.replacedAt = now;
  }
  state.instances[key] = {
    instanceId,
    key: { ...candidate },
    replacedAt: null,
    uses: Object.create(null),
  };
  state.currentKeyId = candidate.keyId;
  return true;
}

/** Record a successful reusable-key use under its exact retained parent. */
export function recordKyberPreKeyUse(
  state: StoredKyberPreKeyState | null | undefined,
  identityType: IdentityType,
  use: KyberPreKeyUse
): void {
  const parent = assertKyberPreKeyUse(state, identityType, use);
  parent.uses[kyberPreKeyUseKey(identityType, use)] = true;
}

export function assertKyberPreKeyUse(
  state: StoredKyberPreKeyState | null | undefined,
  identityType: IdentityType,
  use: KyberPreKeyUse
): StoredKyberPreKeyInstance {
  const parent = state?.instances[String(use.kyberPreKeyId)];
  if (!parent) throw new Error(`Kyber prekey ${use.kyberPreKeyId} is not retained`);
  if (parent.instanceId !== use.kyberPreKeyInstanceId) {
    throw new Error(`Kyber prekey ${use.kyberPreKeyId} instance mismatch`);
  }
  const key = kyberPreKeyUseKey(identityType, use);
  if (parent.uses[key]) throw new ReusedBaseKeyError(use.kyberPreKeyId, use.signedPreKeyId);
  return parent;
}

export function recordKyberPreKeyUseById(
  state: StoredKyberPreKeyState | null | undefined,
  identityType: IdentityType,
  use: UnboundKyberPreKeyUse
): void {
  const parent = state?.instances[String(use.kyberPreKeyId)];
  if (!parent) throw new Error(`Kyber prekey ${use.kyberPreKeyId} is not retained`);
  recordKyberPreKeyUse(state, identityType, { ...use, kyberPreKeyInstanceId: parent.instanceId });
}
