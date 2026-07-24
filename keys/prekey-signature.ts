import {
  base64ToBytes,
  concatBytes,
  sign,
  stringToBytes,
  verify,
} from '../internal/crypto';
import { deriveIdentityCommitment } from './identity';
import type { CompositeIdentityV1, IdentityKeyPair } from './types';
import type { PublicKey, Signature } from './branded';

export const PREKEY_SIGNATURE_V1_DOMAIN = 'signal-protocol-js prekey signature v1';
export const PREKEY_ALGORITHM_X25519 = 0x01;
export const PREKEY_ALGORITHM_ML_KEM_1024 = 0x0a;

function uint32be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error('Prekey ID must be an unsigned 32-bit integer');
  }
  return new Uint8Array([value >>> 24, value >>> 16, value >>> 8, value]);
}

export function createPreKeySignatureContext(
  identity: CompositeIdentityV1,
  algorithmTag: number,
  keyId: number,
  serializedPublicKey: Uint8Array
): Uint8Array {
  if (algorithmTag !== PREKEY_ALGORITHM_X25519 && algorithmTag !== PREKEY_ALGORITHM_ML_KEM_1024) {
    throw new Error(`Unsupported prekey algorithm tag: ${String(algorithmTag)}`);
  }
  if (serializedPublicKey.length === 0) throw new Error('Prekey public key cannot be empty');
  if (
    algorithmTag === PREKEY_ALGORITHM_ML_KEM_1024 &&
    serializedPublicKey[0] !== PREKEY_ALGORITHM_ML_KEM_1024
  ) {
    throw new Error('ML-KEM-1024 prekey signature requires the complete 0x0A-tagged public key');
  }
  return concatBytes(
    stringToBytes(PREKEY_SIGNATURE_V1_DOMAIN),
    deriveIdentityCommitment(identity),
    new Uint8Array([algorithmTag]),
    uint32be(keyId),
    serializedPublicKey
  );
}

export async function signPreKey(
  identityKeyPair: IdentityKeyPair,
  algorithmTag: number,
  keyId: number,
  serializedPublicKey: Uint8Array
): Promise<Signature> {
  const identity: CompositeIdentityV1 = {
    version: 1,
    x25519PublicKey: identityKeyPair.dhKey.publicKey,
    ed25519PublicKey: identityKeyPair.signingKey.publicKey,
  };
  return await sign(
    identityKeyPair.signingKey.privateKey,
    createPreKeySignatureContext(identity, algorithmTag, keyId, serializedPublicKey)
  );
}

export async function verifyPreKeySignature(
  identity: CompositeIdentityV1,
  algorithmTag: number,
  keyId: number,
  serializedPublicKey: PublicKey | Uint8Array,
  signature: Signature
): Promise<boolean> {
  const bytes =
    typeof serializedPublicKey === 'string'
      ? base64ToBytes(serializedPublicKey)
      : serializedPublicKey;
  return await verify(
    identity.ed25519PublicKey,
    createPreKeySignatureContext(identity, algorithmTag, keyId, bytes),
    signature
  );
}

/** Sign the canonical tagged ML-KEM-1024 prekey in its full identity context. */
export async function signMlKem1024PreKey(
  identityKeyPair: IdentityKeyPair,
  keyId: number,
  serializedPublicKey: Uint8Array
): Promise<Signature> {
  return signPreKey(
    identityKeyPair,
    PREKEY_ALGORITHM_ML_KEM_1024,
    keyId,
    serializedPublicKey
  );
}

/** Verify the canonical tagged ML-KEM-1024 prekey in its full identity context. */
export async function verifyMlKem1024PreKey(
  identity: CompositeIdentityV1,
  keyId: number,
  serializedPublicKey: PublicKey | Uint8Array,
  signature: Signature
): Promise<boolean> {
  return verifyPreKeySignature(
    identity,
    PREKEY_ALGORITHM_ML_KEM_1024,
    keyId,
    serializedPublicKey,
    signature
  );
}
