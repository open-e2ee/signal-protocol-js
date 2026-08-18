/**
 * X3DH (Extended Triple Diffie-Hellman) Key Agreement
 *
 * Implements the X3DH key agreement protocol for establishing shared secrets
 * between two parties. X3DH provides mutual authentication and forward secrecy.
 *
 * X3DH runs 3-4 ECDH operations:
 * - DH1: Initiator's identity key × Responder's signed prekey
 * - DH2: Initiator's ephemeral key × Responder's identity key
 * - DH3: Initiator's ephemeral key × Responder's signed prekey
 * - DH4: Initiator's ephemeral key × Responder's one-time prekey (if available)
 *
 * @see https://signal.org/docs/specifications/x3dh/
 */

import { defaultSignalProtocolLogger, type ILogger } from '../../../logger';
import {
  generateECDHKeyPair,
  computeSharedSecret,
  concatBytes,
  base64ToBytes,
  stringToBytes,
  hkdf,
  secureZeroBytes,
  validateX25519PublicKey,
} from '../../crypto';
import { PREKEY_ALGORITHM_X25519, verifyPreKeySignature } from '../../../keys/prekey-signature';
import type {
  IdentityKeyPair,
  EcSignedPreKey,
  EcOneTimePreKey,
  PreKeyBundle,
  PublicKey,
  PrivateKey,
} from '../../../keys';
import type { Base64 } from '../../../types';

// ============================================================================
// TYPES
// ============================================================================

/**
 * Ephemeral key pair for X3DH protocol
 */
export {};
export interface EphemeralKeyPair {
  publicKey: PublicKey;
  privateKey: PrivateKey;
}

/**
 * X3DH key agreement result
 */
export interface X3DHResult {
  /** The shared secret derived from X3DH (32 bytes) - initial root key (SK) */
  sharedSecret: Uint8Array;
  /**
   * Additional derived bytes from HKDF for compatibility.
   * Bytes 32-64: Reserved by this wire format
   * Bytes 64-96: Compatibility receiving chain key (the DH ratchet replaces it)
   *
   * Only present when derived with extended output size.
   */
  additionalDerivedBytes?: Uint8Array;
  /** Our ephemeral public key (sent to partner) */
  ephemeralPublicKey: PublicKey;
  /** Our ephemeral key pair (needed for session initialization as DHs) */
  ephemeralKeyPair: EphemeralKeyPair;
  /** ID of the signed prekey we used */
  usedSignedPreKeyId: number;
  /** ID of the one-time prekey we used (if any) */
  usedOneTimePreKeyId?: number;
  /** Kyber ciphertext for PQXDH (Kyber sessions only) */
  kyberCiphertext?: Base64;
  /** ID of the Kyber prekey we used (if any) */
  usedKyberPreKeyId?: number;
  /** Whether the session used PQXDH */
  usedPQXDH: boolean;
}

/**
 * X3DH responder result
 */
export interface X3DHResponderResult {
  /** The shared secret derived from X3DH (32 bytes) - initial root key (SK) */
  sharedSecret: Uint8Array;
  /**
   * Additional derived bytes from HKDF for compatibility.
   * Only present when derived with extended output size.
   */
  additionalDerivedBytes?: Uint8Array;
  /** Whether the session used PQXDH */
  usedPQXDH: boolean;
}

/**
 * Information needed for X3DH responder to derive shared secret
 */
export interface X3DHResponderInput {
  /** Sender's identity DH public key */
  senderIdentityKey: PublicKey;
  /** Sender's ephemeral public key from PreKeyMessage */
  senderEphemeralKey: PublicKey;
  /** ID of our signed prekey for this session */
  usedSignedPreKeyId: number;
  /** ID of our one-time prekey for this session (if any) */
  usedOneTimePreKeyId?: number;
  /** Kyber ciphertext for PQXDH (if any) */
  kyberCiphertext?: Base64;
  /** ID of our Kyber prekey for this session (if any) */
  usedKyberPreKeyId?: number;
}

// ============================================================================
// FUNCTIONS
// ============================================================================

/**
 * Run the X3DH key agreement as initiator (Alice)
 *
 * The caller invokes this when Alice wants to establish a session with Bob.
 * Alice uses Bob's prekey bundle for the key agreement.
 *
 * @param myIdentityKey My identity key pair
 * @param theirBundle Partner's prekey bundle
 * @param infoString HKDF info string for key derivation
 * @returns X3DH result containing shared secret and metadata
 *
 * @see https://signal.org/docs/specifications/x3dh/#the-x3dh-protocol
 */
export async function performX3DH(
  myIdentityKey: IdentityKeyPair,
  theirBundle: PreKeyBundle,
  infoString: string,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): Promise<X3DHResult> {
  logger.breadcrumb('X3DH initiator key agreement', {
    category: 'E2EE',
    level: 'info',
    data: { operation: 'x3dh', role: 'initiator' },
  });

  // H4: Validate incoming public keys are canonical X25519 points.
  // Must reject low-order/torsion points BEFORE any DH operations to prevent
  // small-subgroup attacks that force all-zero shared secrets.
  validateX25519PublicKey(theirBundle.identity.x25519PublicKey, 'remote identity key', logger);
  validateX25519PublicKey(theirBundle.ecSignedPreKey.publicKey, 'remote signed prekey', logger);
  if (theirBundle.ecOneTimePreKey) {
    validateX25519PublicKey(
      theirBundle.ecOneTimePreKey.publicKey,
      'remote one-time prekey',
      logger
    );
  }
  // Note: kemLastResortPreKey uses ML-KEM-1024 (1568 bytes), not X25519 - skip validation

  // Step 1: Verify signed prekey signature
  const isValid = await verifyPreKeySignature(
    theirBundle.identity,
    PREKEY_ALGORITHM_X25519,
    theirBundle.ecSignedPreKey.keyId,
    theirBundle.ecSignedPreKey.publicKey,
    theirBundle.ecSignedPreKey.signature
  );

  if (!isValid) {
    throw new Error('Invalid signed prekey signature');
  }

  // Step 2: Generate ephemeral key for this session
  const ephemeralKey = await generateECDHKeyPair();

  logger.debug('Alice X3DH: Key inputs', {
    category: 'E2EE',
    data: {
      myIdentityPub: myIdentityKey.dhKey.publicKey.substring(0, 20),
      myEphemeralPub: ephemeralKey.publicKey.substring(0, 20),
      bobIdentityPub: theirBundle.identity.x25519PublicKey.substring(0, 20),
      bobSignedPreKeyPub: theirBundle.ecSignedPreKey.publicKey.substring(0, 20),
      bobSignedPreKeyId: theirBundle.ecSignedPreKey.keyId,
      // DIAGNOSTIC: Log one-time prekey details to compare with Bob's side
      hasOneTimePreKey: !!theirBundle.ecOneTimePreKey,
      oneTimePreKeyId: theirBundle.ecOneTimePreKey?.keyId,
      oneTimePreKeyPub: theirBundle.ecOneTimePreKey?.publicKey?.substring(0, 20),
    },
  });

  const intermediateSecrets = new Set<Uint8Array>();
  const trackSecret = <T extends Uint8Array>(secret: T): T => {
    intermediateSecrets.add(secret);
    return secret;
  };

  try {
  // Step 3: ECDH operations

  // DH1: My identity DH private key × Their signed prekey public key
  const dh1 = trackSecret(await computeSharedSecret(
    myIdentityKey.dhKey.privateKey,
    theirBundle.ecSignedPreKey.publicKey
  ));

  // DH2: My ephemeral private key × Their identity DH public key
  const dh2 = trackSecret(await computeSharedSecret(
    ephemeralKey.privateKey,
    theirBundle.identity.x25519PublicKey
  ));

  // DH3: My ephemeral private key × Their signed prekey public key
  const dh3 = trackSecret(await computeSharedSecret(
    ephemeralKey.privateKey,
    theirBundle.ecSignedPreKey.publicKey
  ));

  // DH4: My ephemeral private key × Their one-time prekey public key (if available)
  let dh4: Uint8Array | null = null;
  if (theirBundle.ecOneTimePreKey) {
    dh4 = trackSecret(await computeSharedSecret(ephemeralKey.privateKey, theirBundle.ecOneTimePreKey.publicKey));
  }

  // Step 4: Concatenate all DH outputs to create input key material (IKM)
  const dhOutputs = dh4 ? [dh1, dh2, dh3, dh4] : [dh1, dh2, dh3];

  // Per Signal Protocol X3DH spec: Prepend F || (32 bytes of 0xFF)
  // 32 bytes is correct for X25519 (the only curve the reference implementation uses).
  const F = new Uint8Array(32).fill(0xff);
  const ikm = trackSecret(concatBytes(F, ...dhOutputs));

  // Step 5: Use HKDF to derive shared secret
  // Per Signal Protocol X3DH spec: Use zero-filled salt
  const salt = new Uint8Array(32); // 32 bytes of zeros

  // Use configurable info string for session derivation
  const info = stringToBytes(infoString);

  // Derive 96 bytes from X3DH:
  // - Bytes 0-32: Shared secret (SK) / initial root key
  // - Bytes 32-64: Reserved (not used)
  // - Bytes 64-96: Compatibility receiving chain key
  const derivedKeys = trackSecret(await hkdf(ikm, salt, info, 96));
  const sharedSecret = derivedKeys.slice(0, 32);
  const additionalDerivedBytes = derivedKeys.slice(32, 96);

  // Step 6: Secure cleanup - zero ALL intermediate key material
  secureZeroBytes(dh1);
  secureZeroBytes(dh2);
  secureZeroBytes(dh3);
  if (dh4) secureZeroBytes(dh4);
  secureZeroBytes(ikm); // Zero IKM after HKDF
  secureZeroBytes(derivedKeys); // Zero derivedKeys after slicing

  // Note: The ephemeral private key (ephemeralKey.privateKey) is an immutable
  // Base64 string, and JavaScript cannot zero it. The byte-form copies
  // created internally by computeSharedSecret() are local variables that go
  // out of scope, and nothing zeroes them explicitly. The JS/TS runtime
  // imposes this limit. Callers that decode the key pair to bytes for session
  // initialization should zero their own decoded copies when done.

  logger.breadcrumb('X3DH initiator key agreement complete', {
    category: 'E2EE',
    level: 'info',
    data: { operation: 'x3dh', usedOneTimePreKey: !!theirBundle.ecOneTimePreKey },
  });

  return {
    sharedSecret,
    additionalDerivedBytes,
    ephemeralPublicKey: ephemeralKey.publicKey,
    ephemeralKeyPair: ephemeralKey,
    usedSignedPreKeyId: theirBundle.ecSignedPreKey.keyId,
    usedOneTimePreKeyId: theirBundle.ecOneTimePreKey?.keyId,
    usedPQXDH: false,
  };
  } finally {
    for (const secret of intermediateSecrets) secureZeroBytes(secret);
  }
}

/**
 * Run the X3DH key agreement as responder (Bob)
 *
 * The caller invokes this when Bob receives Alice's PreKeyMessage.
 * Bob uses his own prekeys and Alice's keys to derive the same shared secret.
 *
 * @param myIdentityKey My identity key pair
 * @param mySignedPreKey My signed prekey for this session
 * @param myOneTimePreKey My one-time prekey for this session (if any)
 * @param input Information from Alice's PreKeyMessage
 * @param infoString HKDF info string for key derivation
 * @returns X3DH responder result containing shared secret
 *
 * @see https://signal.org/docs/specifications/x3dh/#the-x3dh-protocol
 */
export async function performX3DHResponder(
  myIdentityKey: IdentityKeyPair,
  mySignedPreKey: EcSignedPreKey,
  myOneTimePreKey: EcOneTimePreKey | null,
  input: X3DHResponderInput,
  infoString: string,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): Promise<X3DHResponderResult> {
  logger.breadcrumb('X3DH responder key agreement', {
    category: 'E2EE',
    level: 'info',
    data: { operation: 'x3dh', role: 'responder' },
  });

  logger.debug('Bob X3DH: Key inputs', {
    category: 'E2EE',
    data: {
      myIdentityPub: myIdentityKey.dhKey.publicKey.substring(0, 20),
      mySignedPreKeyPub: mySignedPreKey.publicKey.substring(0, 20),
      aliceIdentityPub: input.senderIdentityKey.substring(0, 20),
      aliceEphemeralPub: input.senderEphemeralKey.substring(0, 20),
    },
  });

  // H4: Validate incoming public keys are canonical X25519 points
  validateX25519PublicKey(input.senderIdentityKey, 'sender identity key', logger);
  validateX25519PublicKey(input.senderEphemeralKey, 'sender ephemeral key', logger);

  const intermediateSecrets = new Set<Uint8Array>();
  const trackSecret = <T extends Uint8Array>(secret: T): T => {
    intermediateSecrets.add(secret);
    return secret;
  };

  try {

  // Step 1: ECDH operations (same as initiator but using Bob's private keys)

  // DH1: Bob's signed prekey private × Alice's identity public
  const dh1 = trackSecret(await computeSharedSecret(mySignedPreKey.privateKey, input.senderIdentityKey));

  // DH2: Bob's identity private × Alice's ephemeral public
  const dh2 = trackSecret(await computeSharedSecret(myIdentityKey.dhKey.privateKey, input.senderEphemeralKey));

  // DH3: Bob's signed prekey private × Alice's ephemeral public
  const dh3 = trackSecret(await computeSharedSecret(mySignedPreKey.privateKey, input.senderEphemeralKey));

  // DH4: Bob's one-time prekey private × Alice's ephemeral public (if available)
  let dh4: Uint8Array | null = null;
  if (myOneTimePreKey && input.usedOneTimePreKeyId !== undefined) {
    dh4 = trackSecret(await computeSharedSecret(myOneTimePreKey.privateKey, input.senderEphemeralKey));
    logger.breadcrumb('One-time prekey used in X3DH', {
      category: 'E2EE',
      level: 'debug',
      data: { operation: 'x3dh' },
    });
  }

  // Step 2: Concatenate all DH outputs (same order as initiator)
  const dhOutputs = dh4 ? [dh1, dh2, dh3, dh4] : [dh1, dh2, dh3];

  // Per Signal Protocol X3DH spec: Prepend F || (32 bytes of 0xFF)
  // 32 bytes is correct for X25519 (the only curve the reference implementation uses).
  const F = new Uint8Array(32).fill(0xff);
  const ikm = trackSecret(concatBytes(F, ...dhOutputs));

  // Step 3: Use HKDF to derive shared secret
  // Per Signal Protocol X3DH spec: Use zero-filled salt
  const salt = new Uint8Array(32); // 32 bytes of zeros

  // Use configurable info string for session derivation
  const info = stringToBytes(infoString);

  // Derive 96 bytes from X3DH (matches initiator)
  const derivedKeys = trackSecret(await hkdf(ikm, salt, info, 96));
  const sharedSecret = derivedKeys.slice(0, 32);
  const additionalDerivedBytes = derivedKeys.slice(32, 96);

  // Step 4: Secure cleanup - zero ALL intermediate key material
  secureZeroBytes(dh1);
  secureZeroBytes(dh2);
  secureZeroBytes(dh3);
  if (dh4) secureZeroBytes(dh4);
  secureZeroBytes(ikm); // Zero IKM after HKDF
  secureZeroBytes(derivedKeys); // Zero derivedKeys after slicing

  logger.breadcrumb('X3DH responder key agreement complete', {
    category: 'E2EE',
    level: 'info',
    data: { operation: 'x3dh', usedOneTimePreKey: !!dh4 },
  });

  return {
    sharedSecret,
    additionalDerivedBytes,
    usedPQXDH: false,
  };
  } finally {
    for (const secret of intermediateSecrets) secureZeroBytes(secret);
  }
}

/**
 * Calculate X3DH shared secret from DH outputs
 *
 * This is a lower-level function that takes pre-computed DH outputs
 * and derives the shared secret. Useful when a caller runs the DH operations
 * separately (e.g., with hardware security modules).
 *
 * @param dh1 DH1 output (IKa × SPKb or SPKb × IKa)
 * @param dh2 DH2 output (EKa × IKb or IKb × EKa)
 * @param dh3 DH3 output (EKa × SPKb or SPKb × EKa)
 * @param dh4 DH4 output (EKa × OPKb or OPKb × EKa), optional
 * @param infoString HKDF info string for key derivation
 * @returns Shared secret (32 bytes)
 */
export async function calculateX3DHSharedSecret(
  dh1: Uint8Array,
  dh2: Uint8Array,
  dh3: Uint8Array,
  dh4: Uint8Array | undefined,
  infoString: string
): Promise<Uint8Array> {
  // Concatenate all DH outputs
  const dhOutputs = dh4 ? [dh1, dh2, dh3, dh4] : [dh1, dh2, dh3];

  // Per Signal Protocol X3DH spec: Prepend F || (32 bytes of 0xFF)
  // 32 bytes is correct for X25519 (the only curve the reference implementation uses).
  const F = new Uint8Array(32).fill(0xff);
  const ikm = concatBytes(F, ...dhOutputs);

  // Use HKDF to derive shared secret
  const salt = new Uint8Array(32); // 32 bytes of zeros
  const info = stringToBytes(infoString);

  return await hkdf(ikm, salt, info, 32);
}
