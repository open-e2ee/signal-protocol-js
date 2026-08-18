/**
 * PQXDH (Post-Quantum Extended Diffie-Hellman) Key Agreement
 *
 * Implements the PQXDH key agreement protocol which extends X3DH with
 * standardized ML-KEM-1024 for the post-quantum contribution.
 *
 * The negotiated PQXDH mode runs X3DH plus ML-KEM-1024:
 * - All X3DH DH operations (DH1-DH4)
 * - ML-KEM encapsulation/decapsulation
 * - Combines both secrets with HKDF for hybrid security
 *
 * The intended hybrid property is conditional. Confidentiality survives a
 * break of one contribution only while the other contribution and the wider
 * authenticated protocol assumptions remain secure. See docs/SECURITY.md.
 *
 * @see https://signal.org/docs/specifications/pqxdh/
 */

import { defaultSignalProtocolLogger, type ILogger } from '../../../logger';
import {
  generateECDHKeyPair,
  computeSharedSecret,
  concatBytes,
  bytesToBase64,
  base64ToBytes,
  stringToBytes,
  hkdf,
  secureZeroBytes,
  mlKem1024Encapsulate,
  mlKem1024Decapsulate,
  concatPQXDHSecrets,
  validateX25519PublicKey,
} from '../../crypto';
import {
  PREKEY_ALGORITHM_ML_KEM_1024,
  PREKEY_ALGORITHM_X25519,
  verifyPreKeySignature,
} from '../../../keys/prekey-signature';
import type {
  IdentityKeyPair,
  EcSignedPreKey,
  EcOneTimePreKey,
  KyberPreKey,
  KemOneTimePreKey,
  PreKeyBundle,
  PublicKey,
  PrivateKey,
} from '../../../keys';
import type { Base64 } from '../../../types';
import { EncryptionError, EncryptionErrorCode } from '../../../types';

// ============================================================================
// KEY TYPES RE-EXPORT (for convenience - can also import from keys/)
// ============================================================================
export {};
export type {
  IdentityKeyPair,
  EcSignedPreKey,
  EcOneTimePreKey,
  KyberPreKey,
  PreKeyBundle,
  KeyPair,
} from '../../../keys';

// ============================================================================
// PQXDH-SPECIFIC TYPES
// ============================================================================

/**
 * Ephemeral key pair for PQXDH protocol
 */
export interface EphemeralKeyPair {
  publicKey: PublicKey;
  privateKey: PrivateKey;
}

/**
 * PQXDH key agreement result
 */
export interface PQXDHResult {
  /** The shared secret derived from PQXDH (32 bytes) - initial root key (SK) */
  sharedSecret: Uint8Array;
  /**
   * Additional derived bytes from HKDF for compatibility.
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
  /** Kyber ciphertext for PQXDH last-resort prekey (sent to partner) */
  kyberCiphertext?: Base64;
  /** ID of the Kyber last-resort prekey we used */
  usedKyberPreKeyId?: number;
  /** Kyber ciphertext for one-time KEM prekey (sent to partner) */
  kemOneTimePreKeyCiphertext?: Base64;
  /** ID of the KEM one-time prekey we used (if any) */
  usedKemOneTimePreKeyId?: number;
  /** Whether the session used PQXDH (always true for this type) */
  usedPQXDH: boolean;
}

/**
 * PQXDH responder result
 */
export interface PQXDHResponderResult {
  /** The shared secret derived from PQXDH (32 bytes) - initial root key (SK) */
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
 * Information needed for PQXDH responder to derive shared secret
 */
export interface PQXDHResponderInput {
  /** Sender's identity DH public key */
  senderIdentityKey: PublicKey;
  /** Sender's ephemeral public key from PreKeyMessage */
  senderEphemeralKey: PublicKey;
  /** ID of our signed prekey for this session */
  usedSignedPreKeyId: number;
  /** ID of our one-time prekey for this session (if any) */
  usedOneTimePreKeyId?: number;
  /**
   * Kyber ciphertext for PQXDH last-resort prekey (fallback)
   * Per PQXDH spec: use EITHER this OR kemOneTimePreKeyCiphertext, not both
   */
  kyberCiphertext?: Base64;
  /** ID of our Kyber last-resort prekey for this session */
  usedKyberPreKeyId?: number;
  /**
   * Kyber ciphertext for one-time KEM prekey (preferred)
   * Per PQXDH spec: use EITHER this OR kyberCiphertext, not both
   */
  kemOneTimePreKeyCiphertext?: Base64;
  /** ID of our one-time KEM prekey for this session (if any) */
  usedKemOneTimePreKeyId?: number;
}

// ============================================================================
// FUNCTIONS
// ============================================================================

/**
 * Run the PQXDH key agreement as initiator (Alice)
 *
 * This extends X3DH with Kyber post-quantum security.
 * Alice uses Bob's prekey bundle (including Kyber prekey) for the key agreement.
 *
 * @param myIdentityKey My identity key pair
 * @param theirBundle Partner's prekey bundle (must include Kyber prekey)
 * @param infoString HKDF info string for key derivation
 * @returns PQXDH result containing shared secret and metadata.
 *   **Caller must zero** `sharedSecret` and `additionalDerivedBytes` after use
 *   (e.g., via `secureZeroBytes()`). This function zeroes the source
 *   `derivedKeys` buffer internally, but the returned slices are the caller's
 *   responsibility.
 *
 * @see https://signal.org/docs/specifications/pqxdh/#the-pqxdh-protocol
 */
export async function performPQXDH(
  myIdentityKey: IdentityKeyPair,
  theirBundle: PreKeyBundle,
  infoString: string,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): Promise<PQXDHResult> {
  logger.breadcrumb('PQXDH initiator key agreement', {
    category: 'E2EE',
    level: 'info',
    data: { operation: 'pqxdh', role: 'initiator', pq_contribution: 'ml-kem-1024' },
  });

  // PQXDH requires one signed KEM prekey - either one-time or last-resort.
  // The session/handshake.ts orchestration layer handles fallback to X3DH.
  if (!theirBundle.kemOneTimePreKey && !theirBundle.kemLastResortPreKey) {
    logger.breadcrumb('PQXDH: KEM prekey missing from bundle', {
      category: 'E2EE',
      level: 'warn',
    });
    throw new EncryptionError(
      'Key agreement failed',
      EncryptionErrorCode.SIGNATURE_VERIFICATION_FAILED
    );
  }

  // Step 1: Verify signed prekey signature
  const isValid = await verifyPreKeySignature(
    theirBundle.identity,
    PREKEY_ALGORITHM_X25519,
    theirBundle.ecSignedPreKey.keyId,
    theirBundle.ecSignedPreKey.publicKey,
    theirBundle.ecSignedPreKey.signature
  );

  if (!isValid) {
    logger.breadcrumb('PQXDH: Signed prekey signature verification failed', {
      category: 'E2EE',
      level: 'warn',
    });
    throw new EncryptionError(
      'Key agreement failed',
      EncryptionErrorCode.SIGNATURE_VERIFICATION_FAILED
    );
  }

  // Step 2: Validate all incoming X25519 public keys before DH operations
  // Prevents small-subgroup attacks from malicious server-provided keys
  // Validate every remote DH input before use.
  validateX25519PublicKey(theirBundle.identity.x25519PublicKey, 'remote identity key', logger);
  validateX25519PublicKey(theirBundle.ecSignedPreKey.publicKey, 'remote signed prekey', logger);
  if (theirBundle.ecOneTimePreKey) {
    validateX25519PublicKey(
      theirBundle.ecOneTimePreKey.publicKey,
      'remote one-time prekey',
      logger
    );
  }

  // Step 3: Generate ephemeral key for this session
  const ephemeralKey = await generateECDHKeyPair();

  const intermediateSecrets = new Set<Uint8Array>();
  const trackSecret = <T extends Uint8Array>(secret: T): T => {
    intermediateSecrets.add(secret);
    return secret;
  };

  try {

  // Step 4: ECDH operations (same as X3DH)

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

  // Step 5: Concatenate all DH outputs to create input key material (IKM)
  const dhOutputs = dh4 ? [dh1, dh2, dh3, dh4] : [dh1, dh2, dh3];

  // Per Signal Protocol X3DH spec: Prepend F || (32 bytes of 0xFF)
  const F = new Uint8Array(32).fill(0xff);
  let ikm = trackSecret(concatBytes(F, ...dhOutputs));

  // Step 6: KEM encapsulation.
  // Per PQXDH spec Section 3.3, use EITHER one-time (preferred) OR last-resort
  // (fallback). From the Signal Protocol PQXDH design:
  //
  // > "One of either Bob's signed one-time pqkem prekey... or Bob's
  // > last-resort signed pqkem prekey if no signed one-time pqkem prekey remains"
  let kyberSharedSecret: Uint8Array;
  let kyberCiphertext: Base64 | undefined;
  let kemOneTimePreKeyCiphertext: Base64 | undefined;
  let usedKemOneTimePreKeyId: number | undefined;
  let usedKemPreKeyType: 'one-time' | 'last-resort';

  if (theirBundle.kemOneTimePreKey) {
    // PREFER one-time KEM prekey for per-session PQ forward secrecy
    logger.breadcrumb('PQXDH: Performing Kyber encapsulation (one-time preferred)', {
      category: 'E2EE',
      level: 'debug',
      data: { operation: 'pqxdh', keyId: theirBundle.kemOneTimePreKey.keyId },
    });

    // Verify the one-time KEM prekey signature immediately before encapsulation.
    const kemOtpPublicKeyBytes = base64ToBytes(theirBundle.kemOneTimePreKey.publicKey);
    const kemOtpSignatureValid = await verifyPreKeySignature(
      theirBundle.identity,
      PREKEY_ALGORITHM_ML_KEM_1024,
      theirBundle.kemOneTimePreKey.keyId,
      kemOtpPublicKeyBytes,
      theirBundle.kemOneTimePreKey.signature
    );

    if (!kemOtpSignatureValid) {
      logger.breadcrumb('PQXDH: KEM one-time prekey signature verification failed', {
        category: 'E2EE',
        level: 'warn',
      });
      throw new EncryptionError(
        'Key agreement failed',
        EncryptionErrorCode.SIGNATURE_VERIFICATION_FAILED
      );
    }

    const kemOtpResult = await mlKem1024Encapsulate(kemOtpPublicKeyBytes);
    kyberSharedSecret = trackSecret(kemOtpResult.sharedSecret);
    kemOneTimePreKeyCiphertext = bytesToBase64(kemOtpResult.ciphertext);
    usedKemOneTimePreKeyId = theirBundle.kemOneTimePreKey.keyId;
    usedKemPreKeyType = 'one-time';

    logger.breadcrumb('PQXDH: Kyber ciphertext generated (one-time)', {
      category: 'E2EE',
      level: 'debug',
      data: { ciphertextLength: kemOtpResult.ciphertext.length, keyId: usedKemOneTimePreKeyId },
    });
  } else {
    const lastResortKemPreKey = theirBundle.kemLastResortPreKey!;

    // FALLBACK to last-resort KEM prekey when one-time exhausted
    logger.breadcrumb('PQXDH: Performing Kyber encapsulation (last-resort fallback)', {
      category: 'E2EE',
      level: 'debug',
      data: { operation: 'pqxdh' },
    });

    const kyberPublicKeyBytes = base64ToBytes(lastResortKemPreKey.publicKey);
    const kyberSignatureValid = await verifyPreKeySignature(
      theirBundle.identity,
      PREKEY_ALGORITHM_ML_KEM_1024,
      lastResortKemPreKey.keyId,
      kyberPublicKeyBytes,
      lastResortKemPreKey.signature
    );

    if (!kyberSignatureValid) {
      logger.breadcrumb('PQXDH: Kyber prekey signature verification failed', {
        category: 'E2EE',
        level: 'warn',
      });
      throw new EncryptionError(
        'Key agreement failed',
        EncryptionErrorCode.SIGNATURE_VERIFICATION_FAILED
      );
    }

    const kyberResult = await mlKem1024Encapsulate(kyberPublicKeyBytes);
    kyberSharedSecret = trackSecret(kyberResult.sharedSecret);
    kyberCiphertext = bytesToBase64(kyberResult.ciphertext);
    usedKemPreKeyType = 'last-resort';

    logger.breadcrumb('PQXDH: Kyber ciphertext generated (last-resort)', {
      category: 'E2EE',
      level: 'debug',
      data: { ciphertextLength: kyberResult.ciphertext.length },
    });
  }

  // Step 7: Append single Kyber shared secret to IKM per PQXDH specification,
  // where IKM = F || DH1 || DH2 || DH3 || [DH4] || SS.
  // The Signal Protocol PQXDH flow runs one KEM encapsulation per session.
  // Only the KEM shared secret enters IKM. The public key is not additional data.
  ikm = trackSecret(concatPQXDHSecrets(ikm, kyberSharedSecret));

  // Step 8: Single HKDF derivation per PQXDH spec, where
  // SK = KDF(F || DH1 || DH2 || DH3 || [DH4] || SS, zero_salt, info).
  // Per Signal Protocol spec: Use zero-filled salt.
  const salt = new Uint8Array(32); // 32 bytes of zeros

  // Use the configured session-derivation domain string.
  const info = stringToBytes(infoString);

  // Derive 96 bytes from PQXDH (matches X3DH initiator pattern)
  // This is the ONLY HKDF call - single-step KDF per spec
  const derivedKeys = trackSecret(await hkdf(ikm, salt, info, 96));
  const sharedSecret = derivedKeys.slice(0, 32);
  const additionalDerivedBytes = derivedKeys.slice(32, 96);

  // Step 9: Secure cleanup - zero ALL intermediate key material
  // Best-effort overwrite of owned typed arrays. JavaScript cannot provide
  // physical-erasure guarantees.
  // The brief window between computation and zeroing is unavoidable in JS
  // and acceptable.
  secureZeroBytes(dh1);
  secureZeroBytes(dh2);
  secureZeroBytes(dh3);
  if (dh4) secureZeroBytes(dh4);
  secureZeroBytes(kyberSharedSecret);
  secureZeroBytes(ikm); // Zero IKM after HKDF
  secureZeroBytes(derivedKeys); // Zero derivedKeys after slicing

  // Note: The ephemeral private key (ephemeralKey.privateKey) is an immutable
  // Base64 string, and JavaScript cannot zero it. The byte-form copies
  // created internally by computeSharedSecret() are local variables that go
  // out of scope, and nothing zeroes them explicitly. The JS/TS runtime
  // imposes this limit. Callers that decode the key pair to bytes for session
  // initialization should zero their own decoded copies when done.

  logger.breadcrumb('PQXDH initiator key agreement complete', {
    category: 'E2EE',
    level: 'info',
    data: {
      operation: 'pqxdh',
      usedOneTimePreKey: !!theirBundle.ecOneTimePreKey,
      usedKemPreKeyType,
      pq_contribution: 'ml-kem-1024',
    },
  });

  return {
    sharedSecret,
    additionalDerivedBytes,
    ephemeralPublicKey: ephemeralKey.publicKey,
    ephemeralKeyPair: ephemeralKey,
    usedSignedPreKeyId: theirBundle.ecSignedPreKey.keyId,
    usedOneTimePreKeyId: theirBundle.ecOneTimePreKey?.keyId,
    // Per PQXDH spec: the session uses only one KEM key
    // Set the ID for whichever key type the session used
    kyberCiphertext,
    usedKyberPreKeyId:
      usedKemPreKeyType === 'last-resort' ? theirBundle.kemLastResortPreKey!.keyId : undefined,
    kemOneTimePreKeyCiphertext,
    usedKemOneTimePreKeyId,
    usedPQXDH: true,
  };
  } finally {
    for (const secret of intermediateSecrets) secureZeroBytes(secret);
  }
}

/**
 * Run the PQXDH key agreement as responder (Bob)
 *
 * The caller invokes this when Bob receives Alice's PreKeyMessage with KEM
 * ciphertext.
 * Bob uses his own prekeys and Alice's keys to derive the same shared secret.
 *
 * Supports exactly one KEM mode per session: one-time KEM or last-resort KEM.
 *
 * @param myIdentityKey My identity key pair
 * @param mySignedPreKey My signed prekey for this session
 * @param myOneTimePreKey My one-time prekey for this session (if any)
 * @param myKyberPreKey My Kyber last-resort prekey for decapsulation
 * @param myKemOneTimePreKey My one-time KEM prekey for decapsulation (if any)
 * @param input Information from Alice's PreKeyMessage
 * @param infoString HKDF info string for key derivation
 * @returns PQXDH responder result containing shared secret.
 *   **Caller must zero** `sharedSecret` and `additionalDerivedBytes` after use
 *   (e.g., via `secureZeroBytes()`). This function zeroes the source
 *   `derivedKeys` buffer internally, but the returned slices are the caller's
 *   responsibility.
 *
 * @see https://signal.org/docs/specifications/pqxdh/#the-pqxdh-protocol
 */
export async function performPQXDHResponder(
  myIdentityKey: IdentityKeyPair,
  mySignedPreKey: EcSignedPreKey,
  myOneTimePreKey: EcOneTimePreKey | null,
  myKyberPreKey: KyberPreKey | null,
  myKemOneTimePreKey: KemOneTimePreKey | null,
  input: PQXDHResponderInput,
  infoString: string,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): Promise<PQXDHResponderResult> {
  logger.breadcrumb('PQXDH responder key agreement', {
    category: 'E2EE',
    level: 'info',
    data: { operation: 'pqxdh', role: 'responder', pq_contribution: 'ml-kem-1024' },
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

  // Step 1: ECDH operations (same as X3DH)

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
    logger.breadcrumb('One-time prekey used in PQXDH', {
      category: 'E2EE',
      level: 'debug',
      data: { operation: 'pqxdh' },
    });
  }

  // Step 2: Concatenate all DH outputs (same order as initiator)
  const dhOutputs = dh4 ? [dh1, dh2, dh3, dh4] : [dh1, dh2, dh3];

  // Per Signal Protocol X3DH spec: Prepend F || (32 bytes of 0xFF)
  const F = new Uint8Array(32).fill(0xff);
  let ikm = trackSecret(concatBytes(F, ...dhOutputs));

  // Step 3: Kyber KEM decapsulation.
  // Per PQXDH spec Section 3.3, EITHER one-time (preferred) OR last-resort
  // (fallback). The initiator uses one KEM key per session, so we must match
  // their choice.
  let kyberSharedSecret: Uint8Array;
  let kyberCiphertextBytes: Uint8Array;
  let kyberPrivateKeyBytes: Uint8Array;
  let usedKemPreKeyType: 'one-time' | 'last-resort';

  if (input.kemOneTimePreKeyCiphertext && myKemOneTimePreKey) {
    // The initiator used the one-time KEM prekey (preferred path)
    logger.breadcrumb('PQXDH: Responder decapsulating Kyber ciphertext (one-time)', {
      category: 'E2EE',
      level: 'info',
      data: { operation: 'pqxdh-responder', keyId: input.usedKemOneTimePreKeyId },
    });

    kyberCiphertextBytes = trackSecret(base64ToBytes(input.kemOneTimePreKeyCiphertext));
    kyberPrivateKeyBytes = trackSecret(base64ToBytes(myKemOneTimePreKey.privateKey));
    usedKemPreKeyType = 'one-time';

    kyberSharedSecret = trackSecret(
      await mlKem1024Decapsulate(kyberCiphertextBytes, kyberPrivateKeyBytes)
    );

    logger.breadcrumb('PQXDH: Responder decapsulated one-time KEM prekey', {
      category: 'E2EE',
      level: 'info',
      data: { operation: 'pqxdh-responder', keyId: input.usedKemOneTimePreKeyId },
    });

    // CRITICAL: The caller is responsible for deleting the one-time KEM prekey
    // from storage immediately after this function returns successfully.
    // This provides per-session post-quantum forward secrecy.
  } else if (input.kyberCiphertext) {
    // The initiator used the last-resort KEM prekey (fallback when one-time exhausted)
    if (!myKyberPreKey) {
      logger.breadcrumb('PQXDH: Last-resort Kyber prekey required but not provided', {
        category: 'E2EE',
        level: 'warn',
      });
      throw new EncryptionError(
        'Key agreement failed',
        EncryptionErrorCode.SIGNATURE_VERIFICATION_FAILED
      );
    }

    logger.breadcrumb('PQXDH: Responder decapsulating Kyber ciphertext (last-resort)', {
      category: 'E2EE',
      level: 'info',
      data: { operation: 'pqxdh-responder' },
    });

    kyberCiphertextBytes = trackSecret(base64ToBytes(input.kyberCiphertext));
    kyberPrivateKeyBytes = trackSecret(base64ToBytes(myKyberPreKey.privateKey));
    usedKemPreKeyType = 'last-resort';

    kyberSharedSecret = trackSecret(
      await mlKem1024Decapsulate(kyberCiphertextBytes, kyberPrivateKeyBytes)
    );
  } else {
    logger.breadcrumb('PQXDH: No Kyber ciphertext provided for responder', {
      category: 'E2EE',
      level: 'warn',
    });
    throw new EncryptionError(
      'Key agreement failed',
      EncryptionErrorCode.SIGNATURE_VERIFICATION_FAILED
    );
  }

  // Step 4: Append single Kyber shared secret to IKM per PQXDH specification,
  // where IKM = F || DH1 || DH2 || DH3 || [DH4] || SS.
  // The Signal Protocol PQXDH flow runs one KEM encapsulation per session.
  ikm = trackSecret(concatPQXDHSecrets(ikm, kyberSharedSecret));

  logger.breadcrumb('PQXDH: Responder completed post-quantum key agreement', {
    category: 'E2EE',
    level: 'info',
    data: {
      operation: 'pqxdh-responder',
      usedKemPreKeyType,
      pq_contribution: 'ml-kem-1024',
    },
  });

  // Step 5: Single HKDF derivation per PQXDH spec, where
  // SK = KDF(F || DH1 || DH2 || DH3 || [DH4] || SS, zero_salt, info).
  // Per Signal Protocol spec: Use zero-filled salt.
  const salt = new Uint8Array(32); // 32 bytes of zeros

  // Use the configured session-derivation domain string.
  const info = stringToBytes(infoString);

  // Derive 96 bytes from PQXDH (matches initiator pattern)
  // This is the ONLY HKDF call - single-step KDF per spec
  const derivedKeys = trackSecret(await hkdf(ikm, salt, info, 96));
  const sharedSecret = derivedKeys.slice(0, 32);
  const additionalDerivedBytes = derivedKeys.slice(32, 96);

  // Step 6: Secure cleanup - zero ALL intermediate key material
  // DH outputs
  secureZeroBytes(dh1);
  secureZeroBytes(dh2);
  secureZeroBytes(dh3);
  if (dh4) secureZeroBytes(dh4);
  // Kyber shared secret and keys
  secureZeroBytes(kyberSharedSecret);
  secureZeroBytes(kyberCiphertextBytes);
  secureZeroBytes(kyberPrivateKeyBytes);
  // Zero the combined IKM and derivedKeys after HKDF
  secureZeroBytes(ikm);
  secureZeroBytes(derivedKeys); // Zero derivedKeys after slicing

  logger.breadcrumb('PQXDH responder key agreement complete', {
    category: 'E2EE',
    level: 'info',
    data: {
      operation: 'pqxdh',
      usedOneTimePreKey: !!dh4,
      usedKemPreKeyType,
      pq_contribution: 'ml-kem-1024',
    },
  });

  return {
    sharedSecret,
    additionalDerivedBytes,
    usedPQXDH: true,
  };
  } finally {
    for (const secret of intermediateSecrets) secureZeroBytes(secret);
  }
}
