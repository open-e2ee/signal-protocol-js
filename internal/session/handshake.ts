/**
 * Handshake - X3DH/PQXDH Key Agreement
 *
 * Handles the cryptographic key agreement phase of the Signal Protocol.
 * This module performs the X3DH (Extended Triple Diffie-Hellman) or PQXDH
 * (Post-Quantum Extended Diffie-Hellman) handshake to derive shared secrets.
 *
 * Used by establish.ts to perform key agreement before session creation.
 *
 * @see https://signal.org/docs/specifications/x3dh/
 * @see https://signal.org/docs/specifications/pqxdh/
 */

import { defaultSignalLogger, type ILogger } from '../../logger';
import { getErrorMessage } from '../../utils/errors';
import {
  performPQXDH as pqxdhKeyAgreement,
  performPQXDHResponder as pqxdhResponderKeyAgreement,
} from '../protocol/pqxdh';
import {
  performX3DH as x3dhKeyAgreement,
  performX3DHResponder as x3dhResponderKeyAgreement,
  type X3DHResponderInput,
} from '../protocol/x3dh';
import type { PQXDHResponderInput } from '../protocol/pqxdh';
import type {
  IdentityKeyPair,
  EcSignedPreKey,
  EcOneTimePreKey,
  KyberPreKey,
  KemOneTimePreKey,
  PreKeyBundle,
  PublicKey,
} from '../../keys';
import type { PreKeyMessage } from '../../types';
import { EncryptionError, EncryptionErrorCode, PQXDHRequiredError } from '../../types/errors';
import type { ProtocolStrategyConfig } from '../../types';
import {
  resolveKeyExchangeInfoStrings,
  type ProtocolSelectionEvent,
} from '../../types/protocol-config';
import type { KeyAgreementResult, ResponderKeyAgreementResult } from './types';
import type { Base64 } from '../../types/utils';
import {
  base64ToBytes,
  bytesToBase64,
  parseMlKem1024PublicKey,
  validateX25519PublicKey,
} from '../crypto';
import { encodeCompositeIdentityV1 } from '../../keys/identity';

/**
 * Options for key agreement operations
 */
export {};
export interface KeyAgreementOptions {
  /** Protocol strategy configuration */
  protocolStrategy?: ProtocolStrategyConfig;
  /** Remote address for error messages and callbacks (userId:deviceId) */
  remoteAddress?: string;
  /** Resolved logger for handshake diagnostics */
  logger?: Required<ILogger>;
}

/**
 * Build X3DHResponderInput from PreKeyMessage.
 * Centralizes the construction to avoid duplication.
 */
export function buildX3DHResponderInput(
  prekeyMessage: PreKeyMessage,
  senderIdentityKey: PublicKey,
  senderEphemeralKey: PublicKey
): X3DHResponderInput {
  return {
    senderIdentityKey,
    senderEphemeralKey,
    usedSignedPreKeyId: prekeyMessage.usedSignedPreKeyId!,
    usedOneTimePreKeyId: prekeyMessage.usedOneTimePreKeyId,
  };
}

function bundleHasAnyKemMaterial(prekeyBundle: PreKeyBundle): boolean {
  return !!prekeyBundle.kemLastResortPreKey || !!prekeyBundle.kemOneTimePreKey;
}

function assertUint32(value: unknown, label: string, min = 0, max = 0xffff_ffff): void {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) {
    throw new Error(`${label} must be an integer between ${min} and ${max}`);
  }
}

function decodeCanonicalBase64(value: unknown, label: string, expectedLength: number): Uint8Array {
  if (typeof value !== 'string') throw new Error(`${label} must be canonical base64`);
  let decoded: Uint8Array;
  try {
    decoded = base64ToBytes(value as Base64);
  } catch (error) {
    throw new Error(`${label} must be canonical base64`, { cause: error });
  }
  if (decoded.length !== expectedLength || bytesToBase64(decoded) !== value) {
    throw new Error(`${label} must be canonical base64 for exactly ${expectedLength} bytes`);
  }
  return decoded;
}

/** Validate the complete structured bundle before protocol selection or crypto work. */
export function validatePreKeyBundle(prekeyBundle: PreKeyBundle): void {
  if (typeof prekeyBundle !== 'object' || prekeyBundle === null) {
    throw new Error('PreKeyBundle must be an object');
  }
  assertUint32(prekeyBundle.registrationId, 'registrationId', 1, 16_384);
  assertUint32(prekeyBundle.deviceId, 'deviceId', 1);
  encodeCompositeIdentityV1(prekeyBundle.identity);
  validateX25519PublicKey(prekeyBundle.identity.x25519PublicKey, 'bundle identity key');

  if (!prekeyBundle.ecSignedPreKey) throw new Error('PreKeyBundle requires ecSignedPreKey');
  assertUint32(prekeyBundle.ecSignedPreKey.keyId, 'EC signed prekey ID');
  decodeCanonicalBase64(prekeyBundle.ecSignedPreKey.publicKey, 'EC signed prekey', 32);
  validateX25519PublicKey(prekeyBundle.ecSignedPreKey.publicKey, 'bundle EC signed prekey');
  decodeCanonicalBase64(prekeyBundle.ecSignedPreKey.signature, 'EC signed prekey signature', 64);

  if (prekeyBundle.ecOneTimePreKey) {
    assertUint32(prekeyBundle.ecOneTimePreKey.keyId, 'EC one-time prekey ID');
    decodeCanonicalBase64(prekeyBundle.ecOneTimePreKey.publicKey, 'EC one-time prekey', 32);
    validateX25519PublicKey(prekeyBundle.ecOneTimePreKey.publicKey, 'bundle EC one-time prekey');
  }

  for (const [label, prekey] of [
    ['KEM last-resort prekey', prekeyBundle.kemLastResortPreKey],
    ['KEM one-time prekey', prekeyBundle.kemOneTimePreKey],
  ] as const) {
    if (!prekey) continue;
    assertUint32(prekey.keyId, `${label} ID`);
    const publicKey = decodeCanonicalBase64(prekey.publicKey, label, 1569);
    parseMlKem1024PublicKey(publicKey);
    decodeCanonicalBase64(prekey.signature, `${label} signature`, 64);
  }
}

// ============================================================================
// Key Agreement Functions
// ============================================================================

/**
 * Perform key agreement as initiator (Alice)
 *
 * ORCHESTRATION LAYER: Requires PQXDH by default for session establishment.
 *
 * Explicit `allowClassicalFallback` permits X3DH only when the peer bundle has
 * no KEM material at all. If any KEM material is present, PQXDH must succeed.
 *
 * @param identityKeyPair Our identity key pair
 * @param prekeyBundle Partner's prekey bundle
 * @param options Protocol strategy options
 * @returns Key agreement result with shared secret
 * @throws {PQXDHRequiredError} If PQXDH is required but unavailable
 */
export async function performKeyAgreement(
  identityKeyPair: IdentityKeyPair,
  prekeyBundle: PreKeyBundle,
  options: KeyAgreementOptions = {}
): Promise<KeyAgreementResult> {
  const { protocolStrategy, remoteAddress = 'unknown', logger = defaultSignalLogger } = options;
  const infoStrings = resolveKeyExchangeInfoStrings(protocolStrategy?.keyExchangeInfoString);
  validatePreKeyBundle(prekeyBundle);

  if (!bundleHasAnyKemMaterial(prekeyBundle)) {
    if (protocolStrategy?.allowClassicalFallback) {
      logger.warn('Partner lacks KEM prekeys; using explicit X3DH compatibility fallback', {
        category: 'E2EE',
        data: { remoteAddress },
      });

      const x3dhResult = await x3dhKeyAgreement(
        identityKeyPair,
        prekeyBundle,
        infoStrings.x3dh,
        logger
      );

      invokeProtocolCallback(
        protocolStrategy,
        {
          usedPQXDH: false,
          usedTripleRatchet: false,
          usedClassicalFallback: true,
          classicalFallbackReason: 'remote_lacks_kem',
          remoteAddress,
          timestamp: Date.now(),
        },
        logger
      );

      return {
        sharedSecret: x3dhResult.sharedSecret,
        additionalDerivedBytes: x3dhResult.additionalDerivedBytes,
        ephemeralKeyPair: x3dhResult.ephemeralKeyPair,
        usedSignedPreKeyId: x3dhResult.usedSignedPreKeyId,
        usedOneTimePreKeyId: x3dhResult.usedOneTimePreKeyId,
        usedPQXDH: false,
        usedClassicalFallback: true,
      };
    }

    logger.error('Partner lacks KEM prekey required for PQXDH', {
      category: 'E2EE',
      data: { remoteAddress },
    });
    throw new PQXDHRequiredError(remoteAddress, 'no_kyber_prekey');
  }

  try {
    const pqxdhResult = await pqxdhKeyAgreement(
      identityKeyPair,
      prekeyBundle,
      infoStrings.pqxdh,
      logger
    );

    logger.breadcrumb('PQXDH: Post-quantum key agreement complete', {
      category: 'E2EE',
      level: 'info',
      data: { operation: 'pqxdh', pq_contribution: 'ml-kem-1024' },
    });

    invokeProtocolCallback(
      protocolStrategy,
      {
        usedPQXDH: true,
        usedTripleRatchet: true,
        usedClassicalFallback: false,
        remoteAddress,
        timestamp: Date.now(),
      },
      logger
    );

    return {
      sharedSecret: pqxdhResult.sharedSecret,
      additionalDerivedBytes: pqxdhResult.additionalDerivedBytes,
      ephemeralKeyPair: pqxdhResult.ephemeralKeyPair,
      usedSignedPreKeyId: pqxdhResult.usedSignedPreKeyId,
      usedOneTimePreKeyId: pqxdhResult.usedOneTimePreKeyId,
      kyberCiphertext: pqxdhResult.kyberCiphertext,
      usedKyberPreKeyId: pqxdhResult.usedKyberPreKeyId,
      kemOneTimePreKeyCiphertext: pqxdhResult.kemOneTimePreKeyCiphertext,
      usedKemOneTimePreKeyId: pqxdhResult.usedKemOneTimePreKeyId,
      usedPQXDH: true,
      usedClassicalFallback: false,
    };
  } catch (error) {
    const pqxdhError = error instanceof Error ? error : new Error(String(error));
    logger.error('PQXDH failed after KEM material was selected; aborting without fallback', {
      category: 'E2EE',
      data: { error: pqxdhError.message, remoteAddress },
    });
    throw new PQXDHRequiredError(remoteAddress, 'pqxdh_failed', {
      originalError: pqxdhError,
    });
  }
}

/**
 * Helper to invoke protocol selection callback safely
 */
function invokeProtocolCallback(
  config: ProtocolStrategyConfig | undefined,
  event: ProtocolSelectionEvent,
  logger: Required<ILogger>
): void {
  if (config?.onProtocolSelected) {
    try {
      config.onProtocolSelected(event);
    } catch (error) {
      logger.warn('Protocol selection callback failed', {
        category: 'E2EE',
        data: { error: getErrorMessage(error) },
      });
    }
  }
}

/**
 * Perform key agreement as responder (Bob)
 *
 * Requires PQXDH metadata by default and rejects malformed PQXDH metadata.
 * Explicit `allowClassicalFallback` permits X3DH only for X3DH-only
 * PreKeyMessages with no KEM metadata at all.
 *
 * @param identityKeyPair Our identity key pair
 * @param signedPreKey Our signed prekey that Alice used
 * @param oneTimePreKey Our one-time prekey that Alice used (if any)
 * @param kyberPreKey Our Kyber prekey that Alice used (if any)
 * @param prekeyMessage Alice's PreKeyMessage
 * @param aliceIdentityKey Alice's identity key
 * @param aliceEphemeralKey Alice's ephemeral key
 * @param options Protocol strategy options
 * @returns Key agreement result with shared secret
 * @throws {PQXDHRequiredError} If PQXDH is required but fails
 */
export async function performResponderKeyAgreement(
  identityKeyPair: IdentityKeyPair,
  signedPreKey: EcSignedPreKey,
  oneTimePreKey: EcOneTimePreKey | null,
  kyberPreKey: KyberPreKey | null,
  kemOneTimePreKey: KemOneTimePreKey | null,
  prekeyMessage: PreKeyMessage,
  aliceIdentityKey: PublicKey,
  aliceEphemeralKey: PublicKey,
  options: KeyAgreementOptions = {}
): Promise<ResponderKeyAgreementResult> {
  const { protocolStrategy, remoteAddress = 'unknown', logger = defaultSignalLogger } = options;
  const infoStrings = resolveKeyExchangeInfoStrings(protocolStrategy?.keyExchangeInfoString);

  // Build base X3DH responder input
  const x3dhInput = buildX3DHResponderInput(prekeyMessage, aliceIdentityKey, aliceEphemeralKey);

  // Try PQXDH when any KEM ciphertext is present.
  // Per PQXDH spec: exactly one KEM mode per session (one-time OR last-resort).
  // Validate each metadata pair independently to reject malformed/ambiguous messages.
  const hasLastResortId = prekeyMessage.usedKyberPreKeyId !== undefined;
  const hasLastResortCiphertext = !!prekeyMessage.kyberCiphertext;
  const hasOneTimeId = prekeyMessage.usedKemOneTimePreKeyId !== undefined;
  const hasOneTimeCiphertext = !!prekeyMessage.kemOneTimePreKeyCiphertext;

  if (hasLastResortId !== hasLastResortCiphertext) {
    logger.error('PreKeyMessage has incomplete Kyber metadata', {
      category: 'E2EE',
      data: {
        remoteAddress,
        mode: 'last-resort',
        hasPreKeyId: hasLastResortId,
        hasCiphertext: hasLastResortCiphertext,
      },
    });
    throw new EncryptionError(
      'Invalid PreKeyMessage: incomplete Kyber metadata',
      EncryptionErrorCode.INVALID_CIPHERTEXT,
      { operation: 'performResponderKeyAgreement', remoteAddress }
    );
  }

  if (hasOneTimeId !== hasOneTimeCiphertext) {
    logger.error('PreKeyMessage has incomplete Kyber metadata', {
      category: 'E2EE',
      data: {
        remoteAddress,
        mode: 'one-time',
        hasPreKeyId: hasOneTimeId,
        hasCiphertext: hasOneTimeCiphertext,
      },
    });
    throw new EncryptionError(
      'Invalid PreKeyMessage: incomplete Kyber metadata',
      EncryptionErrorCode.INVALID_CIPHERTEXT,
      { operation: 'performResponderKeyAgreement', remoteAddress }
    );
  }

  const hasLastResortMetadata = hasLastResortId && hasLastResortCiphertext;
  const hasOneTimeMetadata = hasOneTimeId && hasOneTimeCiphertext;

  if (hasLastResortMetadata && hasOneTimeMetadata) {
    logger.error('PreKeyMessage has ambiguous Kyber metadata (both KEM modes present)', {
      category: 'E2EE',
      data: { remoteAddress },
    });
    throw new EncryptionError(
      'Invalid PreKeyMessage: ambiguous Kyber metadata',
      EncryptionErrorCode.INVALID_CIPHERTEXT,
      { operation: 'performResponderKeyAgreement', remoteAddress }
    );
  }

  const hasAnyKyberMetadata = hasLastResortMetadata || hasOneTimeMetadata;

  if (hasAnyKyberMetadata) {
    // If PQ metadata is present, process as PQXDH only (no downgrade to X3DH).
    if (hasLastResortMetadata && !kyberPreKey) {
      logger.error('Kyber prekey not found for PQXDH message', {
        category: 'E2EE',
        data: { kyberPreKeyId: prekeyMessage.usedKyberPreKeyId, remoteAddress },
      });
      throw new PQXDHRequiredError(remoteAddress, 'no_kyber_prekey');
    }
    if (hasOneTimeMetadata && !kemOneTimePreKey) {
      logger.error('KEM one-time prekey not found for PQXDH message', {
        category: 'E2EE',
        data: { kemOneTimePreKeyId: prekeyMessage.usedKemOneTimePreKeyId, remoteAddress },
      });
      throw new PQXDHRequiredError(remoteAddress, 'no_kyber_prekey');
    }

    try {
      const pqxdhInput: PQXDHResponderInput = {
        ...x3dhInput,
        kyberCiphertext: prekeyMessage.kyberCiphertext,
        usedKyberPreKeyId: prekeyMessage.usedKyberPreKeyId,
        kemOneTimePreKeyCiphertext: prekeyMessage.kemOneTimePreKeyCiphertext,
        usedKemOneTimePreKeyId: prekeyMessage.usedKemOneTimePreKeyId,
      };

      const pqxdhResult = await pqxdhResponderKeyAgreement(
        identityKeyPair,
        signedPreKey,
        oneTimePreKey,
        kyberPreKey, // May be null when using one-time path
        kemOneTimePreKey,
        pqxdhInput,
        infoStrings.pqxdh,
        logger
      );

      logger.breadcrumb('PQXDH responder key agreement completed', {
        category: 'E2EE',
        level: 'info',
        data: { operation: 'pqxdh', role: 'responder', pq_contribution: 'ml-kem-1024' },
      });

      // Invoke protocol selection callback
      invokeProtocolCallback(
        protocolStrategy,
        {
          usedPQXDH: true,
          usedTripleRatchet: true,
          usedClassicalFallback: false,
          remoteAddress,
          timestamp: Date.now(),
        },
        logger
      );

      return {
        sharedSecret: pqxdhResult.sharedSecret,
        additionalDerivedBytes: pqxdhResult.additionalDerivedBytes,
        usedPQXDH: pqxdhResult.usedPQXDH,
        usedClassicalFallback: false,
      };
    } catch (error) {
      const pqxdhError = error instanceof Error ? error : new Error(String(error));
      logger.error(
        'PQXDH responder failed after KEM metadata was selected; aborting without fallback',
        {
          category: 'E2EE',
          data: { error: pqxdhError.message, remoteAddress },
        }
      );
      throw new PQXDHRequiredError(remoteAddress, 'pqxdh_failed', {
        originalError: pqxdhError,
      });
    }
  }

  if (protocolStrategy?.allowClassicalFallback) {
    logger.warn('PreKeyMessage has no KEM metadata; using explicit X3DH compatibility fallback', {
      category: 'E2EE',
      data: { remoteAddress },
    });

    const x3dhResult = await x3dhResponderKeyAgreement(
      identityKeyPair,
      signedPreKey,
      oneTimePreKey,
      x3dhInput,
      infoStrings.x3dh,
      logger
    );

    invokeProtocolCallback(
      protocolStrategy,
      {
        usedPQXDH: false,
        usedTripleRatchet: false,
        usedClassicalFallback: true,
        classicalFallbackReason: 'remote_lacks_kem',
        remoteAddress,
        timestamp: Date.now(),
      },
      logger
    );

    return {
      sharedSecret: x3dhResult.sharedSecret,
      additionalDerivedBytes: x3dhResult.additionalDerivedBytes,
      usedPQXDH: false,
      usedClassicalFallback: true,
    };
  }

  logger.error('PreKeyMessage missing KEM metadata required for PQXDH', {
    category: 'E2EE',
    data: { remoteAddress },
  });
  throw new PQXDHRequiredError(remoteAddress, 'no_kyber_prekey');
}
