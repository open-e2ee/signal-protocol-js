/**
 * Handshake - PQXDH Key Agreement
 *
 * Handles the cryptographic key agreement phase of the Signal Protocol.
 * This module runs the PQXDH (Post-Quantum Extended Diffie-Hellman)
 * handshake to derive shared secrets. Every new session requires PQXDH. A
 * peer bundle or PreKeyMessage without ML-KEM material is refused.
 *
 * establish.ts calls this module for key agreement before it creates a session.
 *
 * @see https://signal.org/docs/specifications/pqxdh/
 */

import { defaultSignalProtocolLogger, type Logger } from '../../logger';
import { getErrorMessage } from '../../utils/errors';
import {
  performPQXDH as pqxdhKeyAgreement,
  performPQXDHResponder as pqxdhResponderKeyAgreement,
} from '../protocol/pqxdh';
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
  logger?: Required<Logger>;
}

/**
 * Build the PQXDH responder input from a PreKeyMessage.
 * Centralizes the construction to avoid duplication.
 */
export function buildPqxdhResponderInput(
  prekeyMessage: PreKeyMessage,
  senderIdentityKey: PublicKey,
  senderEphemeralKey: PublicKey
): PQXDHResponderInput {
  return {
    senderIdentityKey,
    senderEphemeralKey,
    usedSignedPreKeyId: prekeyMessage.usedSignedPreKeyId!,
    usedOneTimePreKeyId: prekeyMessage.usedOneTimePreKeyId,
    kyberCiphertext: prekeyMessage.kyberCiphertext,
    usedKyberPreKeyId: prekeyMessage.usedKyberPreKeyId,
    kemOneTimePreKeyCiphertext: prekeyMessage.kemOneTimePreKeyCiphertext,
    usedKemOneTimePreKeyId: prekeyMessage.usedKemOneTimePreKeyId,
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
 * Run the key agreement as initiator (Alice)
 *
 * ORCHESTRATION LAYER: Requires PQXDH for session establishment. A peer
 * bundle without KEM material is refused, and a PQXDH failure aborts the
 * session.
 *
 * @param identityKeyPair Our identity key pair
 * @param prekeyBundle Partner's prekey bundle
 * @param options Protocol strategy options
 * @returns Key agreement result with shared secret
 * @throws {PQXDHRequiredError} If the bundle has no KEM prekey or PQXDH fails
 */
export async function performKeyAgreement(
  identityKeyPair: IdentityKeyPair,
  prekeyBundle: PreKeyBundle,
  options: KeyAgreementOptions = {}
): Promise<KeyAgreementResult> {
  const { protocolStrategy, remoteAddress = 'unknown', logger = defaultSignalProtocolLogger } = options;
  const infoStrings = resolveKeyExchangeInfoStrings(protocolStrategy?.keyExchangeInfoString);
  validatePreKeyBundle(prekeyBundle);

  if (!bundleHasAnyKemMaterial(prekeyBundle)) {
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
  logger: Required<Logger>
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
 * Run the key agreement as responder (Bob)
 *
 * Requires PQXDH metadata and rejects malformed PQXDH metadata. A
 * PreKeyMessage without KEM metadata is refused.
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
 * @throws {PQXDHRequiredError} If the KEM metadata or prekey is missing, or PQXDH fails
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
  const { protocolStrategy, remoteAddress = 'unknown', logger = defaultSignalProtocolLogger } = options;
  const infoStrings = resolveKeyExchangeInfoStrings(protocolStrategy?.keyExchangeInfoString);

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
      const pqxdhInput = buildPqxdhResponderInput(
        prekeyMessage,
        aliceIdentityKey,
        aliceEphemeralKey
      );

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
          remoteAddress,
          timestamp: Date.now(),
        },
        logger
      );

      return {
        sharedSecret: pqxdhResult.sharedSecret,
        additionalDerivedBytes: pqxdhResult.additionalDerivedBytes,
        usedPQXDH: pqxdhResult.usedPQXDH,
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

  logger.error('PreKeyMessage missing KEM metadata required for PQXDH', {
    category: 'E2EE',
    data: { remoteAddress },
  });
  throw new PQXDHRequiredError(remoteAddress, 'no_kyber_prekey');
}
