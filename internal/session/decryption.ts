/**
 * Decryption utilities for Signal Protocol
 *
 * @module session/decryption
 *
 * Internal helpers for SessionCipher decryption operations.
 * Extracted from cipher.ts to reduce file size.
 *
 * These functions handle:
 * - Skipped message key lookup (out-of-order messages)
 * - Message body decryption with AES-CBC + HMAC-SHA256
 * - Identity-bound MAC verification (Section 3 variant)
 *
 * @see https://signal.org/docs/specifications/doubleratchet/#decrypting-messages
 */

import { defaultSignalProtocolLogger, type ILogger } from '../../logger';
import type { PreKeyMessage, RatchetMessage, SessionState } from '../../types';
import { EncryptionError, EncryptionErrorCode } from '../../types';
import * as CryptoUtils from '../crypto';
import { asBase64 } from '../../types/utils';
import { deriveSPQRReceiveKey, tryGetSkippedSPQRKey } from '../protocol/spqr';
import {
  decodeSPQRWire,
  signalProtocolMessageAddressesEqual,
  spqrWireEpochToInternalEpoch,
} from '../encoding/proto';
import { tryGetSkippedKey } from '../protocol/double-ratchet/chains';
import { deriveIdentityCommitment } from '../../keys/identity';
import { verifyCompositeIdentityMessageMac } from './identity-binding';

export interface ProtobufMacContext {
  readonly serializedForMac: Uint8Array;
  readonly mac: Uint8Array;
  readonly addresses: Uint8Array;
}

/**
 * Build the protobuf MAC context from a framed SignalProtocolMessage envelope.
 *
 * The session cipher parses envelope shape, but decryption owns the exact bytes
 * that are authenticated. Keeping this construction here prevents call sites
 * from hand-assembling partial authentication context.
 */
export function createProtobufMacContext(
  framedMessage: Uint8Array,
  envelopeMac: Uint8Array,
  addresses: Uint8Array
): ProtobufMacContext {
  if (envelopeMac.length === 0 || framedMessage.length <= envelopeMac.length) {
    throw new EncryptionError(
      'Invalid protobuf SignalProtocolMessage envelope for MAC context',
      EncryptionErrorCode.INVALID_CIPHERTEXT,
      {
        framedLength: framedMessage.length,
        macLength: envelopeMac.length,
      }
    );
  }

  if (addresses.length === 0) {
    throw new EncryptionError(
      'SignalProtocolMessage address binding is required for MAC context',
      EncryptionErrorCode.INVALID_CIPHERTEXT
    );
  }

  return {
    serializedForMac: framedMessage.slice(0, framedMessage.length - envelopeMac.length),
    mac: envelopeMac.slice(),
    addresses: addresses.slice(),
  };
}

// ============================================================================
// Replay detection work equalization (best effort)
// ============================================================================

/**
 * Perform best-effort dummy work before rejecting a detected replay.
 *
 * This reduces gross source-path differences, but randomness, WebCrypto,
 * scheduling, and the JIT prevent timing equivalence or constant-time claims.
 */
export {};
export async function performReplayRejectionWork(): Promise<void> {
  // Generate random data for dummy operation
  const dummyKey = await CryptoUtils.generateRandomBytes(32);
  const dummyData = await CryptoUtils.generateRandomBytes(32);
  const dummyIV = await CryptoUtils.generateRandomBytes(16);

  // Perform actual AES-CBC operation to match real decrypt timing (~1ms).
  // Using AES-CBC (not AES-GCM) because real message decryption uses AES-CBC-HMAC,
  // and timing must match to prevent distinguishing rejections from real decrypts.
  try {
    await CryptoUtils.aesCbcEncrypt(dummyKey, dummyData, dummyIV);
  } catch {
    // Expected to fail - we're just burning CPU time
  }

  // Best-effort overwrite of owned temporary arrays.
  CryptoUtils.secureZeroBytes(dummyKey);
  CryptoUtils.secureZeroBytes(dummyData);
  CryptoUtils.secureZeroBytes(dummyIV);
}

/**
 * Try to decrypt message with skipped message keys
 *
 * Implements Signal Protocol Section 3.5 - TrySkippedMessageKeys().
 * Checks stored skipped message keys (receiverChains)
 * indexed by (ratchetKey, counter) to see if any matches the message.
 * Used for handling out-of-order messages.
 *
 * @param session - Current session state containing receiverChains
 * @param ratchetKey - Sender's ratchet public key from message
 * @param counter - Message counter from plaintext header
 * @param message - The full message to decrypt if key is found
 * @returns Decrypted plaintext or null if no skipped key matches
 *
 * An early return after a successful key lookup does not depend on secret
 * comparison work; MAC verification remains the timing-sensitive path.
 *
 * @internal
 * @see https://signal.org/docs/specifications/doubleratchet/#handling-missing-messages
 */
export async function trySkippedMessageKeys(
  session: SessionState,
  ratchetKey: string,
  counter: number,
  message: RatchetMessage | PreKeyMessage,
  protobufMacContext?: ProtobufMacContext,
  pqRatchetBytes?: Uint8Array,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): Promise<string | null> {
  // Use tryGetSkippedKey which handles both v3 receiverChains and legacy MKSKIPPED
  // Cast session to DoubleRatchetState since tryGetSkippedKey expects that interface
  const messageKeyBytes = tryGetSkippedKey(
    session as Parameters<typeof tryGetSkippedKey>[0],
    asBase64(ratchetKey),
    counter,
    logger
  );

  if (!messageKeyBytes) {
    // No skipped key found for this (ratchetKey, counter) combination
    return null;
  }

  logger.debug('Found skipped message key', {
    category: 'E2EE',
    data: {
      operation: 'skipped-key-found',
      counter,
      ratchetKeyPrefix: ratchetKey.substring(0, 20),
    },
  });

  const finalMessageKeyBytes = messageKeyBytes;
  let pqMessageKeySalt: Uint8Array | undefined;

  // Triple Ratchet: If enabled, combine EC key with PQ key
  // The stored key is EC-only, but Alice encrypted with combined key
  // Decode SPQR epoch/messageNumber from opaque pqRatchet bytes (without advancing the main chain)
  if (session.tripleRatchet?.enabled && session.tripleRatchet.spqrState && pqRatchetBytes?.length) {
    const pqr = decodeSPQRWire(pqRatchetBytes);
    const spqrEpoch = pqr.epoch === undefined ? undefined : spqrWireEpochToInternalEpoch(pqr.epoch);
    const spqrMessageNumber = pqr.chainIndex;

    if (spqrEpoch !== undefined && spqrMessageNumber !== undefined && spqrMessageNumber >= 1) {
      logger.debug('Triple Ratchet: Combining skipped EC key with PQ key', {
        category: 'E2EE',
        data: {
          operation: 'skipped-key-triple-ratchet',
          spqrEpoch,
          spqrMessageNumber,
        },
      });

      // First try to get the PQ key from SPQR's skipped keys
      // (for out-of-order messages where SPQR chain has already advanced)
      let pqMessageKey = await tryGetSkippedSPQRKey(
        session.tripleRatchet.spqrState,
        spqrEpoch,
        spqrMessageNumber
      );

      // If not found in skipped keys, derive from current SPQR state.
      if (!pqMessageKey) {
        pqMessageKey = await deriveSPQRReceiveKey(
          session.tripleRatchet.spqrState,
          spqrMessageNumber,
          spqrEpoch,
          logger
        );
      }

      // If we have a PQ key, pass it as optional salt to
      // expandMessageKey.
      if (pqMessageKey) {
        pqMessageKeySalt = pqMessageKey;
      }
    }
    // No epoch/messageNumber: bootstrap SPQR metadata has no derived PQ key yet.
  }

  let plaintext: string;
  try {
    // Decrypt with the found key
    plaintext = await decryptWithKey(
      finalMessageKeyBytes,
      message as RatchetMessage,
      session,
      protobufMacContext,
      pqMessageKeySalt,
      logger
    );
  } finally {
    // Best-effort overwrite owned message-key bytes.
    CryptoUtils.secureZeroBytes(finalMessageKeyBytes);
    if (pqMessageKeySalt) {
      CryptoUtils.secureZeroBytes(pqMessageKeySalt);
      pqMessageKeySalt = undefined;
    }
  }

  // Note: tryGetSkippedKey already deleted the key from storage (one-time use)

  return plaintext;
}

/**
 * Decrypt message body with a specific message key
 *
 * Performs identity-bound MAC verification, then AES-256-CBC decryption.
 * The message key is expanded to 80 bytes (32 enc + 32 auth + 16 IV)
 * before use.
 *
 * Identity-bound MAC includes:
 * - MESSAGE_VERSION_BYTE
 * - Sender identity key
 * - Receiver identity key
 * - Serialized header (protobuf format)
 * - Ciphertext
 *
 * @param messageKey - 32-byte message key for this specific message
 * @param message - RatchetMessage containing ciphertext, MAC, and header
 * @param session - Session state containing identity keys for MAC verification
 * @param optionalPqSalt - Optional PQ message key salt for Triple Ratchet V1 mode
 * @returns Decrypted plaintext string
 * @throws {EncryptionError} If MAC verification fails or decryption fails
 *
 * @internal
 */
export async function decryptWithKey(
  messageKey: Uint8Array,
  message: RatchetMessage,
  session: SessionState,
  protobufMacContext?: ProtobufMacContext,
  optionalPqSalt?: Uint8Array,
  logger: Required<ILogger> = defaultSignalProtocolLogger
): Promise<string> {
  const { encryptionKey, authKey, iv } = await CryptoUtils.expandMessageKey(
    messageKey,
    optionalPqSalt
  );

  try {
    // Verify identity-bound MAC (Section 3 variant)
    // Per Signal Protocol Section 3 - "associated_data SHOULD contain sender's and receiver's identity public keys"
    let macValid: boolean;
    if (protobufMacContext) {
      macValid = verifyCompositeIdentityMessageMac(
        authKey,
        session.remoteIdentity,
        session.localIdentity,
        protobufMacContext.serializedForMac,
        protobufMacContext.mac
      );
    } else {
      // Alpha profile break: retained only for internal unit callers,
      // using the same composite commitment authority as protobuf messages.
      const serializedHeader = CryptoUtils.serializeHeader(
        message.ratchetKey,
        message.previousCounter,
        message.counter
      );
      const ciphertextBytes = CryptoUtils.base64ToBytes(message.ciphertext);
      macValid = verifyCompositeIdentityMessageMac(
        authKey,
        session.remoteIdentity,
        session.localIdentity,
        CryptoUtils.concatBytes(serializedHeader, ciphertextBytes),
        CryptoUtils.base64ToBytes(message.mac)
      );
    }

    if (!macValid) {
      // Log diagnostic data at WARN level (not ERROR) because:
      // - For implicit messages (typing indicators, receipts), this is expected and will be discarded
      // - For real messages, handleDecryptionError will log at ERROR level after this
      // This prevents ERROR log spam for ephemeral messages that can't be decrypted
      logger.warn('MAC verification failed - diagnostic data', {
        category: 'E2EE',
        data: {
          operation: 'decrypt',
          counter: message.counter,
          wireFormat: protobufMacContext ? 'protobuf' : 'json',
          // Key fingerprints for correlation (first 20 chars of base64)
          senderIdentityKeyFingerprint: CryptoUtils.bytesToBase64(
            deriveIdentityCommitment(session.remoteIdentity)
          ).substring(
            0,
            20
          ),
          receiverIdentityKeyFingerprint: CryptoUtils.bytesToBase64(
            deriveIdentityCommitment(session.localIdentity)
          ).substring(
            0,
            20
          ),
          // Data sizes for sanity check
          macContextLength: protobufMacContext?.serializedForMac.length,
          macLength:
            protobufMacContext?.mac.length ?? CryptoUtils.base64ToBytes(message.mac).length,
          // Ratchet public key (helps identify session state)
          ratchetKeyFingerprint: message.ratchetKey.substring(0, 20),
          previousCounter: message.previousCounter,
        },
      });
      throw new EncryptionError(
        'Message authentication failed - MAC mismatch',
        EncryptionErrorCode.DECRYPTION_FAILED,
        { operation: 'decryptWithKey' }
      );
    }

    if (protobufMacContext) {
      let addressesValid = false;
      try {
        addressesValid = signalProtocolMessageAddressesEqual(
          protobufMacContext.addresses,
          session.remoteAddress,
          session.localAddress
        );
      } catch (error) {
        logger.warn('SignalProtocolMessage address binding decode failed', {
          category: 'E2EE',
          data: {
            operation: 'decrypt',
            error: error instanceof Error ? error.message : String(error),
            remoteAddress: `${session.remoteAddress.userId}:${session.remoteAddress.deviceId}`,
            localAddress: `${session.localAddress.userId}:${session.localAddress.deviceId}`,
          },
        });
      }

      if (!addressesValid) {
        logger.warn('SignalProtocolMessage address binding mismatch', {
          category: 'E2EE',
          data: {
            operation: 'decrypt',
            remoteAddress: `${session.remoteAddress.userId}:${session.remoteAddress.deviceId}`,
            localAddress: `${session.localAddress.userId}:${session.localAddress.deviceId}`,
          },
        });
        throw new EncryptionError(
          'Message authentication failed - address binding mismatch',
          EncryptionErrorCode.DECRYPTION_FAILED,
          { operation: 'decryptWithKey' }
        );
      }
    }

    // Decrypt message body with AES-CBC
    // Note: MAC was already verified above (identity-bound MAC), so use simple AES-CBC decrypt
    const paddedPlaintext = await CryptoUtils.aesCbcDecrypt(encryptionKey, iv, message.ciphertext);

    // Remove ISO/IEC 7816-4 padding.
    const plaintextBytes = CryptoUtils.unpadMessage(paddedPlaintext);

    return CryptoUtils.bytesToString(plaintextBytes);
  } finally {
    CryptoUtils.secureZeroBytes(encryptionKey);
    CryptoUtils.secureZeroBytes(authKey);
    CryptoUtils.secureZeroBytes(iv);
  }
}
