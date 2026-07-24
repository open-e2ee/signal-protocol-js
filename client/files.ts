/**
 * File encryption/decryption operations for SignalProtocolClient
 *
 * Extracted from SignalProtocolClient class to reduce file size.
 * Uses two-layer encryption: AES-GCM for files, Signal Protocol for key exchange.
 */

import * as CryptoUtils from '../internal/crypto';
import type { Ciphertext } from '../keys';
import { EncryptionError, EncryptionErrorCode, asBase64 } from '../types';
import { ProtocolAddress } from '../types/address';
import { callHook } from './event-hooks';
import type { SignalProtocolClientContext } from './types';

/**
 * Encrypt file blob with two-layer encryption
 *
 * Layer 1: Random symmetric key encrypts the file
 * Layer 2: Signal Protocol encrypts the symmetric key
 *
 * This allows efficient storage of large files with Signal Protocol key rotation.
 *
 * @param ctx - Client context with dependencies
 * @param remoteAddress - Remote party's protocol address (userId:deviceId)
 * @param fileBlob - File data to encrypt
 * @param mimeType - Optional MIME type (defaults to fileBlob.type)
 * @returns Encrypted blob, key ID, and encrypted key
 */
export {};
export async function encryptFile(
  ctx: SignalProtocolClientContext,
  remoteAddress: ProtocolAddress,
  fileBlob: Blob,
  mimeType?: string
): Promise<{
  encryptedBlob: Blob;
  keyId: string;
  encryptedKey: Ciphertext;
}> {
  const sessionId = ProtocolAddress.toString(remoteAddress);
  // Generate random symmetric key for file OUTSIDE try block
  // so we can best-effort overwrite the owned bytes in finally.
  const fileKey = await CryptoUtils.generateRandomBytes(32);

  try {
    const keyId = CryptoUtils.bytesToBase64(await CryptoUtils.generateRandomBytes(16));

    // Read file data
    const fileData = await fileBlob.arrayBuffer();
    const fileBytes = new Uint8Array(fileData);

    // Encrypt file with AES-GCM
    const encrypted = await CryptoUtils.aesGcmEncrypt(fileKey, fileBytes);

    // Store encrypted data as JSON string in Blob
    const encryptedDataString = JSON.stringify(encrypted);
    const encryptedBlob = new Blob([encryptedDataString], { type: 'application/json' });

    // Encrypt the symmetric key with Signal Protocol
    // Include MIME type in encrypted metadata for proper decryption
    const keyMetadata = JSON.stringify({
      key: CryptoUtils.bytesToBase64(fileKey),
      mimeType: mimeType || fileBlob.type || 'application/octet-stream',
      version: 1,
    });
    const encryptedKey = await ctx.manager.encrypt(remoteAddress, keyMetadata);

    return { encryptedBlob, keyId, encryptedKey };
  } catch (error) {
    // Call hook: encryption error
    await callHook(ctx.hooks, 'onEncryptionError', sessionId, error as Error);

    // Preserve EncryptionError codes
    if (error instanceof EncryptionError) {
      throw error;
    }

    throw new EncryptionError(
      `Failed to encrypt file for session ${sessionId}`,
      EncryptionErrorCode.ENCRYPTION_FAILED,
      { originalError: error as Error }
    );
  } finally {
    // Best-effort overwrite owned key bytes, including on error.
    // This prevents crypto key material from remaining in memory after failures
    CryptoUtils.secureZeroBytes(fileKey);
  }
}

/**
 * Decrypt file blob
 *
 * @param ctx - Client context with dependencies
 * @param remoteAddress - Remote party's protocol address (userId:deviceId)
 * @param encryptedBlob - Encrypted file data
 * @param encryptedKey - Encrypted symmetric key
 * @returns Decrypted file blob with correct MIME type
 */
export async function decryptFile(
  ctx: SignalProtocolClientContext,
  remoteAddress: ProtocolAddress,
  encryptedBlob: Blob,
  encryptedKey: Ciphertext
): Promise<Blob> {
  const sessionId = ProtocolAddress.toString(remoteAddress);
  // Track fileKey outside try block so we can zero it in finally
  let fileKey: Uint8Array | undefined;

  try {
    // Decrypt the symmetric key with Signal Protocol
    const keyMetadataStr = await ctx.manager.decrypt(remoteAddress, encryptedKey);

    // Validate JSON structure before using
    let keyMetadata: { key: string; mimeType?: string; version?: number };
    try {
      const parsed = JSON.parse(keyMetadataStr);
      // Validate required fields
      if (typeof parsed?.key !== 'string') {
        throw new Error('Invalid key metadata: missing or invalid "key" field');
      }
      keyMetadata = parsed;
    } catch (parseError) {
      throw new EncryptionError(
        'Invalid file key metadata format',
        EncryptionErrorCode.DECRYPTION_FAILED,
        { originalError: parseError as Error }
      );
    }

    fileKey = CryptoUtils.base64ToBytes(asBase64(keyMetadata.key));

    // Read encrypted file data (stored as JSON)
    const encryptedDataString = await encryptedBlob.text();

    // Validate encrypted data structure
    let encrypted: { ciphertext: string; iv: string; authTag: string };
    try {
      const parsed = JSON.parse(encryptedDataString);
      if (
        typeof parsed?.ciphertext !== 'string' ||
        typeof parsed?.iv !== 'string' ||
        typeof parsed?.authTag !== 'string'
      ) {
        throw new Error('Invalid encrypted data: missing required fields');
      }
      encrypted = parsed;
    } catch (parseError) {
      throw new EncryptionError(
        'Invalid encrypted file data format',
        EncryptionErrorCode.DECRYPTION_FAILED,
        { originalError: parseError as Error }
      );
    }

    // Decrypt file with AES-GCM
    const fileBytes = await CryptoUtils.aesGcmDecrypt(
      fileKey,
      asBase64(encrypted.ciphertext),
      asBase64(encrypted.iv),
      asBase64(encrypted.authTag)
    );

    // Convert Uint8Array to Blob with correct MIME type from encrypted metadata
    // Use ArrayBuffer slice to satisfy TypeScript's strict BlobPart types
    // (Uint8Array.buffer may be larger than the view, so we slice to exact bounds)
    // Cast needed because .slice() returns ArrayBufferLike which includes SharedArrayBuffer
    const finalMimeType = keyMetadata.mimeType || 'application/octet-stream';
    const arrayBuffer = fileBytes.buffer.slice(
      fileBytes.byteOffset,
      fileBytes.byteOffset + fileBytes.byteLength
    ) as ArrayBuffer;
    return new Blob([arrayBuffer], { type: finalMimeType });
  } catch (error) {
    // Call hook: decryption error
    await callHook(ctx.hooks, 'onDecryptionError', sessionId, error as Error);

    // Re-throw if already an EncryptionError (from validation above)
    if (error instanceof EncryptionError) {
      throw error;
    }

    throw new EncryptionError(
      `Failed to decrypt file for session ${sessionId}`,
      EncryptionErrorCode.DECRYPTION_FAILED,
      { originalError: error as Error }
    );
  } finally {
    // Best-effort overwrite owned key bytes, including on error.
    if (fileKey) {
      CryptoUtils.secureZeroBytes(fileKey);
    }
  }
}

/**
 * Encrypt multiple files in batch
 *
 * More efficient than calling encryptFile() multiple times.
 * Each file gets its own encryption key for granular access control.
 *
 * @param ctx - Client context with dependencies
 * @param remoteAddress - Remote party's protocol address (userId:deviceId)
 * @param files - Array of file blobs with optional MIME types
 * @returns Array of encrypted file results in the same order
 */
export async function encryptFiles(
  ctx: SignalProtocolClientContext,
  remoteAddress: ProtocolAddress,
  files: Array<{ blob: Blob; mimeType?: string }>
): Promise<
  Array<{
    encryptedBlob: Blob;
    keyId: string;
    encryptedKey: Ciphertext;
  }>
> {
  if (files.length === 0) {
    return [];
  }

  const sessionId = ProtocolAddress.toString(remoteAddress);
  const results: Array<{
    encryptedBlob: Blob;
    keyId: string;
    encryptedKey: Ciphertext;
  }> = [];

  try {
    // Encrypt each file
    for (const file of files) {
      const result = await encryptFile(ctx, remoteAddress, file.blob, file.mimeType);
      results.push(result);
    }

    return results;
  } catch (error) {
    // Call hook: encryption error
    await callHook(ctx.hooks, 'onEncryptionError', sessionId, error as Error);

    // Preserve EncryptionError codes
    if (error instanceof EncryptionError) {
      throw error;
    }

    throw new EncryptionError(
      `Failed to encrypt batch of ${files.length} files for session ${sessionId}`,
      EncryptionErrorCode.ENCRYPTION_FAILED,
      { originalError: error as Error }
    );
  }
}

/**
 * Decrypt multiple files in batch
 *
 * More efficient than calling decryptFile() multiple times.
 *
 * @param ctx - Client context with dependencies
 * @param remoteAddress - Remote party's protocol address (userId:deviceId)
 * @param files - Array of encrypted file data
 * @returns Array of decrypted file blobs in the same order
 */
export async function decryptFiles(
  ctx: SignalProtocolClientContext,
  remoteAddress: ProtocolAddress,
  files: Array<{
    encryptedBlob: Blob;
    encryptedKey: Ciphertext;
  }>
): Promise<Blob[]> {
  if (files.length === 0) {
    return [];
  }

  const sessionId = ProtocolAddress.toString(remoteAddress);
  const results: Blob[] = [];

  try {
    // Decrypt each file
    for (const file of files) {
      const result = await decryptFile(ctx, remoteAddress, file.encryptedBlob, file.encryptedKey);
      results.push(result);
    }

    return results;
  } catch (error) {
    // Call hook: decryption error
    await callHook(ctx.hooks, 'onDecryptionError', sessionId, error as Error);

    // Preserve EncryptionError codes (e.g., PREKEY_NOT_FOUND triggers key rotation)
    if (error instanceof EncryptionError) {
      throw error;
    }

    throw new EncryptionError(
      `Failed to decrypt batch of ${files.length} files for session ${sessionId}`,
      EncryptionErrorCode.DECRYPTION_FAILED,
      { originalError: error as Error }
    );
  }
}
