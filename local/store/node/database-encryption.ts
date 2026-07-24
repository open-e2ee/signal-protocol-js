/**
 * Database Encryption for Node.js
 *
 * Provides AES-256-GCM encryption/decryption for database records using node:crypto.
 * Compatible with Web Crypto API encryption used in Expo/React Native.
 *
 * Encryption Spec:
 * - Algorithm: AES-256-GCM (AEAD)
 * - Key Size: 256 bits (32 bytes)
 * - IV Size: 96 bits (12 bytes) - recommended for GCM
 * - Auth Tag: 128 bits (16 bytes)
 * - Format: Base64-encoded strings for storage
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { EncryptionError, EncryptionErrorCode } from '../../../types';

/**
 * AES-256-GCM algorithm
 */
export {};
const AES_ALGORITHM = 'aes-256-gcm';

/**
 * AES key size (256 bits)
 */
const AES_KEY_SIZE = 32; // bytes

/**
 * IV size (96 bits, recommended for GCM)
 */
const IV_SIZE = 12; // bytes

/**
 * Authentication tag size (128 bits)
 */
const AUTH_TAG_SIZE = 16; // bytes

/**
 * Encrypted record structure
 *
 * Returned by encryptRecord(), stored in filesystem.
 */
export interface EncryptedRecord {
  encrypted_data: string; // Base64-encoded ciphertext
  iv: string; // Base64-encoded initialization vector
  auth_tag: string; // Base64-encoded authentication tag
}

/**
 * Encrypt a record for storage
 *
 * Serializes the record to JSON, encrypts with AES-256-GCM, and returns
 * the encrypted data with IV and authentication tag.
 *
 * @param plaintext - Object to encrypt (will be JSON.stringify'd)
 * @param dbKey - 32-byte database encryption key
 * @returns Encrypted record with data, IV, and auth tag
 * @throws EncryptionError if encryption fails
 */
export function encryptRecord(plaintext: unknown, dbKey: Uint8Array): EncryptedRecord {
  try {
    // Validate database key
    if (dbKey.length !== AES_KEY_SIZE) {
      throw new Error(
        `Invalid database key size: expected ${AES_KEY_SIZE} bytes, got ${dbKey.length}`
      );
    }

    // Serialize plaintext to JSON
    const plaintextJson = JSON.stringify(plaintext);

    // Generate unique IV for this record
    const iv = randomBytes(IV_SIZE);

    // Create cipher
    const cipher = createCipheriv(AES_ALGORITHM, Buffer.from(dbKey), iv);

    // Encrypt data
    const encrypted = Buffer.concat([cipher.update(plaintextJson, 'utf8'), cipher.final()]);

    // Get authentication tag
    const authTag = cipher.getAuthTag();

    // Validate auth tag size
    if (authTag.length !== AUTH_TAG_SIZE) {
      throw new Error(
        `Invalid auth tag size: expected ${AUTH_TAG_SIZE} bytes, got ${authTag.length}`
      );
    }

    // Return Base64-encoded result
    return {
      encrypted_data: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      auth_tag: authTag.toString('base64'),
    };
  } catch (error) {
    throw new EncryptionError('Failed to encrypt record', EncryptionErrorCode.ENCRYPTION_FAILED, {
      originalError: error as Error,
    });
  }
}

/**
 * Decrypt a record from storage
 *
 * Decrypts with AES-256-GCM and verifies authentication tag.
 *
 * @param encrypted - Encrypted record from storage
 * @param dbKey - 32-byte database encryption key
 * @returns Decrypted plaintext object
 * @throws EncryptionError if decryption fails or auth tag invalid (tampering detected)
 */
export function decryptRecord<T = unknown>(encrypted: EncryptedRecord, dbKey: Uint8Array): T {
  try {
    // Validate database key
    if (dbKey.length !== AES_KEY_SIZE) {
      throw new Error(
        `Invalid database key size: expected ${AES_KEY_SIZE} bytes, got ${dbKey.length}`
      );
    }

    // Convert from Base64
    const ciphertext = Buffer.from(encrypted.encrypted_data, 'base64');
    const iv = Buffer.from(encrypted.iv, 'base64');
    const authTag = Buffer.from(encrypted.auth_tag, 'base64');

    // Validate IV size
    if (iv.length !== IV_SIZE) {
      throw new Error(`Invalid IV size: expected ${IV_SIZE} bytes, got ${iv.length}`);
    }

    // Validate auth tag size
    if (authTag.length !== AUTH_TAG_SIZE) {
      throw new Error(
        `Invalid auth tag size: expected ${AUTH_TAG_SIZE} bytes, got ${authTag.length}`
      );
    }

    // Create decipher
    const decipher = createDecipheriv(AES_ALGORITHM, Buffer.from(dbKey), iv);
    decipher.setAuthTag(authTag);

    // Decrypt data
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    // Parse JSON
    const plaintextJson = decrypted.toString('utf8');
    return JSON.parse(plaintextJson) as T;
  } catch (error) {
    throw new EncryptionError(
      'Failed to decrypt record (data may be tampered or corrupted)',
      EncryptionErrorCode.DECRYPTION_FAILED,
      { originalError: error as Error }
    );
  }
}

/**
 * Encrypt multiple records in batch
 *
 * More efficient than encrypting one at a time.
 *
 * @param records - Array of plaintext objects
 * @param dbKey - 32-byte database encryption key
 * @returns Array of encrypted records
 */
export function encryptRecordsBatch(records: unknown[], dbKey: Uint8Array): EncryptedRecord[] {
  return records.map((record) => encryptRecord(record, dbKey));
}

/**
 * Decrypt multiple records in batch
 *
 * More efficient than decrypting one at a time.
 *
 * @param encryptedRecords - Array of encrypted records
 * @param dbKey - 32-byte database encryption key
 * @returns Array of decrypted plaintext objects
 */
export function decryptRecordsBatch<T = unknown>(
  encryptedRecords: EncryptedRecord[],
  dbKey: Uint8Array
): T[] {
  return encryptedRecords.map((record) => decryptRecord<T>(record, dbKey));
}

/**
 * Re-encrypt a record with a new database key
 *
 * Used during key rotation. Decrypts with old key and re-encrypts with new key.
 *
 * @param encrypted - Encrypted record with old key
 * @param oldKey - Old database encryption key
 * @param newKey - New database encryption key
 * @returns Re-encrypted record
 */
export function reEncryptRecord(
  encrypted: EncryptedRecord,
  oldKey: Uint8Array,
  newKey: Uint8Array
): EncryptedRecord {
  // Decrypt with old key
  const plaintext = decryptRecord(encrypted, oldKey);

  // Encrypt with new key
  return encryptRecord(plaintext, newKey);
}

/**
 * Verify encrypted record integrity
 *
 * Checks if the record can be decrypted without actually decrypting it.
 * Note: This still requires decryption to verify the auth tag.
 *
 * @param encrypted - Encrypted record
 * @param dbKey - Database encryption key
 * @returns true if record is valid and can be decrypted
 */
export function verifyRecord(encrypted: EncryptedRecord, dbKey: Uint8Array): boolean {
  try {
    decryptRecord(encrypted, dbKey);
    return true;
  } catch {
    return false;
  }
}

/**
 * Get estimated size of encrypted record
 *
 * Useful for debugging and performance monitoring.
 *
 * @param encrypted - Encrypted record
 * @returns Size estimate in bytes
 */
export function getEncryptedRecordSize(encrypted: EncryptedRecord): number {
  return encrypted.encrypted_data.length + encrypted.iv.length + encrypted.auth_tag.length;
}

/**
 * Validate encrypted record structure
 *
 * @param record - Record to validate
 * @returns true if structure is valid
 */
export function isValidEncryptedRecord(record: unknown): record is EncryptedRecord {
  if (typeof record !== 'object' || record === null) {
    return false;
  }

  const r = record as Record<string, unknown>;

  return (
    typeof r.encrypted_data === 'string' &&
    typeof r.iv === 'string' &&
    typeof r.auth_tag === 'string' &&
    r.encrypted_data.length > 0 &&
    r.iv.length > 0 &&
    r.auth_tag.length > 0
  );
}
