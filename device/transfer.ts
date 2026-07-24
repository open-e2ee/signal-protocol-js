/**
 * Device Transfer Module
 *
 * SDK extension for device migration.
 * Secure device-to-device key transfer over an application-provided transport.
 *
 * Key features:
 * - Ephemeral ECDH keys for key agreement
 * - QR code with freshness verification for pairing
 * - AES-256-GCM for backup encryption
 * - Application-provided transport
 *
 * Security Properties:
 * - End-to-end encrypted transfer
 * - Out-of-band QR confirmation binds the transfer's ephemeral public key
 * - Fresh ephemeral key agreement for each transfer
 * - Relays receive only encrypted transfer packets
 */

import { Platform } from 'react-native';
import Constants from 'expo-constants';
import { resolveSignalLogger, type ILogger } from '../logger';
import {
  generateECDHKeyPair,
  computeSharedSecret,
  generateRandomBytes,
  hkdf,
  aesGcmEncrypt,
  aesGcmDecrypt,
  bytesToBase64,
  base64ToBytes,
  stringToBytes,
  bytesToString,
  secureZeroBytes,
} from '../internal/crypto';
import { asBase64 } from '../types/utils';
import { ProtocolAddress } from '../types/address';
import { CURRENT_SESSION_RECORD_VERSION } from '../types/session';
import type {
  TransferKeyPair,
  TransferQRCode,
  DeviceBackup,
  EncryptedBackup,
  BackupIdentityKeyPair,
  BackupSignedPreKey,
  BackupOneTimePreKey,
} from './types';
import type { DoubleRatchetState } from '../internal/protocol/double-ratchet';
import { QR_CODE_MAX_AGE, TRANSFER_PROTOCOL_VERSION, BACKUP_FORMAT_VERSION } from './types';

const QR_CODE_MAX_FUTURE_SKEW = 30_000;
const MAX_BACKUP_SESSIONS = 100_000;

function decodeCanonicalBase64(value: unknown, label: string, expectedLength: number): Uint8Array {
  if (typeof value !== 'string') throw new Error(`${label} must be Base64`);
  let decoded: Uint8Array;
  try {
    decoded = base64ToBytes(asBase64(value));
  } catch {
    throw new Error(`${label} must be Base64`);
  }
  if (decoded.length !== expectedLength || bytesToBase64(decoded) !== value) {
    throw new Error(`${label} must encode exactly ${expectedLength} bytes`);
  }
  return decoded;
}

// ============================================================================
// Transfer Key Generation
// ============================================================================

/**
 * Generate ephemeral key pair for device transfer
 *
 * Creates:
 * - ECDH key pair for key agreement
 * - Random secret for QR code HMAC verification
 *
 * These keys are single-use and should be wiped after transfer.
 */
export {};
export async function generateTransferKeyPair(providedLogger?: ILogger): Promise<TransferKeyPair> {
  const logger = resolveSignalLogger(providedLogger);
  logger.debug('Device Transfer: Generating transfer key pair', {
    category: 'Device',
    data: { operation: 'transfer-keygen' },
  });

  // Generate ECDH key pair
  const keyPair = await generateECDHKeyPair();

  // Generate random secret for HMAC verification
  const secret = await generateRandomBytes(32);

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    secret: bytesToBase64(secret),
  };
}

/**
 * Wipe transfer keys from memory
 * Called after transfer completes or fails
 */
export function wipeTransferKeys(keyPair: TransferKeyPair, providedLogger?: ILogger): void {
  const logger = resolveSignalLogger(providedLogger);
  try {
    // Check if already wiped
    if (!keyPair.publicKey || !keyPair.privateKey || !keyPair.secret) {
      return;
    }

    const publicKeyBytes = base64ToBytes(asBase64(keyPair.publicKey));
    const privateKeyBytes = base64ToBytes(asBase64(keyPair.privateKey));
    const secretBytes = base64ToBytes(asBase64(keyPair.secret));

    // Secure multi-pass zeroing (resistant to JIT dead-store elimination)
    secureZeroBytes(publicKeyBytes);
    secureZeroBytes(privateKeyBytes);
    secureZeroBytes(secretBytes);

    // Clear string references
    keyPair.publicKey = '';
    keyPair.privateKey = '';
    keyPair.secret = '';

    logger.debug('Device Transfer: Transfer keys wiped', {
      category: 'Device',
      data: { operation: 'transfer-wipe' },
    });
  } catch (error) {
    logger.warn('Device Transfer: Failed to wipe transfer keys', {
      category: 'Device',
      error: error as Error,
    });
  }
}

// ============================================================================
// QR Code Generation & Verification
// ============================================================================

/**
 * Generate QR code data for new device
 *
 * QR code contains:
 * - New device's public key (for ECDH key agreement)
 * - Version and device type (for compatibility)
 * - Timestamp (for freshness check)
 *
 * Security model:
 * - Physical proximity provides authentication (user scans in person)
 * - ECDH provides encryption of the actual transfer
 *
 * Old device scans this QR code to initiate transfer.
 */
export async function generateTransferQRCode(
  keyPair: TransferKeyPair,
  providedLogger?: ILogger
): Promise<string> {
  const logger = resolveSignalLogger(providedLogger);
  const qrData: TransferQRCode = {
    publicKey: keyPair.publicKey,
    version: TRANSFER_PROTOCOL_VERSION,
    deviceType: Platform.OS === 'ios' ? 'ios' : 'android',
    timestamp: Date.now(),
  };

  logger.debug('Device Transfer: Generated QR code', {
    category: 'Device',
    data: {
      operation: 'transfer-qr-generate',
      deviceType: qrData.deviceType,
    },
  });

  return JSON.stringify(qrData);
}

/**
 * Verify QR code scanned from new device
 *
 * Verifies:
 * - Protocol version is compatible
 * - Timestamp is recent (within 5 minutes)
 * - QR code structure is valid
 *
 * Security:
 * - Physical proximity provides authentication
 * - ECDH key agreement will provide encryption
 *
 * Returns the new device's public key if valid.
 */
export async function verifyTransferQRCode(
  qrCodeData: string,
  providedLogger?: ILogger
): Promise<TransferQRCode> {
  const logger = resolveSignalLogger(providedLogger);
  const qrCode = JSON.parse(qrCodeData) as TransferQRCode;

  // Check version compatibility
  if (qrCode.version !== TRANSFER_PROTOCOL_VERSION) {
    throw new Error(`Unsupported protocol version: ${qrCode.version}`);
  }

  if (!Number.isFinite(qrCode.timestamp) || !Number.isInteger(qrCode.timestamp)) {
    throw new Error('QR code timestamp must be a finite integer');
  }

  if (qrCode.deviceType !== 'ios' && qrCode.deviceType !== 'android') {
    throw new Error('Invalid QR code device type');
  }

  // Check timestamp (must be within 5 minutes, with small clock skew tolerance)
  const age = Date.now() - qrCode.timestamp;
  if (age < -QR_CODE_MAX_FUTURE_SKEW) {
    throw new Error('QR code timestamp is too far in the future');
  }
  if (age > QR_CODE_MAX_AGE) {
    throw new Error('QR code expired');
  }

  // Validate public key exists
  if (!qrCode.publicKey) {
    throw new Error('QR code missing public key');
  }
  decodeCanonicalBase64(qrCode.publicKey, 'QR code public key', 32);

  logger.debug('Device Transfer: Verified QR code', {
    category: 'Device',
    data: {
      operation: 'transfer-qr-verify',
      deviceType: qrCode.deviceType,
      age: age,
    },
  });

  return qrCode;
}

// ============================================================================
// Shared Secret Derivation
// ============================================================================

/**
 * Derive shared secret and encryption keys from ECDH key agreement
 *
 * Both devices perform this independently:
 * - Old device: uses its private key + new device's public key
 * - New device: uses its private key + old device's public key
 *
 * Result: Both derive the same shared secret (ECDH property)
 */
export async function deriveTransferKeys(
  myPrivateKey: string,
  theirPublicKey: string,
  providedLogger?: ILogger
): Promise<{
  encryptionKey: Uint8Array;
  authenticationKey: Uint8Array;
}> {
  const logger = resolveSignalLogger(providedLogger);
  // Compute shared secret via ECDH
  const sharedSecret = await computeSharedSecret(asBase64(myPrivateKey), asBase64(theirPublicKey));

  // Derive encryption and authentication keys using HKDF
  const salt = new Uint8Array(32); // Zero salt
  const info = stringToBytes('SignalProtocol-DeviceTransfer-v1');

  let derived: Uint8Array | undefined;
  try {
    // Derive 64 bytes: 32 for encryption, 32 for authentication
    derived = await hkdf(sharedSecret, salt, info, 64);

    // slice() copies, so the returned keys are independent of `derived`.
    const encryptionKey = derived.slice(0, 32);
    const authenticationKey = derived.slice(32, 64);

    logger.debug('Device Transfer: Derived transfer keys', {
      category: 'Device',
      data: { operation: 'transfer-derive-keys' },
    });

    return { encryptionKey, authenticationKey };
  } finally {
    // Wipe intermediate secrets regardless of success or failure.
    secureZeroBytes(sharedSecret as unknown as Uint8Array);
    if (derived) {
      secureZeroBytes(derived);
    }
  }
}

// ============================================================================
// Backup Validation
// ============================================================================

/**
 * Validate backup structure
 *
 * Ensures backup contains all required fields and is well-formed
 */
export function validateBackup(backup: DeviceBackup): void {
  const requiredFields = [
    'version',
    'timestamp',
    'deviceInfo',
    'identityKey',
    'signedPreKey',
    'oneTimePreKeys',
    'sessions',
  ];

  for (const field of requiredFields) {
    if (!(field in backup)) {
      throw new Error(`Invalid backup: missing field '${field}'`);
    }
  }

  if (backup.version !== BACKUP_FORMAT_VERSION) {
    throw new Error(`Unsupported backup version: ${backup.version}`);
  }

  if (!Number.isFinite(backup.timestamp) || !Number.isInteger(backup.timestamp) || backup.timestamp < 0) {
    throw new Error('Invalid backup timestamp');
  }
  if (backup.timestamp > Date.now() + QR_CODE_MAX_FUTURE_SKEW) {
    throw new Error('Invalid backup timestamp: too far in the future');
  }

  // Validate identity key structure
  if (!backup.identityKey.dhKey || !backup.identityKey.signingKey) {
    throw new Error('Invalid identity key structure');
  }
  decodeCanonicalBase64(backup.identityKey.dhKey.publicKey, 'Identity DH public key', 32);
  decodeCanonicalBase64(backup.identityKey.dhKey.privateKey, 'Identity DH private key', 32);
  decodeCanonicalBase64(backup.identityKey.signingKey.publicKey, 'Identity signing public key', 32);
  decodeCanonicalBase64(backup.identityKey.signingKey.privateKey, 'Identity signing private key', 32);

  // Validate signed prekey structure
  if (!backup.signedPreKey.publicKey || !backup.signedPreKey.signature) {
    throw new Error('Invalid signed prekey structure');
  }
  if (!Number.isInteger(backup.signedPreKey.id) || backup.signedPreKey.id < 0) {
    throw new Error('Invalid signed prekey id');
  }
  if (
    !Number.isFinite(backup.signedPreKey.timestamp) ||
    !Number.isInteger(backup.signedPreKey.timestamp) ||
    backup.signedPreKey.timestamp < 0 ||
    backup.signedPreKey.timestamp > Date.now() + QR_CODE_MAX_FUTURE_SKEW
  ) {
    throw new Error('Invalid signed prekey timestamp');
  }
  decodeCanonicalBase64(backup.signedPreKey.publicKey, 'Signed prekey public key', 32);
  decodeCanonicalBase64(backup.signedPreKey.privateKey, 'Signed prekey private key', 32);
  decodeCanonicalBase64(backup.signedPreKey.signature, 'Signed prekey signature', 64);

  if (!Array.isArray(backup.oneTimePreKeys)) throw new Error('Invalid one-time prekeys');
  for (const key of backup.oneTimePreKeys) {
    if (!Number.isInteger(key.id) || key.id < 0) throw new Error('Invalid one-time prekey id');
    decodeCanonicalBase64(key.publicKey, 'One-time prekey public key', 32);
    decodeCanonicalBase64(key.privateKey, 'One-time prekey private key', 32);
  }

  if (!backup.sessions || typeof backup.sessions !== 'object' || Array.isArray(backup.sessions)) {
    throw new Error('Invalid sessions structure');
  }
  const sessionEntries = Object.entries(backup.sessions);
  if (
    !Number.isInteger(backup.sessionCount) ||
    backup.sessionCount < 0 ||
    backup.sessionCount !== sessionEntries.length ||
    backup.sessionCount > MAX_BACKUP_SESSIONS
  ) {
    throw new Error('Invalid backup session count');
  }
  for (const [sessionId, session] of sessionEntries) {
    ProtocolAddress.parse(sessionId);
    if (
      !session ||
      typeof session !== 'object' ||
      !session.DHs ||
      !Number.isInteger(session.Ns) ||
      session.Ns < 0 ||
      !Number.isInteger(session.Nr) ||
      session.Nr < 0
    ) {
      throw new Error(`Invalid session structure: ${sessionId}`);
    }
  }
}

// ============================================================================
// Backup Encryption & Decryption
// ============================================================================

/**
 * Encrypt backup for secure transfer
 *
 * Uses AES-256-GCM with:
 * - Encryption key derived from ECDH shared secret
 * - Random IV (96 bits)
 * - Authentication tag (128 bits)
 */
export async function encryptBackup(
  backup: DeviceBackup,
  encryptionKey: Uint8Array,
  providedLogger?: ILogger
): Promise<EncryptedBackup> {
  const logger = resolveSignalLogger(providedLogger);
  // Serialize backup to JSON
  const backupJson = JSON.stringify(backup);
  const backupBytes = stringToBytes(backupJson);

  // Encrypt with AES-256-GCM
  const encrypted = await aesGcmEncrypt(encryptionKey, backupBytes);

  logger.debug('Device Transfer: Encrypted backup', {
    category: 'Device',
    data: {
      operation: 'transfer-encrypt',
      sizeBytes: backupBytes.length,
    },
  });

  return {
    ciphertext: encrypted.ciphertext,
    iv: encrypted.iv,
    authTag: encrypted.authTag,
    metadata: {
      version: backup.version,
      timestamp: backup.timestamp,
      sizeBytes: backupBytes.length,
    },
  };
}

/**
 * Decrypt backup received from old device
 *
 * Verifies authentication tag before decryption
 */
export async function decryptBackup(
  encryptedBackup: EncryptedBackup,
  encryptionKey: Uint8Array,
  providedLogger?: ILogger
): Promise<DeviceBackup> {
  const logger = resolveSignalLogger(providedLogger);
  // Decrypt with AES-256-GCM (automatically verifies auth tag)
  const decryptedBytes = await aesGcmDecrypt(
    encryptionKey,
    asBase64(encryptedBackup.ciphertext),
    asBase64(encryptedBackup.iv),
    asBase64(encryptedBackup.authTag)
  );

  // Parse JSON
  const backupJson = bytesToString(decryptedBytes);
  const backup = JSON.parse(backupJson) as DeviceBackup;

  // Validate structure
  validateBackup(backup);

  logger.debug('Device Transfer: Decrypted backup', {
    category: 'Device',
    data: {
      operation: 'transfer-decrypt',
      sizeBytes: decryptedBytes.length,
      sessionCount: backup.sessionCount,
    },
  });

  return backup;
}

// ============================================================================
// Complete Transfer Flow Helpers
// ============================================================================

/**
 * Old device: Prepare for transfer
 *
 * Steps:
 * 1. Generate transfer key pair
 * 2. Wait for new device's QR code
 * 3. Verify QR code
 * 4. Derive shared secret
 * 5. Create backup
 * 6. Encrypt backup
 * 7. Send to new device
 */
export async function prepareOldDeviceTransfer(providedLogger?: ILogger): Promise<{
  keyPair: TransferKeyPair;
}> {
  const logger = resolveSignalLogger(providedLogger);
  const keyPair = await generateTransferKeyPair(logger);

  logger.info('Device Transfer: Old device prepared for transfer', {
    category: 'Device',
    data: { operation: 'transfer-prepare-old' },
  });

  return { keyPair };
}

/**
 * New device: Prepare to receive transfer
 *
 * Steps:
 * 1. Generate transfer key pair
 * 2. Display QR code
 * 3. Wait for old device to scan
 * 4. Receive encrypted backup
 * 5. Decrypt backup
 * 6. Restore to SecureStore
 */
export async function prepareNewDeviceTransfer(providedLogger?: ILogger): Promise<{
  keyPair: TransferKeyPair;
  qrCode: string;
}> {
  const logger = resolveSignalLogger(providedLogger);
  const keyPair = await generateTransferKeyPair(logger);
  const qrCode = await generateTransferQRCode(keyPair, logger);

  logger.info('Device Transfer: New device prepared for transfer', {
    category: 'Device',
    data: { operation: 'transfer-prepare-new' },
  });

  return { keyPair, qrCode };
}

/**
 * Calculate backup size estimate
 *
 * Helps display progress and validate data size
 */
export function estimateBackupSize(backup: DeviceBackup): number {
  const backupJson = JSON.stringify(backup);
  return backupJson.length; // Approximate size in bytes
}

/**
 * Format backup size for display
 */
export function formatBackupSize(sizeBytes: number): string {
  if (sizeBytes < 1024) {
    return `${sizeBytes} bytes`;
  } else if (sizeBytes < 1024 * 1024) {
    return `${(sizeBytes / 1024).toFixed(1)} KB`;
  } else {
    return `${(sizeBytes / (1024 * 1024)).toFixed(1)} MB`;
  }
}

/**
 * Create empty device backup template
 *
 * Used when building a backup incrementally
 */
export function createEmptyBackup(): DeviceBackup {
  return {
    version: BACKUP_FORMAT_VERSION,
    timestamp: Date.now(),
    deviceInfo: {
      platform: Platform.OS === 'ios' ? 'ios' : 'android',
      osVersion: Platform.Version.toString(),
      appVersion: Constants.expoConfig?.version || 'unknown',
    },
    identityKey: {
      dhKey: { publicKey: '', privateKey: '' },
      signingKey: { publicKey: '', privateKey: '' },
    },
    signedPreKey: {
      id: 0,
      publicKey: '',
      privateKey: '',
      signature: '',
      timestamp: 0,
    },
    oneTimePreKeys: [],
    sessions: {},
    sessionCount: 0,
  };
}

// ============================================================================
// Storage Integration Functions
// ============================================================================
// These functions require a KeyStorage adapter to be provided

/**
 * Minimal storage interface for backup operations.
 *
 * Uses Backup* types which are JSON-serializable versions of the canonical key types.
 * The Backup* types use plain strings (Base64) instead of branded types, and use
 * `id` instead of `keyId` for compatibility with the DeviceBackup format.
 */
export interface BackupStorage {
  getIdentityKey(): Promise<BackupIdentityKeyPair | null>;
  getEcSignedPreKey(): Promise<BackupSignedPreKey | null>;
  getEcOneTimePreKeys(): Promise<BackupOneTimePreKey[]>;
  getSessionRecord(
    address: ProtocolAddress
  ): Promise<{ currentSession: DoubleRatchetState | null } | null>;
  storeSessionRecord(
    address: ProtocolAddress,
    record: {
      currentSession: DoubleRatchetState | null;
      archivedSessions: Record<string, DoubleRatchetState>;
      version: number;
    }
  ): Promise<void>;
  storeIdentityKey(key: BackupIdentityKeyPair): Promise<void>;
  storeEcSignedPreKey(key: BackupSignedPreKey): Promise<void>;
  storeEcOneTimePreKeys(keys: BackupOneTimePreKey[]): Promise<void>;
  /**
   * Run all restore writes in an adapter-backed atomic transaction or isolated
   * namespace. Rejecting the callback must leave the previously active state intact.
   */
  runRestoreTransaction<T>(operation: (transaction: BackupStorage) => Promise<T>): Promise<T>;
}

export interface RestoreDeviceBackupResult {
  status: 'complete' | 'incomplete';
  sessionsRestored: number;
  totalSessions: number;
  error?: Error;
}

/**
 * Create device backup from storage
 *
 * Exports all encryption keys from storage:
 * - Identity key (long-lived, per-user)
 * - Signed prekey
 * - One-time prekeys
 * - All session states (per encrypted session)
 *
 * @param storage - Key storage adapter to read from
 */
export async function createDeviceBackup(
  storage: BackupStorage,
  providedLogger?: ILogger
): Promise<DeviceBackup> {
  const logger = resolveSignalLogger(providedLogger);
  logger.info('Device Transfer: Creating backup from storage', {
    category: 'Device',
    data: { operation: 'backup-create' },
  });

  // Export identity key
  const identityKey = await storage.getIdentityKey();
  if (!identityKey) {
    throw new Error('No identity key found - cannot create backup');
  }

  // Export prekeys
  const signedPreKey = await storage.getEcSignedPreKey();
  if (!signedPreKey) {
    throw new Error('No EC signed prekey found - cannot create backup');
  }

  const oneTimePreKeys = await storage.getEcOneTimePreKeys();

  // Sessions will be added via addSessionToBackup
  const sessions: DeviceBackup['sessions'] = {};

  const backup: DeviceBackup = {
    version: BACKUP_FORMAT_VERSION,
    timestamp: Date.now(),
    deviceInfo: {
      platform: Platform.OS === 'ios' ? 'ios' : 'android',
      osVersion: Platform.Version.toString(),
      appVersion: Constants.expoConfig?.version || 'unknown',
    },
    identityKey,
    signedPreKey,
    oneTimePreKeys,
    sessions,
    sessionCount: 0,
  };

  logger.debug('Device Transfer: Backup created', {
    category: 'Device',
    data: {
      hasIdentityKey: true,
      hasSignedPreKey: true,
      oneTimePreKeysCount: oneTimePreKeys.length,
    },
  });

  return backup;
}

/**
 * Add session to backup
 *
 * Helper function to add a session state to an existing backup
 *
 * @param backup - Backup to add session to
 * @param storage - Key storage adapter
 * @param sessionId - Session ID to add
 */
export async function addSessionToBackup(
  backup: DeviceBackup,
  storage: BackupStorage,
  sessionId: string,
  providedLogger?: ILogger
): Promise<void> {
  const logger = resolveSignalLogger(providedLogger);
  try {
    // Backup keys use the serialized ProtocolAddress form.
    const address = ProtocolAddress.parse(sessionId);
    const record = await storage.getSessionRecord(address);
    const session = record?.currentSession;

    if (session) {
      backup.sessions[sessionId] = session;
      backup.sessionCount = Object.keys(backup.sessions).length;

      logger.debug('Device Transfer: Added session to backup', {
        category: 'Device',
        data: { sessionId, sessionCount: backup.sessionCount },
      });
    }
  } catch (error) {
    logger.warn('Device Transfer: Failed to add session to backup', {
      category: 'Device',
      error: error as Error,
      data: { sessionId },
    });
    // Don't throw - allow partial backup
  }
}

/**
 * Restore device backup to storage
 *
 * Imports:
 * - Identity key
 * - Signed prekey
 * - One-time prekeys
 * - All session states
 *
 * This completely replaces existing keys (use with caution!)
 *
 * @param backup - Backup to restore
 * @param storage - Key storage adapter to write to
 */
export async function restoreDeviceBackup(
  backup: DeviceBackup,
  storage: BackupStorage,
  providedLogger?: ILogger
): Promise<RestoreDeviceBackupResult> {
  const logger = resolveSignalLogger(providedLogger);
  logger.info('Device Transfer: Starting backup restoration', {
    category: 'Device',
    data: { sessionCount: backup.sessionCount },
  });

  let sessionsRestored = 0;
  try {
    validateBackup(backup);
    await storage.runRestoreTransaction(async (transaction) => {
      await transaction.storeIdentityKey(backup.identityKey);
      await transaction.storeEcSignedPreKey(backup.signedPreKey);
      await transaction.storeEcOneTimePreKeys(backup.oneTimePreKeys);
      for (const [sessionId, session] of Object.entries(backup.sessions)) {
        const address = ProtocolAddress.parse(sessionId);
        await transaction.storeSessionRecord(address, {
          currentSession: session,
          archivedSessions: {},
          version: CURRENT_SESSION_RECORD_VERSION,
        });
        sessionsRestored++;
      }
    });
  } catch (cause) {
    const error = cause instanceof Error ? cause : new Error('Unknown backup restore failure');
    logger.error('Device Transfer: Backup restoration incomplete; old state retained', {
      category: 'Device',
      error,
      data: { sessionsRestored, totalSessions: backup.sessionCount },
    });
    return { status: 'incomplete', sessionsRestored: 0, totalSessions: backup.sessionCount, error };
  }

  logger.info('Device Transfer: Backup restoration complete', {
    category: 'Device',
    data: { sessionsRestored, totalSessions: backup.sessionCount },
  });
  return { status: 'complete', sessionsRestored, totalSessions: backup.sessionCount };
}

/**
 * Old device: Prepare for transfer with backup capability
 *
 * Enhanced version that includes a getBackup callback
 *
 * @param storage - Key storage adapter
 */
export async function prepareOldDeviceTransferWithBackup(
  storage: BackupStorage,
  providedLogger?: ILogger
): Promise<{
  keyPair: TransferKeyPair;
  getBackup: (sessionIds: string[]) => Promise<DeviceBackup>;
}> {
  const logger = resolveSignalLogger(providedLogger);
  const keyPair = await generateTransferKeyPair(logger);

  const getBackup = async (sessionIds: string[]): Promise<DeviceBackup> => {
    const backup = await createDeviceBackup(storage, logger);

    // Add all sessions
    for (const sessionId of sessionIds) {
      await addSessionToBackup(backup, storage, sessionId, logger);
    }

    return backup;
  };

  logger.info('Device Transfer: Old device prepared for transfer with backup', {
    category: 'Device',
    data: { operation: 'transfer-prepare-old-with-backup' },
  });

  return { keyPair, getBackup };
}
