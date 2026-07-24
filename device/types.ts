/**
 * Device Transfer Type Definitions
 *
 * SDK extension for secure device-to-device migration.
 *
 * Key features:
 * - Ephemeral ECDH keys for key agreement
 * - QR code pairing with freshness verification
 * - AES-256-GCM encrypted backup transfer
 * - Application-provided transport
 *
 * Security Properties:
 * - End-to-end encrypted transfer
 * - Out-of-band QR confirmation binds the transfer's ephemeral public key
 * - Fresh ephemeral key agreement for each transfer
 * - Transports receive encrypted transfer packets
 */

import type { DoubleRatchetState } from '../internal/protocol/double-ratchet';
import type { ILogger } from '../logger';

// ============================================================================
// Transfer Key Types
// ============================================================================

/**
 * Ephemeral key pair for device transfer
 * Generated fresh for each transfer session
 */
export {};
export interface TransferKeyPair {
  /** Base64 ECDH public key */
  publicKey: string;
  /** Base64 ECDH private key */
  privateKey: string;
  /** Base64 random secret for HMAC verification */
  secret: string;
}

/**
 * QR code data structure
 * Displayed on new device, scanned by old device
 */
export interface TransferQRCode {
  /** New device's transfer public key */
  publicKey: string;
  /** Protocol version (for future compatibility) */
  version: number;
  /** Device platform type */
  deviceType: 'ios' | 'android';
  /** Creation timestamp (for freshness check) */
  timestamp: number;
}

// ============================================================================
// Backup Types (Serialized forms for JSON transfer)
// ============================================================================

/**
 * Identity key pair for backup/transfer (JSON-serializable).
 *
 * Uses plain strings instead of branded types because backups are
 * serialized to JSON for device transfer. The canonical `IdentityKeyPair`
 * type is in `keys/types.ts`.
 */
export interface BackupIdentityKeyPair {
  /** X25519 DH public/private key */
  dhKey: {
    publicKey: string;
    privateKey: string;
  };
  /** Ed25519 signing key */
  signingKey: {
    publicKey: string;
    privateKey: string;
  };
}

/**
 * Signed prekey for backup/transfer (JSON-serializable).
 *
 * Uses plain strings for JSON serialization. The canonical `EcSignedPreKey`
 * type is in `keys/types.ts`.
 */
export interface BackupSignedPreKey {
  /** Key ID */
  id: number;
  /** X25519 public key (Base64) */
  publicKey: string;
  /** X25519 private key (Base64) */
  privateKey: string;
  /** Ed25519 signature of public key (Base64) */
  signature: string;
  /** Timestamp when key was generated */
  timestamp: number;
}

/**
 * One-time prekey for backup/transfer (JSON-serializable).
 *
 * Uses plain strings for JSON serialization. The canonical `EcOneTimePreKey`
 * type is in `keys/types.ts`.
 */
export interface BackupOneTimePreKey {
  /** Key ID */
  id: number;
  /** X25519 public key (Base64) */
  publicKey: string;
  /** X25519 private key (Base64) */
  privateKey: string;
}

/**
 * Complete device backup structure
 * Contains all encryption keys needed to restore account
 */
export interface DeviceBackup {
  /** Backup format version */
  version: number;
  /** Creation timestamp */
  timestamp: number;

  /** Device metadata */
  deviceInfo: {
    platform: 'ios' | 'android';
    osVersion: string;
    appVersion: string;
  };

  /** Long-lived identity key */
  identityKey: BackupIdentityKeyPair;
  /** Current signed prekey */
  signedPreKey: BackupSignedPreKey;
  /** Available one-time prekeys */
  oneTimePreKeys: BackupOneTimePreKey[];

  /** Session states (per encrypted session) */
  sessions: Record<string, DoubleRatchetState>;

  /** Session count */
  sessionCount: number;
  /** Total message count (optional) */
  messageCount?: number;
  /** Photo count (optional) */
  photoCount?: number;
}

/**
 * Encrypted backup ready for transfer
 */
export interface EncryptedBackup {
  /** Base64 encrypted backup */
  ciphertext: string;
  /** Base64 IV for AES-GCM */
  iv: string;
  /** Base64 authentication tag */
  authTag: string;
  /** Backup metadata */
  metadata: {
    version: number;
    timestamp: number;
    sizeBytes: number;
  };
}

/**
 * Transfer packet containing encrypted backup and sender's public key
 * The receiver needs the sender's public key to derive the encryption key via ECDH
 */
export interface TransferPacket {
  /** Base64 sender's ECDH public key */
  senderPublicKey: string;
  /** Encrypted backup data */
  encryptedBackup: EncryptedBackup;
  /** SHA-256 checksum of encrypted data for verification */
  checksum: string;
  /** Total size in bytes for progress tracking */
  totalSize: number;
  /** Whether data is compressed */
  compressed: boolean;
}

// ============================================================================
// Transfer Session Types
// ============================================================================

/**
 * Transfer session state
 */
export interface TransferSession {
  /** Session ID */
  id: string;
  /** Role in transfer */
  role: 'sender' | 'receiver';
  /** Current status */
  status: TransferStatus;
  /** Transfer key pair (ephemeral) */
  keyPair?: TransferKeyPair;
  /** Partner's public key (from QR code) */
  partnerPublicKey?: string;
  /** Derived shared secret */
  sharedSecret?: Uint8Array;
  /** Error message if failed */
  error?: string;
  /** Transfer progress (0-100) */
  progress?: number;
}

/**
 * Transfer status enum
 */
export type TransferStatus = 'idle' | 'pairing' | 'transferring' | 'complete' | 'error';

// ============================================================================
// Connection Types
// ============================================================================

/**
 * Connection role
 */
export type ConnectionRole = 'sender' | 'receiver';

/**
 * Connection status
 */
export type ConnectionStatus =
  | 'idle'
  | 'advertising' // Receiver waiting for connection
  | 'discovering' // Sender looking for receiver
  | 'connecting' // Establishing connection
  | 'connected' // Connected and ready
  | 'transferring' // Data transfer in progress
  | 'complete' // Transfer complete
  | 'error' // Error occurred
  | 'closed'; // Connection closed

/**
 * Transfer progress callback (simple percentage)
 */
export type ProgressCallback = (progress: number) => void;

/**
 * Detailed transfer progress callback
 */
export type DetailedProgressCallback = (info: {
  percentage: number; // 0-100
  bytesTransferred: number;
  totalBytes: number;
  speed?: number; // bytes per second
}) => void;

/**
 * Local connection interface
 */
export interface LocalConnection {
  role: ConnectionRole;
  status: ConnectionStatus;
  error?: string;

  // Connection lifecycle
  connect(): Promise<void>;
  disconnect(): Promise<void>;

  // Data transfer
  sendData(data: TransferPacket): Promise<void>;
  receiveData(): Promise<TransferPacket>;

  // Progress tracking
  onProgress(callback: ProgressCallback): void;
}

/**
 * Connection configuration
 */
export interface ConnectionConfig {
  role: ConnectionRole;
  /** Unique device identifier */
  deviceId: string;
  /** Connection timeout (ms) */
  timeout?: number;
  /** Optional logger for transfer/runtime diagnostics */
  logger?: ILogger;
}

/**
 * Retry configuration for network operations
 */
export interface RetryConfig {
  /** Maximum number of retry attempts */
  maxRetries: number;
  /** Initial delay in ms */
  initialDelay: number;
  /** Maximum delay in ms */
  maxDelay: number;
  /** Exponential backoff multiplier */
  backoffMultiplier: number;
}

/**
 * Relay configuration with Convex operations
 */
export interface RelayConfig extends ConnectionConfig {
  createChannel: (channelId: string) => Promise<void>;
  uploadData: (channelId: string, data: string) => Promise<void>;
  downloadData: (channelId: string) => Promise<{ status: string; data: string | null }>;
  deleteChannel: (channelId: string) => Promise<void>;
  completeChannel: (channelId: string) => Promise<void>;
  retryConfig?: RetryConfig;
}

// ============================================================================
// Constants
// ============================================================================

/**
 * Default retry configuration
 */
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 3,
  initialDelay: 1000, // 1 second
  maxDelay: 10000, // 10 seconds
  backoffMultiplier: 2, // Double delay each time
};

/**
 * QR code expiry time (5 minutes)
 */
export const QR_CODE_MAX_AGE = 5 * 60 * 1000;

/**
 * Transfer protocol version
 */
export const TRANSFER_PROTOCOL_VERSION = 1;

/**
 * Backup format version
 */
export const BACKUP_FORMAT_VERSION = 1;
