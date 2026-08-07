/**
 * Device Transfer Module
 *
 * SDK extension for secure device-to-device migration.
 *
 * Key features:
 * - Ephemeral ECDH keys for key agreement
 * - QR code pairing with freshness verification
 * - AES-256-GCM encrypted backup transfer
 * - Application-provided transport or relay connection
 *
 * Security Properties:
 * - End-to-end encrypted transfer
 * - Out-of-band QR confirmation binds the transfer's ephemeral public key
 * - Fresh ephemeral key agreement for each transfer
 * - Relays receive only encrypted transfer packets
 */

// Transfer functions
export {};
export {
  generateTransferKeyPair,
  wipeTransferKeys,
  generateTransferQRCode,
  verifyTransferQRCode,
  deriveTransferKeys,
  encryptBackup,
  decryptBackup,
  validateBackup,
  prepareOldDeviceTransfer,
  prepareNewDeviceTransfer,
  estimateBackupSize,
  formatBackupSize,
  createEmptyBackup,
  // Storage integration functions
  createDeviceBackup,
  addSessionToBackup,
  restoreDeviceBackup,
  prepareOldDeviceTransferWithBackup,
} from './transfer';

// Transfer types (from transfer module)
export type { BackupStorage, RestoreDeviceBackupResult } from './transfer';

// Connection functions
export {
  RelayConnection,
  createRelayConnection,
  generateConnectionId,
} from './connection';

// Types
export type {
  // Transfer types
  TransferKeyPair,
  TransferQRCode,
  DeviceBackup,
  EncryptedBackup,
  TransferPacket,
  TransferSession,
  TransferStatus,
  BackupIdentityKeyPair,
  BackupSignedPreKey,
  BackupOneTimePreKey,
  // Connection types
  LocalConnection,
  ConnectionConfig,
  ConnectionRole,
  ConnectionStatus,
  ProgressCallback,
  DetailedProgressCallback,
  RetryConfig,
  RelayConfig,
} from './types';

// Constants
export {
  DEFAULT_RETRY_CONFIG,
  QR_CODE_MAX_AGE,
  TRANSFER_PROTOCOL_VERSION,
  BACKUP_FORMAT_VERSION,
} from './types';

// Provisioning functions (device linking via QR code)
//
// `getDeviceMetadata` is deliberately absent: it reads the platform, and lives
// on `./device/expo-metadata` so that the provisioning protocol stays importable
// off Expo. Callers elsewhere build `LocalDeviceMetadata` themselves.
export {
  generateProvisioningQR,
  provisionDevice,
  parseProvisioningQR,
  connectToProvisioningSession,
  receiveProvisioningMessage,
  cancelProvisioning,
} from './provisioning';

// Device name encryption/decryption
export { encryptDeviceName, decryptDeviceName } from './device-name-crypto';

// Provisioning types
export type {
  ProvisioningKeyPair,
  ProvisioningQRData,
  ProvisioningMessage,
  LocalDeviceMetadata,
  ProvisioningIdentityStore,
  ProvisioningLocalStateStore,
  ProvisioningSendOptions,
  ProvisioningReceiveOptions,
  ProvisioningUsernameStateStore,
} from './provisioning';

// Device ID utilities (for non-React contexts)
export { getDeviceId, getDeviceIdSync, clearDeviceIdCache, preloadDeviceId } from './device-id';

// Device constants (shared across codebase)
export {
  DEVICE_ID_KEY,
  DEVICE_NAME_KEY,
  DEVICE_REGISTERED_USER_ID_KEY,
  DEVICE_OWNER_SENTINEL,
  DEFAULT_DEVICE_ID,
  MAX_DEVICES,
} from './constants';

// Device Lifecycle Management (extracted from host lifecycle for testability)
export { DeviceLifecycleManager } from './lifecycle';
export type {
  // Dependency interfaces
  ISecureStore,
  IConvexClient,
  DeviceLifecycleApi,
  IKeyStorageOps,
  ILogger,
  DeviceLifecycleDeps,
  // Device info
  DeviceInfo,
  DeviceMetadata,
  // Results
  InitializationResult,
  StaleCheckResult,
  RegistrationResult,
  // Progress
  RegistrationStage,
  RegistrationProgress,
  OnProgress,
  // Options
  RegisterDeviceOptions,
  HandleStaleDeviceOptions,
  // State machine
  DeviceChoice,
  DeviceRegistrationState,
  VerifiedInitializationResult,
  ActionResult,
} from './lifecycle';
