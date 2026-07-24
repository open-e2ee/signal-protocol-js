/**
 * SESAME (Secure Encrypted Stored Authenticated Messaging Extension)
 *
 * @layer 2 - Orchestration
 * @implements ISesameManager
 *
 * Signal Protocol Section 7 - SESAME
 * Multi-device session management for encrypted asynchronous messaging.
 *
 * Key features:
 * - Per-device identity keys for security isolation
 * - Session convergence through receive-activated switching
 * - 3-phase message sending process
 * - Automatic session expiration and cleanup
 * - Retry request mechanism for failed decryption
 *
 * @see https://signal.org/docs/specifications/sesame/
 */

// Core SESAME manager
export {};
export { SesameManager, MAX_SEND_RETRIES } from './manager';
export type { IProtocolManager } from './manager';

// Session resolution shared with the lower session domain
export { SessionResolver } from '../session/session-resolver';
export type { DecryptionCandidate } from '../session/session-resolver';

// Types
export type {
  // ID types (plain types per Signal Protocol spec)
  UserID,
  DeviceID,
  SessionID,
  // ProtocolAddress is exported from the public package
  // Configuration
  SesameConfig,
  // Records
  DeviceRecord,
  UserRecord,
  // Messages
  SesameMessage,
  RetryRequest,
  RetryResult,
  // Device list
  DeviceListResponse,
  PreKeyBundleData,
  // Manager interface
  ISesameManager,
  // Send options
  SesameSendOptions,
  // Statistics
  SesameStats,
  // Storage interface
  ISesameStorage,
} from './types';

// Enums, constants, and helpers
export {
  RetryReason,
  DEFAULT_SESAME_CONFIG,
  MIN_DEVICE_ID,
  MAX_DEVICE_ID,
  // Session record helpers (SESAME integration)
  createSesameSessionRecord,
  updateSessionRecordAfterSend,
  updateSessionRecordAfterReceive,
  getSessionMetadata,
} from './types';

// Error classes
export {
  SesameError,
  NoActiveSessionError,
  DecryptionFailedError,
  StaleDeviceListError,
  SessionExpiredError,
  SesameDeviceNotFoundError,
  SesameSessionNotFoundError,
  SesameDecryptionError,
} from './types';

// Configuration validation
export { validateSesameConfig, assertValidSesameConfig, SesameConfigError } from './validation';
export type { SesameConfigValidation } from './validation';

// Multi-device session utilities (app-level SESAME operations)
export {
  // Device discovery
  getActiveDevices,
  // Session establishment
  establishMultiDeviceSessions,
  establishDeviceSession,
  // Multi-device encryption
  encryptForAllDevices,
  encryptForDevice,
  // Session management
  checkDeviceSessions,
  deleteAllDeviceSessions,
} from './device-registry';

// Multi-device types
export type {
  DevicePreKeyBundle,
  DeviceMessage,
  MultiDeviceSessionResult,
  MultiDeviceEncryptionResult,
} from './device-registry';
