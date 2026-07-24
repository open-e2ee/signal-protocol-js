/**
 * Device Lifecycle Types
 *
 * Interfaces for device registration, stale detection, and re-registration.
 * Extracted from host lifecycle for testability.
 *
 * @see lib/device/host lifecycle
 */

import type { IdentityType } from '../../keys/types';
import type { IdentityKeyPair } from '../../keys';

// ============================================================================
// Dependency Interfaces (for Dependency Injection)
// ============================================================================

/**
 * SecureStore operations required by DeviceLifecycleManager.
 * Matches expo-secure-store API for production use.
 */
export {};
export interface ISecureStore {
  getItemAsync(key: string): Promise<string | null>;
  setItemAsync(key: string, value: string): Promise<void>;
  deleteItemAsync(key: string): Promise<void>;
}

/**
 * Convex client operations required by DeviceLifecycleManager.
 * Abstracts Convex React client for testability.
 */
export interface IConvexClient {
  query<T>(func: unknown, args: unknown): Promise<T>;
  mutation<T>(func: unknown, args: unknown): Promise<T>;
}

/**
 * App-owned Convex function references required by DeviceLifecycleManager.
 *
 * Kept as opaque values because the manager only forwards them to the injected
 * Convex client; it does not depend on generated Convex types directly.
 */
export interface DeviceLifecycleApi {
  devices: {
    getDevices: unknown;
    registerDevice: unknown;
    removeDevice: unknown;
    getDeviceByIdfv: unknown;
    unlinkSecondaryDevices: unknown;
    unlinkAllDevices: unknown;
  };
  keys: {
    getIdentityKey: unknown;
  };
}

/**
 * KeyStorage operations for crypto state cleanup.
 * Called when device becomes stale and needs re-registration.
 */
export interface IKeyStorageOps {
  /** Clear all sessions (per SESAME spec: old sessions invalid after re-registration) */
  clearAllSessions(): Promise<void>;
  /** Clear all message records (orphaned after session clear) */
  clearAllMessageRecords(): Promise<number>;
  /** Get the local identity public key (base64-encoded) */
  getIdentityPublicKey?(): Promise<string | null>;
  /** Get the local identity key pair for decrypting encrypted device names */
  getIdentityKey?(identityType: IdentityType): Promise<IdentityKeyPair | null>;
  /** Check if identity key exists for the given type (generated at registration) */
  hasIdentityKey?(identityType: IdentityType): Promise<boolean>;
  /** Generate and store a new identity key pair (generated at registration) */
  generateAndStoreIdentityKey?(identityType: IdentityType): Promise<{ publicKey: string }>;
}

/**
 * Logger interface for DeviceLifecycleManager.
 * Matches lib/logger API.
 */
export interface ILogger {
  debug(message: string, meta?: { category?: string; data?: Record<string, unknown> }): void;
  info(message: string, meta?: { category?: string; data?: Record<string, unknown> }): void;
  warn(
    message: string,
    meta?: { category?: string; error?: Error; data?: Record<string, unknown> }
  ): void;
  error(
    message: string,
    meta?: { category?: string; error?: Error; data?: Record<string, unknown> }
  ): void;
  breadcrumb(
    message: string,
    meta?: { category?: string; level?: string; data?: Record<string, unknown> }
  ): void;
}

/**
 * Dependencies injected into DeviceLifecycleManager.
 * All dependencies are injectable for verifiability and platform composition.
 */
export interface DeviceLifecycleDeps {
  /** SecureStore for device ID persistence */
  secureStore: ISecureStore;
  /** Convex client for backend operations */
  convex: IConvexClient;
  /** App-owned Convex function references */
  api: DeviceLifecycleApi;
  /** KeyStorage for crypto cleanup */
  keyStorage: IKeyStorageOps;
  /** Logger instance */
  logger: ILogger;
  /** Device name generator (defaults to expo-device based) */
  generateDeviceName?: () => string;
  /** Device fingerprint getter (defaults to RNDeviceInfo.getUniqueId()) */
  getDeviceFingerprint?: () => Promise<string | undefined>;
  /** Identity types to generate keys for (defaults to ['aci']) */
  identityTypes?: readonly IdentityType[];
}

// ============================================================================
// Device Info Types
// ============================================================================

/**
 * Raw device info as returned from the server.
 * The server stores encrypted device names as bytes (v.bytes()).
 * Use `mapServerDeviceInfo()` in manager.ts to convert to local DeviceInfo.
 */
export interface ServerDeviceInfo {
  /** Device ID (1-5) */
  deviceId: number;
  /** Encrypted device name (server stores as bytes) */
  encryptedDeviceName?: ArrayBuffer;
  /** Device type */
  deviceType?: 'mobile' | 'desktop' | 'tablet' | 'web';
  /** Device completed setup (has keys) - false = soft deleted */
  registered: boolean;
  /** Secondary device linked to primary (always false for primary deviceId=1) */
  linked: boolean;
  /** Whether device can receive messages (user-controlled) */
  enabled: boolean;
  /** Whether device is currently online (system-controlled) */
  active: boolean;
  /** Last seen timestamp */
  lastSeen: number;
  /** Device creation timestamp */
  createdAt: number;
  /** Timestamp when linked (for non-primary devices) */
  linkedAt?: number;
  /** Platform (ios/android/web) */
  platform?: string;
  /** App version */
  appVersion?: string;
  /** OS version */
  osVersion?: string;
  /** Device fingerprint for reclaim (iOS IDFV / Android ID) */
  idfv?: string;
}

/**
 * Local device info used by UI and host lifecycle.
 * Contains plaintext deviceName (decrypted from server's encryptedDeviceName).
 */
export interface DeviceInfo {
  /** Device ID (1-5) */
  deviceId: number;
  /** Human-readable device name (e.g., "iPhone 15 Pro") — plaintext for local display */
  deviceName?: string;
  /** Device type */
  deviceType?: 'mobile' | 'desktop' | 'tablet' | 'web';
  /** Device completed setup (has keys) - false = soft deleted */
  registered: boolean;
  /** Secondary device linked to primary (always false for primary deviceId=1) */
  linked: boolean;
  /** Whether device can receive messages (user-controlled) */
  enabled: boolean;
  /** Whether device is currently online (system-controlled) */
  active: boolean;
  /** Last seen timestamp */
  lastSeen: number;
  /** Device creation timestamp */
  createdAt: number;
  /** Timestamp when linked (for non-primary devices) */
  linkedAt?: number;
  /** Platform (ios/android/web) */
  platform?: string;
  /** App version */
  appVersion?: string;
  /** OS version */
  osVersion?: string;
  /** Device fingerprint for reclaim (iOS IDFV / Android ID) */
  idfv?: string;
}

/**
 * Metadata fields that can be backfilled via heartbeat.
 */
export interface DeviceMetadata {
  idfv?: string;
  platform?: string;
  appVersion?: string;
  osVersion?: string;
}

// ============================================================================
// Result Types
// ============================================================================

/**
 * Result of device initialization.
 * Indicates how device was resolved: loaded from storage, newly registered, reclaimed via IDFV, or re-registered after stale detection.
 */
export type InitializationResult =
  | { status: 'loaded'; deviceId: number; deviceName: string | null }
  | { status: 'registered'; deviceId: number; deviceName: string }
  | { status: 'reclaimed'; deviceId: number; deviceName: string }
  | { status: 'stale-reregistered'; oldDeviceId: number; newDeviceId: number; deviceName: string };

/**
 * Result of stale device check.
 * Used to determine if re-registration is needed.
 *
 * Reasons:
 * - 'not-found': Device record doesn't exist in backend
 * - 'removed': Device exists but registered=false (soft deleted)
 * - 'unlinked': Secondary device exists but linked=false (detached from primary)
 * - 'disabled': Device exists but enabled=false (user paused message delivery)
 */
export type StaleCheckResult =
  | { stale: false; deviceId: number; deviceRecord: DeviceInfo }
  | { stale: true; reason: 'not-found' | 'removed' | 'unlinked' | 'disabled'; storedId: number };

/**
 * Result of device registration.
 */
export interface RegistrationResult {
  deviceId: number;
  deviceName: string;
  isPrimary: boolean;
  /** True if device was reclaimed via IDFV match (app reinstall on same physical device) */
  reclaimed: boolean;
}

// ============================================================================
// Progress Types
// ============================================================================

/**
 * Registration progress stages.
 */
export type RegistrationStage =
  | 'generating-name'
  | 'checking-devices'
  | 'registering'
  | 'saving'
  | 'complete';

/**
 * Progress callback for registration.
 */
export interface RegistrationProgress {
  stage: RegistrationStage;
  message: string;
}

/**
 * Progress callback type.
 */
export type OnProgress = (progress: RegistrationProgress) => void;

// ============================================================================
// Options Types
// ============================================================================

/**
 * Options for device registration.
 */
export interface RegisterDeviceOptions {
  /**
   * Force primary device registration/recovery.
   *
   * Auth-based registration only supports primary bootstrap/recovery. Secondary
   * devices must be provisioned from an existing device and should not call the
   * generic registration path directly.
   */
  forceDeviceId?: number;
  /** Progress callback */
  onProgress?: OnProgress;
}

/**
 * Options for stale device handling.
 */
export interface HandleStaleDeviceOptions {
  /** Progress callback */
  onProgress?: OnProgress;
}

// ============================================================================
// Device Registration State Machine Types
// ============================================================================

/**
 * Choice option for user during device registration.
 */
export interface DeviceChoice {
  /** Unique identifier for the choice */
  id: 'make_primary' | 'link_device';
  /** User-friendly title */
  title: string;
  /** Description of what happens when chosen */
  description: string;
  /** Whether this is a destructive action (will unlink other devices) */
  destructive?: boolean;
  /** Whether this requires QR code scanning */
  requiresQR?: boolean;
}

/**
 * Device registration state machine states.
 *
 * STATE 1: loading - Initial state while gathering data
 * STATE 2a: verified_return - IDFV matches, keys match → auto-proceed
 * STATE 2b: reclaim_reinstall - IDFV matches, no local key → reinstall reclaim
 * STATE 2c: key_mismatch - IDFV matches, keys differ → security alert
 * STATE 3: first_device - No devices exist → auto-register as primary
 * STATE 4: orphan_state - Devices exist but none are primary → reset needed
 * STATE 5: unknown_device - Unknown device, primary exists → user choice
 * STATE 6: orphaned_linked_device - Linked device with stale primary → attention needed
 * STATE 7: choice_required - User must make a choice
 * STATE 8: complete - Registration complete
 */
export type DeviceRegistrationState =
  | { status: 'loading' }
  | { status: 'verified_return'; deviceId: number; isPrimary: boolean }
  | { status: 'reclaim_reinstall'; deviceId: number; isPrimary: boolean }
  | { status: 'key_mismatch'; deviceId: number; isPrimary: boolean; serverKeyPrefix?: string }
  | { status: 'first_device' }
  | { status: 'orphan_state'; devices: DeviceInfo[] }
  | { status: 'unknown_device'; devices: DeviceInfo[]; hasPrimary: true }
  | { status: 'orphaned_linked_device'; deviceId: number }
  | { status: 'choice_required'; options: DeviceChoice[] }
  | { status: 'complete'; deviceId: number; isPrimary: boolean };

/**
 * Result of initializeWithVerification() method.
 * Extended from InitializationResult to include all state machine outcomes.
 */
export type VerifiedInitializationResult =
  | { status: 'complete'; deviceId: number; deviceName: string; isPrimary: boolean }
  | { status: 'user_choice_required'; state: DeviceRegistrationState };

/**
 * Result of action handlers (makePrimary, handleReinstallReclaim, etc.)
 */
export interface ActionResult {
  success: boolean;
  deviceId?: number;
  deviceName?: string;
  isPrimary?: boolean;
  error?: string;
}
