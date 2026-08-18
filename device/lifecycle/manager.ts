/**
 * DeviceLifecycleManager
 *
 * Manages device registration, stale detection, and re-registration.
 * Extracted from host lifecycle for testability.
 *
 * Key responsibilities:
 * - Load device ID from SecureStore
 * - Verify device exists in backend
 * - Detect stale devices (deleted or deactivated)
 * - Register new devices
 * - Clean up orphaned crypto keys on re-registration
 *
 * This class is framework-agnostic and can be used:
 * - In React via host lifecycle (thin wrapper)
 * - In local development with in-memory dependencies
 * - In background tasks or workers
 *
 * @see lib/device/host lifecycle - React wrapper
 */

import * as Device from 'expo-device';
import { Platform } from 'react-native';
import RNDeviceInfo from 'react-native-device-info';
import { DEVICE_ID_KEY, DEVICE_NAME_KEY, LOCAL_IDENTITY_KEY, MAX_DEVICES } from '../constants';
import { clearDeviceIdCache } from '../device-id';
import { decryptDeviceName } from '../device-name-crypto';
import type {
  ActionResult,
  DeviceChoice,
  DeviceInfo,
  DeviceLifecycleDeps,
  HandleStaleDeviceOptions,
  InitializationResult,
  OnProgress,
  RegisterDeviceOptions,
  RegistrationResult,
  ServerDeviceInfo,
  StaleCheckResult,
  VerifiedInitializationResult,
} from './types';
import type { IdentityKeyPair } from '../../keys';

export {};

/**
 * DeviceLifecycleManager handles device registration and stale detection.
 *
 * Usage:
 * ```typescript
 * const manager = new DeviceLifecycleManager(userId, {
 *   secureStore,
 *   convex,
 *   keyStorage,
 *   logger,
 * });
 *
 * const result = await manager.initialize();
 * if (result.status === 'stale-reregistered') {
 *   console.log(`Re-registered from ${result.oldDeviceId} to ${result.newDeviceId}`);
 * }
 * ```
 */
export class DeviceLifecycleManager {
  private userId: string;
  private deps: DeviceLifecycleDeps;

  constructor(userId: string, deps: DeviceLifecycleDeps) {
    this.userId = userId;
    this.deps = deps;
  }

  /**
   * Get the user ID this manager was created for.
   * Used to check if manager needs to be recreated for a different user.
   */
  getUserId(): string {
    return this.userId;
  }

  /**
   * Map a server device response to local DeviceInfo.
   * Converts `encryptedDeviceName` (bytes) to `deviceName` (string).
   */
  private async mapServerDeviceInfo(server: ServerDeviceInfo): Promise<DeviceInfo> {
    return {
      deviceId: server.deviceId,
      deviceName: server.encryptedDeviceName
        ? await this.decryptStoredDeviceName(server.encryptedDeviceName)
        : undefined,
      deviceType: server.deviceType,
      registered: server.registered,
      linked: server.linked,
      enabled: server.enabled,
      active: server.active,
      lastSeen: server.lastSeen,
      createdAt: server.createdAt,
      linkedAt: server.linkedAt,
      platform: server.platform,
      appVersion: server.appVersion,
      osVersion: server.osVersion,
      idfv: server.idfv,
    };
  }

  private async decryptStoredDeviceName(encrypted: ArrayBuffer): Promise<string | undefined> {
    const identityKey = await this.tryGetStoredIdentityKeyPairForDecryption();
    if (!identityKey) {
      return undefined;
    }

    try {
      return await decryptDeviceName(encrypted, identityKey.dhKey.privateKey);
    } catch (error) {
      this.deps.logger.warn('Failed to decrypt stored device name', {
        category: 'Device',
        error: error as Error,
      });
      return undefined;
    }
  }

  private async loadStoredIdentityKeyPair(): Promise<IdentityKeyPair | null> {
    return (await this.deps.keyStorage.getIdentityKey?.('aci')) ?? null;
  }

  private async tryGetStoredIdentityKeyPairForDecryption(): Promise<IdentityKeyPair | null> {
    try {
      return await this.loadStoredIdentityKeyPair();
    } catch (error) {
      this.deps.logger.warn('Failed to load local identity key pair for device-name decryption', {
        category: 'Device',
        error: error as Error,
      });
      return null;
    }
  }

  private createBackendStateError(operation: string, error: unknown): Error {
    const cause = error instanceof Error ? error : new Error(String(error));
    return new Error(`Failed to ${operation}: ${cause.message}`);
  }

  // ==========================================================================
  // Public API
  // ==========================================================================

  /**
   * Initialize device - load from storage or register new.
   *
   * Flow:
   * 1. Try to load device ID from SecureStore
   * 2. If found, verify it exists in backend
   * 3. If stale, clean up and re-register
   * 4. If not found, register new device
   *
   * @param onProgress - Optional progress callback
   * @returns Initialization result indicating how device was resolved
   */
  async initialize(onProgress?: OnProgress): Promise<InitializationResult> {
    // Step 1: Try to load from SecureStore
    const stored = await this.loadStoredDeviceId();

    if (stored) {
      // Step 2: Verify device still exists in backend
      const staleCheck = await this.checkDeviceStale(stored.deviceId);

      if (!staleCheck.stale) {
        // Device is valid, use it
        this.deps.logger.debug('Stored device ID verified', {
          category: 'Device',
          data: { deviceId: stored.deviceId },
        });
        return {
          status: 'loaded',
          deviceId: stored.deviceId,
          deviceName: stored.deviceName,
        };
      }

      // Step 3: Device is stale, handle re-registration
      this.deps.logger.warn('Stored device ID is stale, re-registering', {
        category: 'Device',
        data: { staleDeviceId: stored.deviceId, reason: staleCheck.reason },
      });

      const result = await this.handleStaleDevice(stored.deviceId, { onProgress });

      // Check if stale device was reclaimed via fingerprint (same physical device)
      if (result.reclaimed) {
        this.deps.logger.info('Stale device reclaimed via fingerprint', {
          category: 'Device',
          data: { oldDeviceId: stored.deviceId, reclaimedDeviceId: result.deviceId },
        });
        return {
          status: 'reclaimed',
          deviceId: result.deviceId,
          deviceName: result.deviceName,
        };
      }

      return {
        status: 'stale-reregistered',
        oldDeviceId: stored.deviceId,
        newDeviceId: result.deviceId,
        deviceName: result.deviceName,
      };
    }

    // Step 4: No stored device, register new (may reclaim via IDFV)
    this.deps.logger.debug('No stored device ID, registering new device', {
      category: 'Device',
    });

    const result = await this.registerDevice({ onProgress });

    // Check if device was reclaimed via fingerprint match
    if (result.reclaimed) {
      this.deps.logger.info('Device reclaimed via fingerprint', {
        category: 'Device',
        data: { deviceId: result.deviceId },
      });

      // Clear orphaned crypto state from previous installation
      // Server already cleared prekeys. Local sessions are now invalid
      await this.clearLocalCryptoState();

      return {
        status: 'reclaimed',
        deviceId: result.deviceId,
        deviceName: result.deviceName,
      };
    }

    return {
      status: 'registered',
      deviceId: result.deviceId,
      deviceName: result.deviceName,
    };
  }

  /**
   * Load device ID from SecureStore.
   *
   * @returns Device ID and name, or null if not stored
   */
  async loadStoredDeviceId(): Promise<{ deviceId: number; deviceName: string | null } | null> {
    try {
      const storedId = await this.deps.secureStore.getItemAsync(DEVICE_ID_KEY);
      const storedName = await this.deps.secureStore.getItemAsync(DEVICE_NAME_KEY);

      if (storedId) {
        const id = parseInt(storedId, 10);
        if (id >= 1 && id <= MAX_DEVICES) {
          return { deviceId: id, deviceName: storedName };
        }
        this.deps.logger.warn('Stored device ID out of range', {
          category: 'Device',
          data: { storedId: id },
        });
      }
      return null;
    } catch (error) {
      this.deps.logger.error('Failed to load device ID from SecureStore', {
        category: 'Device',
        error: error as Error,
      });
      return null;
    }
  }

  /**
   * Check if stored device ID is still valid in backend.
   *
   * A device is considered stale if:
   * - 'not-found': Device record does not exist in backend
   * - 'removed': Device exists but registered=false (soft deleted)
   * - 'unlinked': Secondary device exists but linked=false (detached from primary)
   * - 'disabled': Device exists but enabled=false (user paused message delivery)
   *
   * @param deviceId - Device ID to check
   * @returns Stale check result
   */
  async checkDeviceStale(deviceId: number): Promise<StaleCheckResult> {
    const devices = await this.fetchDevices(true); // Include disabled/unregistered

    const deviceRecord = devices.find((d) => d.deviceId === deviceId);

    if (!deviceRecord) {
      return { stale: true, reason: 'not-found', storedId: deviceId };
    }

    // Check registered (not soft deleted)
    if (!deviceRecord.registered) {
      return { stale: true, reason: 'removed', storedId: deviceId };
    }

    // Check linked for secondary devices (deviceId 2-5)
    if (deviceId !== 1 && !deviceRecord.linked) {
      return { stale: true, reason: 'unlinked', storedId: deviceId };
    }

    // Check enabled (not paused by user)
    if (!deviceRecord.enabled) {
      return { stale: true, reason: 'disabled', storedId: deviceId };
    }

    return { stale: false, deviceId, deviceRecord };
  }

  /**
   * Fetch all devices for current user from backend.
   *
   * @param includeDisabled - Include disabled or unregistered devices
   * @returns List of devices
   */
  async fetchDevices(includeDisabled = false): Promise<DeviceInfo[]> {
    try {
      const result = await this.deps.convex.query<ServerDeviceInfo[]>(
        this.deps.api.devices.getDevices,
        { userId: this.userId, includeDisabled }
      );
      return await Promise.all(result.map((d) => this.mapServerDeviceInfo(d)));
    } catch (error) {
      this.deps.logger.error('Failed to fetch devices', {
        category: 'Device',
        error: error as Error,
      });
      throw this.createBackendStateError('fetch devices from backend', error);
    }
  }

  /**
   * Register a new device with the backend.
   *
   * This path is intentionally limited to auth-based primary bootstrap and
   * primary recovery. Linked devices must already have been provisioned from an
   * existing device. They must not self-register from app auth alone.
   *
   * Uses the application-provided device fingerprint (or the platform value
   * returned by `react-native-device-info`) as a reclaim hint. If the backend
   * accepts that hint, it can reclaim an existing device instead of allocating
   * another one. Fingerprint stability varies by platform, install lifecycle,
   * backup policy, and application configuration. It is not an authentication
   * credential by itself.
   *
   * @param options - Registration options
   * @returns Registration result
   */
  async registerDevice(options: RegisterDeviceOptions = {}): Promise<RegistrationResult> {
    const { forceDeviceId, onProgress } = options;

    // Step 1: Generate device name
    onProgress?.({ stage: 'generating-name', message: 'Generating device name...' });
    this.deps.logger.breadcrumb('Generating device name', {
      category: 'Device',
      level: 'info',
    });
    const name = this.generateDeviceName();

    // Step 2: Get device fingerprint for reclaim detection
    // Typical implementations use IDFV on iOS and Android ID on Android.
    // Their reset and persistence behavior is platform-dependent.
    let idfv: string | undefined;
    try {
      if (this.deps.getDeviceFingerprint) {
        idfv = await this.deps.getDeviceFingerprint();
      } else {
        idfv = await RNDeviceInfo.getUniqueId();
      }
      this.deps.logger.debug('Got device fingerprint for reclaim detection', {
        category: 'Device',
        data: {
          platform: Platform.OS,
          fingerprint: idfv ? idfv.slice(0, 8) + '...' : 'none',
        },
      });
    } catch (error) {
      this.deps.logger.warn('Failed to get device fingerprint (non-fatal)', {
        category: 'Device',
        error: error as Error,
      });
    }

    if (forceDeviceId !== undefined && forceDeviceId !== 1) {
      throw new Error(
        `Auth-based registration only supports primary device bootstrap/recovery. ` +
          `Linked device ${forceDeviceId} must be provisioned from an existing device.`
      );
    }

    // Step 3: Check existing devices to determine if primary
    onProgress?.({ stage: 'checking-devices', message: 'Checking existing devices...' });
    const existingDevices = await this.fetchDevices(true);
    const registeredDevices = existingDevices.filter((device) => device.registered);
    const primaryDevice = registeredDevices.find((device) => device.deviceId === 1);
    const matchedDeviceByFingerprint = idfv
      ? registeredDevices.find((device) => device.idfv === idfv)
      : undefined;

    if (registeredDevices.length > 0 && forceDeviceId !== 1) {
      if (matchedDeviceByFingerprint?.deviceId === 1) {
        this.deps.logger.info('Allowing primary reclaim via fingerprint match', {
          category: 'Device',
          data: { deviceId: matchedDeviceByFingerprint.deviceId },
        });
      } else if (matchedDeviceByFingerprint) {
        throw new Error(
          `Linked device ${matchedDeviceByFingerprint.deviceId} cannot self-register after reinstall. ` +
            'Re-link this device from your primary device via QR provisioning.'
        );
      } else if (primaryDevice) {
        throw new Error(
          'This account already has a primary device. Use QR linking to add this device, ' +
            'or use makePrimary() to replace the existing device set.'
        );
      } else {
        throw new Error(
          'This account has registered devices but no active primary device. ' +
            'Use makePrimary() to reset the account on this device.'
        );
      }
    }

    const isPrimary = forceDeviceId === 1 || registeredDevices.length === 0;

    // Step 4: Register with backend (may reclaim existing device via IDFV)
    onProgress?.({ stage: 'registering', message: 'Registering with server...' });
    this.deps.logger.breadcrumb('Registering device with server', {
      category: 'Device',
      level: 'info',
      data: { deviceName: name, platform: Platform.OS, hasIdfv: !!idfv },
    });

    const deviceType = this.getDeviceType();
    const deviceIdToUse = forceDeviceId ?? (isPrimary ? 1 : undefined);

    // Get app metadata for device registry
    const platform = Platform.OS; // "ios" | "android"
    const osVersion = Device.osVersion ?? undefined;
    let appVersion: string | undefined;
    try {
      appVersion = RNDeviceInfo.getVersion();
    } catch {
      // Non-fatal - app version is optional metadata
    }

    const result = await this.deps.convex.mutation<{ deviceId: number; reclaimed: boolean }>(
      this.deps.api.devices.registerDevice,
      {
        // userId derived server-side from JWT auth
        deviceId: deviceIdToUse,
        deviceType,
        idfv,
        platform,
        appVersion,
        osVersion,
      }
    );

    // Step 5: Save to secure storage
    onProgress?.({ stage: 'saving', message: 'Saving device credentials...' });
    this.deps.logger.breadcrumb('Saving device ID to SecureStore', {
      category: 'Device',
      level: 'info',
      data: { deviceId: result.deviceId, reclaimed: result.reclaimed },
    });

    await this.saveDeviceId(result.deviceId, name);

    // Generate identity keys at registration time.
    await this.ensureIdentityKeys(result.deviceId);

    const logMsg = result.reclaimed
      ? 'Device reclaimed via IDFV successfully'
      : 'Device registered successfully';
    onProgress?.({ stage: 'complete', message: logMsg });
    this.deps.logger.info(logMsg, {
      category: 'Device',
      data: {
        deviceId: result.deviceId,
        deviceName: name,
        isPrimary: result.deviceId === 1,
        reclaimed: result.reclaimed,
      },
    });

    return {
      deviceId: result.deviceId,
      deviceName: name,
      isPrimary: result.deviceId === 1,
      reclaimed: result.reclaimed,
    };
  }

  /**
   * Handle stale device: cleanup and re-register.
   *
   * Per SESAME spec: when device state is deleted, old sessions become invalid.
   * Primary devices can self-recover. Linked devices must be re-linked via QR.
   *
   * @param staleDeviceId - The stale device ID
   * @param options - Options for handling
   * @returns New registration result
   */
  async handleStaleDevice(
    staleDeviceId: number,
    options: HandleStaleDeviceOptions = {}
  ): Promise<RegistrationResult> {
    const { onProgress } = options;

    // Step 1: Clean up orphaned keys in backend
    await this.cleanupOrphanedKeys(staleDeviceId);

    // Step 2: Clear local SecureStore
    await this.clearLocalDevice();

    // Step 3: Clear local crypto state (sessions + message records)
    await this.clearLocalCryptoState();

    if (staleDeviceId !== 1) {
      throw new Error(
        `Linked device ${staleDeviceId} is stale and cannot self-re-register. ` +
          'Re-link this device from your primary device via QR provisioning.'
      );
    }

    // Step 4: Register new device
    return this.registerDevice({ onProgress });
  }

  /**
   * Clear device from local storage.
   * Used for resets or stale-device cleanup.
   */
  async clearLocalDevice(): Promise<void> {
    try {
      await this.deps.secureStore.deleteItemAsync(DEVICE_ID_KEY);
      await this.deps.secureStore.deleteItemAsync(DEVICE_NAME_KEY);
      clearDeviceIdCache();
      this.deps.logger.debug('Cleared local device data', { category: 'Device' });
    } catch (error) {
      this.deps.logger.error('Failed to clear local device', {
        category: 'Device',
        error: error as Error,
      });
      throw error;
    }
  }

  /**
   * Verify device is active and exists.
   *
   * @param deviceId - Device ID to verify
   * @returns True if device exists and is active
   */
  async verifyDevice(deviceId: number): Promise<boolean> {
    const result = await this.checkDeviceStale(deviceId);
    return !result.stale;
  }

  // ==========================================================================
  // Private Methods
  // ==========================================================================

  /**
   * Generate a human-readable device name.
   */
  private generateDeviceName(): string {
    // Allow a custom generator for deterministic integrations.
    if (this.deps.generateDeviceName) {
      return this.deps.generateDeviceName();
    }

    const deviceType = Device.deviceType;
    const modelName = Device.modelName || 'Unknown Device';
    const osName = Platform.OS === 'ios' ? 'iPhone' : 'Android';

    if (deviceType === Device.DeviceType.PHONE) {
      return modelName;
    } else if (deviceType === Device.DeviceType.TABLET) {
      return `${modelName} (Tablet)`;
    } else if (deviceType === Device.DeviceType.DESKTOP) {
      return `${modelName} (Desktop)`;
    } else {
      return `${osName} Device`;
    }
  }

  /**
   * Get device type for backend registration.
   */
  private getDeviceType(): 'mobile' | 'tablet' | 'desktop' {
    if (Device.deviceType === Device.DeviceType.TABLET) {
      return 'tablet';
    } else if (Device.deviceType === Device.DeviceType.DESKTOP) {
      return 'desktop';
    }
    return 'mobile';
  }

  /**
   * Save device ID to SecureStore.
   */
  private async saveDeviceId(id: number, name: string): Promise<void> {
    try {
      await this.deps.secureStore.setItemAsync(DEVICE_ID_KEY, id.toString());
      await this.deps.secureStore.setItemAsync(DEVICE_NAME_KEY, name);
    } catch (error) {
      this.deps.logger.error('Failed to save device ID to SecureStore', {
        category: 'Device',
        error: error as Error,
        data: { deviceId: id, deviceName: name },
      });
      throw error;
    }
  }

  /**
   * Clean up orphaned keys in backend for stale device.
   * Non-fatal - continues even if cleanup fails.
   */
  private async cleanupOrphanedKeys(staleDeviceId: number): Promise<void> {
    try {
      await this.deps.convex.mutation(this.deps.api.devices.removeDevice, {
        deviceId: staleDeviceId,
      });
      this.deps.logger.debug('Cleaned up orphaned keys for stale device', {
        category: 'Device',
        data: { staleDeviceId },
      });
    } catch (error) {
      // Non-fatal - log and continue
      this.deps.logger.warn('Failed to clean up orphaned keys (non-fatal)', {
        category: 'Device',
        error: error instanceof Error ? error : new Error('Unknown error'),
      });
    }
  }

  /**
   * Clear local crypto state (sessions and message records).
   * Per SESAME spec: when device state is deleted, old sessions become invalid.
   */
  private async clearLocalCryptoState(): Promise<void> {
    try {
      await this.deps.keyStorage.clearAllSessions();
      await this.deps.keyStorage.clearAllMessageRecords();
      this.deps.logger.debug('Cleared stale sessions and message records', {
        category: 'Device',
      });
    } catch (error) {
      // Non-fatal - log and continue
      this.deps.logger.warn('Failed to clear stale crypto data (non-fatal)', {
        category: 'Device',
        error: error instanceof Error ? error : new Error('Unknown error'),
      });
    }
  }

  /**
   * Create identity keys for every identity type if they are missing.
   * Generates and stores keys if missing (generate at registration).
   * Saves ACI public key to SecureStore for device verification on subsequent launches.
   */
  private async ensureIdentityKeys(deviceId: number): Promise<void> {
    if (!this.deps.keyStorage.hasIdentityKey || !this.deps.keyStorage.generateAndStoreIdentityKey) {
      return; // Methods not available (e.g., in tests with minimal mocks)
    }

    try {
      const allowIdentityGeneration = deviceId === 1;

      for (const identityType of this.deps.identityTypes ?? (['aci'] as const)) {
        const hasKey = await this.deps.keyStorage.hasIdentityKey(identityType);
        if (!hasKey) {
          if (!allowIdentityGeneration) {
            this.deps.logger.warn(
              'Linked device registration requires a provisioned identity key',
              {
                category: 'Device',
                data: { deviceId, identityType },
              }
            );
            continue;
          }

          this.deps.logger.info('Generating identity key at registration', {
            category: 'Device',
            data: { deviceId, identityType },
          });
          const { publicKey } =
            await this.deps.keyStorage.generateAndStoreIdentityKey(identityType);
          if (identityType === 'aci') {
            await this.saveLocalIdentityKey(publicKey);
          }
        } else if (identityType === 'aci') {
          // Key exists in SQLite but may be missing from SecureStore
          // (e.g., after reinstall reclaim clears SecureStore but keeps SQLite)
          const secureStoreKey = await this.getLocalIdentityKey();
          if (!secureStoreKey && this.deps.keyStorage.getIdentityPublicKey) {
            const publicKey = await this.deps.keyStorage.getIdentityPublicKey();
            if (publicKey) {
              await this.saveLocalIdentityKey(publicKey);
              this.deps.logger.info('Synced existing identity key to SecureStore', {
                category: 'Device',
                data: { keyPrefix: publicKey.slice(0, 8) + '...' },
              });
            }
          }
        }
      }
    } catch (error) {
      // Non-fatal for primary-device bootstrap. Linked devices must already have
      // imported identity state and will fail fast later if that is missing.
      this.deps.logger.warn('Failed to prepare identity keys at registration (non-fatal)', {
        category: 'Device',
        error: error instanceof Error ? error : new Error('Unknown error'),
      });
    }
  }

  // ==========================================================================
  // Identity Key Verification Methods
  // ==========================================================================

  /**
   * Get local identity public key from SecureStore.
   * Returns null if not stored (fresh install or cleared).
   */
  async getLocalIdentityKey(): Promise<string | null> {
    try {
      return await this.deps.secureStore.getItemAsync(LOCAL_IDENTITY_KEY);
    } catch (error) {
      this.deps.logger.warn('Failed to get local identity key', {
        category: 'Device',
        error: error as Error,
      });
      return null;
    }
  }

  /**
   * Get the server's account identity public key.
   * Returns null if the account is not registered or no key was uploaded.
   */
  async getServerIdentityKey(): Promise<string | null> {
    try {
      const key = await this.deps.convex.query<string | null>(this.deps.api.keys.getIdentityKey, {
        userId: this.userId,
        identityType: 'aci',
      });
      return key;
    } catch (error) {
      this.deps.logger.error('Failed to get server identity key', {
        category: 'Device',
        error: error as Error,
      });
      throw this.createBackendStateError('fetch server identity key', error);
    }
  }

  /**
   * Clear local identity key from SecureStore.
   * Called during reset or key mismatch handling.
   */
  async clearLocalIdentityKey(): Promise<void> {
    try {
      await this.deps.secureStore.deleteItemAsync(LOCAL_IDENTITY_KEY);
      this.deps.logger.debug('Cleared local identity key', { category: 'Device' });
    } catch (error) {
      this.deps.logger.warn('Failed to clear local identity key (non-fatal)', {
        category: 'Device',
        error: error as Error,
      });
    }
  }

  /**
   * Save local identity public key to SecureStore.
   * Called after SignalProtocolClient generates identity keys.
   * This is CRITICAL for verifying device on subsequent app launches.
   *
   * @param publicKey - Base64-encoded X25519 public key
   */
  async saveLocalIdentityKey(publicKey: string): Promise<void> {
    try {
      await this.deps.secureStore.setItemAsync(LOCAL_IDENTITY_KEY, publicKey);
      this.deps.logger.info('Saved local identity key', {
        category: 'Device',
        data: { keyPrefix: publicKey.slice(0, 8) + '...' },
      });
    } catch (error) {
      this.deps.logger.error('Failed to save local identity key', {
        category: 'Device',
        error: error as Error,
      });
      throw error;
    }
  }

  /**
   * Get device fingerprint (IDFV on iOS, Android ID on Android).
   */
  private async getDeviceFingerprint(): Promise<string | undefined> {
    try {
      if (this.deps.getDeviceFingerprint) {
        return await this.deps.getDeviceFingerprint();
      }
      return await RNDeviceInfo.getUniqueId();
    } catch (error) {
      this.deps.logger.warn('Failed to get device fingerprint', {
        category: 'Device',
        error: error as Error,
      });
      return undefined;
    }
  }

  /**
   * Get device by IDFV from server.
   */
  private async getDeviceByIdfv(idfv: string): Promise<DeviceInfo | null> {
    try {
      const device = await this.deps.convex.query<ServerDeviceInfo | null>(
        this.deps.api.devices.getDeviceByIdfv,
        { idfv }
      );
      return device ? this.mapServerDeviceInfo(device) : null;
    } catch (error) {
      this.deps.logger.error('Failed to query device by fingerprint', {
        category: 'Device',
        error: error as Error,
      });
      throw this.createBackendStateError('query device by fingerprint', error);
    }
  }

  // ==========================================================================
  // State Machine: initializeWithVerification
  // ==========================================================================

  /**
   * Initialize device with full identity key verification.
   *
   * This is the new recommended entry point that implements the full state machine:
   * 1. Get IDFV (device fingerprint)
   * 2. Get local identity key from SecureStore
   * 3. Query server for device by IDFV
   * 4. Get all devices, check hasPrimary
   * 5. Determine state based on IDFV match, key match, device presence
   *
   * For simple states (first_device, verified_return, reclaim_reinstall), auto-proceeds.
   * For complex states requiring user choice, returns the state for UI handling.
   *
   * @param onProgress - Optional progress callback
   * @returns Result indicating completion or user choice needed
   */
  async initializeWithVerification(onProgress?: OnProgress): Promise<VerifiedInitializationResult> {
    this.deps.logger.debug('Starting initializeWithVerification', { category: 'Device' });

    // Step 1: Get device fingerprint (IDFV)
    const idfv = await this.getDeviceFingerprint();
    this.deps.logger.debug('Got device fingerprint', {
      category: 'Device',
      data: { hasIdfv: !!idfv, prefix: idfv?.slice(0, 8) },
    });

    // Step 2: Get local identity key
    let localIdentityKey = await this.getLocalIdentityKey();
    let localIdentityPair: IdentityKeyPair | null = null;
    try {
      localIdentityPair = await this.loadStoredIdentityKeyPair();
    } catch (error) {
      this.deps.logger.warn(
        'Failed to load local identity key pair during verification; treating as missing local identity',
        {
          category: 'Device',
          error: error as Error,
        }
      );
    }

    if (localIdentityPair) {
      const localIdentityPublicKey = localIdentityPair.dhKey.publicKey;
      if (localIdentityKey !== localIdentityPublicKey) {
        const hadSecureStoreKey = !!localIdentityKey;
        localIdentityKey = localIdentityPublicKey;

        try {
          await this.saveLocalIdentityKey(localIdentityPublicKey);
          this.deps.logger.info(
            hadSecureStoreKey
              ? 'Repaired stale SecureStore identity key from local key pair'
              : 'Restored missing SecureStore identity key from local key pair',
            {
              category: 'Device',
              data: { keyPrefix: localIdentityPublicKey.slice(0, 8) + '...' },
            }
          );
        } catch (error) {
          this.deps.logger.warn('Failed to sync SecureStore identity key from local key pair', {
            category: 'Device',
            error: error as Error,
          });
        }
      }
    }

    const hasUsableLocalIdentity = !!localIdentityPair;
    this.deps.logger.debug('Got local identity key', {
      category: 'Device',
      data: { hasLocalKey: !!localIdentityKey, hasLocalKeyPair: hasUsableLocalIdentity },
    });

    // Step 3: Query server for device by IDFV
    let deviceByIdfv: DeviceInfo | null = null;
    if (idfv) {
      deviceByIdfv = await this.getDeviceByIdfv(idfv);
    }
    this.deps.logger.debug('IDFV device lookup result', {
      category: 'Device',
      data: {
        found: !!deviceByIdfv,
        deviceId: deviceByIdfv?.deviceId,
        active: deviceByIdfv?.active,
      },
    });

    // Step 4: Get all devices and determine hasPrimary
    const allDevices = await this.fetchDevices(true);
    // Filter to registered devices (not soft deleted)
    const registeredDevices = allDevices.filter((d) => d.registered);
    const primaryDevice = registeredDevices.find((d) => d.deviceId === 1);
    const hasPrimary = !!primaryDevice;

    this.deps.logger.debug('Device state analysis', {
      category: 'Device',
      data: {
        totalDevices: allDevices.length,
        registeredDevices: registeredDevices.length,
        hasPrimary,
      },
    });

    // Step 5: Determine state based on conditions

    // CASE A: IDFV matches an existing device
    if (deviceByIdfv) {
      const deviceId = deviceByIdfv.deviceId;
      const isPrimary = deviceId === 1;

      // Linked devices cannot self-reclaim after reinstall because they must
      // receive the shared account identity from an existing device.
      if (!hasUsableLocalIdentity && !isPrimary) {
        this.deps.logger.info('Linked device reinstall requires QR relink', {
          category: 'Device',
          data: { deviceId },
        });

        return {
          status: 'user_choice_required',
          state: { status: 'unknown_device', devices: registeredDevices, hasPrimary: true },
        };
      }

      // Get server identity key for this device
      const serverIdentityKey = await this.getServerIdentityKey();

      // STATE 2b: No local key (reinstall) → reclaim and re-register
      if (!hasUsableLocalIdentity) {
        this.deps.logger.info('STATE 2b: Reinstall detected (IDFV match, no usable local key)', {
          category: 'Device',
          data: { deviceId, isPrimary, hasLocalKey: !!localIdentityKey },
        });

        // Auto-handle reinstall reclaim
        const result = await this.handleReinstallReclaim(deviceId, isPrimary, onProgress);
        if (result.success && result.deviceId !== undefined) {
          return {
            status: 'complete',
            deviceId: result.deviceId,
            deviceName: result.deviceName ?? 'Unknown Device',
            isPrimary: result.isPrimary ?? false,
          };
        }

        // If reclaim failed, return error state
        return {
          status: 'user_choice_required',
          state: { status: 'reclaim_reinstall', deviceId, isPrimary },
        };
      }

      // STATE 2d: Device exists but no server identity key (incomplete registration)
      // This happens when device was registered but keys were never uploaded
      if (!serverIdentityKey) {
        if (!isPrimary) {
          this.deps.logger.info('Linked device without server identity requires QR relink', {
            category: 'Device',
            data: { deviceId, hasLocalKey: !!localIdentityKey },
          });

          return {
            status: 'user_choice_required',
            state: { status: 'unknown_device', devices: registeredDevices, hasPrimary: true },
          };
        }

        this.deps.logger.info('STATE 2d: Device exists but no server identity key', {
          category: 'Device',
          data: { deviceId, isPrimary, hasLocalKey: !!localIdentityKey },
        });

        // Treat as reinstall - clear local state and re-register
        const result = await this.handleReinstallReclaim(deviceId, isPrimary, onProgress);
        if (result.success && result.deviceId !== undefined) {
          return {
            status: 'complete',
            deviceId: result.deviceId,
            deviceName: result.deviceName ?? 'Unknown Device',
            isPrimary: result.isPrimary ?? false,
          };
        }

        // If reclaim failed, return error state
        return {
          status: 'user_choice_required',
          state: { status: 'reclaim_reinstall', deviceId, isPrimary },
        };
      }

      // STATE 2a: Keys match → verified return
      if (serverIdentityKey && localIdentityKey === serverIdentityKey && hasUsableLocalIdentity) {
        this.deps.logger.info('STATE 2a: Verified return (keys match)', {
          category: 'Device',
          data: { deviceId, isPrimary },
        });

        // Save device ID and proceed
        const stored = await this.loadStoredDeviceId();
        if (!stored || stored.deviceId !== deviceId) {
          await this.saveDeviceId(deviceId, deviceByIdfv.deviceName ?? this.generateDeviceName());
        }

        return {
          status: 'complete',
          deviceId,
          deviceName: deviceByIdfv.deviceName ?? 'Unknown Device',
          isPrimary,
        };
      }

      // STATE 2c: Keys differ → security concern
      if (serverIdentityKey && localIdentityKey !== serverIdentityKey) {
        const localKeyPrefix = localIdentityKey?.slice(0, 8) ?? 'missing';
        this.deps.logger.warn('STATE 2c: Key mismatch detected', {
          category: 'Device',
          data: {
            deviceId,
            isPrimary,
            localKeyPrefix,
            serverKeyPrefix: serverIdentityKey.slice(0, 8),
          },
        });

        return {
          status: 'user_choice_required',
          state: {
            status: 'key_mismatch',
            deviceId,
            isPrimary,
            serverKeyPrefix: serverIdentityKey.slice(0, 8),
          },
        };
      }
    }

    // CASE B: No IDFV match (unknown device)

    // STATE 3: First device (no devices exist)
    if (registeredDevices.length === 0) {
      this.deps.logger.info('STATE 3: First device', { category: 'Device' });

      // Auto-register as primary
      const result = await this.registerDevice({ onProgress });
      return {
        status: 'complete',
        deviceId: result.deviceId,
        deviceName: result.deviceName,
        isPrimary: result.isPrimary,
      };
    }

    // STATE 4: Orphan state (devices exist but no primary)
    if (!hasPrimary) {
      this.deps.logger.info('STATE 4: Orphan state (no primary)', {
        category: 'Device',
        data: { deviceCount: registeredDevices.length },
      });

      return {
        status: 'user_choice_required',
        state: { status: 'orphan_state', devices: registeredDevices },
      };
    }

    // Check if this is an orphaned linked device (has stored ID but no matching device)
    const storedDevice = await this.loadStoredDeviceId();
    if (storedDevice && storedDevice.deviceId !== 1) {
      const matchingDevice = registeredDevices.find((d) => d.deviceId === storedDevice.deviceId);
      if (!matchingDevice) {
        // STATE 6: Orphaned linked device
        this.deps.logger.info('STATE 6: Orphaned linked device', {
          category: 'Device',
          data: { storedDeviceId: storedDevice.deviceId },
        });

        return {
          status: 'user_choice_required',
          state: { status: 'orphaned_linked_device', deviceId: storedDevice.deviceId },
        };
      }
    }

    // STATE 5: Unknown device with primary exists → user choice required
    this.deps.logger.info('STATE 5: Unknown device (primary exists)', {
      category: 'Device',
      data: { deviceCount: registeredDevices.length },
    });

    return {
      status: 'user_choice_required',
      state: { status: 'unknown_device', devices: registeredDevices, hasPrimary: true },
    };
  }

  // ==========================================================================
  // Action Handlers
  // ==========================================================================

  /**
   * Handle reinstall reclaim (STATE 2b).
   * IDFV matches but no local identity key → user reinstalled app.
   *
   * Actions:
   * 1. Clear local crypto state (sessions invalid after reinstall)
   * 2. If primary device, unlink secondary devices
   * 3. Re-register device to get fresh keys
   */
  async handleReinstallReclaim(
    deviceId: number,
    isPrimary: boolean,
    onProgress?: OnProgress
  ): Promise<ActionResult> {
    try {
      this.deps.logger.info('Handling reinstall reclaim', {
        category: 'Device',
        data: { deviceId, isPrimary },
      });

      // Step 1: Clear local crypto state
      await this.clearLocalCryptoState();
      await this.clearLocalIdentityKey();

      // Step 2: If primary, unlink secondary devices (their sessions are now invalid)
      if (isPrimary) {
        try {
          await this.deps.convex.mutation(this.deps.api.devices.unlinkSecondaryDevices, {});
          this.deps.logger.info('Unlinked secondary devices after primary reinstall', {
            category: 'Device',
          });
        } catch (error) {
          this.deps.logger.warn('Failed to unlink secondary devices (non-fatal)', {
            category: 'Device',
            error: error as Error,
          });
        }
      }

      // Step 3: Register device (will reclaim via IDFV)
      const result = await this.registerDevice({
        forceDeviceId: deviceId,
        onProgress,
      });

      return {
        success: true,
        deviceId: result.deviceId,
        deviceName: result.deviceName,
        isPrimary: result.isPrimary,
      };
    } catch (error) {
      this.deps.logger.error('Failed to handle reinstall reclaim', {
        category: 'Device',
        error: error as Error,
      });
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Make this device the primary device.
   * Used for STATE 5 (unknown device) and STATE 4 (orphan state).
   *
   * Actions:
   * 1. Unlink all existing devices
   * 2. Clear local crypto state
   * 3. Register as primary device (deviceId = 1)
   */
  async makePrimary(onProgress?: OnProgress): Promise<ActionResult> {
    try {
      this.deps.logger.info('Making this device primary', { category: 'Device' });

      // Step 1: Unlink all existing devices
      await this.deps.convex.mutation(this.deps.api.devices.unlinkAllDevices, {});
      this.deps.logger.info('Unlinked all existing devices', { category: 'Device' });

      // Step 2: Clear local crypto state
      await this.clearLocalCryptoState();
      await this.clearLocalDevice();

      // Step 3: Register as primary
      const result = await this.registerDevice({
        forceDeviceId: 1,
        onProgress,
      });

      return {
        success: true,
        deviceId: result.deviceId,
        deviceName: result.deviceName,
        isPrimary: true,
      };
    } catch (error) {
      this.deps.logger.error('Failed to make device primary', {
        category: 'Device',
        error: error as Error,
      });
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Handle key mismatch by resetting and making this device primary.
   * Used for STATE 2c.
   *
   * Actions:
   * 1. Unlink all existing devices
   * 2. Clear local crypto state and identity key
   * 3. Register as primary device with new keys
   */
  async handleKeyMismatchReset(onProgress?: OnProgress): Promise<ActionResult> {
    try {
      this.deps.logger.warn('Handling key mismatch reset', { category: 'Device' });

      // Step 1: Unlink all existing devices
      await this.deps.convex.mutation(this.deps.api.devices.unlinkAllDevices, {});

      // Step 2: Clear local crypto state
      await this.clearLocalCryptoState();
      await this.clearLocalIdentityKey();
      await this.clearLocalDevice();

      // Step 3: Register as primary
      const result = await this.registerDevice({
        forceDeviceId: 1,
        onProgress,
      });

      return {
        success: true,
        deviceId: result.deviceId,
        deviceName: result.deviceName,
        isPrimary: true,
      };
    } catch (error) {
      this.deps.logger.error('Failed to handle key mismatch reset', {
        category: 'Device',
        error: error as Error,
      });
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Handle orphaned linked device by re-linking.
   * Used for STATE 6.
   *
   * Actions:
   * 1. Clear local device data
   * 2. Clear local crypto state
   * 3. Return user_choice_required for QR code linking flow
   *
   * Note: This does not complete registration - user needs to scan QR code.
   */
  async handleOrphanedLinkedDevice(): Promise<ActionResult> {
    try {
      this.deps.logger.info('Handling orphaned linked device', { category: 'Device' });

      // Clear local state
      await this.clearLocalCryptoState();
      await this.clearLocalDevice();

      // Return success but no deviceId - user needs to complete linking flow
      return {
        success: true,
        // No deviceId - user must complete QR code flow
      };
    } catch (error) {
      this.deps.logger.error('Failed to handle orphaned linked device', {
        category: 'Device',
        error: error as Error,
      });
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Get choices for unknown device state (STATE 5).
   */
  getUnknownDeviceChoices(): DeviceChoice[] {
    return [
      {
        id: 'make_primary',
        title: 'Make this my primary device',
        description:
          'This will sign out all other devices. Use this if you no longer have access to your previous devices.',
        destructive: true,
      },
      {
        id: 'link_device',
        title: 'Link this device',
        description: 'Scan a QR code on your primary device to securely link this device.',
        requiresQR: true,
      },
    ];
  }

  /**
   * Get choices for orphan state (STATE 4).
   */
  getOrphanStateChoices(): DeviceChoice[] {
    return [
      {
        id: 'make_primary',
        title: 'Reset account on this device',
        description:
          'Start fresh with this device as your primary. All previous devices will be signed out.',
        destructive: true,
      },
    ];
  }

  /**
   * Get choices for key mismatch state (STATE 2c).
   */
  getKeyMismatchChoices(): DeviceChoice[] {
    return [
      {
        id: 'make_primary',
        title: 'Reset & make this primary',
        description:
          'Clear mismatched keys and register this device as primary. All other devices will be signed out.',
        destructive: true,
      },
      {
        id: 'link_device',
        title: 'Link as new device',
        description: 'Scan a QR code on your primary device to link this as a new device instead.',
        requiresQR: true,
      },
    ];
  }
}
