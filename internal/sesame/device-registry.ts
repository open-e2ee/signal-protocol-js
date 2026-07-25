/**
 * Multi-Device Session Manager (SESAME-inspired)
 *
 * @module sesame/session-manager
 *
 * Manages Signal Protocol sessions across multiple devices for a user.
 * Implements the Signal Protocol SESAME session-management model, which handles
 * the complexity of multi-device end-to-end encryption.
 *
 * ## Overview
 *
 * In multi-device scenarios, each user can have up to 5 devices (deviceId 1-5),
 * and we need to maintain separate Signal Protocol sessions with each device.
 * When sending a message, it must be encrypted separately for each recipient device.
 *
 * ## Session ID Format
 *
 * Session IDs follow the format: `{userId}_{deviceId}`
 * - Example: `user_abc123_1` (primary device)
 * - Example: `user_abc123_2` (linked device)
 *
 * ## Key Responsibilities
 *
 * - **Session ID Management**: Generate and parse device-specific session IDs
 * - **Device Discovery**: Query backend for active devices
 * - **Session Establishment**: Establish sessions with all active devices
 * - **Multi-Device Encryption**: Encrypt messages for all recipient devices
 * - **Graceful Degradation**: Handle partial failures (some devices work, others fail)
 *
 * ## Usage Pattern
 *
 * ```typescript
 * // 1. Establish sessions with all devices when first messaging a user
 * const result = await establishMultiDeviceSessions(signal, relay, userId);
 *
 * // 2. Encrypt message for all devices
 * const encrypted = await encryptForAllDevices(signal, relay, userId, 'Hello!');
 *
 * // 3. Send each device-specific ciphertext
 * for (const { deviceId, ciphertext } of encrypted.messages) {
 *   await sendToDevice(userId, deviceId, ciphertext);
 * }
 * ```
 *
 * ## Design Decisions
 *
 * - **Per-device sessions**: Each device maintains its own Double Ratchet state
 * - **Lazy establishment**: Sessions are established on-demand when encrypting
 * - **Partial success**: Encryption can succeed for some devices even if others fail
 * - **Device limit**: Maximum 5 devices per user (configurable via backend)
 *
 * @see https://signal.org/docs/specifications/sesame/ - Signal Protocol SESAME specification
 * @see https://signal.org/blog/private-groups/ - Multi-device messaging architecture
 */

import type { SignalProtocolClient } from '../../client';
import type { Ciphertext } from '../../keys';
import type { ISignalRelayServer, DeviceInfo, PreKeyBundle } from '../../remote/relay/types';
import { ProtocolAddress } from '../../types/address';
import { defaultSignalLogger, type ILogger } from '../../logger';

/**
 * Device-specific prekey bundle
 */
export {};
export interface DevicePreKeyBundle extends PreKeyBundle {
  deviceId: number;
}

/**
 * Encrypted message for a specific device
 */
export interface DeviceMessage {
  deviceId: number;
  ciphertext: Ciphertext;
}

/**
 * Multi-device session result
 */
export interface MultiDeviceSessionResult {
  userId: string;
  establishedDevices: number[]; // Device IDs that were successfully established
  failedDevices: number[]; // Device IDs that failed
  /** Underlying per-device failures, omitted when a relay simply has no bundle. */
  failedDeviceErrors: Array<{ deviceId: number; error: Error }>;
  totalDevices: number;
}

/**
 * Multi-device encryption result
 */
export interface MultiDeviceEncryptionResult {
  userId: string;
  messages: DeviceMessage[]; // Encrypted messages per device
  successfulDevices: number[]; // Device IDs that were successfully encrypted
  failedDevices: number[]; // Device IDs that failed
  totalDevices: number;
}

// ============================================================================
// Session ID Utilities
// ============================================================================

/**
 * Create a ProtocolAddress for a user's device
 *
 * @param userId - Target user ID
 * @param deviceId - Target device ID (1-5)
 * @returns ProtocolAddress for the device
 *
 * @example
 * ```typescript
 * const address = createDeviceAddress('user_abc123', 2);
 * // Returns: ProtocolAddress { userId: 'user_abc123', deviceId: 2 }
 * ```
 */
export function createDeviceAddress(userId: string, deviceId: number): ProtocolAddress {
  return ProtocolAddress.create(userId, deviceId);
}

// ============================================================================
// Device Discovery
// ============================================================================

/**
 * Get all active devices for a user
 *
 * Fetches device information from the backend to determine which devices
 * should receive messages.
 *
 * @param relay - Signal Protocol relay server interface
 * @param userId - Target user ID
 * @returns Array of active device information
 */
export async function getActiveDevices(
  relay: ISignalRelayServer,
  userId: string,
  logger: Required<ILogger> = defaultSignalLogger
): Promise<DeviceInfo[]> {
  try {
    const devices = await relay.getDevices(userId);
    return devices;
  } catch (error) {
    logger.error('[MultiDevice] Failed to get active devices', {
      category: 'MultiDevice',
      error: error as Error,
      data: { userId },
    });
    throw error;
  }
}

// ============================================================================
// Session Establishment
// ============================================================================

/**
 * Establish sessions with all active devices for a user
 *
 * Fetches prekey bundles for all active devices and establishes sessions.
 * This is typically called once when first messaging a user, or when
 * they link a new device.
 *
 * @param signal - SignalProtocolClient instance
 * @param relay - Signal Protocol relay server interface
 * @param userId - Target user ID
 * @returns Result containing successful and failed device IDs
 *
 * @example
 * ```typescript
 * const result = await establishMultiDeviceSessions(signal, relay, 'user_abc123');
 * console.log(`Established ${result.establishedDevices.length}/${result.totalDevices} sessions`);
 * ```
 */
export async function establishMultiDeviceSessions(
  signal: SignalProtocolClient,
  relay: ISignalRelayServer,
  userId: string
): Promise<MultiDeviceSessionResult> {
  const logger = signal.logger;
  try {
    // First get all active devices
    const devices = await relay.getDevices(userId);

    // Use the current user (signal.userId) as the fetcher for rate limiting
    const fetcherUserId = signal.userId;
    const establishedDevices: number[] = [];
    const failedDevices: number[] = [];
    const failedDeviceErrors: Array<{ deviceId: number; error: Error }> = [];

    // Establish session for each device - check session BEFORE fetching bundle
    // This avoids unnecessary prekey fetches for devices that already have sessions
    for (const device of devices) {
      try {
        const remoteAddress = createDeviceAddress(userId, device.deviceId);

        // Check if session already exists BEFORE fetching bundle
        const hasExistingSession = await signal.hasSession(remoteAddress);
        if (hasExistingSession) {
          logger.info('[MultiDevice] Session already exists', {
            address: ProtocolAddress.toString(remoteAddress),
            deviceId: device.deviceId,
          });
          establishedDevices.push(device.deviceId);
          continue;
        }

        // Only fetch bundle for devices WITHOUT existing sessions
        const bundle = await relay.fetchPreKeyBundle(userId, device.deviceId, fetcherUserId);
        if (!bundle) {
          logger.warn('[MultiDevice] No bundle available', {
            userId,
            deviceId: device.deviceId,
          });
          failedDevices.push(device.deviceId);
          continue;
        }

        // Establish new session
        await signal.establishSession(remoteAddress, bundle);
        establishedDevices.push(device.deviceId);
        logger.info('[MultiDevice] Session established', {
          address: ProtocolAddress.toString(remoteAddress),
          deviceId: device.deviceId,
        });
      } catch (error) {
        const normalizedError =
          error instanceof Error ? error : new Error(String(error));
        logger.error('[MultiDevice] Failed to establish session', {
          category: 'MultiDevice',
          error: normalizedError,
          data: { userId, deviceId: device.deviceId },
        });
        failedDevices.push(device.deviceId);
        failedDeviceErrors.push({ deviceId: device.deviceId, error: normalizedError });
      }
    }

    return {
      userId,
      establishedDevices,
      failedDevices,
      failedDeviceErrors,
      totalDevices: devices.length,
    };
  } catch (error) {
    logger.error('[MultiDevice] Failed to establish multi-device sessions', {
      category: 'MultiDevice',
      error: error as Error,
      data: { userId },
    });
    throw error;
  }
}

/**
 * Establish session with a specific device
 *
 * Fetches prekey bundle for a specific device and establishes session.
 * Useful when a new device is linked or when re-establishing a failed session.
 *
 * @param signal - SignalProtocolClient instance
 * @param relay - Signal Protocol relay server interface
 * @param userId - Target user ID
 * @param deviceId - Target device ID
 * @returns True if session was established, false if it already existed
 */
export async function establishDeviceSession(
  signal: SignalProtocolClient,
  relay: ISignalRelayServer,
  userId: string,
  deviceId: number
): Promise<boolean> {
  const logger = signal.logger;
  try {
    const remoteAddress = createDeviceAddress(userId, deviceId);

    // Check if session already exists
    const hasExistingSession = await signal.hasSession(remoteAddress);
    if (hasExistingSession) {
      logger.info('[MultiDevice] Session already exists', {
        address: ProtocolAddress.toString(remoteAddress),
        deviceId,
      });
      return false;
    }

    // Fetch prekey bundle for this device
    // Use the current user (signal.userId) as the fetcher for rate limiting
    const bundle = await relay.fetchPreKeyBundle(userId, deviceId, signal.userId);
    if (!bundle) {
      throw new Error(`No prekey bundle found for user ${userId} device ${deviceId}`);
    }

    // Establish session
    await signal.establishSession(remoteAddress, bundle);
    logger.info('[MultiDevice] Session established', {
      address: ProtocolAddress.toString(remoteAddress),
      deviceId,
    });

    return true;
  } catch (error) {
    logger.error('[MultiDevice] Failed to establish device session', {
      category: 'MultiDevice',
      error: error as Error,
      data: { userId, deviceId },
    });
    throw error;
  }
}

// ============================================================================
// Multi-Device Message Encryption
// ============================================================================

/**
 * Encrypt message for all active devices of a user
 *
 * Encrypts the same plaintext message for all active devices.
 * Each device gets its own encrypted copy using its own session.
 *
 * This function handles partial failures gracefully - if some devices fail,
 * the message will still be encrypted for successful devices.
 *
 * @param signal - SignalProtocolClient instance
 * @param relay - Signal Protocol relay server interface
 * @param userId - Target user ID
 * @param plaintext - Message to encrypt
 * @returns Result containing encrypted messages per device
 *
 * @example
 * ```typescript
 * const result = await encryptForAllDevices(signal, relay, 'user_abc123', 'Hello!');
 * console.log(`Encrypted for ${result.successfulDevices.length}/${result.totalDevices} devices`);
 *
 * // Send each device message to the backend
 * for (const deviceMsg of result.messages) {
 *   await sendMessage(userId, deviceMsg.deviceId, deviceMsg.ciphertext);
 * }
 * ```
 */
export async function encryptForAllDevices(
  signal: SignalProtocolClient,
  relay: ISignalRelayServer,
  userId: string,
  plaintext: string
): Promise<MultiDeviceEncryptionResult> {
  const logger = signal.logger;
  try {
    // Get all active devices
    const devices = await getActiveDevices(relay, userId, logger);

    // Graceful fallback: if no devices exist, return empty result instead of throwing
    // This allows single-device operations to work during initialization
    if (devices.length === 0) {
      logger.warn('[MultiDevice] No active devices found, skipping multi-device encryption', {
        category: 'MultiDevice',
        data: { userId },
      });

      return {
        userId,
        messages: [],
        successfulDevices: [],
        failedDevices: [],
        totalDevices: 0,
      };
    }

    const messages: DeviceMessage[] = [];
    const successfulDevices: number[] = [];
    const failedDevices: number[] = [];

    // Encrypt for each device
    for (const device of devices) {
      try {
        const remoteAddress = createDeviceAddress(userId, device.deviceId);

        // Check if session exists
        const hasSession = await signal.hasSession(remoteAddress);
        if (!hasSession) {
          // Try to establish session first
          logger.warn('[MultiDevice] No session found, establishing', {
            address: ProtocolAddress.toString(remoteAddress),
            deviceId: device.deviceId,
          });
          await establishDeviceSession(signal, relay, userId, device.deviceId);
        }

        // Encrypt message
        const ciphertext = await signal.encryptMessage(remoteAddress, plaintext);
        messages.push({
          deviceId: device.deviceId,
          ciphertext,
        });
        successfulDevices.push(device.deviceId);
      } catch (error) {
        logger.error('[MultiDevice] Failed to encrypt for device', {
          category: 'MultiDevice',
          error: error as Error,
          data: { userId, deviceId: device.deviceId },
        });
        failedDevices.push(device.deviceId);
      }
    }

    if (messages.length === 0) {
      throw new Error('Failed to encrypt message for any device');
    }

    return {
      userId,
      messages,
      successfulDevices,
      failedDevices,
      totalDevices: devices.length,
    };
  } catch (error) {
    logger.error('[MultiDevice] Failed to encrypt for all devices', {
      category: 'MultiDevice',
      error: error as Error,
      data: { userId },
    });
    throw error;
  }
}

/**
 * Encrypt message for a specific device
 *
 * Simpler version when you already know the specific device to encrypt for.
 *
 * @param signal - SignalProtocolClient instance
 * @param userId - Target user ID
 * @param deviceId - Target device ID
 * @param plaintext - Message to encrypt
 * @returns Encrypted ciphertext
 */
export async function encryptForDevice(
  signal: SignalProtocolClient,
  userId: string,
  deviceId: number,
  plaintext: string
): Promise<Ciphertext> {
  const logger = signal.logger;
  try {
    const remoteAddress = createDeviceAddress(userId, deviceId);
    return await signal.encryptMessage(remoteAddress, plaintext);
  } catch (error) {
    logger.error('[MultiDevice] Failed to encrypt for device', {
      category: 'MultiDevice',
      error: error as Error,
      data: { userId, deviceId },
    });
    throw error;
  }
}

// ============================================================================
// Session Management
// ============================================================================

/**
 * Check if sessions exist for all active devices
 *
 * @param signal - SignalProtocolClient instance
 * @param relay - Signal Protocol relay server interface
 * @param userId - Target user ID
 * @returns Map of device ID to session existence
 */
export async function checkDeviceSessions(
  signal: SignalProtocolClient,
  relay: ISignalRelayServer,
  userId: string
): Promise<Map<number, boolean>> {
  const logger = signal.logger;
  const devices = await getActiveDevices(relay, userId, logger);
  const sessionMap = new Map<number, boolean>();

  for (const device of devices) {
    const remoteAddress = createDeviceAddress(userId, device.deviceId);
    const hasSession = await signal.hasSession(remoteAddress);
    sessionMap.set(device.deviceId, hasSession);
  }

  return sessionMap;
}

/**
 * Delete all sessions for a user (all devices)
 *
 * Use this when resetting encryption or removing a user from a relationship.
 *
 * @param signal - SignalProtocolClient instance
 * @param relay - Signal Protocol relay server interface
 * @param userId - Target user ID
 */
export async function deleteAllDeviceSessions(
  signal: SignalProtocolClient,
  relay: ISignalRelayServer,
  userId: string
): Promise<void> {
  const logger = signal.logger;
  try {
    const devices = await getActiveDevices(relay, userId, logger);

    for (const device of devices) {
      try {
        const remoteAddress = createDeviceAddress(userId, device.deviceId);
        await signal.deleteSession(remoteAddress);
        logger.info('[MultiDevice] Session deleted', {
          address: ProtocolAddress.toString(remoteAddress),
          deviceId: device.deviceId,
        });
      } catch (error) {
        logger.error('[MultiDevice] Failed to delete session', {
          category: 'MultiDevice',
          error: error as Error,
          data: { userId, deviceId: device.deviceId },
        });
        // Continue with other devices
      }
    }
  } catch (error) {
    logger.error('[MultiDevice] Failed to delete all device sessions', {
      category: 'MultiDevice',
      error: error as Error,
      data: { userId },
    });
    throw error;
  }
}
