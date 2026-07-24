/**
 * Device Provisioning Manager
 *
 * Implements Signal Protocol's device linking flow:
 * 1. Primary device generates ephemeral key pair and QR code
 * 2. New device scans QR code and generates own ephemeral key pair
 * 3. Both devices perform ECDH key agreement to establish shared secret
 * 4. Primary device encrypts provisioned identity keys with shared secret
 * 5. New device decrypts and stores those identities, then initializes
 *
 * Security Properties:
 * - Physical proximity authentication (QR code)
 * - Ephemeral ECDH key agreement (forward secrecy)
 * - AES-256-GCM encryption
 * - 5-minute session TTL
 * - Account identity sharing (not full backup)
 * - The provisioning service carries only encrypted key material
 *
 * Differences from Device Transfer:
 * - Shares identity key only (not full backup with sessions)
 * - Adds new device (doesn't migrate/wipe old device)
 * - Multiple devices remain active
 */

import { Platform } from 'react-native';
import Constants from 'expo-constants';
import type { IProvisioningService } from '../remote/relay/types';
import * as crypto from '../internal/crypto';
import type { IdentityKeyPair, IdentityType } from '../keys';
import { resolveSignalLogger, type ILogger } from '../logger';
import type { ISignalLocalStore } from '../types';
import { asBase64 } from '../types/utils';
import { DEVICE_ID_KEY, LOCAL_IDENTITY_KEY } from './constants';
import { encryptDeviceName } from './device-name-crypto';
import type { SerializedUsernameLinkComponents } from '../username/link';

/**
 * User profile data for provisioning message.
 * Passed as a parameter to avoid coupling to user storage.
 */
export {};
export interface UserProfile {
  name?: string;
  username?: string | null;
  usernameLink?: SerializedUsernameLinkComponents | null;
}

/**
 * Optional local group-state store used to sync group master keys during provisioning.
 *
 * Signal owns the provisioning semantics; the host app owns the concrete SQLite store.
 */
export interface ProvisioningGroupStateStore {
  getAllMasterKeys(): Promise<Array<{ groupId: string; masterKey: string }>>;
  storeMasterKey(groupId: string, masterKey: Uint8Array): Promise<void>;
  deleteMasterKey(groupId: string): Promise<void>;
}

/**
 * Identity-key storage used during provisioning.
 *
 * Signal owns the provisioning semantics; callers provide their concrete
 * storage adapter so provisioning writes into the same key store used by the
 * runtime client.
 */
export interface ProvisioningIdentityStore extends Pick<
  ISignalLocalStore,
  'getIdentityKey' | 'storeIdentityKey'
> {
  deleteIdentityKey(identityType: IdentityType): Promise<void>;
}

/**
 * Minimal local state store used to persist linked-device bootstrap state.
 *
 * This lets provisioning record the assigned device ID and identity public key
 * without depending on a platform-specific SecureStore implementation.
 */
export interface ProvisioningLocalStateStore {
  setItemAsync(key: string, value: string): Promise<void>;
  deleteItemAsync(key: string): Promise<void>;
}

export interface ProvisioningUsernameStateStore {
  setUsernameState(state: {
    fullUsername: string | null;
    usernameLink: SerializedUsernameLinkComponents | null;
  }): Promise<void>;
  clearUsernameState(): Promise<void>;
}

export interface ProvisioningSendOptions {
  identityStore: ProvisioningIdentityStore;
  /**
   * Identity types to provision onto the linked device.
   *
   * Defaults to probing both `aci` and `pni`, always requiring `aci` and
   * including `pni` when present. Hosts may pass an explicit list when they
   * want to require a specific set.
   */
  identityTypes?: readonly IdentityType[];
  groupStateStore?: ProvisioningGroupStateStore;
  logger?: ILogger;
}

export interface ProvisioningReceiveOptions {
  identityStore: ProvisioningIdentityStore;
  localStateStore?: ProvisioningLocalStateStore;
  groupStateStore?: ProvisioningGroupStateStore;
  usernameStateStore?: ProvisioningUsernameStateStore;
  deviceMetadata: LocalDeviceMetadata;
  logger?: ILogger;
}

// ============================================================================
// Types
// ============================================================================

/**
 * Ephemeral key pair for provisioning session
 * Generated fresh for each linking session
 */
export interface ProvisioningKeyPair {
  publicKey: string; // ECDH public key - Base64
  privateKey: string; // ECDH private key - Base64
}

/**
 * QR code data for device linking
 * Encoded as URL: signalprotocol://link-device?session=xxx&key=xxx
 */
export interface ProvisioningQRData {
  sessionId: string; // Provisioning session ID
  ephemeralPublicKey: string; // Base64-encoded ephemeral public key
}

/**
 * Device metadata collected locally on the new device.
 *
 * `deviceName` stays local until provisioning has delivered the account
 * identity key needed to encrypt it for server storage.
 */
export interface LocalDeviceMetadata {
  deviceName: string;
  platform: string;
  appVersion: string;
  osVersion: string;
}

type ProvisioningConnectionMetadata = Omit<LocalDeviceMetadata, 'deviceName'>;

/**
 * Provisioning message sent from primary to new device
 * Contains provisioned identity keys and user profile
 */
export interface ProvisioningMessage {
  identityKeys: Partial<{
    [K in IdentityType]: {
      dhPublicKey: string; // Base64
      dhPrivateKey: string; // Base64
      signingPublicKey: string; // Base64
      signingPrivateKey: string; // Base64
      registrationId: number;
    };
  }>;
  userId: string;
  deviceId: number; // Assigned by server when provisioning completes
  userProfile: {
    name?: string;
    username?: string | null;
    usernameLink?: SerializedUsernameLinkComponents | null;
  };
  /** Group master keys for cross-device sync (base64-encoded). */
  groupMasterKeys?: Array<{ groupId: string; masterKey: string }>;
}

type SerializedProvisioningMessage = Omit<ProvisioningMessage, 'deviceId'>;

// ============================================================================
// Primary Device Flow
// ============================================================================

const DEFAULT_PROVISIONING_IDENTITY_TYPES = ['aci', 'pni'] as const;

type ProvisionedIdentityKeyPair = NonNullable<ProvisioningMessage['identityKeys']['aci']>;

function toProvisionedIdentityKeyPair(identityKey: IdentityKeyPair): ProvisionedIdentityKeyPair {
  return {
    dhPublicKey: identityKey.dhKey.publicKey,
    dhPrivateKey: identityKey.dhKey.privateKey,
    signingPublicKey: identityKey.signingKey.publicKey,
    signingPrivateKey: identityKey.signingKey.privateKey,
    registrationId: identityKey.registrationId,
  };
}

function fromProvisionedIdentityKeyPair(identityKey: ProvisionedIdentityKeyPair): IdentityKeyPair {
  return {
    dhKey: {
      publicKey: asBase64(identityKey.dhPublicKey) as IdentityKeyPair['dhKey']['publicKey'],
      privateKey: asBase64(identityKey.dhPrivateKey) as IdentityKeyPair['dhKey']['privateKey'],
    },
    signingKey: {
      publicKey: asBase64(
        identityKey.signingPublicKey
      ) as IdentityKeyPair['signingKey']['publicKey'],
      privateKey: asBase64(
        identityKey.signingPrivateKey
      ) as IdentityKeyPair['signingKey']['privateKey'],
    },
    registrationId: identityKey.registrationId,
  };
}

async function collectProvisioningIdentityKeys(
  identityStore: ProvisioningIdentityStore,
  explicitIdentityTypes?: readonly IdentityType[]
): Promise<ProvisioningMessage['identityKeys']> {
  const requestedIdentityTypes = explicitIdentityTypes ?? DEFAULT_PROVISIONING_IDENTITY_TYPES;
  const identityKeys: ProvisioningMessage['identityKeys'] = {};

  for (const identityType of requestedIdentityTypes) {
    const identityKey = await identityStore.getIdentityKey(identityType);
    if (!identityKey) {
      if (identityType === 'aci' || explicitIdentityTypes) {
        throw new Error(`Identity key not found for primary device (${identityType})`);
      }
      continue;
    }

    identityKeys[identityType] = toProvisionedIdentityKeyPair(identityKey);
  }

  if (!identityKeys.aci) {
    throw new Error('Provisioning requires an ACI identity key');
  }

  return identityKeys;
}

/**
 * Default custom URL scheme prefix for device-linking QR codes, targeting the
 * `signalprotocol://` scheme. Override per call via the `linkPrefix` parameter.
 */
export const DEFAULT_PROVISIONING_LINK_PREFIX = 'signalprotocol://link-device';

/**
 * Generate QR Code for Device Linking (Primary Device)
 *
 * Creates a provisioning session and generates QR code data.
 * The QR code contains the session ID and ephemeral public key.
 *
 * @param relay - Provisioning service interface
 * @param userId - Current user ID
 * @param providedLogger - Optional logger
 * @param linkPrefix - Custom scheme prefix (defaults to {@link DEFAULT_PROVISIONING_LINK_PREFIX})
 * @returns QR code URL and ephemeral key pair
 */
export async function generateProvisioningQR(
  relay: IProvisioningService,
  userId: string,
  providedLogger?: ILogger,
  linkPrefix: string = DEFAULT_PROVISIONING_LINK_PREFIX
): Promise<{
  qrCodeUrl: string;
  sessionId: string;
  ephemeralKeyPair: ProvisioningKeyPair;
}> {
  const logger = resolveSignalLogger(providedLogger);
  try {
    // Generate ephemeral ECDH key pair
    const ephemeralKeyPair = await crypto.generateECDHKeyPair();

    // Create provisioning session on backend
    const { sessionId } = await relay.createProvisioningSession(userId, ephemeralKeyPair.publicKey);

    // Build QR code URL
    // URL-encode the base64 key to handle +, /, and = characters
    const qrCodeUrl = `${linkPrefix}?session=${encodeURIComponent(sessionId)}&key=${encodeURIComponent(ephemeralKeyPair.publicKey)}`;

    logger.info('[Provisioning] QR code generated', { sessionId });

    return {
      qrCodeUrl,
      sessionId,
      ephemeralKeyPair,
    };
  } catch (error) {
    logger.error('[Provisioning] Failed to generate QR code', error);
    throw error;
  }
}

/**
 * Send Provisioning Payload to New Device (Primary Device)
 *
 * Called after new device connects to provisioning session.
 * Encrypts and sends all provisioned identity keys to the new device.
 *
 * @param relay - Provisioning service interface
 * @param userProfile - User profile data (name, username, avatarUrl)
 * @param sessionId - Provisioning session ID
 * @param ephemeralPrivateKey - Primary's ephemeral private key
 * @param newDeviceEphemeralPublicKey - New device's ephemeral public key
 * @param userId - User ID
 */
export async function provisionDevice(
  relay: IProvisioningService,
  userProfile: UserProfile,
  sessionId: string,
  ephemeralPrivateKey: string,
  newDeviceEphemeralPublicKey: string,
  userId: string,
  options: ProvisioningSendOptions
): Promise<void> {
  const logger = resolveSignalLogger(options.logger);
  try {
    const identityKeys = await collectProvisioningIdentityKeys(
      options.identityStore,
      options.identityTypes
    );

    // Gather group master keys for cross-device sync
    const groupKeys = options.groupStateStore
      ? await options.groupStateStore.getAllMasterKeys()
      : [];

    // Build provisioning message
    const provisioningMessage: SerializedProvisioningMessage = {
      identityKeys,
      userId,
      userProfile: {
        name: userProfile.name,
        username: userProfile.username,
        usernameLink: userProfile.usernameLink ?? undefined,
      },
      groupMasterKeys: groupKeys.length > 0 ? groupKeys : undefined,
    };

    // Derive shared secret using ECDH
    const sharedSecret = await crypto.computeSharedSecret(
      asBase64(ephemeralPrivateKey),
      asBase64(newDeviceEphemeralPublicKey)
    );

    // Derive encryption key from shared secret using HKDF
    const encryptionKey = await crypto.hkdf(
      sharedSecret,
      new Uint8Array(32), // salt
      crypto.stringToBytes('DeviceProvisioning'),
      32 // key length
    );

    // Encrypt provisioning message with AES-256-GCM
    const plaintextBytes = crypto.stringToBytes(JSON.stringify(provisioningMessage));
    const encrypted = await crypto.aesGcmEncrypt(encryptionKey, plaintextBytes);

    // Send encrypted message to backend
    await relay.sendProvisioningMessage(sessionId, JSON.stringify(encrypted), userId);

    logger.info('[Provisioning] Identities sent to new device', {
      sessionId,
      identityTypes: Object.keys(identityKeys),
    });

    // Wipe ephemeral keys for security
    // Note: ephemeralPrivateKey is Base64 string, can't be securely zeroed
    crypto.secureZeroBytes(sharedSecret);
    crypto.secureZeroBytes(encryptionKey);
  } catch (error) {
    logger.error('[Provisioning] Failed to provision device', error);
    throw error;
  }
}

// ============================================================================
// New Device Flow
// ============================================================================

/**
 * Parse Provisioning QR Code (New Device)
 *
 * Extracts session ID and ephemeral public key from QR code URL.
 *
 * @param qrCodeData - QR code data (URL format)
 * @returns Session ID and primary's ephemeral public key (Base64)
 */
export function parseProvisioningQR(
  qrCodeData: string,
  providedLogger?: ILogger,
  linkPrefix: string = DEFAULT_PROVISIONING_LINK_PREFIX
): {
  sessionId: string;
  primaryEphemeralPublicKey: string;
} {
  const logger = resolveSignalLogger(providedLogger);
  try {
    // Parse URL: signalprotocol://link-device?session=xxx&key=xxx
    const url = new URL(qrCodeData);
    const expected = new URL(linkPrefix);
    if (
      url.protocol !== expected.protocol ||
      url.hostname !== expected.hostname ||
      url.port !== expected.port ||
      url.pathname !== expected.pathname ||
      url.username !== expected.username ||
      url.password !== expected.password ||
      url.hash !== ''
    ) {
      throw new Error('Invalid provisioning QR code prefix');
    }

    const sessionId = url.searchParams.get('session');
    const keyBase64 = url.searchParams.get('key');

    if (!sessionId || !keyBase64) {
      throw new Error('Invalid provisioning QR code: missing session or key');
    }

    let decodedKey: Uint8Array;
    try {
      decodedKey = crypto.base64ToBytes(asBase64(keyBase64));
    } catch {
      throw new Error('Invalid provisioning QR code key');
    }
    if (decodedKey.length !== 32 || crypto.bytesToBase64(decodedKey) !== keyBase64) {
      throw new Error('Invalid provisioning QR code key: expected 32-byte X25519 key');
    }

    return {
      sessionId,
      primaryEphemeralPublicKey: keyBase64,
    };
  } catch (error) {
    logger.error('[Provisioning] Failed to parse QR code', error);
    throw new Error('Invalid provisioning QR code format');
  }
}

/**
 * Connect to Provisioning Session (New Device)
 *
 * Generates ephemeral key pair and connects to provisioning session.
 *
 * @param relay - Provisioning service interface
 * @param sessionId - Provisioning session ID
 * @param deviceMetadata - New device metadata
 * @returns Ephemeral key pair for decryption
 */
export async function connectToProvisioningSession(
  relay: IProvisioningService,
  sessionId: string,
  deviceMetadata: LocalDeviceMetadata,
  providedLogger?: ILogger
): Promise<ProvisioningKeyPair> {
  const logger = resolveSignalLogger(providedLogger);
  try {
    // Generate ephemeral key pair
    const ephemeralKeyPair = await crypto.generateECDHKeyPair();

    // Connect to provisioning session
    await relay.connectNewDevice(
      sessionId,
      ephemeralKeyPair.publicKey,
      toProvisioningConnectionMetadata(deviceMetadata)
    );

    logger.info('[Provisioning] Connected to session', { sessionId });

    return ephemeralKeyPair;
  } catch (error) {
    logger.error('[Provisioning] Failed to connect', error);
    throw error;
  }
}

/**
 * Receive Provisioning Message (New Device)
 *
 * Polls for and decrypts provisioning message from primary device.
 * Finalizes the server-side device link, then stores the received bootstrap
 * state in the caller-provided Signal key store.
 *
 * @param relay - Provisioning service interface
 * @param sessionId - Provisioning session ID
 * @param ephemeralPrivateKey - New device's ephemeral private key
 * @param primaryEphemeralPublicKey - Primary device's ephemeral public key
 * @returns Provisioning message with identity keys and user info
 */
export async function receiveProvisioningMessage(
  relay: IProvisioningService,
  sessionId: string,
  ephemeralPrivateKey: string,
  primaryEphemeralPublicKey: string,
  options: ProvisioningReceiveOptions
): Promise<ProvisioningMessage> {
  const logger = resolveSignalLogger(options.logger);
  const storedIdentityTypes: IdentityType[] = [];
  const storedGroupIds: string[] = [];
  let storedDeviceId = false;
  let storedLocalIdentity = false;
  let storedUsernameState = false;
  let serverLinkedDeviceId: number | null = null;

  const rollbackLocalProvisioningState = async (): Promise<void> => {
    for (const identityType of storedIdentityTypes.slice().reverse()) {
      await options.identityStore.deleteIdentityKey(identityType);
    }
    if (storedLocalIdentity && options.localStateStore) {
      await options.localStateStore.deleteItemAsync(LOCAL_IDENTITY_KEY);
    }
    if (storedDeviceId && options.localStateStore) {
      await options.localStateStore.deleteItemAsync(DEVICE_ID_KEY);
    }
    if (storedUsernameState && options.usernameStateStore) {
      await options.usernameStateStore.clearUsernameState();
    }
    for (const groupId of storedGroupIds.slice().reverse()) {
      await options.groupStateStore?.deleteMasterKey(groupId);
    }
  };

  let sharedSecret: Uint8Array | null = null;
  let decryptionKey: Uint8Array | null = null;
  try {
    // Poll for provisioning message
    const result = await relay.getProvisioningMessage(sessionId);

    if (result.status !== 'ready' || !result.message) {
      throw new Error(`Provisioning message not ready: ${result.status}`);
    }

    // Parse encrypted message
    const encrypted = JSON.parse(result.message);

    // Derive shared secret (same as primary device)
    sharedSecret = await crypto.computeSharedSecret(
      asBase64(ephemeralPrivateKey),
      asBase64(primaryEphemeralPublicKey)
    );

    // Derive decryption key (same as primary device)
    decryptionKey = await crypto.hkdf(
      sharedSecret,
      new Uint8Array(32),
      crypto.stringToBytes('DeviceProvisioning'),
      32
    );

    // Decrypt provisioning message
    const plaintextBytes = await crypto.aesGcmDecrypt(
      decryptionKey,
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.authTag
    );
    const provisioningPayload: SerializedProvisioningMessage = JSON.parse(
      crypto.bytesToString(plaintextBytes)
    );

    const aciIdentityKey = provisioningPayload.identityKeys.aci;
    if (!aciIdentityKey) {
      throw new Error('Provisioning message missing ACI identity key');
    }

    const encryptedDeviceName = await encryptDeviceName(
      options.deviceMetadata.deviceName,
      asBase64(aciIdentityKey.dhPublicKey)
    );

    // Finalize the server-side link before mutating local Signal state.
    const completion = await relay.completeProvisioning(sessionId, {
      encryptedDeviceName,
      platform: options.deviceMetadata.platform,
      appVersion: options.deviceMetadata.appVersion,
      osVersion: options.deviceMetadata.osVersion,
    });
    serverLinkedDeviceId = completion.deviceId;

    for (const identityType of DEFAULT_PROVISIONING_IDENTITY_TYPES) {
      const identityKey = provisioningPayload.identityKeys[identityType];
      if (!identityKey) {
        continue;
      }

      await options.identityStore.storeIdentityKey(
        fromProvisionedIdentityKeyPair(identityKey),
        identityType
      );
      storedIdentityTypes.push(identityType);
    }

    if (options.localStateStore) {
      await options.localStateStore.setItemAsync(DEVICE_ID_KEY, completion.deviceId.toString());
      storedDeviceId = true;
      await options.localStateStore.setItemAsync(LOCAL_IDENTITY_KEY, aciIdentityKey.dhPublicKey);
      storedLocalIdentity = true;
    }

    if (options.usernameStateStore) {
      await options.usernameStateStore.setUsernameState({
        fullUsername: provisioningPayload.userProfile.username ?? null,
        usernameLink: provisioningPayload.userProfile.usernameLink ?? null,
      });
      storedUsernameState = true;
    }

    if (provisioningPayload.groupMasterKeys && options.groupStateStore) {
      for (const entry of provisioningPayload.groupMasterKeys) {
        const keyBytes = crypto.base64ToBytes(asBase64(entry.masterKey));
        await options.groupStateStore.storeMasterKey(entry.groupId, keyBytes);
        crypto.secureZeroBytes(keyBytes);
        storedGroupIds.push(entry.groupId);
      }
      logger.info('[Provisioning] Stored group master keys', {
        count: provisioningPayload.groupMasterKeys.length,
      });
    }

    await relay.acknowledgeProvisioning(sessionId);

    logger.info('[Provisioning] Provisioned identities stored after server link', {
      deviceId: completion.deviceId,
      identityTypes: storedIdentityTypes,
    });

    return {
      ...provisioningPayload,
      deviceId: completion.deviceId,
    };
  } catch (error) {
    if (serverLinkedDeviceId !== null) {
      try {
        await relay.rollbackProvisioning(sessionId);
      } catch (rollbackError) {
        logger.error('[Provisioning] Failed to roll back server-side provisioning', rollbackError);
      }
    }
    if (
      storedIdentityTypes.length > 0 ||
      storedGroupIds.length > 0 ||
      storedDeviceId ||
      storedLocalIdentity ||
      storedUsernameState
    ) {
      try {
        await rollbackLocalProvisioningState();
      } catch (rollbackError) {
        logger.error('[Provisioning] Failed to roll back local provisioning state', rollbackError);
      }
    }
    logger.error('[Provisioning] Failed to receive provisioning message', error);
    throw error;
  } finally {
    if (sharedSecret) {
      crypto.secureZeroBytes(sharedSecret);
    }
    if (decryptionKey) {
      crypto.secureZeroBytes(decryptionKey);
    }
    // Note: ephemeralPrivateKey is a Base64 string that will be garbage collected
  }
}

// ============================================================================
// Utilities
// ============================================================================

/**
 * Get Device Metadata (New Device)
 *
 * Collects device information for provisioning.
 *
 * The device name remains local until provisioning has delivered the account
 * identity key needed to encrypt it for server storage.
 *
 * @param deviceName - Human-readable device name chosen on the new device
 * @returns Local device metadata
 */
export function getDeviceMetadata(deviceName: string): LocalDeviceMetadata {
  return {
    deviceName,
    platform: Platform.OS,
    appVersion: Constants.expoConfig?.version ?? 'unknown',
    osVersion: Platform.Version.toString(),
  };
}

function toProvisioningConnectionMetadata(
  metadata: LocalDeviceMetadata
): ProvisioningConnectionMetadata {
  return {
    platform: metadata.platform,
    appVersion: metadata.appVersion,
    osVersion: metadata.osVersion,
  };
}

/**
 * Cancel Provisioning Session
 *
 * Deletes provisioning session and cleans up.
 *
 * @param relay - Provisioning service interface
 * @param sessionId - Session ID to cancel
 */
export async function cancelProvisioning(
  relay: IProvisioningService,
  sessionId: string,
  userId: string,
  providedLogger?: ILogger
): Promise<void> {
  const logger = resolveSignalLogger(providedLogger);
  try {
    await relay.deleteProvisioningSession(sessionId, userId);

    logger.info('[Provisioning] Session cancelled', { sessionId });
  } catch (error) {
    logger.error('[Provisioning] Failed to cancel session', error);
    // Don't throw - cleanup is best-effort
  }
}
