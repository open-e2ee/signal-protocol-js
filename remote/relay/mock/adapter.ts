/**
 * Mock Signal Protocol Relay Server
 *
 * In-memory implementation of ISignalProtocolRelayServer for local development.
 * Simulates a backend server without any network calls.
 *
 * WARNING: All data is lost when the adapter is destroyed.
 * DO NOT use in production.
 */

import type {
  ISignalProtocolRelayServer,
  Envelope,
  SealedSenderAuth,
  DeviceInfo,
  DeviceRegistration,
  PreKeyUpload,
  PreKeyBundle,
  EcSignedPreKeyUpload,
  KemLastResortPreKeyUpload,
  Unsubscribe,
  GroupMemberDevice,
  GroupChangeEntry,
  RetryRequest,
  AccountIdentityProvisioning,
  AccountIdentityRotation,
} from '../types';
import type { GroupAuthorization } from '../../../internal/groups-v2/manager';
import type { PublicKey, Signature } from '../../../keys/branded';
import type { CompositeIdentityV1, IdentityType } from '../../../keys/types';
import {
  compositeIdentitiesEqual,
  decodeCompositeIdentityV1,
  deriveIdentityCommitment,
  encodeCompositeIdentityV1,
} from '../../../keys/identity';
import { constantTimeEqual } from '../../../internal/crypto/utils';
import { PROVISIONING_SESSION_TTL_MS } from '../../../device/constants';
import {
  generateServerSecretParams,
  serverSign,
  type ServerSecretParams,
} from '../../../internal/protocol/zk/groups/server-params';
import {
  issueAuthCredential as issueAuthCredentialZk,
  serializeAuthCredentialResponse,
} from '../../../internal/protocol/zk/groups/auth-credential';
import {
  SERVICE_ID_ACI,
  SERVICE_ID_PNI,
  uuidToBytes,
  type ServiceId,
} from '../../../internal/protocol/zk/groups/uid-struct';
import { SECONDS_PER_DAY } from '../../../internal/protocol/zk/groups/group-params';
import {
  defaultExpiration,
  deriveForExpiration,
  issueEndorsements,
  serializeEndorsementsResponse,
} from '../../../internal/protocol/zk/groups/group-send-endorsement';
import { UidEncryptionDomain } from '../../../internal/protocol/zk/groups/uid-encryption';
import { Ciphertext } from '../../../internal/protocol/zk/credentials/attributes';
import { ristretto255 } from '@noble/curves/ed25519.js';
import { MAX_DEVICES } from '../../../device/constants';
import { SealedSenderAuthError } from '../../../types/errors';
import {
  MockRelayFailureController,
  type MockRelayFailureOptions,
} from './failures';

export interface MockSignalProtocolRelayServerOptions {
  failures?: MockRelayFailureOptions;
}

/**
 * Simulate the serialization boundary of a real relay.
 *
 * Values entering or leaving the in-memory server must never share mutable
 * references with caller-owned objects.
 */
function cloneRelayValue<T>(value: T): T {
  return structuredClone(value);
}

/**
 * Mock Signal Protocol Relay Server for local development
 *
 * Provides in-memory backend simulation with the same interface as production adapters.
 * Useful when a real backend is intentionally unnecessary.
 *
 * @example
 * ```typescript
 * const relay = new MockSignalProtocolRelayServer();
 *
 * // Register a device
 * const deviceId = await relay.registerDevice('alice', { encryptedDeviceName: new ArrayBuffer(0) });
 *
 * // Upload prekeys
 * await relay.uploadPreKeys('alice', deviceId, [...]);
 *
 * // Fetch prekey bundle for session establishment
 * const bundle = await relay.fetchPreKeyBundle('alice', deviceId);
 * ```
 */
/** Canonically encoded account identity. */
export {};

export class MockSignalProtocolRelayServer implements ISignalProtocolRelayServer {
  readonly failures: MockRelayFailureController;

  // Device registry
  private devices = new Map<string, DeviceInfo[]>(); // key: userId

  // Identity keys per account (ACI/PNI), shared across all devices
  private identityKeys = new Map<string, Uint8Array>(); // key: `${userId}:${identityType}`

  // Registration IDs remain per-device even though identity keys are account-level
  private registrationIds = new Map<string, number>(); // key: `${userId}:${deviceId}:${identityType}`

  // Prekeys per device
  private ecPreKeys = new Map<string, PreKeyUpload[]>(); // key: `${userId}:${deviceId}:${identityType}`
  private consumedEcPreKeyIds = new Map<string, Set<number>>(); // key: `${userId}:${deviceId}:${identityType}`
  private ecSignedPreKeys = new Map<string, PreKeyUpload>(); // key: `${userId}:${deviceId}:${identityType}`
  private kemOneTimePreKeys = new Map<string, PreKeyUpload[]>(); // key: `${userId}:${deviceId}:${identityType}`
  private consumedKemOneTimePreKeyIds = new Map<string, Set<number>>(); // key: `${userId}:${deviceId}:${identityType}`
  private kemLastResortPreKeys = new Map<string, PreKeyUpload>(); // key: `${userId}:${deviceId}:${identityType}`

  // Messages/envelopes
  private pendingMessages = new Map<string, Envelope[]>(); // key: `${userId}:${deviceId}`
  private clientMessageReceipts = new Map<string, { messageId: string; serverTimestamp: number }>(); // key: `${userId}:${deviceId}:${clientMessageId}`
  private messageCounter = 0;

  // Subscriptions
  private subscriptions = new Map<string, ((envelope: Envelope) => void)[]>();

  // Group members for deterministic group-message fanout.
  private groupMembers = new Map<string, GroupMemberDevice[]>(); // key: groupId

  // Provisioning sessions
  private provisioningSessions = new Map<
    string,
    {
      userId: string;
      ephemeralPublicKey: string;
      newDeviceEphemeralPublicKey?: string;
      deviceMetadata?: {
        platform?: string;
        appVersion?: string;
        osVersion?: string;
      };
      encryptedMessage?: string;
      assignedDeviceId?: number;
      status:
        | 'waiting'
        | 'connected'
        | 'ready'
        | 'linked_pending_ack'
        | 'completed'
        | 'rolled_back'
        | 'expired';
      createdAt: number;
    }
  >();
  private provisioningCounter = 0;

  // Key metadata (for key rotation checks and server key verification)
  private ecSignedPreKeyMetadata = new Map<
    string,
    { keyId: number; createdAt: number; expiresAt: number; publicKey: string }
  >(); // key: `${userId}:${deviceId}:${identityType}`
  private kemLastResortPreKeyMetadata = new Map<
    string,
    { keyId: number; createdAt: number; expiresAt: number; publicKey: string }
  >(); // key: `${userId}:${deviceId}:${identityType}`

  // Retry requests (SESAME spec §6.2)
  private retryRequests = new Map<string, RetryRequest[]>(); // key: `${originalSenderUserId}:${originalSenderDeviceId}`
  private retryRequestSubscriptions = new Map<
    string,
    ((request: RetryRequest) => Promise<void>)[]
  >();

  // GroupsV2 encrypted state (server-opaque)
  private groupStates = new Map<string, { encryptedState: Uint8Array; version: number }>(); // key: hex(groupId)
  private groupChangeLogs = new Map<string, GroupChangeEntry[]>(); // key: hex(groupId)

  // Server secret params for signing and ZK auth (deterministic local seed)
  private serverSecretParams: ServerSecretParams = generateServerSecretParams(new Uint8Array(32));

  constructor(options: MockSignalProtocolRelayServerOptions = {}) {
    this.failures = new MockRelayFailureController(
      options.failures,
      (targetKey, envelope) => this.deliverEnvelope(targetKey, envelope),
      (targetKey) => this.deliverPending(targetKey)
    );
  }

  /** Build a storage key with explicit identity-type separation. */
  private storageKey(userId: string, deviceId: number, identityType: IdentityType = 'aci'): string {
    return `${userId}:${deviceId}:${identityType}`;
  }

  /** Identity key storage is account-scoped, not device-scoped. */
  private identityStorageKey(userId: string, identityType: IdentityType = 'aci'): string {
    return `${userId}:${identityType}`;
  }

  /** Remove every device-scoped prekey bound to one retired account identity. */
  private clearIdentityPreKeys(userId: string, identityType: IdentityType): void {
    const prefix = `${userId}:`;
    const suffix = `:${identityType}`;
    const stores: Array<Map<string, unknown>> = [
      this.ecSignedPreKeys,
      this.kemLastResortPreKeys,
      this.ecPreKeys,
      this.consumedEcPreKeyIds,
      this.kemOneTimePreKeys,
      this.consumedKemOneTimePreKeyIds,
      this.ecSignedPreKeyMetadata,
      this.kemLastResortPreKeyMetadata,
    ];

    // The prekey tables are authoritative. Device registration is a separate
    // service and may be incomplete or temporarily unavailable during reset.
    for (const store of stores) {
      for (const key of store.keys()) {
        if (key.startsWith(prefix) && key.endsWith(suffix)) {
          store.delete(key);
        }
      }
    }
  }

  // ============================================================================
  // Envelope Delivery
  // ============================================================================

  async send(envelope: Envelope): Promise<{ messageId: string; serverTimestamp: number }> {
    await this.failures.waitForLatency();
    const targetKey = `${envelope.targetUserId}:${envelope.targetDeviceId}`;
    const receiptKey = envelope.clientMessageId ? `${targetKey}:${envelope.clientMessageId}` : null;
    if (receiptKey) {
      const existing = this.clientMessageReceipts.get(receiptKey);
      if (existing) {
        return cloneRelayValue(existing);
      }
    }

    const id = `msg-${++this.messageCounter}`;
    const serverTimestamp = Date.now();

    const storedEnvelope: Envelope = {
      ...cloneRelayValue(envelope),
      id,
      serverTimestamp,
    };

    // Store in pending messages
    const pending = this.pendingMessages.get(targetKey) || [];
    pending.push(storedEnvelope);
    this.pendingMessages.set(targetKey, pending);

    // Notify live subscribers through the deterministic failure controller.
    // With no subscriber, the pending mailbox alone owns the envelope.
    if ((this.subscriptions.get(targetKey)?.length ?? 0) > 0) {
      this.failures.deliver(targetKey, storedEnvelope);
    }

    if (receiptKey) {
      this.clientMessageReceipts.set(receiptKey, { messageId: id, serverTimestamp });
    }

    return cloneRelayValue({ messageId: id, serverTimestamp });
  }

  subscribe(
    userId: string,
    deviceId: number,
    onEnvelope: (envelope: Envelope) => void
  ): Unsubscribe {
    const key = `${userId}:${deviceId}`;
    const subscribers = this.subscriptions.get(key) || [];
    const isFirstSubscriber = subscribers.length === 0;
    subscribers.push(onEnvelope);
    this.subscriptions.set(key, subscribers);

    // Deliver any pending messages only to the newly added subscriber.
    if (!this.failures.isDisconnected(key)) {
      if (isFirstSubscriber) {
        this.failures.discardReordered(key);
      }
      const pending = this.pendingMessages.get(key) || [];
      for (const envelope of pending) {
        if (this.failures.isReorderBuffered(key, envelope.id)) continue;
        onEnvelope(cloneRelayValue(envelope));
      }
    }

    return () => {
      const subs = this.subscriptions.get(key) || [];
      const idx = subs.indexOf(onEnvelope);
      if (idx >= 0) {
        subs.splice(idx, 1);
      }
    };
  }

  async markDelivered(envelopeId: string): Promise<void> {
    // Remove from all pending message queues
    for (const [key, messages] of this.pendingMessages.entries()) {
      const idx = messages.findIndex((m) => m.id === envelopeId);
      if (idx >= 0) {
        messages.splice(idx, 1);
        if (messages.length === 0) {
          this.pendingMessages.delete(key);
        }
        break;
      }
    }
  }

  // ============================================================================
  // Device Registry
  // ============================================================================

  async getDevices(userId: string): Promise<DeviceInfo[]> {
    return cloneRelayValue(this.devices.get(userId) || []);
  }

  async registerDevice(userId: string, device: DeviceRegistration): Promise<number> {
    const existing = this.devices.get(userId) || [];
    const occupiedIds = new Set(
      existing
        .filter((candidate) => candidate.registered)
        .map((candidate) => candidate.deviceId)
    );
    const requestedDeviceId = device.deviceId;
    if (
      requestedDeviceId !== undefined &&
      (!Number.isInteger(requestedDeviceId) ||
        requestedDeviceId < 1 ||
        requestedDeviceId > MAX_DEVICES)
    ) {
      throw new Error(`Device ID must be between 1 and ${MAX_DEVICES}`);
    }

    const deviceId =
      requestedDeviceId ??
      Array.from({ length: MAX_DEVICES }, (_, index) => index + 1).find(
        (candidate) => !occupiedIds.has(candidate)
      );
    if (deviceId === undefined || occupiedIds.has(deviceId)) {
      throw new Error('Maximum devices limit reached');
    }
    const isPrimary = deviceId === 1;

    const now = Date.now();
    const deviceInfo: DeviceInfo = {
      deviceId,
      encryptedDeviceName: device.encryptedDeviceName
        ? cloneRelayValue(device.encryptedDeviceName)
        : undefined,
      deviceType: device.deviceType,
      registered: true, // Setup complete
      linked: isPrimary ? false : true, // Primary is never "linked", secondary is linked
      enabled: true, // Can receive messages
      active: false, // Not online yet (set by markDeviceConnected)
      lastSeen: now,
      createdAt: now,
      linkedAt: isPrimary ? undefined : now,
    };

    const reusableIndex = existing.findIndex((candidate) => candidate.deviceId === deviceId);
    if (reusableIndex >= 0) {
      existing[reusableIndex] = deviceInfo;
    } else {
      existing.push(deviceInfo);
    }
    this.devices.set(userId, existing);

    return deviceId;
  }

  async removeDevice(userId: string, deviceId: number): Promise<void> {
    const devices = this.devices.get(userId) || [];
    const device = devices.find((d) => d.deviceId === deviceId);
    if (device) {
      // Soft delete: mark as unregistered
      device.registered = false;
      device.linked = false;
      device.enabled = false;
      device.active = false;
    }

    // Clean up device-scoped keys for both identity types
    for (const idType of ['aci', 'pni'] as const) {
      const deviceKey = this.storageKey(userId, deviceId, idType);
      this.registrationIds.delete(deviceKey);
      this.ecPreKeys.delete(deviceKey);
      this.consumedEcPreKeyIds.delete(deviceKey);
      this.ecSignedPreKeys.delete(deviceKey);
      this.kemOneTimePreKeys.delete(deviceKey);
      this.consumedKemOneTimePreKeyIds.delete(deviceKey);
      this.kemLastResortPreKeys.delete(deviceKey);
      this.ecSignedPreKeyMetadata.delete(deviceKey);
      this.kemLastResortPreKeyMetadata.delete(deviceKey);
    }
    this.pendingMessages.delete(`${userId}:${deviceId}`);
  }

  // Note: updatePushToken removed - push tokens are managed by convex/signal/push.ts

  /**
   * Mock: Mark device as connected.
   * In local development, pass userId directly since there is no JWT.
   */
  async markDeviceConnected(deviceId: number, userId?: string): Promise<void> {
    if (!userId) return; // No-op without userId (matches production behavior without auth)

    const devices = this.devices.get(userId) || [];
    const device = devices.find((d) => d.deviceId === deviceId);
    if (device) {
      device.active = true;
      device.lastSeen = Date.now();
    }
  }

  /**
   * Mock: Mark device as disconnected.
   * In local development, pass userId directly since there is no JWT.
   */
  async markDeviceDisconnected(deviceId: number, userId?: string): Promise<void> {
    if (!userId) return; // No-op without userId (matches production behavior without auth)

    const devices = this.devices.get(userId) || [];
    const device = devices.find((d) => d.deviceId === deviceId);
    if (device) {
      device.active = false;
      device.lastSeen = Date.now();
    }
  }

  async heartbeat(_deviceId: number): Promise<void> {
    // No-op in the in-memory adapter; heartbeats do not affect local state.
  }

  // ============================================================================
  // Identity Keys
  // ============================================================================

  async provisionIdentityKey(request: AccountIdentityProvisioning): Promise<void> {
    const { userId, deviceId, identity, registrationId, identityType = 'aci' } = request;
    const accountKey = this.identityStorageKey(userId, identityType);
    const deviceKey = this.storageKey(userId, deviceId, identityType);
    const encodedCurrent = this.identityKeys.get(accountKey);
    if (encodedCurrent) {
      const current = decodeCompositeIdentityV1(encodedCurrent);
      if (!compositeIdentitiesEqual(current, identity)) {
        throw new Error(
          'Account identity already exists with a different composite tuple; explicit rotation required'
        );
      }
    }

    const encodedIdentity = encodeCompositeIdentityV1(identity);
    this.identityKeys.set(accountKey, encodedIdentity);
    this.registrationIds.set(deviceKey, registrationId);
  }

  async rotateIdentityKey(request: AccountIdentityRotation): Promise<void> {
    const {
      userId,
      deviceId,
      identity,
      registrationId,
      identityType = 'aci',
      expectedCurrentCommitment,
    } = request;
    const accountKey = this.identityStorageKey(userId, identityType);
    const encodedCurrent = this.identityKeys.get(accountKey);
    if (!encodedCurrent) {
      throw new Error('Cannot rotate an account identity that has not been provisioned');
    }

    const current = decodeCompositeIdentityV1(encodedCurrent);
    if (!constantTimeEqual(deriveIdentityCommitment(current), expectedCurrentCommitment)) {
      throw new Error('Account identity rotation compare-and-swap failed');
    }
    if (compositeIdentitiesEqual(current, identity)) {
      throw new Error('Account identity rotation requires a different composite tuple');
    }

    const encodedIdentity = encodeCompositeIdentityV1(identity);
    const deviceKey = this.storageKey(userId, deviceId, identityType);

    // Commit only after every precondition and input has been validated.
    this.identityKeys.set(accountKey, encodedIdentity);
    this.registrationIds.set(deviceKey, registrationId);

    // Every device's prekeys are bound to the retired account identity.
    this.clearIdentityPreKeys(userId, identityType);
  }

  async getIdentityKey(
    userId: string,
    identityType?: IdentityType
  ): Promise<CompositeIdentityV1 | null> {
    const key = this.identityStorageKey(userId, identityType);
    const encoded = this.identityKeys.get(key);
    return encoded ? cloneRelayValue(decodeCompositeIdentityV1(encoded)) : null;
  }

  // ============================================================================
  // Prekey Management
  // ============================================================================

  async uploadPreKeys(
    userId: string,
    deviceId: number,
    keys: PreKeyUpload[],
    identityType?: IdentityType
  ): Promise<void> {
    const key = this.storageKey(userId, deviceId, identityType);
    const now = Date.now();
    const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

    for (const preKey of keys) {
      switch (preKey.type) {
        case 'ecPreKey': {
          if (this.failures.shouldExhaustOneTimePreKeys()) break;
          if (this.consumedEcPreKeyIds.get(key)?.has(preKey.keyId)) break;
          const existing = this.ecPreKeys.get(key) || [];
          const stored = cloneRelayValue(preKey);
          const index = existing.findIndex((candidate) => candidate.keyId === stored.keyId);
          if (index >= 0) existing[index] = stored;
          else existing.push(stored);
          this.ecPreKeys.set(key, existing);
          break;
        }
        case 'ecSignedPreKey': {
          this.ecSignedPreKeys.set(key, cloneRelayValue(preKey));
          // Auto-populate metadata for server key verification
          this.ecSignedPreKeyMetadata.set(key, {
            keyId: preKey.keyId,
            createdAt: now,
            expiresAt: now + THIRTY_DAYS_MS,
            publicKey: preKey.publicKey,
          });
          break;
        }
        case 'kemOneTimePreKey': {
          if (this.failures.shouldExhaustOneTimePreKeys()) break;
          if (this.consumedKemOneTimePreKeyIds.get(key)?.has(preKey.keyId)) break;
          const existing = this.kemOneTimePreKeys.get(key) || [];
          const stored = cloneRelayValue(preKey);
          const index = existing.findIndex((candidate) => candidate.keyId === stored.keyId);
          if (index >= 0) existing[index] = stored;
          else existing.push(stored);
          this.kemOneTimePreKeys.set(key, existing);
          break;
        }
        case 'kemLastResortPreKey': {
          this.kemLastResortPreKeys.set(key, cloneRelayValue(preKey));
          // Auto-populate metadata for server key verification
          this.kemLastResortPreKeyMetadata.set(key, {
            keyId: preKey.keyId,
            createdAt: now,
            expiresAt: now + THIRTY_DAYS_MS,
            publicKey: preKey.publicKey,
          });
          break;
        }
      }
    }
  }

  async fetchPreKeyBundle(
    userId: string,
    deviceId: number,
    _fetcherUserId?: string,
    identityType?: IdentityType
  ): Promise<PreKeyBundle | null> {
    const deviceKey = this.storageKey(userId, deviceId, identityType);
    const accountKey = this.identityStorageKey(userId, identityType);

    // Identity keys are account-level; registration IDs are device-level.
    const encodedIdentity = this.identityKeys.get(accountKey);
    const registrationId = this.registrationIds.get(deviceKey);
    if (!encodedIdentity || registrationId === undefined) {
      return null;
    }

    // Get signed prekey (required)
    const ecSignedPreKey = this.ecSignedPreKeys.get(deviceKey);
    if (!ecSignedPreKey) {
      return null;
    }

    // Get and consume one-time prekey (optional)
    const ecPreKeys = this.ecPreKeys.get(deviceKey) || [];
    const exhaustOneTimePreKeys = this.failures.shouldExhaustOneTimePreKeys();
    if (exhaustOneTimePreKeys) {
      this.recordConsumedPreKeyIds(this.consumedEcPreKeyIds, deviceKey, ecPreKeys);
      this.recordConsumedPreKeyIds(
        this.consumedKemOneTimePreKeyIds,
        deviceKey,
        this.kemOneTimePreKeys.get(deviceKey) || []
      );
      this.ecPreKeys.delete(deviceKey);
      this.kemOneTimePreKeys.delete(deviceKey);
    }
    const ecOneTimePreKey =
      !exhaustOneTimePreKeys && ecPreKeys.length > 0 ? ecPreKeys.shift()! : null;
    if (ecOneTimePreKey) {
      this.recordConsumedPreKeyIds(
        this.consumedEcPreKeyIds,
        deviceKey,
        [ecOneTimePreKey]
      );
    }
    if (ecPreKeys.length === 0) {
      this.ecPreKeys.delete(deviceKey);
    }

    // Get KEM one-time prekey (consumed like EC one-time prekeys)
    // Per PQXDH spec Section 3.2: one-time KEM prekeys provide per-session PQ forward secrecy
    const kemOneTimePreKeys = this.kemOneTimePreKeys.get(deviceKey) || [];
    const kemOneTimePreKey =
      !exhaustOneTimePreKeys && kemOneTimePreKeys.length > 0
        ? kemOneTimePreKeys.shift()!
        : null;
    if (kemOneTimePreKey) {
      this.recordConsumedPreKeyIds(
        this.consumedKemOneTimePreKeyIds,
        deviceKey,
        [kemOneTimePreKey]
      );
    }
    if (kemOneTimePreKeys.length === 0) {
      this.kemOneTimePreKeys.delete(deviceKey);
    }

    // Get last-resort Kyber prekey (always returned if available)
    // This is SEPARATE from the one-time KEM prekeys
    const kemLastResortPreKey = this.kemLastResortPreKeys.get(deviceKey) || null;

    // Cast to branded types - ISignalProtocolRelayServer returns PreKeyBundle with branded types
    // Adapters handle the casting internally so callers don't need to
    return cloneRelayValue({
      registrationId,
      deviceId,
      identity: decodeCompositeIdentityV1(encodedIdentity),
      ecSignedPreKey: {
        keyId: ecSignedPreKey.keyId,
        publicKey: ecSignedPreKey.publicKey as PublicKey,
        signature: ecSignedPreKey.signature! as Signature,
      },
      ecOneTimePreKey: ecOneTimePreKey
        ? {
            keyId: ecOneTimePreKey.keyId,
            publicKey: ecOneTimePreKey.publicKey as PublicKey,
          }
        : null,
      kemLastResortPreKey: kemLastResortPreKey
        ? {
            keyId: kemLastResortPreKey.keyId,
            publicKey: kemLastResortPreKey.publicKey as PublicKey,
            signature: kemLastResortPreKey.signature! as Signature,
          }
        : null,
      kemOneTimePreKey: kemOneTimePreKey
        ? {
            keyId: kemOneTimePreKey.keyId,
            publicKey: kemOneTimePreKey.publicKey as PublicKey,
            signature: kemOneTimePreKey.signature! as Signature,
          }
        : null,
    });
  }

  async getPreKeyCount(
    userId: string,
    deviceId: number,
    type: 'ec' | 'kem',
    identityType?: IdentityType
  ): Promise<number> {
    const key = this.storageKey(userId, deviceId, identityType);
    if (type === 'ec') {
      return (this.ecPreKeys.get(key) || []).length;
    } else {
      return (this.kemOneTimePreKeys.get(key) || []).length;
    }
  }

  async clearStaleKemPreKeys(
    userId: string,
    deviceId: number,
    identityType?: IdentityType
  ): Promise<{ cleared: number }> {
    const key = this.storageKey(userId, deviceId, identityType);
    const kemKeys = this.kemOneTimePreKeys.get(key) || [];
    const clearedCount = kemKeys.length;
    this.kemOneTimePreKeys.set(key, []);
    return { cleared: clearedCount };
  }

  // ============================================================================
  // Convenience Methods (Key Rotation)
  // ============================================================================

  async uploadEcSignedPreKey(
    userId: string,
    ecSignedPreKey: EcSignedPreKeyUpload,
    identityType?: IdentityType
  ): Promise<void> {
    await this.uploadPreKeys(
      userId,
      ecSignedPreKey.deviceId,
      [
        {
          type: 'ecSignedPreKey',
          keyId: ecSignedPreKey.keyId,
          publicKey: ecSignedPreKey.publicKey,
          signature: ecSignedPreKey.signature,
        },
      ],
      identityType
    );
  }

  async uploadKemLastResortPreKey(
    userId: string,
    kemLastResortPreKey: KemLastResortPreKeyUpload,
    identityType?: IdentityType
  ): Promise<void> {
    await this.uploadPreKeys(
      userId,
      kemLastResortPreKey.deviceId,
      [
        {
          type: 'kemLastResortPreKey',
          keyId: kemLastResortPreKey.keyId,
          publicKey: kemLastResortPreKey.publicKey,
          signature: kemLastResortPreKey.signature,
        },
      ],
      identityType
    );
  }

  async getGroupMembers(groupId: string): Promise<GroupMemberDevice[]> {
    return cloneRelayValue(this.groupMembers.get(groupId) || []);
  }

  async getActiveDevices(userId: string): Promise<GroupMemberDevice[]> {
    const deviceInfos = this.devices.get(userId) || [];
    return deviceInfos
      .filter((device) => device.registered && device.enabled)
      .map((device) => ({ userId, deviceId: device.deviceId }));
  }

  // ============================================================================
  // Provisioning Service (IProvisioningService)
  // ============================================================================

  async createProvisioningSession(
    userId: string,
    ephemeralPublicKey: string
  ): Promise<{ sessionId: string }> {
    const sessionId = `prov-${++this.provisioningCounter}`;
    const now = Date.now();
    const reservedDeviceIds = new Set<number>();

    for (const device of this.devices.get(userId) || []) {
      if (device.deviceId !== 1 && device.registered && device.linked) {
        reservedDeviceIds.add(device.deviceId);
      }
    }

    for (const session of this.provisioningSessions.values()) {
      const sessionExpired = now - session.createdAt > PROVISIONING_SESSION_TTL_MS;
      if (
        session.userId === userId &&
        session.assignedDeviceId &&
        !sessionExpired &&
        session.status !== 'completed' &&
        session.status !== 'rolled_back' &&
        session.status !== 'expired'
      ) {
        reservedDeviceIds.add(session.assignedDeviceId);
      }
    }

    const assignedDeviceId = [2, 3, 4, 5].find((deviceId) => !reservedDeviceIds.has(deviceId));
    if (!assignedDeviceId) {
      throw new Error(`No linked device slots available for ${userId}`);
    }
    this.provisioningSessions.set(sessionId, {
      userId,
      ephemeralPublicKey,
      status: 'waiting',
      createdAt: Date.now(),
      assignedDeviceId,
    });
    return { sessionId };
  }

  async connectNewDevice(
    sessionId: string,
    ephemeralPublicKey: string,
    deviceMetadata: {
      platform?: string;
      appVersion?: string;
      osVersion?: string;
    }
  ): Promise<void> {
    const session = this.provisioningSessions.get(sessionId);
    if (!session) {
      throw new Error(`Provisioning session ${sessionId} not found`);
    }
    if (session.status !== 'waiting') {
      throw new Error(`Provisioning session ${sessionId} is not in waiting state`);
    }

    session.newDeviceEphemeralPublicKey = ephemeralPublicKey;
    session.deviceMetadata = cloneRelayValue(deviceMetadata);
    session.status = 'connected';
  }

  async sendProvisioningMessage(
    sessionId: string,
    encryptedMessage: string,
    _userId?: string
  ): Promise<void> {
    const session = this.provisioningSessions.get(sessionId);
    if (!session) {
      throw new Error(`Provisioning session ${sessionId} not found`);
    }
    if (session.status !== 'connected') {
      throw new Error(`Provisioning session ${sessionId} is not in connected state`);
    }

    session.encryptedMessage = encryptedMessage;
    session.status = 'ready';
  }

  async getProvisioningMessage(sessionId: string): Promise<{
    status:
      | 'waiting'
      | 'connected'
      | 'ready'
      | 'linked_pending_ack'
      | 'completed'
      | 'rolled_back'
      | 'expired';
    message: string | null;
  }> {
    const session = this.provisioningSessions.get(sessionId);
    if (!session) {
      return { status: 'expired', message: null };
    }

    // Check expiration (5 minutes)
    if (Date.now() - session.createdAt > PROVISIONING_SESSION_TTL_MS) {
      session.status = 'expired';
    }

    return {
      status: session.status,
      message:
        session.status === 'ready' || session.status === 'linked_pending_ack'
          ? session.encryptedMessage || null
          : null,
    };
  }

  async completeProvisioning(
    sessionId: string,
    deviceMetadata: {
      encryptedDeviceName: ArrayBuffer;
      platform?: string;
      appVersion?: string;
      osVersion?: string;
    }
  ): Promise<{ deviceId: number }> {
    const session = this.provisioningSessions.get(sessionId);
    if (!session) {
      throw new Error(`Provisioning session ${sessionId} not found`);
    }
    if (session.status !== 'ready' && session.status !== 'linked_pending_ack') {
      throw new Error(`Provisioning session ${sessionId} is not ready`);
    }
    if (!session.assignedDeviceId) {
      throw new Error(`Provisioning session ${sessionId} has no assigned device ID`);
    }

    if (session.status === 'linked_pending_ack') {
      return { deviceId: session.assignedDeviceId };
    }

    const existingDevices = this.devices.get(session.userId) ?? [];
    const now = Date.now();

    const activeExistingDevice = existingDevices.find(
      (device) => device.deviceId === session.assignedDeviceId && device.registered && device.linked
    );
    if (activeExistingDevice) {
      throw new Error(`Provisioning session ${sessionId} has no available linked device slot`);
    }

    const reusableDevice = existingDevices.find(
      (device) => device.deviceId === session.assignedDeviceId
    );
    const nextState: DeviceInfo = {
      deviceId: session.assignedDeviceId,
      encryptedDeviceName: cloneRelayValue(deviceMetadata.encryptedDeviceName),
      deviceType: 'mobile',
      registered: true,
      linked: true,
      enabled: true,
      active: true,
      lastSeen: now,
      createdAt: now,
      linkedAt: now,
    };

    if (reusableDevice) {
      Object.assign(reusableDevice, nextState);
    } else {
      existingDevices.push(nextState);
    }

    this.devices.set(session.userId, existingDevices);
    session.status = 'linked_pending_ack';
    return { deviceId: session.assignedDeviceId };
  }

  async acknowledgeProvisioning(sessionId: string): Promise<void> {
    const session = this.provisioningSessions.get(sessionId);
    if (!session) {
      throw new Error(`Provisioning session ${sessionId} not found`);
    }
    if (session.status !== 'linked_pending_ack') {
      throw new Error(`Provisioning session ${sessionId} is not awaiting acknowledgment`);
    }

    session.status = 'completed';
    delete session.encryptedMessage;
    delete session.newDeviceEphemeralPublicKey;
  }

  async rollbackProvisioning(sessionId: string): Promise<void> {
    const session = this.provisioningSessions.get(sessionId);
    if (!session || !session.assignedDeviceId || session.status !== 'linked_pending_ack') {
      return;
    }

    const existingDevices = this.devices.get(session.userId) ?? [];
    this.devices.set(
      session.userId,
      existingDevices.filter((device) => device.deviceId !== session.assignedDeviceId)
    );
    session.status = 'rolled_back';
  }

  async deleteProvisioningSession(sessionId: string, _userId?: string): Promise<void> {
    const session = this.provisioningSessions.get(sessionId);
    if (session?.assignedDeviceId && session.status === 'linked_pending_ack') {
      await this.rollbackProvisioning(sessionId);
    }
    this.provisioningSessions.delete(sessionId);
  }

  // ============================================================================
  // Key Rotation Service (IKeyRotationService)
  // ============================================================================

  async getEcSignedPreKeyMetadata(
    userId: string,
    deviceId: number,
    identityType?: IdentityType
  ): Promise<{ keyId: number; createdAt: number; expiresAt: number; publicKey: string } | null> {
    const key = this.storageKey(userId, deviceId, identityType);
    const metadata = this.ecSignedPreKeyMetadata.get(key);
    return metadata ? cloneRelayValue(metadata) : null;
  }

  async getKemLastResortPreKeyMetadata(
    userId: string,
    deviceId: number,
    identityType?: IdentityType
  ): Promise<{ keyId: number; createdAt: number; expiresAt: number; publicKey: string } | null> {
    const key = this.storageKey(userId, deviceId, identityType);
    const metadata = this.kemLastResortPreKeyMetadata.get(key);
    return metadata ? cloneRelayValue(metadata) : null;
  }

  // ============================================================================
  // Sealed Sender (Anonymous Delivery)
  // ============================================================================

  /** Mock sender certificate store (base64 cert per userId:deviceId) */
  private senderCertificates = new Map<string, string>();

  /** Return the sender certificate configured for this device. */
  async fetchSenderCertificate(deviceId: number): Promise<string> {
    const key = `cert:${deviceId}`;
    const cert = this.senderCertificates.get(key);
    if (cert) return cert;
    throw new Error(
      `No sender certificate configured for device ${deviceId}; call setSenderCertificate() first`
    );
  }

  /**
   * Mock: Send sealed sender message (anonymous delivery).
   * Same as send() but without sender identification.
   */
  async sendUnidentified(
    envelope: Envelope,
    auth: SealedSenderAuth
  ): Promise<{ messageId: string; serverTimestamp: number }> {
    if (this.failures.shouldRejectAuthorization()) {
      throw new SealedSenderAuthError();
    }
    // Mock: pass through without validation; callers can override if needed.
    void auth; // Accept but don't validate in mock
    return this.send({
      ...envelope,
      senderUserId: '',
      senderDeviceId: 0,
      messageType: 'unidentified_sender',
    });
  }

  /**
   * Mock: Send V2 multi-recipient sealed sender message.
   * Parses the binary blob, constructs per-device ReceivedMessages,
   * and fans out via send().
   */
  async sendMultiRecipientUnidentified(
    sentMessageBase64: string,
    auth: SealedSenderAuth,
    timestamp: number,
    groupId?: string,
    recipientUserIds?: string[],
    clientMessageId?: string
  ): Promise<{ messageId: string; serverTimestamp: number; uuids404: string[] }> {
    void auth; // Accept but don't validate in mock

    const { base64ToBytes, bytesToBase64 } = await import('../../../internal/crypto');
    const { asBase64 } = await import('../../../types/utils');
    const { deserializeSentMessage, serializeReceivedMessage } =
      await import('../../../internal/protocol/sealed-sender/v2-binary');

    const parsed = deserializeSentMessage(base64ToBytes(asBase64(sentMessageBase64)));

    let firstResult: { messageId: string; serverTimestamp: number } | undefined;
    const uuids404: string[] = [];

    for (let i = 0; i < parsed.recipients.length; i++) {
      const recipient = parsed.recipients[i];
      const userId = recipientUserIds?.[i] ?? recipient.serviceId;

      for (const device of recipient.devices) {
        // Construct per-device ReceivedMessage
        const receivedMsg = serializeReceivedMessage(
          recipient.encryptedMessageKey,
          recipient.authenticationTag,
          parsed.ephemeralPublic,
          parsed.messageCiphertext
        );

        const result = await this.send({
          targetUserId: userId,
          targetDeviceId: device.deviceId,
          senderUserId: '',
          senderDeviceId: 0,
          ciphertext: bytesToBase64(receivedMsg),
          messageType: 'unidentified_sender',
          groupId,
          timestamp,
          clientMessageId,
        });

        if (!firstResult) firstResult = result;
      }
    }

    return {
      messageId: firstResult?.messageId ?? `multi-${Date.now()}`,
      serverTimestamp: firstResult?.serverTimestamp ?? Date.now(),
      uuids404,
    };
  }

  /**
   * Set a sender certificate for deterministic local development.
   */
  setSenderCertificate(deviceId: number, certificate: string): void {
    this.senderCertificates.set(`cert:${deviceId}`, certificate);
  }

  // ============================================================================
  // Retry Requests (SESAME Spec §6.2)
  // ============================================================================

  async sendRetryRequest(request: RetryRequest): Promise<void> {
    const key = `${request.originalSenderUserId}:${request.originalSenderDeviceId}`;
    const existing = this.retryRequests.get(key) || [];
    existing.push(cloneRelayValue(request));
    this.retryRequests.set(key, existing);

    // Notify subscribers
    const subscribers = this.retryRequestSubscriptions.get(key) || [];
    for (const handler of subscribers) {
      await handler(cloneRelayValue(request));
    }
  }

  subscribeRetryRequests(
    userId: string,
    deviceId: number,
    handler: (request: RetryRequest) => Promise<void>
  ): Unsubscribe {
    const key = `${userId}:${deviceId}`;
    const subscribers = this.retryRequestSubscriptions.get(key) || [];
    subscribers.push(handler);
    this.retryRequestSubscriptions.set(key, subscribers);

    // Deliver any pending retry requests
    const pending = this.retryRequests.get(key) || [];
    for (const request of pending) {
      handler(cloneRelayValue(request));
    }

    return () => {
      const subs = this.retryRequestSubscriptions.get(key) || [];
      const idx = subs.indexOf(handler);
      if (idx >= 0) {
        subs.splice(idx, 1);
      }
    };
  }

  // ============================================================================
  // GroupsV2 State (encrypted, server-opaque)
  // ============================================================================

  async createGroupState(
    groupId: Uint8Array,
    encryptedState: Uint8Array,
    _authorization: GroupAuthorization
  ): Promise<void> {
    const key = this.groupIdToHex(groupId);
    this.groupStates.set(key, { encryptedState: cloneRelayValue(encryptedState), version: 0 });
    this.groupChangeLogs.set(key, []);
  }

  async getGroupState(
    groupId: Uint8Array,
    _authorization: GroupAuthorization
  ): Promise<{
    encryptedState: Uint8Array;
    version: number;
  } | null> {
    const key = this.groupIdToHex(groupId);
    const state = this.groupStates.get(key);
    return state ? cloneRelayValue(state) : null;
  }

  async getGroupChanges(
    groupId: Uint8Array,
    fromVersion: number,
    _authorization: GroupAuthorization
  ): Promise<GroupChangeEntry[]> {
    const key = this.groupIdToHex(groupId);
    const changes = this.groupChangeLogs.get(key) ?? [];
    return cloneRelayValue(changes.filter((c) => c.version > fromVersion));
  }

  async submitGroupChange(
    groupId: Uint8Array,
    expectedVersion: number,
    encryptedChange: Uint8Array,
    updatedEncryptedState: Uint8Array,
    _authorization: GroupAuthorization
  ): Promise<{ serverSignature: Uint8Array }> {
    const key = this.groupIdToHex(groupId);
    const current = this.groupStates.get(key);
    if (!current) {
      throw new Error(`Group not found: ${key}`);
    }
    if (current.version !== expectedVersion) {
      throw new Error(`Version conflict: expected ${expectedVersion}, got ${current.version}`);
    }

    const newVersion = current.version + 1;
    const randomness = crypto.getRandomValues(new Uint8Array(32));
    const serverSignature = serverSign(this.serverSecretParams, randomness, encryptedChange);
    const entry: GroupChangeEntry = {
      version: newVersion,
      encryptedChange: cloneRelayValue(encryptedChange),
      serverSignature,
      timestamp: Date.now(),
    };

    current.encryptedState = cloneRelayValue(updatedEncryptedState);
    current.version = newVersion;

    const changes = this.groupChangeLogs.get(key) ?? [];
    changes.push(cloneRelayValue(entry));
    this.groupChangeLogs.set(key, changes);

    return cloneRelayValue({ serverSignature });
  }

  // ============================================================================
  // ZK Auth Credentials (anonymous group access)
  // ============================================================================

  private userIdentities = new Map<string, { uuid: string; phoneNumberIdentifier?: string }>();

  private getOrCreateIdentity(userId: string): { uuid: string; phoneNumberIdentifier?: string } {
    let identity = this.userIdentities.get(userId);
    if (!identity) {
      // No phoneNumberIdentifier — mock matches username-based (non-phone) app pattern
      identity = { uuid: crypto.randomUUID() };
      this.userIdentities.set(userId, identity);
    }
    return identity;
  }

  async issueAuthCredential(userId: string): Promise<Uint8Array> {
    const identity = this.getOrCreateIdentity(userId);
    const aci: ServiceId = { kind: SERVICE_ID_ACI, uuid: uuidToBytes(identity.uuid) };
    // Nil PNI for non-phone apps — credential math only needs issuance/reception consistency
    const NIL_PNI_UUID = '00000000-0000-0000-0000-000000000000';
    const pni: ServiceId = {
      kind: SERVICE_ID_PNI,
      uuid: uuidToBytes(identity.phoneNumberIdentifier ?? NIL_PNI_UUID),
    };

    const redemptionTime = Math.floor(Date.now() / 1000 / SECONDS_PER_DAY) * SECONDS_PER_DAY;
    const randomness = crypto.getRandomValues(new Uint8Array(32));

    const response = issueAuthCredentialZk(
      this.serverSecretParams.credentialKeyPair,
      aci,
      pni,
      redemptionTime,
      randomness
    );

    return serializeAuthCredentialResponse(response);
  }

  async refreshGroupSendEndorsements(
    groupId: Uint8Array,
    _authorization: GroupAuthorization
  ): Promise<{ endorsements: Uint8Array; expiration: number }> {
    const key = this.groupIdToHex(groupId);
    const group = this.groupStates.get(key);
    if (!group) {
      throw new Error(`Group not found: ${key}`);
    }

    // Extract UidEncCiphertext objects from the serialized encrypted state.
    // Matches the same parsing logic used by convex/signal/groups.ts.
    const memberCiphertexts = this.extractMemberCiphertexts(group.encryptedState);
    if (memberCiphertexts.length === 0) {
      throw new Error('Empty group');
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    const expiration = defaultExpiration(nowSeconds);

    const derivedKeyPair = deriveForExpiration(
      this.serverSecretParams.endorsementKeyPair,
      expiration
    );

    const randomness = crypto.getRandomValues(new Uint8Array(32));
    const endorsementsResponse = issueEndorsements(memberCiphertexts, derivedKeyPair, randomness);

    const serialized = serializeEndorsementsResponse(endorsementsResponse);
    return { endorsements: serialized, expiration };
  }

  /**
   * Extract UidEncCiphertext objects from serialized encrypted group state JSON.
   *
   * The encrypted state is JSON with `{ __bytes: hex }` markers for binary fields.
   * Each member's `userId` is a 65-byte UuidCiphertext:
   * [ServiceIdKind (1 byte)] [E_A1 (32 bytes)] [E_A2 (32 bytes)].
   */
  private extractMemberCiphertexts(encryptedState: Uint8Array): Ciphertext[] {
    const json = new TextDecoder().decode(encryptedState);
    const parsed = JSON.parse(json) as {
      members: Array<{ userId: { __bytes: string } }>;
    };

    if (!parsed.members || !Array.isArray(parsed.members)) {
      throw new Error('Invalid group state: missing members array');
    }

    const RistrettoPoint = ristretto255.Point;
    return parsed.members.map((member) => {
      const hex = member.userId.__bytes;
      const len = hex.length >>> 1;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
      }
      if (bytes.length !== 65) {
        throw new Error(`Invalid UuidCiphertext length: ${bytes.length}`);
      }
      const E_A1 = RistrettoPoint.fromBytes(bytes.slice(1, 33));
      const E_A2 = RistrettoPoint.fromBytes(bytes.slice(33, 65));
      return new Ciphertext(E_A1, E_A2, UidEncryptionDomain);
    });
  }

  // ============================================================================
  // Deterministic inspection and setup
  // ============================================================================

  /**
   * Clear all in-memory data.
   */
  clear(): void {
    this.devices.clear();
    this.identityKeys.clear();
    this.registrationIds.clear();
    this.ecPreKeys.clear();
    this.consumedEcPreKeyIds.clear();
    this.ecSignedPreKeys.clear();
    this.kemOneTimePreKeys.clear();
    this.consumedKemOneTimePreKeyIds.clear();
    this.kemLastResortPreKeys.clear();
    this.pendingMessages.clear();
    this.clientMessageReceipts.clear();
    this.subscriptions.clear();
    this.groupMembers.clear();
    this.provisioningSessions.clear();
    this.ecSignedPreKeyMetadata.clear();
    this.kemLastResortPreKeyMetadata.clear();
    this.retryRequests.clear();
    this.retryRequestSubscriptions.clear();
    this.groupStates.clear();
    this.groupChangeLogs.clear();
    this.userIdentities.clear();
    this.senderCertificates.clear();
    this.failures.reset();
    this.messageCounter = 0;
    this.provisioningCounter = 0;
  }

  /**
   * Set group members for deterministic local setup.
   */
  setGroupMembers(groupId: string, members: GroupMemberDevice[]): void {
    this.groupMembers.set(groupId, cloneRelayValue(members));
  }

  /**
   * Inspect pending messages for a device.
   */
  getPendingMessages(userId: string, deviceId: number): Envelope[] {
    const key = `${userId}:${deviceId}`;
    return cloneRelayValue(this.pendingMessages.get(key) || []);
  }

  /**
   * Inspect pending retry requests for a device.
   */
  getPendingRetryRequests(userId: string, deviceId: number): RetryRequest[] {
    const key = `${userId}:${deviceId}`;
    return cloneRelayValue(this.retryRequests.get(key) || []);
  }

  /**
   * Mark a retry request as handled (remove from pending)
   */
  markRetryRequestHandled(userId: string, deviceId: number, failedTimestamp: number): void {
    const key = `${userId}:${deviceId}`;
    const requests = this.retryRequests.get(key) || [];
    const idx = requests.findIndex((r) => r.failedTimestamp === failedTimestamp);
    if (idx >= 0) {
      requests.splice(idx, 1);
      if (requests.length === 0) {
        this.retryRequests.delete(key);
      }
    }
  }

  /**
   * Set EC signed-prekey metadata for deterministic key rotation.
   */
  setEcSignedPreKeyMetadata(
    userId: string,
    deviceId: number,
    metadata: { keyId: number; createdAt: number; expiresAt: number; publicKey: string },
    identityType: IdentityType = 'aci'
  ): void {
    const key = this.storageKey(userId, deviceId, identityType);
    this.ecSignedPreKeyMetadata.set(key, cloneRelayValue(metadata));
  }

  /**
   * Set Kyber prekey metadata for deterministic key rotation.
   */
  setKemLastResortPreKeyMetadata(
    userId: string,
    deviceId: number,
    metadata: { keyId: number; createdAt: number; expiresAt: number; publicKey: string },
    identityType: IdentityType = 'aci'
  ): void {
    const key = this.storageKey(userId, deviceId, identityType);
    this.kemLastResortPreKeyMetadata.set(key, cloneRelayValue(metadata));
  }

  /**
   * Set the prekey count for deterministic key rotation.
   *
   * Creates placeholder prekeys to simulate a specific count.
   * Exposes exact threshold behavior without a remote backend.
   *
   * @param userId - User ID
   * @param deviceId - Device ID
   * @param type - Key type ('ec' for classical, 'kem' for post-quantum)
   * @param count - Number of prekeys to simulate
   */
  setPreKeyCount(
    userId: string,
    deviceId: number,
    type: 'ec' | 'kem',
    count: number,
    identityType: IdentityType = 'aci'
  ): void {
    const key = this.storageKey(userId, deviceId, identityType);
    // Create placeholder prekeys to set the count
    const placeholderKeys: PreKeyUpload[] = Array.from({ length: count }, (_, i) => ({
      type: type === 'ec' ? ('ecPreKey' as const) : ('kemOneTimePreKey' as const),
      keyId: i + 1,
      publicKey: `placeholder-${i}`,
    }));
    if (type === 'ec') {
      this.consumedEcPreKeyIds.delete(key);
      this.ecPreKeys.set(key, placeholderKeys);
    } else {
      this.consumedKemOneTimePreKeyIds.delete(key);
      this.kemOneTimePreKeys.set(key, placeholderKeys);
    }
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  private recordConsumedPreKeyIds(
    consumed: Map<string, Set<number>>,
    storageKey: string,
    preKeys: PreKeyUpload[]
  ): void {
    if (preKeys.length === 0) return;
    const keyIds = consumed.get(storageKey) || new Set<number>();
    for (const preKey of preKeys) {
      keyIds.add(preKey.keyId);
    }
    consumed.set(storageKey, keyIds);
  }

  private groupIdToHex(groupId: Uint8Array): string {
    return Array.from(groupId)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  private deliverEnvelope(targetKey: string, envelope: Envelope): void {
    const subscribers = this.subscriptions.get(targetKey) || [];
    for (const callback of subscribers) {
      callback(cloneRelayValue(envelope));
    }
  }

  private deliverPending(targetKey: string): void {
    if (this.failures.isDisconnected(targetKey)) return;
    this.failures.discardReordered(targetKey);
    const pending = this.pendingMessages.get(targetKey) || [];
    for (const envelope of pending) {
      this.failures.deliver(targetKey, envelope);
    }
  }

  private uint8ArrayToBase64(data: Uint8Array): string {
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(data).toString('base64');
    }
    let binary = '';
    const len = data.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(data[i]);
    }
    return btoa(binary);
  }
}
