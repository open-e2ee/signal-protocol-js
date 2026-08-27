import type { PrivateKey } from '../keys';
import {
  generateEcOneTimePreKeys,
  generateEcSignedPreKey,
  generateIdentityKeyPair,
  generateKemOneTimePreKeys,
  generateKyberLastResortPreKey,
} from '../keys';
import type { CompositeIdentityV1 } from '../keys/types';
import { createCompositeIdentityV1 } from '../keys/identity';
import {
  base64ToBytes,
  bytesToBase64,
  concatBytes,
  generateSigningKeyPair,
  sha256,
  sign,
  stringToBytes,
} from '../internal/crypto';
import type { ISignalProtocolRelayServer } from '../remote/relay/types';
import type { ISignalProtocolLocalStore, Base64 } from '../types';
import { SignalProtocolClient } from './client';
import type { SignalProtocolClientCompositionOptions } from './compose';
import { createSignalProtocolClientConfig } from './compose';
import type { SealedSenderAccessMode } from './config';

export {
  pullHostedRelayAfterWake,
  registerHostedRelayPush,
  removeHostedRelayPush,
} from './hosted-push';
export type {
  HostedRelayMailboxAcknowledgmentRequest,
  HostedRelayMailboxPullRequest,
  HostedRelayPushAdapter,
  HostedRelayPushRegistration,
  HostedRelayPushRegistrationRequest,
  HostedRelayPushRemovalRequest,
  HostedRelayTokenPushRegistration,
  HostedRelayWakeClient,
  HostedRelayWakeOptions,
  HostedRelayWakeResult,
  HostedRelayWebPushRegistration,
} from './hosted-push';

const DEVICE_AUTHENTICATION_METADATA_PREFIX =
  'hostedRelay.deviceAuthentication.v1:';
const REGISTRATION_SNAPSHOT_METADATA_PREFIX =
  'hostedRelay.registrationSnapshot.v1:';
const HOSTED_REGISTRATION_ONE_TIME_PREKEY_COUNT = 10;
const DEVICE_AUTHENTICATION_SIGNATURE_LABEL = stringToBytes(
  'OpenE2EE Relay device authentication v1\0'
);

/** Why the hosted Relay needs a fresh identity assertion. */
export type IdentityAssertionPurpose = 'register' | 'refresh' | 'recover';

/** Assurance requested from the application's identity provider. */
export type IdentityAssertionAssurance = 'normal' | 'recent' | 'step-up';

/** Provider role requested while an identity migration is in progress. */
export type IdentityAssertionProviderRole = 'source' | 'target';

/** Additional context for a purpose-aware assertion request. */
export interface IdentityAssertionRequest {
  readonly purpose: IdentityAssertionPurpose;
  readonly assurance?: IdentityAssertionAssurance;
  readonly migration?: {
    readonly action: HostedRelayIdentityMigrationAction;
    readonly providerRole: IdentityAssertionProviderRole;
  };
}

/** Stable application callback for a signed identity-provider assertion. */
export type GetIdentityAssertion = (
  request: IdentityAssertionRequest
) => Promise<string>;

/** Hosted identity operation progress suitable for application UI. */
export type HostedRelayIdentityProgress =
  | {
      readonly operation: 'bootstrap' | 'recovery';
      readonly phase:
        | 'preparing-local-state'
        | 'requesting-assertion'
        | 'submitting'
        | 'complete';
    }
  | {
      readonly operation: 'migration';
      readonly action: HostedRelayIdentityMigrationAction;
      readonly phase: 'requesting-assertion' | 'submitting' | 'complete';
      readonly providerRole?: IdentityAssertionProviderRole;
      readonly state?: HostedRelayIdentityMigrationState;
    }
  | {
      readonly operation: 'device-link';
      readonly phase: 'preparing-linked-device' | 'submitting' | 'complete';
      readonly deviceId?: number;
    };

/** Receives typed progress without receiving assertions or private key material. */
export type HostedRelayIdentityProgressCallback = (
  progress: HostedRelayIdentityProgress
) => void;

/** A device proof signer whose private key never leaves the SDK-owned local store. */
export interface HostedRelayDeviceAuthentication {
  readonly publicKey: Uint8Array;
  /**
   * Sign a Relay challenge with domain separation and publishable-key binding.
   * The adapter verifies `label || publishableKey || 0x00 || challenge`.
   */
  signChallenge(challenge: Uint8Array): Promise<Uint8Array>;
}

/** Public prekey material sent during one atomic hosted Relay registration. */
export interface HostedRelayRegistrationPreKey {
  readonly algorithm: 'ec-x25519' | 'kem-ml-kem-1024';
  readonly keyId: number;
  readonly publicKey: Uint8Array;
  readonly signature?: Uint8Array;
}

/** Complete EC/PQ inventory bound to the hosted device registration. */
export interface HostedRelayRegistrationPreKeys {
  readonly oneTimePreKeys: readonly HostedRelayRegistrationPreKey[];
  readonly signedPreKeys: readonly HostedRelayRegistrationPreKey[];
}

/** Request passed to a hosted Relay bootstrap transport. */
export interface HostedRelayBootstrapRequest {
  readonly publishableKey: string;
  readonly assertion: string;
  readonly assertionPurpose: IdentityAssertionPurpose;
  readonly signalIdentity: CompositeIdentityV1;
  readonly registrationId: number;
  /** Stable for exact retries and changes when the public registration material changes. */
  readonly operationId: string;
  readonly registrationPreKeys: HostedRelayRegistrationPreKeys;
  readonly deviceAuthentication: HostedRelayDeviceAuthentication;
}

/** Canonical identity and authenticated Relay returned by hosted bootstrap. */
export interface HostedRelayBootstrapResult {
  readonly canonicalAccountId: string;
  readonly deviceId: number;
  readonly relayScopeId: Uint8Array;
  readonly relay: ISignalProtocolRelayServer;
}

export type HostedRelayIdentityMigrationAction =
  | 'prepare'
  | 'inspect'
  | 'cutover'
  | 'rollback'
  | 'finalize';

export type HostedRelayIdentityMigrationState =
  | 'abandoned'
  | 'prepared'
  | 'cutover'
  | 'rolled-back'
  | 'finalized';

export interface HostedRelayIdentityMigrationSnapshot {
  readonly accountPreserved: true;
  readonly collision: false;
  readonly expiresAt: number;
  readonly manifestVersion: number;
  readonly operationId: string;
  readonly primaryProvider: IdentityAssertionProviderRole;
  readonly proof: 'active-device' | 'dual-assertion';
  readonly rollbackDeadline?: number;
  readonly state: HostedRelayIdentityMigrationState;
}

export interface HostedRelayIdentityMigrationRequest {
  readonly action: HostedRelayIdentityMigrationAction;
  readonly publishableKey: string;
  readonly operationId: string;
  readonly manifestVersion?: number;
  readonly authorization:
    | {
        readonly kind: 'active-device';
        readonly deviceAuthentication: HostedRelayDeviceAuthentication;
      }
    | {
        readonly kind: 'assertion';
        readonly assertion: string;
      };
  readonly targetAssertion?: string;
}

export interface HostedRelayManagedDeviceLinkRequest {
  readonly publishableKey: string;
  readonly signalIdentity: CompositeIdentityV1;
  readonly registrationId: number;
  readonly operationId: string;
  readonly registrationPreKeys: HostedRelayRegistrationPreKeys;
  readonly activeDeviceAuthentication: HostedRelayDeviceAuthentication;
  readonly newDeviceAuthentication: HostedRelayDeviceAuthentication;
}

export interface HostedRelayManagedDeviceLinkResult
  extends HostedRelayBootstrapResult {
  readonly accountPreserved: true;
  readonly protocolStateCopied: false;
}

/**
 * SDK or integration-owned hosted Relay transport.
 *
 * Certificate roots are pinned in this adapter, outside the bootstrap response.
 * A Relay response cannot select the root that validates its own certificates.
 */
export interface HostedRelayBootstrapAdapter {
  readonly certificateTrust: {
    readonly environment: 'development' | 'production';
    readonly trustRoots: readonly Uint8Array[];
    readonly revokedIssuerKeyIds: readonly number[];
  };
  bootstrap(
    request: HostedRelayBootstrapRequest
  ): Promise<HostedRelayBootstrapResult>;
}

/** Transport boundary for the hosted Relay identity-migration state machine. */
export interface HostedRelayIdentityMigrationAdapter {
  migrate(
    request: HostedRelayIdentityMigrationRequest
  ): Promise<HostedRelayIdentityMigrationSnapshot>;
}

/** Transport boundary for canonical managed device linking. */
export interface HostedRelayManagedDeviceLinkAdapter
  extends HostedRelayBootstrapAdapter {
  linkDevice(
    request: HostedRelayManagedDeviceLinkRequest
  ): Promise<HostedRelayManagedDeviceLinkResult>;
}

/** Compact, runtime-neutral hosted Relay client configuration. */
export interface HostedSignalProtocolClientOptions extends Omit<
  SignalProtocolClientCompositionOptions,
  'adapters' | 'identity' | 'sealedSender'
> {
  readonly adapters: Omit<
    SignalProtocolClientCompositionOptions['adapters'],
    'relay'
  >;
  readonly hosted: {
    readonly publishableKey: string;
    readonly bootstrap: HostedRelayBootstrapAdapter;
    readonly getIdentityAssertion: GetIdentityAssertion;
    readonly assertionPurpose?: IdentityAssertionPurpose;
    readonly assurance?: IdentityAssertionAssurance;
    readonly onProgress?: HostedRelayIdentityProgressCallback;
    readonly sealedSenderAccessMode?: SealedSenderAccessMode;
  };
}

export interface HostedRelayIdentityMigrationOptions {
  readonly action: HostedRelayIdentityMigrationAction;
  readonly adapter: HostedRelayIdentityMigrationAdapter;
  readonly getIdentityAssertion: GetIdentityAssertion;
  readonly manifestVersion?: number;
  readonly operationId: string;
  readonly onProgress?: HostedRelayIdentityProgressCallback;
  readonly publishableKey: string;
  readonly authorization:
    | {
        readonly kind: 'active-device';
        readonly storage: ISignalProtocolLocalStore;
      }
    | {
        readonly kind: 'assertion';
        readonly providerRole: IdentityAssertionProviderRole;
      };
}

export interface HostedRelayManagedDeviceLinkOptions extends Omit<
  SignalProtocolClientCompositionOptions,
  'adapters' | 'identity' | 'sealedSender'
> {
  readonly adapters: Omit<
    SignalProtocolClientCompositionOptions['adapters'],
    'relay'
  >;
  readonly activeDeviceStorage: ISignalProtocolLocalStore;
  readonly hosted: {
    readonly publishableKey: string;
    readonly adapter: HostedRelayManagedDeviceLinkAdapter;
    readonly onProgress?: HostedRelayIdentityProgressCallback;
    readonly sealedSenderAccessMode?: SealedSenderAccessMode;
  };
}

interface StoredDeviceAuthentication {
  publicKey: Base64;
  privateKey: PrivateKey;
}

interface StoredHostedRegistrationPreKey {
  algorithm: HostedRelayRegistrationPreKey['algorithm'];
  keyId: number;
  publicKey: Base64;
  signature?: Base64;
}

interface StoredHostedRegistrationSnapshot {
  operationId: Base64;
  registrationId: number;
  signalIdentity: CompositeIdentityV1;
  oneTimePreKeys: StoredHostedRegistrationPreKey[];
  signedPreKeys: StoredHostedRegistrationPreKey[];
}

function uint32be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error(
      'Hosted Relay prekey ID must be an unsigned 32-bit integer'
    );
  }
  return new Uint8Array([value >>> 24, value >>> 16, value >>> 8, value]);
}

function lengthPrefixed(value: Uint8Array): Uint8Array {
  return concatBytes(uint32be(value.length), value);
}

async function deriveHostedRegistrationOperationId(
  identity: CompositeIdentityV1,
  registrationId: number,
  prekeys: HostedRelayRegistrationPreKeys
): Promise<string> {
  const entries = [
    ...prekeys.signedPreKeys.map((prekey) => ({ ...prekey, kind: 1 })),
    ...prekeys.oneTimePreKeys.map((prekey) => ({ ...prekey, kind: 2 })),
  ].sort((left, right) => {
    const leftIdentifier = `${left.kind}:${left.algorithm}:${left.keyId}`;
    const rightIdentifier = `${right.kind}:${right.algorithm}:${right.keyId}`;
    return leftIdentifier < rightIdentifier
      ? -1
      : leftIdentifier > rightIdentifier
        ? 1
        : 0;
  });
  const material = entries.flatMap((prekey) => [
    new Uint8Array([prekey.kind, prekey.algorithm === 'ec-x25519' ? 1 : 10]),
    uint32be(prekey.keyId),
    lengthPrefixed(prekey.publicKey),
    lengthPrefixed(prekey.signature ?? new Uint8Array()),
  ]);
  const encodedIdentity = concatBytes(
    new Uint8Array([1, 1]),
    base64ToBytes(identity.x25519PublicKey),
    new Uint8Array([2]),
    base64ToBytes(identity.ed25519PublicKey)
  );
  return bytesToBase64(
    await sha256(
      concatBytes(
        stringToBytes('OpenE2EE Relay hosted registration operation v1\0'),
        uint32be(registrationId),
        lengthPrefixed(encodedIdentity),
        ...material
      )
    )
  );
}

function encodeRegistrationPreKey(
  prekey: HostedRelayRegistrationPreKey
): StoredHostedRegistrationPreKey {
  return {
    algorithm: prekey.algorithm,
    keyId: prekey.keyId,
    publicKey: bytesToBase64(prekey.publicKey),
    ...(prekey.signature === undefined
      ? {}
      : { signature: bytesToBase64(prekey.signature) }),
  };
}

function decodeRegistrationPreKey(
  value: unknown,
  kind: 'one-time' | 'signed'
): HostedRelayRegistrationPreKey {
  if (
    typeof value !== 'object' ||
    value === null ||
    !('algorithm' in value) ||
    !('keyId' in value) ||
    !('publicKey' in value) ||
    (value.algorithm !== 'ec-x25519' &&
      value.algorithm !== 'kem-ml-kem-1024') ||
    !Number.isSafeInteger(value.keyId) ||
    (value.keyId as number) < 0 ||
    (value.keyId as number) > 0xffff_ffff ||
    typeof value.publicKey !== 'string' ||
    !('signature' in value || kind === 'one-time') ||
    ('signature' in value && typeof value.signature !== 'string')
  ) {
    throw new Error('Stored hosted Relay registration snapshot is invalid');
  }
  const publicKey = base64ToBytes(value.publicKey as Base64);
  const signature =
    'signature' in value ? base64ToBytes(value.signature as Base64) : undefined;
  if (
    publicKey.length === 0 ||
    publicKey.length > 4 * 1024 ||
    (signature !== undefined && signature.length !== 64) ||
    (kind === 'signed' && signature === undefined) ||
    (kind === 'one-time' &&
      value.algorithm === 'kem-ml-kem-1024' &&
      signature === undefined) ||
    (kind === 'one-time' &&
      value.algorithm === 'ec-x25519' &&
      signature !== undefined)
  ) {
    throw new Error('Stored hosted Relay registration snapshot is invalid');
  }
  return {
    algorithm: value.algorithm,
    keyId: value.keyId as number,
    publicKey,
    ...(signature === undefined ? {} : { signature }),
  };
}

async function decodeRegistrationSnapshot(
  value: string,
  identity: CompositeIdentityV1,
  registrationId: number
): Promise<{
  operationId: string;
  registrationPreKeys: HostedRelayRegistrationPreKeys;
}> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error('Stored hosted Relay registration snapshot is invalid');
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    !('operationId' in parsed) ||
    !('registrationId' in parsed) ||
    !('signalIdentity' in parsed) ||
    !('oneTimePreKeys' in parsed) ||
    !('signedPreKeys' in parsed) ||
    typeof parsed.operationId !== 'string' ||
    parsed.registrationId !== registrationId ||
    typeof parsed.signalIdentity !== 'object' ||
    parsed.signalIdentity === null ||
    !('version' in parsed.signalIdentity) ||
    parsed.signalIdentity.version !== identity.version ||
    !('x25519PublicKey' in parsed.signalIdentity) ||
    parsed.signalIdentity.x25519PublicKey !== identity.x25519PublicKey ||
    !('ed25519PublicKey' in parsed.signalIdentity) ||
    parsed.signalIdentity.ed25519PublicKey !== identity.ed25519PublicKey ||
    !Array.isArray(parsed.oneTimePreKeys) ||
    !Array.isArray(parsed.signedPreKeys) ||
    parsed.oneTimePreKeys.length === 0 ||
    parsed.oneTimePreKeys.length > 200 ||
    parsed.signedPreKeys.length !== 2 ||
    base64ToBytes(parsed.operationId as Base64).length !== 32
  ) {
    throw new Error('Stored hosted Relay registration snapshot is invalid');
  }
  const registrationPreKeys = {
    oneTimePreKeys: parsed.oneTimePreKeys.map((prekey) =>
      decodeRegistrationPreKey(prekey, 'one-time')
    ),
    signedPreKeys: parsed.signedPreKeys.map((prekey) =>
      decodeRegistrationPreKey(prekey, 'signed')
    ),
  };
  const operationId = await deriveHostedRegistrationOperationId(
    identity,
    registrationId,
    registrationPreKeys
  );
  if (operationId !== parsed.operationId) {
    throw new Error('Stored hosted Relay registration snapshot is invalid');
  }
  return { operationId, registrationPreKeys };
}

async function getOrCreateRegistrationSnapshot(
  storage: ISignalProtocolLocalStore,
  publishableKey: string,
  identity: CompositeIdentityV1,
  registrationId: number,
  identityKeyPair: NonNullable<
    Awaited<ReturnType<ISignalProtocolLocalStore['getIdentityKey']>>
  >
): Promise<{
  operationId: string;
  registrationPreKeys: HostedRelayRegistrationPreKeys;
}> {
  const metadataKey = `${REGISTRATION_SNAPSHOT_METADATA_PREFIX}${bytesToBase64(
    await sha256(
      concatBytes(
        stringToBytes(publishableKey),
        new Uint8Array([0]),
        uint32be(registrationId),
        base64ToBytes(identity.x25519PublicKey),
        base64ToBytes(identity.ed25519PublicKey)
      )
    )
  )}`;
  const stored = await storage.getMetadata(metadataKey);
  if (stored) {
    return decodeRegistrationSnapshot(stored, identity, registrationId);
  }
  const registrationPreKeys = await getOrCreateRegistrationPreKeys(
    storage,
    identityKeyPair
  );
  const operationId = await deriveHostedRegistrationOperationId(
    identity,
    registrationId,
    registrationPreKeys
  );
  const snapshot: StoredHostedRegistrationSnapshot = {
    operationId: operationId as Base64,
    registrationId,
    signalIdentity: identity,
    oneTimePreKeys: registrationPreKeys.oneTimePreKeys.map(
      encodeRegistrationPreKey
    ),
    signedPreKeys: registrationPreKeys.signedPreKeys.map(
      encodeRegistrationPreKey
    ),
  };
  await storage.setMetadata(metadataKey, JSON.stringify(snapshot));
  return { operationId, registrationPreKeys };
}

async function getOrCreateRegistrationPreKeys(
  storage: ISignalProtocolLocalStore,
  identity: NonNullable<
    Awaited<ReturnType<ISignalProtocolLocalStore['getIdentityKey']>>
  >
): Promise<HostedRelayRegistrationPreKeys> {
  let signedPreKey = await storage.getEcSignedPreKey(undefined, 'aci');
  if (!signedPreKey) {
    signedPreKey = await generateEcSignedPreKey(identity);
    await storage.storeEcSignedPreKey(signedPreKey, 'aci');
  }
  let kyberPreKey = await storage.getKyberPreKey('aci');
  if (!kyberPreKey) {
    kyberPreKey = await generateKyberLastResortPreKey(identity, 1);
    await storage.storeKyberPreKey(kyberPreKey, 'aci');
  }
  let ecOneTimePreKeys = await storage.getEcOneTimePreKeys('aci');
  if (ecOneTimePreKeys.length === 0) {
    ecOneTimePreKeys = await generateEcOneTimePreKeys(
      HOSTED_REGISTRATION_ONE_TIME_PREKEY_COUNT,
      0
    );
    await storage.storeEcOneTimePreKeys(ecOneTimePreKeys, 'aci');
  }
  let kemOneTimePreKeys = await storage.getKemOneTimePreKeys('aci');
  if (kemOneTimePreKeys.length === 0) {
    kemOneTimePreKeys = await generateKemOneTimePreKeys(
      identity,
      HOSTED_REGISTRATION_ONE_TIME_PREKEY_COUNT,
      0
    );
    await storage.storeKemOneTimePreKeys(kemOneTimePreKeys, 'aci');
  }
  return {
    signedPreKeys: [
      {
        algorithm: 'ec-x25519',
        keyId: signedPreKey.keyId,
        publicKey: base64ToBytes(signedPreKey.publicKey),
        signature: base64ToBytes(signedPreKey.signature),
      },
      {
        algorithm: 'kem-ml-kem-1024',
        keyId: kyberPreKey.keyId,
        publicKey: base64ToBytes(kyberPreKey.publicKey),
        signature: base64ToBytes(kyberPreKey.signature),
      },
    ],
    oneTimePreKeys: [
      ...ecOneTimePreKeys.map((prekey) => ({
        algorithm: 'ec-x25519' as const,
        keyId: prekey.keyId,
        publicKey: base64ToBytes(prekey.publicKey),
      })),
      ...kemOneTimePreKeys.map((prekey) => ({
        algorithm: 'kem-ml-kem-1024' as const,
        keyId: prekey.keyId,
        publicKey: base64ToBytes(prekey.publicKey),
        signature: base64ToBytes(prekey.signature),
      })),
    ],
  };
}

function decodeStoredDeviceAuthentication(
  value: string
): StoredDeviceAuthentication {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error('Stored hosted Relay device authentication key is invalid');
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    !('publicKey' in parsed) ||
    !('privateKey' in parsed) ||
    typeof parsed.publicKey !== 'string' ||
    typeof parsed.privateKey !== 'string' ||
    base64ToBytes(parsed.publicKey as Base64).length !== 32 ||
    base64ToBytes(parsed.privateKey as Base64).length !== 32
  ) {
    throw new Error('Stored hosted Relay device authentication key is invalid');
  }
  return parsed as StoredDeviceAuthentication;
}

async function getOrCreateDeviceAuthentication(
  storage: ISignalProtocolLocalStore,
  publishableKey: string
): Promise<HostedRelayDeviceAuthentication> {
  const metadataKey = await deviceAuthenticationMetadataKey(publishableKey);
  const stored = await storage.getMetadata(metadataKey);
  let keyPair: StoredDeviceAuthentication;
  if (stored) {
    keyPair = decodeStoredDeviceAuthentication(stored);
  } else {
    keyPair = await generateSigningKeyPair();
    await storage.setMetadata(metadataKey, JSON.stringify(keyPair));
  }
  return deviceAuthenticationSigner(keyPair, publishableKey);
}

async function getExistingDeviceAuthentication(
  storage: ISignalProtocolLocalStore,
  publishableKey: string
): Promise<HostedRelayDeviceAuthentication> {
  const stored = await storage.getMetadata(
    await deviceAuthenticationMetadataKey(publishableKey)
  );
  if (!stored) {
    throw new Error(
      'Hosted Relay active device authentication key is not registered'
    );
  }
  return deviceAuthenticationSigner(
    decodeStoredDeviceAuthentication(stored),
    publishableKey
  );
}

async function deviceAuthenticationMetadataKey(
  publishableKey: string
): Promise<string> {
  return `${DEVICE_AUTHENTICATION_METADATA_PREFIX}${bytesToBase64(
    await sha256(stringToBytes(publishableKey))
  )}`;
}

function deviceAuthenticationSigner(
  keyPair: StoredDeviceAuthentication,
  publishableKey: string
): HostedRelayDeviceAuthentication {
  return {
    publicKey: base64ToBytes(keyPair.publicKey),
    signChallenge: async (challenge) => {
      if (!(challenge instanceof Uint8Array) || challenge.length === 0) {
        throw new Error('Hosted Relay device challenge must not be empty');
      }
      const payload = concatBytes(
        DEVICE_AUTHENTICATION_SIGNATURE_LABEL,
        stringToBytes(publishableKey),
        new Uint8Array([0]),
        challenge
      );
      return base64ToBytes(await sign(keyPair.privateKey, payload));
    },
  };
}

function assertHostedBootstrapResult(
  result: HostedRelayBootstrapResult,
  bootstrap: HostedRelayBootstrapAdapter
): void {
  if (!result.canonicalAccountId || result.canonicalAccountId.length > 512) {
    throw new Error(
      'Hosted Relay returned an invalid canonical account binding'
    );
  }
  if (!Number.isSafeInteger(result.deviceId) || result.deviceId < 1) {
    throw new Error('Hosted Relay returned an invalid device binding');
  }
  if (
    !(result.relayScopeId instanceof Uint8Array) ||
    result.relayScopeId.length !== 16
  ) {
    throw new Error(
      'Hosted Relay returned an invalid project-environment scope'
    );
  }
  if (!result.relay) {
    throw new Error(
      'Hosted Relay bootstrap did not return an authenticated Relay'
    );
  }
  if (bootstrap.certificateTrust.trustRoots.length === 0) {
    throw new Error('Hosted Relay adapter has no pinned certificate root');
  }
  for (const root of bootstrap.certificateTrust.trustRoots) {
    if (!(root instanceof Uint8Array) || root.length !== 32) {
      throw new Error(
        'Hosted Relay adapter has an invalid pinned certificate root'
      );
    }
  }
  for (const keyId of bootstrap.certificateTrust.revokedIssuerKeyIds) {
    if (!Number.isSafeInteger(keyId) || keyId < 0 || keyId > 0xffff_ffff) {
      throw new Error(
        'Hosted Relay adapter has an invalid revoked issuer key ID'
      );
    }
  }
}

function assertPublishableKey(value: string): string {
  const publishableKey = value.trim();
  if (!publishableKey || publishableKey.length > 512) {
    throw new Error('Hosted Relay publishable key is invalid');
  }
  return publishableKey;
}

function assertOperationId(value: string): string {
  if (!value || value.length > 128) {
    throw new Error('Hosted Relay operation ID is invalid');
  }
  return value;
}

function assertIdentityAssertion(assertion: string): string {
  if (!assertion || assertion.length > 64 * 1024) {
    throw new Error('Identity provider returned an invalid assertion');
  }
  return assertion;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function createClientFromHostedResult(
  result: HostedRelayBootstrapResult,
  bootstrap: HostedRelayBootstrapAdapter,
  adapters: Omit<SignalProtocolClientCompositionOptions['adapters'], 'relay'>,
  clientOptions: Omit<
    SignalProtocolClientCompositionOptions,
    'adapters' | 'identity' | 'sealedSender'
  >,
  sealedSenderAccessMode?: SealedSenderAccessMode
): Promise<SignalProtocolClient> {
  assertHostedBootstrapResult(result, bootstrap);
  const config = createSignalProtocolClientConfig({
    ...clientOptions,
    adapters: {
      ...adapters,
      relay: result.relay,
    },
    identity: {
      userId: result.canonicalAccountId,
      deviceId: result.deviceId,
    },
    sealedSender: {
      accessMode: sealedSenderAccessMode,
      relayScopeId: result.relayScopeId,
      revokedIssuerKeyIds: bootstrap.certificateTrust.revokedIssuerKeyIds,
      trustModel: 'hosted',
      trustRoots: bootstrap.certificateTrust.trustRoots.map(
        (root) => new Uint8Array(root)
      ),
    },
  });
  return SignalProtocolClient.create(result.canonicalAccountId, config);
}

/**
 * Advance one hosted provider-migration transition without accepting an account ID.
 *
 * The application supplies provider assertions through the same purpose-aware
 * callback used by hosted bootstrap. The transport owns device-token storage
 * and the HTTP representation.
 */
export async function advanceHostedRelayIdentityMigration(
  options: HostedRelayIdentityMigrationOptions
): Promise<HostedRelayIdentityMigrationSnapshot> {
  const publishableKey = assertPublishableKey(options.publishableKey);
  const operationId = assertOperationId(options.operationId);
  if (
    options.action === 'prepare' &&
    (!Number.isSafeInteger(options.manifestVersion) ||
      options.manifestVersion! < 1)
  ) {
    throw new Error('Hosted Relay migration manifest version is invalid');
  }
  if (
    options.action === 'prepare' &&
    options.authorization.kind === 'assertion' &&
    options.authorization.providerRole !== 'source'
  ) {
    throw new Error(
      'Hosted Relay migration prepare requires source-provider authorization'
    );
  }
  const requestAssertion = async (
    providerRole: IdentityAssertionProviderRole
  ): Promise<string> => {
    options.onProgress?.({
      operation: 'migration',
      action: options.action,
      phase: 'requesting-assertion',
      providerRole,
    });
    return assertIdentityAssertion(
      await options.getIdentityAssertion({
        purpose: 'refresh',
        migration: { action: options.action, providerRole },
      })
    );
  };

  const authorization =
    options.authorization.kind === 'active-device'
      ? {
          kind: 'active-device' as const,
          deviceAuthentication: await getExistingDeviceAuthentication(
            options.authorization.storage,
            publishableKey
          ),
        }
      : {
          kind: 'assertion' as const,
          assertion: await requestAssertion(
            options.authorization.providerRole
          ),
        };
  const targetAssertion =
    options.action === 'prepare'
      ? await requestAssertion('target')
      : undefined;

  options.onProgress?.({
    operation: 'migration',
    action: options.action,
    phase: 'submitting',
  });
  const snapshot = await options.adapter.migrate({
    action: options.action,
    publishableKey,
    operationId,
    ...(options.manifestVersion === undefined
      ? {}
      : { manifestVersion: options.manifestVersion }),
    authorization,
    ...(targetAssertion === undefined ? {} : { targetAssertion }),
  });
  if (
    snapshot.accountPreserved !== true ||
    snapshot.collision !== false ||
    snapshot.operationId !== operationId
  ) {
    throw new Error('Hosted Relay returned an invalid migration snapshot');
  }
  options.onProgress?.({
    operation: 'migration',
    action: options.action,
    phase: 'complete',
    state: snapshot.state,
  });
  return snapshot;
}

/**
 * Bind a provisioned linked-device store to the Relay-authoritative account.
 *
 * The linked store must already contain the account identity delivered by the
 * SDK provisioning protocol. Only public identity and fresh linked-device
 * prekey material crosses this managed boundary.
 */
export async function linkHostedRelayDevice(
  options: HostedRelayManagedDeviceLinkOptions
): Promise<SignalProtocolClient> {
  const { adapters, activeDeviceStorage, hosted, ...clientOptions } = options;
  const publishableKey = assertPublishableKey(hosted.publishableKey);
  hosted.onProgress?.({
    operation: 'device-link',
    phase: 'preparing-linked-device',
  });
  const [identity, activeIdentity] = await Promise.all([
    adapters.storage.getIdentityKey('aci'),
    activeDeviceStorage.getIdentityKey('aci'),
  ]);
  if (!identity) {
    throw new Error(
      'Hosted Relay linked device requires a provisioned ACI identity'
    );
  }
  if (
    !activeIdentity ||
    activeIdentity.dhKey.publicKey !== identity.dhKey.publicKey ||
    activeIdentity.signingKey.publicKey !== identity.signingKey.publicKey
  ) {
    throw new Error(
      'Hosted Relay linked device identity does not match the active account'
    );
  }
  const signalIdentity = createCompositeIdentityV1(identity);
  const { operationId, registrationPreKeys } =
    await getOrCreateRegistrationSnapshot(
      adapters.storage,
      publishableKey,
      signalIdentity,
      identity.registrationId,
      identity
    );
  const [activeDeviceAuthentication, newDeviceAuthentication] =
    await Promise.all([
      getExistingDeviceAuthentication(activeDeviceStorage, publishableKey),
      getOrCreateDeviceAuthentication(adapters.storage, publishableKey),
    ]);
  if (
    equalBytes(
      activeDeviceAuthentication.publicKey,
      newDeviceAuthentication.publicKey
    )
  ) {
    throw new Error('Hosted Relay device link requires a new device key');
  }

  hosted.onProgress?.({ operation: 'device-link', phase: 'submitting' });
  const result = await hosted.adapter.linkDevice({
    publishableKey,
    signalIdentity,
    registrationId: identity.registrationId,
    operationId,
    registrationPreKeys,
    activeDeviceAuthentication,
    newDeviceAuthentication,
  });
  if (
    result.accountPreserved !== true ||
    result.protocolStateCopied !== false
  ) {
    throw new Error('Hosted Relay returned an invalid managed device link');
  }
  const client = await createClientFromHostedResult(
    result,
    hosted.adapter,
    adapters,
    clientOptions,
    hosted.sealedSenderAccessMode
  );
  hosted.onProgress?.({
    operation: 'device-link',
    phase: 'complete',
    deviceId: result.deviceId,
  });
  return client;
}

/**
 * Create a hosted Relay client without accepting a caller-supplied account or device ID.
 *
 * The Relay verifies the assertion and device proof, then returns the canonical
 * account, registered device, scope, and authenticated transport used by the client.
 */
export async function createHostedSignalProtocolClient(
  options: HostedSignalProtocolClientOptions
): Promise<SignalProtocolClient> {
  const { adapters, hosted, ...clientOptions } = options;
  const publishableKey = assertPublishableKey(hosted.publishableKey);
  const operation =
    hosted.assertionPurpose === 'recover' ? 'recovery' : 'bootstrap';
  hosted.onProgress?.({ operation, phase: 'preparing-local-state' });

  const storage = adapters.storage;
  let identity = await storage.getIdentityKey('aci');
  if (!identity) {
    identity = await generateIdentityKeyPair();
    await storage.storeIdentityKey(identity, 'aci');
  }
  const deviceAuthentication = await getOrCreateDeviceAuthentication(
    storage,
    publishableKey
  );
  const signalIdentity = createCompositeIdentityV1(identity);
  const { operationId, registrationPreKeys } =
    await getOrCreateRegistrationSnapshot(
      storage,
      publishableKey,
      signalIdentity,
      identity.registrationId,
      identity
    );
  const assertionPurpose = hosted.assertionPurpose ?? 'register';
  hosted.onProgress?.({ operation, phase: 'requesting-assertion' });
  const assertion = await hosted.getIdentityAssertion({
    purpose: assertionPurpose,
    assurance: hosted.assurance,
  });
  assertIdentityAssertion(assertion);

  hosted.onProgress?.({ operation, phase: 'submitting' });
  const result = await hosted.bootstrap.bootstrap({
    publishableKey,
    assertion,
    assertionPurpose,
    signalIdentity,
    registrationId: identity.registrationId,
    operationId,
    registrationPreKeys,
    deviceAuthentication,
  });
  const client = await createClientFromHostedResult(
    result,
    hosted.bootstrap,
    adapters,
    clientOptions,
    hosted.sealedSenderAccessMode
  );
  hosted.onProgress?.({ operation, phase: 'complete' });
  return client;
}
