import type {
  AccountIdentityProvisioning,
  AccountIdentityRotation,
  DeliveryClass,
  DeviceInfo,
  DeviceRegistration,
  EcSignedPreKeyUpload,
  Envelope,
  GroupChangeEntry,
  GroupChangePage,
  GroupMemberDevice,
  ISignalProtocolRelayServer,
  KemLastResortPreKeyUpload,
  PreKeyBundle,
  PreKeyUpload,
  Unsubscribe,
} from '../remote/relay/types';
import type { GroupAuthorization } from '../internal/groups/manager';
import type { RetryRequest } from '../internal/sesame/types';
import type {
  CompositeIdentityV1,
  IdentityType,
} from '../keys/types';
import {
  createCompositeIdentityV1,
  decodeCompositeIdentityV1,
  encodeCompositeIdentityV1,
} from '../keys/identity';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToUrlSafeBase64,
  concatBytes,
  generateUuidV4,
  sha256,
  stringToBytes,
  urlSafeToBase64,
} from '../internal/crypto';
import type { Base64, ISignalProtocolLocalStore } from '../types';
import type { PublicKey, Signature } from '../keys';
import type { IncomingEnvelope } from './types';
import type { HostedRelayConnection } from './hosted-connection';
import type {
  HostedRelayDeviceAuthentication,
  HostedRelayRegistrationPreKey,
  HostedRelayRegistrationPreKeys,
} from './hosted';
import type {
  RemoteObjectDownload,
  RemoteObjectDownloadRequest,
  RemoteObjectUpload,
  RemoteObjectUploadRequest,
  SignalProtocolRemoteObjectStore,
} from '../remote/object-store';
import type {
  HostedRelayPushRegistration,
  HostedRelayPushRuntime,
} from './hosted-push';

const SESSION_METADATA_PREFIX = 'hostedRelay.session.v1:';
const DEVICE_TOKEN_REFRESH_SECONDS = 60;
const MAXIMUM_RESPONSE_BYTES = 1024 * 1024;
const HOSTED_ONE_TIME_PREKEY_LIMIT = 100;
const PREKEY_EXPIRY_MILLISECONDS = 30 * 24 * 60 * 60 * 1000;
const POLL_MILLISECONDS = 2_000;
const DELIVERY_WIRE_VERSION = 1;
const DEVICE_AUTHENTICATION_SIGNATURE_LABEL = stringToBytes(
  'OpenE2EE Relay device authentication v1\0',
);
const REGISTRATION_MATERIAL_LABEL = stringToBytes(
  'OpenE2EE Relay registration material v1\0',
);
const REGISTRATION_CHALLENGE_LABEL = stringToBytes(
  'OpenE2EE Relay registration challenge v1\0',
);
const RECOVERY_CHALLENGE_LABEL = stringToBytes(
  'OpenE2EE Relay recovery challenge v1\0',
);
const TOKEN_REFRESH_CHALLENGE_LABEL = stringToBytes(
  'OpenE2EE Relay device token refresh challenge v1\0',
);

type JsonRecord = Record<string, unknown>;

interface StoredHostedRelaySession {
  canonicalAccountId: string;
  deviceId: number;
  deviceToken: string;
  generation: number;
  mailboxGeneration: number;
  relayScopeId: string;
}

interface HostedDeviceDirectoryEntry {
  deviceId: number;
  generation: number;
  mailboxGeneration: number;
}

interface HostedPreKeyStatus {
  identityPublicMaterial: Uint8Array;
  oneTimePreKeyCounts: Readonly<Record<string, number>>;
  profile: string;
  registrationId: number;
  signedPreKeys: readonly {
    acceptedAtMilliseconds: number;
    algorithm: string;
    keyId: number;
    publicKey: Uint8Array;
    signature: Uint8Array;
  }[];
}

interface HostedDeliveryWireEnvelope {
  ciphertext: string;
  contentHint?: number;
  messageType: Envelope['messageType'];
  timestamp: number;
  version: typeof DELIVERY_WIRE_VERSION;
}

export interface HostedRelayTransportBootstrapRequest {
  readonly assertion: string;
  readonly assertionPurpose: 'register' | 'recover';
  readonly connection: HostedRelayConnection;
  readonly deviceAuthentication: HostedRelayDeviceAuthentication;
  readonly operationId: string;
  readonly registrationId: number;
  readonly registrationPreKeys: HostedRelayRegistrationPreKeys;
  readonly signalIdentity: CompositeIdentityV1;
  readonly storage: ISignalProtocolLocalStore;
}

export interface HostedRelayTransportResult {
  readonly canonicalAccountId: string;
  readonly deviceId: number;
  readonly relay: ISignalProtocolRelayServer;
  readonly relayScopeId: Uint8Array;
  readonly remoteObjectStore: SignalProtocolRemoteObjectStore;
  readonly transport: HostedRelayHttpTransport;
}

export class HostedRelayHttpError extends Error {
  public readonly code: string;
  public readonly data?: Readonly<Record<string, unknown>>;
  public readonly status: number;

  public constructor(
    status: number,
    code: string,
    message: string,
    data?: Readonly<Record<string, unknown>>,
  ) {
    super(message);
    this.name = 'HostedRelayHttpError';
    this.status = status;
    this.code = code;
    this.data = data;
  }
}

function record(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function uint32be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error('Hosted Relay unsigned integer is invalid');
  }
  return new Uint8Array([value >>> 24, value >>> 16, value >>> 8, value]);
}

function lengthPrefixed(value: Uint8Array): Uint8Array {
  return concatBytes(uint32be(value.length), value);
}

function text(value: string): Uint8Array {
  return lengthPrefixed(stringToBytes(value));
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function canonicalBase64(value: Uint8Array): string {
  return bytesToBase64(value);
}

function decodeCanonicalBase64(value: unknown, label: string): Uint8Array {
  if (typeof value !== 'string') throw new Error(`${label} is invalid`);
  const decoded = base64ToBytes(value as Base64);
  if (bytesToBase64(decoded) !== value) throw new Error(`${label} is invalid`);
  return decoded;
}

function decodeBase64Url(value: string, label: string): Uint8Array {
  try {
    const decoded = base64ToBytes(urlSafeToBase64(value) as Base64);
    if (bytesToUrlSafeBase64(decoded) !== value) throw new Error();
    return decoded;
  } catch {
    throw new Error(`${label} is invalid`);
  }
}

function relayScopeId(connection: HostedRelayConnection): string {
  return bytesToUrlSafeBase64(connection.relayScopeId);
}

function identifiedEndpoint(connection: HostedRelayConnection): string {
  return connection.protocolEndpoint.replace(/\/$/u, '');
}

async function parseResponse(response: Response): Promise<unknown> {
  const body = await response.text();
  if (body.length > MAXIMUM_RESPONSE_BYTES) {
    throw new Error('Managed Relay response is too large');
  }
  if (response.ok && response.status === 204) {
    if (body.length !== 0) {
      throw new Error('Managed Relay returned an invalid response');
    }
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error('Managed Relay returned invalid JSON');
  }
  if (!response.ok) {
    const error = record(parsed) && record(parsed.error) ? parsed.error : {};
    const code = typeof error.code === 'string' ? error.code : 'UNKNOWN';
    const message =
      typeof error.message === 'string'
        ? error.message
        : 'Managed Relay request failed';
    throw new HostedRelayHttpError(response.status, code, message);
  }
  return parsed;
}

async function postJson(
  connection: HostedRelayConnection,
  path: string,
  body: JsonRecord,
  token?: string,
): Promise<unknown> {
  const headers = new Headers({
    accept: 'application/json',
    'content-type': 'application/json',
  });
  if (token !== undefined) headers.set('authorization', `Bearer ${token}`);
  let response: Response;
  try {
    response = await fetch(`${identifiedEndpoint(connection)}${path}`, {
      body: JSON.stringify(body),
      headers,
      method: 'POST',
    });
  } catch (cause) {
    throw new Error('Managed Relay request could not be completed', { cause });
  }
  return parseResponse(response);
}

function assertionIdentifier(assertion: string): string {
  const parts = assertion.split('.');
  if (parts.length !== 3) {
    throw new Error('Identity provider returned an invalid assertion');
  }
  let claims: unknown;
  try {
    claims = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(parts[1]!, 'Assertion claims')),
    );
  } catch {
    throw new Error('Identity provider returned an invalid assertion');
  }
  if (!record(claims) || typeof claims.jti !== 'string' || !claims.jti) {
    throw new Error('Identity provider returned an invalid assertion');
  }
  return claims.jti;
}

function serializedPreKey(prekey: HostedRelayRegistrationPreKey): JsonRecord {
  return {
    algorithm: prekey.algorithm,
    keyId: prekey.keyId,
    publicKey: canonicalBase64(prekey.publicKey),
    ...(prekey.signature === undefined
      ? {}
      : { signature: canonicalBase64(prekey.signature) }),
  };
}

function signalRegistration(
  identity: CompositeIdentityV1,
  registrationId: number,
  prekeys: HostedRelayRegistrationPreKeys,
): JsonRecord {
  return {
    identity,
    oneTimePreKeys: prekeys.oneTimePreKeys.map(serializedPreKey),
    registrationId,
    signedPreKeys: prekeys.signedPreKeys.map(serializedPreKey),
  };
}

async function registrationMaterialFingerprint(
  identity: CompositeIdentityV1,
  registrationId: number,
  prekeys: HostedRelayRegistrationPreKeys,
): Promise<string> {
  const entries = [
    ...prekeys.signedPreKeys.map((prekey) => ({
      ...prekey,
      kind: 'signed' as const,
    })),
    ...prekeys.oneTimePreKeys.map((prekey) => ({
      ...prekey,
      kind: 'one-time' as const,
    })),
  ].sort((left, right) =>
    `${left.kind}:${left.algorithm}:${String(left.keyId)}`.localeCompare(
      `${right.kind}:${right.algorithm}:${String(right.keyId)}`,
    ),
  );
  return bytesToUrlSafeBase64(
    await sha256(
      concatBytes(
        REGISTRATION_MATERIAL_LABEL,
        text('aci'),
        text('signal-composite-v1'),
        uint32be(registrationId),
        lengthPrefixed(encodeCompositeIdentityV1(identity)),
        ...entries.flatMap((prekey) => [
          text(prekey.kind),
          text(prekey.algorithm),
          uint32be(prekey.keyId),
          lengthPrefixed(prekey.publicKey),
          lengthPrefixed(prekey.signature ?? new Uint8Array()),
        ]),
      ),
    ),
  );
}

async function registrationChallenge(
  request: HostedRelayTransportBootstrapRequest,
): Promise<Uint8Array> {
  return sha256(
    concatBytes(
      request.assertionPurpose === 'recover'
        ? RECOVERY_CHALLENGE_LABEL
        : REGISTRATION_CHALLENGE_LABEL,
      text(relayScopeId(request.connection)),
      text(assertionIdentifier(request.assertion)),
      text(request.operationId),
      text(
        await registrationMaterialFingerprint(
          request.signalIdentity,
          request.registrationId,
          request.registrationPreKeys,
        ),
      ),
    ),
  );
}

async function sessionMetadataKey(
  connection: HostedRelayConnection,
): Promise<string> {
  return `${SESSION_METADATA_PREFIX}${bytesToUrlSafeBase64(
    await sha256(
      concatBytes(
        stringToBytes(connection.publishableKey),
        new Uint8Array([0]),
        connection.relayScopeId,
      ),
    ),
  )}`;
}

function parseSession(value: string, connection: HostedRelayConnection): StoredHostedRelaySession {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error('Stored hosted Relay session is invalid');
  }
  if (
    !record(parsed) ||
    Object.keys(parsed).sort().join(',') !==
      'canonicalAccountId,deviceId,deviceToken,generation,mailboxGeneration,relayScopeId' ||
    typeof parsed.canonicalAccountId !== 'string' ||
    !parsed.canonicalAccountId ||
    !Number.isSafeInteger(parsed.deviceId) ||
    (parsed.deviceId as number) < 1 ||
    typeof parsed.deviceToken !== 'string' ||
    !parsed.deviceToken ||
    !Number.isSafeInteger(parsed.generation) ||
    (parsed.generation as number) < 0 ||
    !Number.isSafeInteger(parsed.mailboxGeneration) ||
    (parsed.mailboxGeneration as number) < 0 ||
    parsed.relayScopeId !== relayScopeId(connection)
  ) {
    throw new Error('Stored hosted Relay session is invalid');
  }
  return parsed as unknown as StoredHostedRelaySession;
}

function tokenExpiration(token: string, session: StoredHostedRelaySession): number {
  const parts = token.split('.');
  if (parts.length !== 3) return 0;
  try {
    const claims: unknown = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(parts[1]!, 'Device token')),
    );
    if (
      !record(claims) ||
      claims.account_id !== session.canonicalAccountId ||
      claims.device_id !== session.deviceId ||
      claims.generation !== session.generation ||
      claims.mailbox_generation !== session.mailboxGeneration ||
      claims.relay_scope_id !== session.relayScopeId ||
      !Number.isSafeInteger(claims.exp)
    ) {
      return 0;
    }
    return claims.exp as number;
  } catch {
    return 0;
  }
}

function requiredNumber(object: JsonRecord, key: string): number {
  const value = object[key];
  if (!Number.isSafeInteger(value)) throw new Error('Managed Relay returned invalid data');
  return value as number;
}

function requiredString(object: JsonRecord, key: string): string {
  const value = object[key];
  if (typeof value !== 'string' || !value) throw new Error('Managed Relay returned invalid data');
  return value;
}

function unsupported(operation: string): never {
  throw new Error(`Managed Relay does not support ${operation} through this contract`);
}

function encodeDeliveryWire(envelope: Envelope): Uint8Array {
  const ciphertext =
    envelope.ciphertext instanceof Uint8Array
      ? bytesToBase64(envelope.ciphertext)
      : envelope.ciphertext;
  if (bytesToBase64(base64ToBytes(ciphertext as Base64)) !== ciphertext) {
    throw new Error('Managed Relay envelope ciphertext is invalid');
  }
  const wire: HostedDeliveryWireEnvelope = {
    ciphertext,
    ...(envelope.contentHint === undefined
      ? {}
      : { contentHint: envelope.contentHint }),
    messageType: envelope.messageType,
    timestamp: envelope.timestamp,
    version: DELIVERY_WIRE_VERSION,
  };
  return stringToBytes(JSON.stringify(wire));
}

function decodeDeliveryWire(value: Uint8Array): HostedDeliveryWireEnvelope {
  let wire: unknown;
  try {
    wire = JSON.parse(new TextDecoder().decode(value));
  } catch {
    throw new Error('Managed Relay mailbox envelope is invalid');
  }
  if (
    !record(wire) ||
    typeof wire.ciphertext !== 'string' ||
    bytesToBase64(base64ToBytes(wire.ciphertext as Base64)) !== wire.ciphertext ||
    (wire.contentHint !== undefined && !Number.isSafeInteger(wire.contentHint)) ||
    typeof wire.messageType !== 'string' ||
    !Number.isSafeInteger(wire.timestamp) ||
    wire.version !== DELIVERY_WIRE_VERSION
  ) {
    throw new Error('Managed Relay mailbox envelope is invalid');
  }
  return wire as unknown as HostedDeliveryWireEnvelope;
}

export class HostedRelayHttpTransport
  implements ISignalProtocolRelayServer, HostedRelayPushRuntime
{
  private refreshPromise?: Promise<void>;
  private readonly destinationGenerations = new Map<string, number>();

  public constructor(
    private readonly connection: HostedRelayConnection,
    private readonly storage: ISignalProtocolLocalStore,
    private readonly deviceAuthentication: HostedRelayDeviceAuthentication,
    private session: StoredHostedRelaySession,
  ) {}

  public get accountId(): string {
    return this.session.canonicalAccountId;
  }

  public get deviceId(): number {
    return this.session.deviceId;
  }

  public readonly objectStore: SignalProtocolRemoteObjectStore = {
    createUpload: async (input) => this.createObjectUpload(input),
    createDownload: async (input) => this.createObjectDownload(input),
    completeUpload: async ({ objectId }) => {
      await this.authenticatedPost('/objects/commit-upload', {
        objectId,
        publishableKey: this.connection.publishableKey,
      });
    },
    deleteObject: async ({ objectId }) => {
      await this.authenticatedPost('/objects/delete', {
        objectId,
        publishableKey: this.connection.publishableKey,
      });
    },
  };

  private async persistSession(): Promise<void> {
    await this.storage.setMetadata(
      await sessionMetadataKey(this.connection),
      JSON.stringify(this.session),
    );
  }

  private async refreshToken(): Promise<void> {
    const requestedAtSeconds = Math.floor(Date.now() / 1_000);
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const challenge = await sha256(
      concatBytes(
        TOKEN_REFRESH_CHALLENGE_LABEL,
        text(this.session.relayScopeId),
        text(this.session.canonicalAccountId),
        uint32be(this.session.deviceId),
        uint32be(this.session.generation),
        uint32be(this.session.mailboxGeneration),
        text(String(requestedAtSeconds)),
        lengthPrefixed(nonce),
      ),
    );
    const proof = await this.deviceAuthentication.signChallenge(challenge);
    const value = await postJson(this.connection, '/identity/token', {
      accountAddress: this.session.canonicalAccountId,
      deviceId: this.session.deviceId,
      deviceProof: bytesToBase64(proof),
      nonce: bytesToUrlSafeBase64(nonce),
      publishableKey: this.connection.publishableKey,
      requestedAtSeconds,
    });
    if (!record(value) || typeof value.deviceToken !== 'string') {
      throw new Error('Managed Relay returned an invalid device token');
    }
    this.session = { ...this.session, deviceToken: value.deviceToken };
    if (tokenExpiration(this.session.deviceToken, this.session) <= requestedAtSeconds) {
      throw new Error('Managed Relay returned an invalid device token');
    }
    await this.persistSession();
  }

  private async token(force = false): Promise<string> {
    const now = Math.floor(Date.now() / 1_000);
    if (
      !force &&
      tokenExpiration(this.session.deviceToken, this.session) >
        now + DEVICE_TOKEN_REFRESH_SECONDS
    ) {
      return this.session.deviceToken;
    }
    this.refreshPromise ??= this.refreshToken().finally(() => {
      this.refreshPromise = undefined;
    });
    await this.refreshPromise;
    return this.session.deviceToken;
  }

  /** Verify that the stored device authority can obtain a current token. */
  public async ensureAuthenticated(force = false): Promise<void> {
    await this.token(force);
  }

  private async authenticatedPost(path: string, body: JsonRecord): Promise<unknown> {
    let token = await this.token();
    try {
      return await postJson(this.connection, path, body, token);
    } catch (error) {
      if (!(error instanceof HostedRelayHttpError) || error.code !== 'TOKEN_INVALID') {
        throw error;
      }
      token = await this.token(true);
      return postJson(this.connection, path, body, token);
    }
  }

  private assertCurrentIdentity(userId: string, deviceId: number, identityType: IdentityType = 'aci'): void {
    if (
      userId !== this.session.canonicalAccountId ||
      deviceId !== this.session.deviceId ||
      identityType !== 'aci'
    ) {
      throw new Error('Managed Relay operation crossed the current device authority');
    }
  }

  private async directory(userId: string): Promise<readonly HostedDeviceDirectoryEntry[]> {
    const value = await this.authenticatedPost('/identity/devices', {
      accountAddress: userId,
      publishableKey: this.connection.publishableKey,
    });
    if (!record(value) || value.accountAddress !== userId || !Array.isArray(value.devices)) {
      throw new Error('Managed Relay returned an invalid device directory');
    }
    return value.devices.map((candidate) => {
      if (!record(candidate)) throw new Error('Managed Relay returned an invalid device directory');
      const device = {
        deviceId: requiredNumber(candidate, 'deviceId'),
        generation: requiredNumber(candidate, 'generation'),
        mailboxGeneration: requiredNumber(candidate, 'mailboxGeneration'),
      };
      if (device.deviceId < 1 || device.generation < 0 || device.mailboxGeneration < 0) {
        throw new Error('Managed Relay returned an invalid device directory');
      }
      this.destinationGenerations.set(`${userId}\0${String(device.deviceId)}`, device.mailboxGeneration);
      return device;
    });
  }

  private async prekeyStatus(
    userId: string,
    deviceId: number,
    identityType: IdentityType = 'aci',
  ): Promise<HostedPreKeyStatus> {
    if (identityType !== 'aci') unsupported('PNI prekey authority');
    const value = await this.authenticatedPost('/prekeys/status', {
      accountAddress: userId,
      deviceId,
      identityType,
      publishableKey: this.connection.publishableKey,
    });
    if (
      !record(value) ||
      typeof value.identityPublicMaterial !== 'string' ||
      !record(value.oneTimePreKeyCounts) ||
      typeof value.profile !== 'string' ||
      !Array.isArray(value.signedPreKeys)
    ) {
      throw new Error('Managed Relay returned invalid prekey status');
    }
    const signedPreKeys = value.signedPreKeys.map((candidate) => {
      if (!record(candidate)) throw new Error('Managed Relay returned invalid prekey status');
      return {
        acceptedAtMilliseconds: requiredNumber(candidate, 'acceptedAtMilliseconds'),
        algorithm: requiredString(candidate, 'algorithm'),
        keyId: requiredNumber(candidate, 'keyId'),
        publicKey: decodeCanonicalBase64(candidate.publicKey, 'Prekey public key'),
        signature: decodeCanonicalBase64(candidate.signature, 'Prekey signature'),
      };
    });
    const counts: Record<string, number> = {};
    for (const [algorithm, count] of Object.entries(value.oneTimePreKeyCounts)) {
      if (!Number.isSafeInteger(count) || (count as number) < 0) {
        throw new Error('Managed Relay returned invalid prekey status');
      }
      counts[algorithm] = count as number;
    }
    return {
      identityPublicMaterial: decodeCanonicalBase64(value.identityPublicMaterial, 'Signal identity'),
      oneTimePreKeyCounts: counts,
      profile: value.profile,
      registrationId: requiredNumber(value, 'registrationId'),
      signedPreKeys,
    };
  }

  private async currentRegistration(): Promise<{
    identity: CompositeIdentityV1;
    prekeys: HostedRelayRegistrationPreKeys;
    registrationId: number;
  }> {
    const identity = await this.storage.getIdentityKey('aci');
    const ecSigned = await this.storage.getEcSignedPreKey(undefined, 'aci');
    const kemSigned = await this.storage.getKyberPreKey('aci');
    const [ecOneTime, kemOneTime] = await Promise.all([
      this.storage.getEcOneTimePreKeys('aci'),
      this.storage.getKemOneTimePreKeys('aci'),
    ]);
    if (!identity || !ecSigned || !kemSigned || ecOneTime.length === 0 || kemOneTime.length === 0) {
      throw new Error('Hosted Relay local prekey inventory is incomplete');
    }
    const boundedEcOneTime = [...ecOneTime]
      .sort((left, right) => right.keyId - left.keyId)
      .slice(0, HOSTED_ONE_TIME_PREKEY_LIMIT)
      .sort((left, right) => left.keyId - right.keyId);
    const boundedKemOneTime = [...kemOneTime]
      .sort((left, right) => right.keyId - left.keyId)
      .slice(0, HOSTED_ONE_TIME_PREKEY_LIMIT)
      .sort((left, right) => left.keyId - right.keyId);
    return {
      identity: createCompositeIdentityV1(identity),
      registrationId: identity.registrationId,
      prekeys: {
        signedPreKeys: [
          {
            algorithm: 'ec-x25519',
            keyId: ecSigned.keyId,
            publicKey: base64ToBytes(ecSigned.publicKey),
            signature: base64ToBytes(ecSigned.signature),
          },
          {
            algorithm: 'kem-ml-kem-1024',
            keyId: kemSigned.keyId,
            publicKey: base64ToBytes(kemSigned.publicKey),
            signature: base64ToBytes(kemSigned.signature),
          },
        ],
        oneTimePreKeys: [
          ...boundedEcOneTime.map((prekey) => ({
            algorithm: 'ec-x25519' as const,
            keyId: prekey.keyId,
            publicKey: base64ToBytes(prekey.publicKey),
          })),
          ...boundedKemOneTime.map((prekey) => ({
            algorithm: 'kem-ml-kem-1024' as const,
            keyId: prekey.keyId,
            publicKey: base64ToBytes(prekey.publicKey),
            signature: base64ToBytes(prekey.signature),
          })),
        ],
      },
    };
  }

  private async publishCurrentPrekeys(): Promise<void> {
    const current = await this.currentRegistration();
    const fingerprint = await registrationMaterialFingerprint(
      current.identity,
      current.registrationId,
      current.prekeys,
    );
    const result = await this.authenticatedPost('/prekeys/publish', {
      operationId: fingerprint,
      publishableKey: this.connection.publishableKey,
      signalRegistration: signalRegistration(
        current.identity,
        current.registrationId,
        current.prekeys,
      ),
    });
    if (!record(result) || result.published !== true) {
      throw new Error('Managed Relay returned an invalid prekey publication');
    }
  }

  private async pullIncoming(): Promise<readonly IncomingEnvelope[]> {
    const value = await this.authenticatedPost('/mailbox/pull', {
      publishableKey: this.connection.publishableKey,
    });
    if (!record(value) || !Array.isArray(value.messages)) {
      throw new Error('Managed Relay returned an invalid mailbox page');
    }
    return value.messages.map((candidate) => {
      if (!record(candidate) || !record(candidate.sender)) {
        throw new Error('Managed Relay returned an invalid mailbox message');
      }
      const wire = decodeDeliveryWire(
        decodeCanonicalBase64(candidate.envelope, 'Mailbox envelope'),
      );
      return {
        id: requiredString(candidate, 'messageId'),
        senderUserId: requiredString(candidate.sender, 'accountId'),
        senderDeviceId: requiredNumber(candidate.sender, 'deviceId'),
        ciphertext: wire.ciphertext,
        timestamp: wire.timestamp,
        serverTimestamp: requiredNumber(candidate, 'enqueuedAt'),
        messageType: wire.messageType,
        ...(wire.contentHint === undefined ? {} : { contentHint: wire.contentHint }),
      };
    });
  }

  private async acknowledge(messageIds: readonly string[]): Promise<void> {
    const value = await this.authenticatedPost('/mailbox/acknowledge', {
      messageIds: [...messageIds],
      publishableKey: this.connection.publishableKey,
    });
    if (!record(value) || requiredNumber(value, 'acknowledged') < 0) {
      throw new Error('Managed Relay returned an invalid acknowledgment');
    }
  }

  public async registerPush(
    registration: HostedRelayPushRegistration,
  ): Promise<void> {
    const value = await this.authenticatedPost('/push/register', {
      ...registration,
      publishableKey: this.connection.publishableKey,
    });
    if (value !== undefined) {
      throw new Error('Managed Relay returned an invalid push result');
    }
  }

  public async removePush(): Promise<void> {
    const value = await this.authenticatedPost('/push/remove', {
      publishableKey: this.connection.publishableKey,
    });
    if (value !== undefined) {
      throw new Error('Managed Relay returned an invalid push result');
    }
  }

  public async pullMailbox(): Promise<readonly IncomingEnvelope[]> {
    return this.pullIncoming();
  }

  public async acknowledgeMailbox(
    messageIds: readonly string[],
  ): Promise<void> {
    await this.acknowledge(messageIds);
  }

  private async createObjectUpload(input: RemoteObjectUploadRequest): Promise<RemoteObjectUpload> {
    const value = await this.authenticatedPost('/objects/authorize-upload', {
      contentLength: input.contentLength,
      digest: bytesToUrlSafeBase64(input.digest),
      publishableKey: this.connection.publishableKey,
      requestId: input.requestId,
    });
    if (!record(value) || !record(value.headers)) {
      throw new Error('Managed Relay returned an invalid upload grant');
    }
    return {
      expiresAt: requiredNumber(value, 'expiresAt'),
      headers: Object.fromEntries(
        Object.entries(value.headers).map(([name, header]) => {
          if (typeof header !== 'string') throw new Error('Managed Relay returned an invalid upload grant');
          return [name, header];
        }),
      ),
      objectId: requiredString(value, 'objectId'),
      protocol: 'put',
      uploadUrl: requiredString(value, 'uploadUrl'),
    };
  }

  private async createObjectDownload(input: RemoteObjectDownloadRequest): Promise<RemoteObjectDownload> {
    const value = await this.authenticatedPost('/objects/authorize-download', {
      objectId: input.objectId,
      publishableKey: this.connection.publishableKey,
    });
    if (!record(value)) throw new Error('Managed Relay returned an invalid download grant');
    return {
      downloadUrl: requiredString(value, 'downloadUrl'),
      expiresAt: requiredNumber(value, 'expiresAt'),
    };
  }

  public async send(envelope: Envelope): Promise<{ messageId: string; serverTimestamp: number }> {
    if (
      envelope.senderUserId !== this.session.canonicalAccountId ||
      envelope.senderDeviceId !== this.session.deviceId ||
      envelope.clientMessageId === ''
    ) {
      throw new Error('Managed Relay send authority or operation ID is invalid');
    }
    const messageId = envelope.clientMessageId ?? await generateUuidV4();
    const key = `${envelope.targetUserId}\0${String(envelope.targetDeviceId)}`;
    let generation = this.destinationGenerations.get(key);
    if (generation === undefined) {
      await this.directory(envelope.targetUserId);
      generation = this.destinationGenerations.get(key);
    }
    if (generation === undefined) throw new Error('Managed Relay destination device does not exist');
    let value: unknown;
    try {
      value = await this.authenticatedPost('/delivery/send', {
        deliveryClass: envelope.deliveryClass,
        destination: {
          accountAddress: envelope.targetUserId,
          deviceId: envelope.targetDeviceId,
          generation,
        },
        envelope: bytesToBase64(encodeDeliveryWire(envelope)),
        messageId,
        operationEpochMilliseconds: envelope.timestamp,
        publishableKey: this.connection.publishableKey,
        ...(envelope.recipientRegistrationId === undefined
          ? {}
          : { recipientRegistrationId: envelope.recipientRegistrationId }),
      });
    } catch (error) {
      if (error instanceof HostedRelayHttpError && error.code === 'STALE_DEVICE') {
        throw new HostedRelayHttpError(error.status, error.code, error.message, {
          code: 'STALE_DEVICE',
          message: error.message,
          reason: 'device_reinstalled',
          staleDevices: [envelope.targetDeviceId],
        });
      }
      throw error;
    }
    if (!record(value) || requiredString(value, 'messageId') !== messageId) {
      throw new Error('Managed Relay returned an invalid delivery receipt');
    }
    return {
      messageId,
      serverTimestamp:
        typeof value.enqueuedAt === 'number' ? value.enqueuedAt : envelope.timestamp,
    };
  }

  public subscribe(
    userId: string,
    deviceId: number,
    onEnvelope: (envelope: Envelope) => void,
    options?: { onBatchStart?: () => void; onBatchEnd?: () => void },
  ): Unsubscribe {
    this.assertCurrentIdentity(userId, deviceId);
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      try {
        const messages = await this.pullIncoming();
        if (messages.length > 0) options?.onBatchStart?.();
        for (const message of messages) onEnvelope(message as Envelope);
        if (messages.length > 0) options?.onBatchEnd?.();
      } catch {
        // The durable mailbox keeps the messages. Retry on the next poll.
      } finally {
        if (active) timer = setTimeout(() => void poll(), POLL_MILLISECONDS);
      }
    };
    void poll();
    return () => {
      active = false;
      if (timer !== undefined) clearTimeout(timer);
    };
  }

  public async markDelivered(envelopeId: string): Promise<void> {
    await this.acknowledge([envelopeId]);
  }

  public async getDevices(userId: string): Promise<DeviceInfo[]> {
    return (await this.directory(userId)).map((device) => ({
      deviceId: device.deviceId,
      registered: true,
      linked: device.deviceId > 1,
      enabled: true,
    }));
  }

  public async getActiveDevices(userId: string): Promise<GroupMemberDevice[]> {
    return (await this.directory(userId)).map((device) => ({
      userId,
      deviceId: device.deviceId,
    }));
  }

  public async provisionIdentityKey(request: AccountIdentityProvisioning): Promise<void> {
    this.assertCurrentIdentity(request.userId, request.deviceId, request.identityType);
    const status = await this.prekeyStatus(request.userId, request.deviceId, request.identityType);
    if (
      status.registrationId !== request.registrationId ||
      !equalBytes(status.identityPublicMaterial, encodeCompositeIdentityV1(request.identity))
    ) {
      throw new Error('Managed Relay canonical Signal identity does not match local state');
    }
  }

  public async getIdentityKey(userId: string, identityType: IdentityType = 'aci'): Promise<CompositeIdentityV1 | null> {
    try {
      return decodeCompositeIdentityV1(
        (await this.prekeyStatus(userId, 1, identityType)).identityPublicMaterial,
      );
    } catch (error) {
      if (error instanceof HostedRelayHttpError && error.code === 'NOT_FOUND') return null;
      throw error;
    }
  }

  public async uploadPreKeys(
    userId: string,
    deviceId: number,
    _keys: PreKeyUpload[],
    identityType: IdentityType = 'aci',
  ): Promise<void> {
    this.assertCurrentIdentity(userId, deviceId, identityType);
    await this.publishCurrentPrekeys();
  }

  public async fetchPreKeyBundle(
    userId: string,
    deviceId: number,
    _fetcherUserId?: string,
    identityType: IdentityType = 'aci',
  ): Promise<PreKeyBundle | null> {
    if (identityType !== 'aci') unsupported('PNI prekey authority');
    let value: unknown;
    try {
      value = await this.authenticatedPost('/prekeys/consume', {
        accountAddress: userId,
        deviceId,
        identityType,
        publishableKey: this.connection.publishableKey,
      });
    } catch (error) {
      if (error instanceof HostedRelayHttpError && error.code === 'NOT_FOUND') return null;
      throw error;
    }
    if (!record(value) || !Array.isArray(value.signedPreKeys) || !Array.isArray(value.oneTimePreKeys)) {
      throw new Error('Managed Relay returned an invalid prekey bundle');
    }
    const signed = value.signedPreKeys.map((candidate) => {
      if (!record(candidate)) throw new Error('Managed Relay returned an invalid prekey bundle');
      return {
        algorithm: requiredString(candidate, 'algorithm'),
        keyId: requiredNumber(candidate, 'keyId'),
        publicKey: requiredString(candidate, 'publicKey'),
        signature: requiredString(candidate, 'signature'),
      };
    });
    const oneTime = value.oneTimePreKeys.map((candidate) => {
      if (!record(candidate)) throw new Error('Managed Relay returned an invalid prekey bundle');
      return {
        algorithm: requiredString(candidate, 'algorithm'),
        keyId: requiredNumber(candidate, 'keyId'),
        publicKey: requiredString(candidate, 'publicKey'),
        ...(candidate.signature === undefined
          ? {}
          : { signature: requiredString(candidate, 'signature') }),
      };
    });
    const ecSigned = signed.find((key) => key.algorithm === 'ec-x25519');
    const kemSigned = signed.find((key) => key.algorithm === 'kem-ml-kem-1024');
    if (!ecSigned || !kemSigned) throw new Error('Managed Relay returned an invalid prekey bundle');
    const ecOneTime = oneTime.find((key) => key.algorithm === 'ec-x25519');
    const kemOneTime = oneTime.find((key) => key.algorithm === 'kem-ml-kem-1024');
    return {
      deviceId,
      registrationId: requiredNumber(value, 'registrationId'),
      identity: decodeCompositeIdentityV1(
        decodeCanonicalBase64(value.identityPublicMaterial, 'Signal identity'),
      ),
      ecSignedPreKey: {
        keyId: ecSigned.keyId,
        publicKey: ecSigned.publicKey as PublicKey,
        signature: ecSigned.signature as Signature,
      },
      ecOneTimePreKey: ecOneTime
        ? { keyId: ecOneTime.keyId, publicKey: ecOneTime.publicKey as PublicKey }
        : null,
      kemLastResortPreKey: {
        keyId: kemSigned.keyId,
        publicKey: kemSigned.publicKey as PublicKey,
        signature: kemSigned.signature as Signature,
      },
      kemOneTimePreKey: kemOneTime
        ? {
            keyId: kemOneTime.keyId,
            publicKey: kemOneTime.publicKey as PublicKey,
            signature: kemOneTime.signature as Signature,
          }
        : null,
    };
  }

  public async getPreKeyCount(
    userId: string,
    deviceId: number,
    type: 'ec' | 'kem',
    identityType: IdentityType = 'aci',
  ): Promise<number> {
    const status = await this.prekeyStatus(userId, deviceId, identityType);
    return status.oneTimePreKeyCounts[
      type === 'ec' ? 'ec-x25519' : 'kem-ml-kem-1024'
    ] ?? 0;
  }

  public async getEcSignedPreKeyMetadata(
    userId: string,
    deviceId: number,
    identityType: IdentityType = 'aci',
  ) {
    const key = (await this.prekeyStatus(userId, deviceId, identityType)).signedPreKeys.find(
      (candidate) => candidate.algorithm === 'ec-x25519',
    );
    return key
      ? {
          keyId: key.keyId,
          createdAt: key.acceptedAtMilliseconds,
          expiresAt: key.acceptedAtMilliseconds + PREKEY_EXPIRY_MILLISECONDS,
          publicKey: bytesToBase64(key.publicKey),
        }
      : null;
  }

  public async getKemLastResortPreKeyMetadata(
    userId: string,
    deviceId: number,
    identityType: IdentityType = 'aci',
  ) {
    const key = (await this.prekeyStatus(userId, deviceId, identityType)).signedPreKeys.find(
      (candidate) => candidate.algorithm === 'kem-ml-kem-1024',
    );
    return key
      ? {
          keyId: key.keyId,
          createdAt: key.acceptedAtMilliseconds,
          expiresAt: key.acceptedAtMilliseconds + PREKEY_EXPIRY_MILLISECONDS,
          publicKey: bytesToBase64(key.publicKey),
        }
      : null;
  }

  public async clearStaleKemPreKeys(
    userId: string,
    deviceId: number,
    identityType: IdentityType = 'aci',
  ): Promise<{ cleared: number }> {
    this.assertCurrentIdentity(userId, deviceId, identityType);
    const value = await this.authenticatedPost('/prekeys/clear-stale-kem', {
      publishableKey: this.connection.publishableKey,
    });
    if (!record(value)) throw new Error('Managed Relay returned an invalid prekey result');
    return { cleared: requiredNumber(value, 'cleared') };
  }

  public async uploadEcSignedPreKey(
    userId: string,
    _key: EcSignedPreKeyUpload,
    identityType: IdentityType = 'aci',
  ): Promise<void> {
    this.assertCurrentIdentity(userId, this.session.deviceId, identityType);
    await this.publishCurrentPrekeys();
  }

  public async uploadKemLastResortPreKey(
    userId: string,
    _key: KemLastResortPreKeyUpload,
    identityType: IdentityType = 'aci',
  ): Promise<void> {
    this.assertCurrentIdentity(userId, this.session.deviceId, identityType);
    await this.publishCurrentPrekeys();
  }

  public async rotateIdentityKey(_request: AccountIdentityRotation): Promise<void> {
    unsupported('identity rotation outside the hosted recovery flow');
  }

  public async registerDevice(_userId: string, _device: DeviceRegistration): Promise<number> {
    unsupported('direct device registration');
  }
  public async removeDevice(_userId: string, _deviceId: number): Promise<void> { unsupported('direct device removal'); }
  public async markDeviceConnected(_deviceId: number): Promise<void> { unsupported('connection presence'); }
  public async markDeviceDisconnected(_deviceId: number): Promise<void> { unsupported('connection presence'); }
  public async heartbeat(_deviceId: number): Promise<void> { unsupported('connection presence'); }
  public async createProvisioningSession(_userId: string, _key: string): Promise<{ sessionId: string }> { unsupported('legacy provisioning sessions'); }
  public async connectNewDevice(_sessionId: string, _key: string, _metadata: { platform?: string; appVersion?: string; osVersion?: string }): Promise<void> { unsupported('legacy provisioning sessions'); }
  public async sendProvisioningMessage(_sessionId: string, _message: string, _userId?: string): Promise<void> { unsupported('legacy provisioning sessions'); }
  public async getProvisioningMessage(_sessionId: string): Promise<{ status: 'waiting' | 'connected' | 'ready' | 'linked_pending_ack' | 'completed' | 'rolled_back' | 'expired'; message: string | null; expiresAt: number | null }> { unsupported('legacy provisioning sessions'); }
  public async completeProvisioning(_sessionId: string, _metadata: { encryptedDeviceName: ArrayBuffer; platform?: string; appVersion?: string; osVersion?: string }): Promise<{ deviceId: number }> { unsupported('legacy provisioning sessions'); }
  public async acknowledgeProvisioning(_sessionId: string): Promise<void> { unsupported('legacy provisioning sessions'); }
  public async rollbackProvisioning(_sessionId: string): Promise<void> { unsupported('legacy provisioning sessions'); }
  public async deleteProvisioningSession(_sessionId: string, _userId?: string): Promise<void> { unsupported('legacy provisioning sessions'); }
  public async createGroupState(_groupId: Uint8Array, _state: Uint8Array, _authorization: GroupAuthorization): Promise<void> { unsupported('hosted group-state transport'); }
  public async getGroupState(_groupId: Uint8Array, _authorization: GroupAuthorization, _version?: number): Promise<{ encryptedState: Uint8Array; version: number; baselineSignature: Uint8Array } | null> { unsupported('hosted group-state transport'); }
  public async getGroupJoinInfo(_groupId: Uint8Array, _password: Uint8Array, _authorization: GroupAuthorization): Promise<{ encryptedJoinInfo: Uint8Array; version: number } | null> { unsupported('hosted group-state transport'); }
  public async getGroupChanges(_groupId: Uint8Array, _fromVersion: number, _authorization: GroupAuthorization): Promise<GroupChangePage> { unsupported('hosted group-state transport'); }
  public async submitGroupChange(_groupId: Uint8Array, _expectedVersion: number, _actions: Uint8Array, _password: Uint8Array, _authorization: GroupAuthorization): Promise<GroupChangeEntry> { unsupported('hosted group-state transport'); }
  public async issueAuthCredential(_userId: string): Promise<Uint8Array> { unsupported('hosted group credentials'); }
}

export async function bootstrapHostedRelayTransport(
  request: HostedRelayTransportBootstrapRequest,
): Promise<HostedRelayTransportResult> {
  const proof = await request.deviceAuthentication.signChallenge(
    await registrationChallenge(request),
  );
  const value = await postJson(
    request.connection,
    request.assertionPurpose === 'recover'
      ? '/identity/recover'
      : '/identity/register',
    {
    assertion: request.assertion,
    assertionPurpose: request.assertionPurpose,
    deviceAuthenticationPublicKey: bytesToBase64(
      request.deviceAuthentication.publicKey,
    ),
    deviceProof: bytesToBase64(proof),
    operationId: request.operationId,
    publishableKey: request.connection.publishableKey,
    signalRegistration: signalRegistration(
      request.signalIdentity,
      request.registrationId,
      request.registrationPreKeys,
    ),
    },
  );
  if (!record(value)) throw new Error('Managed Relay returned an invalid registration');
  const session: StoredHostedRelaySession = {
    canonicalAccountId: requiredString(value, 'canonicalAccountId'),
    deviceId: requiredNumber(value, 'deviceId'),
    deviceToken: requiredString(value, 'deviceToken'),
    generation: requiredNumber(
      value,
      request.assertionPurpose === 'recover'
        ? 'deviceAuthorizationGeneration'
        : 'generation',
    ),
    mailboxGeneration: requiredNumber(value, 'mailboxGeneration'),
    relayScopeId: requiredString(value, 'relayScopeId'),
  };
  if (
    session.relayScopeId !== relayScopeId(request.connection) ||
    session.deviceId < 1 ||
    session.generation < 0 ||
    session.mailboxGeneration < 0 ||
    tokenExpiration(session.deviceToken, session) <= Math.floor(Date.now() / 1_000)
  ) {
    throw new Error('Managed Relay returned an invalid registration');
  }
  await request.storage.setMetadata(
    await sessionMetadataKey(request.connection),
    JSON.stringify(session),
  );
  const transport = new HostedRelayHttpTransport(
    request.connection,
    request.storage,
    request.deviceAuthentication,
    session,
  );
  return {
    canonicalAccountId: session.canonicalAccountId,
    deviceId: session.deviceId,
    relay: transport,
    relayScopeId: request.connection.relayScopeId.slice(),
    remoteObjectStore: transport.objectStore,
    transport,
  };
}

export async function resumeHostedRelayTransport(options: {
  readonly connection: HostedRelayConnection;
  readonly deviceAuthentication: HostedRelayDeviceAuthentication;
  readonly storage: ISignalProtocolLocalStore;
}): Promise<HostedRelayTransportResult | undefined> {
  const stored = await options.storage.getMetadata(
    await sessionMetadataKey(options.connection),
  );
  if (!stored) return undefined;
  const session = parseSession(stored, options.connection);
  const transport = new HostedRelayHttpTransport(
    options.connection,
    options.storage,
    options.deviceAuthentication,
    session,
  );
  await transport.ensureAuthenticated(true);
  return {
    canonicalAccountId: session.canonicalAccountId,
    deviceId: session.deviceId,
    relay: transport,
    relayScopeId: options.connection.relayScopeId.slice(),
    remoteObjectStore: transport.objectStore,
    transport,
  };
}
