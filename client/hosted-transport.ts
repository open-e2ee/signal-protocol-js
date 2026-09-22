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
  SignalProtocolRelayServer,
  RelayGroupServer,
  KemLastResortPreKeyUpload,
  PreKeyBundle,
  PreKeyInventory,
  PreKeyUpload,
  SealedSenderAuth,
  Unsubscribe,
} from "../remote/relay/types";
import AsyncLock from "async-lock";
import type { GroupAuthorization } from "../internal/groups/manager";
import type { RetryRequest } from "../internal/sesame/types";
import type { CompositeIdentityV1, IdentityType } from "../keys/types";
import {
  createCompositeIdentityV1,
  decodeCompositeIdentityV1,
  encodeCompositeIdentityV1,
} from "../keys/identity";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToUrlSafeBase64,
  concatBytes,
  generateUuidV4,
  sha256,
  stringToBytes,
  urlSafeToBase64,
} from "../internal/crypto";
import type { Base64, SignalProtocolLocalStore } from "../types";
import type { PublicKey, Signature } from "../keys";
import type { IncomingEnvelope } from "./types";
import type { HostedRelayConnection } from "./hosted-connection";
import type {
  HostedRelayDeviceAuthentication,
  HostedRelayRegistrationPreKey,
  HostedRelayRegistrationPreKeys,
} from "./hosted";
import type {
  RemoteObjectDownload,
  RemoteObjectDownloadRequest,
  RemoteObjectUpload,
  RemoteObjectUploadReceipt,
  RemoteObjectUploadRequest,
  SignalProtocolRemoteObjectStore,
} from "../remote/object-store";
import { RemoteObjectUploadError } from "../remote/object-store";
import type {
  HostedRelayPushRegistration,
  HostedRelayPushRuntime,
} from "./hosted-push";
import {
  subscribeHostedMailbox,
  type MailboxSubscriptionHandle,
} from "./hosted-mailbox-subscription";
import { HostedGroupServer } from "./hosted-groups";
import {
  HostedAnonymousDelivery,
  decodeHostedAnonymousEnvelope,
} from "./hosted-anonymous-delivery";
import {
  applyPreKeyUploads,
  parseHostedPreKeyStatus,
  parseStoredPendingPublication,
  parseStoredPublication,
  publicationMatchesStatus,
  registrationPreKey,
  statusPreKeys,
  storedPreKey,
  storedPublication,
  type HostedPreKeyStatus,
  type StoredHostedPendingPreKeyPublication,
  type StoredHostedPreKeyPublication,
} from "./hosted-prekey-publication";

const SESSION_METADATA_PREFIX = "hostedRelay.session.v1:";
const DEVICE_TOKEN_REFRESH_SECONDS = 60;
const MAXIMUM_RESPONSE_BYTES = 1024 * 1024;
const PREKEY_EXPIRY_MILLISECONDS = 30 * 24 * 60 * 60 * 1000;
const DELIVERY_WIRE_VERSION = 1;
const DEVICE_AUTHENTICATION_SIGNATURE_LABEL = stringToBytes(
  "OpenE2EE Relay device authentication v1\0",
);
const REGISTRATION_MATERIAL_LABEL = stringToBytes(
  "OpenE2EE Relay registration material v1\0",
);
const REGISTRATION_CHALLENGE_LABEL = stringToBytes(
  "OpenE2EE Relay registration challenge v1\0",
);
const RECOVERY_CHALLENGE_LABEL = stringToBytes(
  "OpenE2EE Relay recovery challenge v1\0",
);
const TOKEN_REFRESH_CHALLENGE_LABEL = stringToBytes(
  "OpenE2EE Relay device token refresh challenge v1\0",
);

type JsonRecord = Record<string, unknown>;

interface StoredHostedRelaySession {
  canonicalAccountId: string;
  deviceId: number;
  deviceToken: string;
  generation: number;
  mailboxGeneration: number;
  pendingPreKeyPublication: StoredHostedPendingPreKeyPublication | null;
  preKeyPublication: StoredHostedPreKeyPublication;
  relayScopeId: string;
}

interface HostedDeviceDirectoryEntry {
  deviceId: number;
  generation: number;
  mailboxGeneration: number;
}

const hostedPreKeyPublicationLock = new AsyncLock({ maxPending: 100 });

interface HostedDeliveryWireEnvelope {
  ciphertext: string;
  contentHint?: number;
  messageType: Envelope["messageType"];
  timestamp: number;
  version: typeof DELIVERY_WIRE_VERSION;
}

export interface HostedRelayTransportBootstrapRequest {
  readonly assertion: string;
  readonly assertionPurpose: "register" | "recover";
  readonly connection: HostedRelayConnection;
  readonly deviceAuthentication: HostedRelayDeviceAuthentication;
  readonly operationId: string;
  readonly registrationId: number;
  readonly registrationPreKeys: HostedRelayRegistrationPreKeys;
  readonly signalIdentity: CompositeIdentityV1;
  readonly storage: SignalProtocolLocalStore;
}

export interface HostedRelayTransportResult {
  readonly canonicalAccountId: string;
  readonly deviceId: number;
  readonly relay: SignalProtocolRelayServer;
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
    this.name = "HostedRelayHttpError";
    this.status = status;
    this.code = code;
    this.data = data;
  }
}

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function uint32be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("Signal Protocol Relay unsigned integer is invalid");
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
  if (typeof value !== "string") throw new Error(`${label} is invalid`);
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
  return connection.protocolEndpoint.replace(/\/$/u, "");
}

async function parseResponse(response: Response): Promise<unknown> {
  const body = await response.text();
  if (body.length > MAXIMUM_RESPONSE_BYTES) {
    throw new Error("Signal Protocol Relay response is too large");
  }
  if (response.ok && response.status === 204) {
    if (body.length !== 0) {
      throw new Error("Signal Protocol Relay returned an invalid response");
    }
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error("Signal Protocol Relay returned invalid JSON");
  }
  if (!response.ok) {
    const error = record(parsed) && record(parsed.error) ? parsed.error : {};
    const code = typeof error.code === "string" ? error.code : "UNKNOWN";
    const message =
      typeof error.message === "string"
        ? error.message
        : "Signal Protocol Relay request failed";
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
    accept: "application/json",
    "content-type": "application/json",
  });
  if (token !== undefined) headers.set("authorization", `Bearer ${token}`);
  let response: Response;
  try {
    response = await fetch(`${identifiedEndpoint(connection)}${path}`, {
      body: JSON.stringify(body),
      headers,
      method: "POST",
      credentials: "omit",
      redirect: "error",
    });
  } catch (cause) {
    throw new Error("Signal Protocol Relay request could not be completed", { cause });
  }
  return parseResponse(response);
}

function assertionIdentifier(assertion: string): string {
  const parts = assertion.split(".");
  if (parts.length !== 3) {
    throw new Error("Identity provider returned an invalid assertion");
  }
  let claims: unknown;
  try {
    claims = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(parts[1]!, "Assertion claims")),
    );
  } catch {
    throw new Error("Identity provider returned an invalid assertion");
  }
  if (!record(claims) || typeof claims.jti !== "string" || !claims.jti) {
    throw new Error("Identity provider returned an invalid assertion");
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
      kind: "signed" as const,
    })),
    ...prekeys.oneTimePreKeys.map((prekey) => ({
      ...prekey,
      kind: "one-time" as const,
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
        text("aci"),
        text("signal-composite-v1"),
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
      request.assertionPurpose === "recover"
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

function parseSession(
  value: string,
  connection: HostedRelayConnection,
): StoredHostedRelaySession {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("Stored Signal Protocol Relay session is invalid");
  }
  if (
    !record(parsed) ||
    Object.keys(parsed).sort().join(",") !==
      "canonicalAccountId,deviceId,deviceToken,generation,mailboxGeneration,pendingPreKeyPublication,preKeyPublication,relayScopeId" ||
    typeof parsed.canonicalAccountId !== "string" ||
    !parsed.canonicalAccountId ||
    !Number.isSafeInteger(parsed.deviceId) ||
    (parsed.deviceId as number) < 1 ||
    typeof parsed.deviceToken !== "string" ||
    !parsed.deviceToken ||
    !Number.isSafeInteger(parsed.generation) ||
    (parsed.generation as number) < 0 ||
    !Number.isSafeInteger(parsed.mailboxGeneration) ||
    (parsed.mailboxGeneration as number) < 0 ||
    parsed.relayScopeId !== relayScopeId(connection)
  ) {
    throw new Error("Stored Signal Protocol Relay session is invalid");
  }
  return {
    canonicalAccountId: parsed.canonicalAccountId,
    deviceId: parsed.deviceId as number,
    deviceToken: parsed.deviceToken,
    generation: parsed.generation as number,
    mailboxGeneration: parsed.mailboxGeneration as number,
    pendingPreKeyPublication: parseStoredPendingPublication(
      parsed.pendingPreKeyPublication,
    ),
    preKeyPublication: parseStoredPublication(parsed.preKeyPublication),
    relayScopeId: parsed.relayScopeId,
  };
}

function tokenExpiration(
  token: string,
  session: StoredHostedRelaySession,
): number {
  const parts = token.split(".");
  if (parts.length !== 3) return 0;
  try {
    const claims: unknown = JSON.parse(
      new TextDecoder().decode(decodeBase64Url(parts[1]!, "Device token")),
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
  if (!Number.isSafeInteger(value))
    throw new Error("Signal Protocol Relay returned invalid data");
  return value as number;
}

function requiredString(object: JsonRecord, key: string): string {
  const value = object[key];
  if (typeof value !== "string" || !value)
    throw new Error("Signal Protocol Relay returned invalid data");
  return value;
}

function unsupported(operation: string): never {
  throw new Error(
    `Signal Protocol Relay does not support ${operation} through this contract`,
  );
}

function encodeDeliveryWire(envelope: Envelope): Uint8Array {
  const ciphertext =
    envelope.ciphertext instanceof Uint8Array
      ? bytesToBase64(envelope.ciphertext)
      : envelope.ciphertext;
  if (bytesToBase64(base64ToBytes(ciphertext as Base64)) !== ciphertext) {
    throw new Error("Signal Protocol Relay envelope ciphertext is invalid");
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
    throw new Error("Signal Protocol Relay mailbox envelope is invalid");
  }
  if (
    !record(wire) ||
    typeof wire.ciphertext !== "string" ||
    bytesToBase64(base64ToBytes(wire.ciphertext as Base64)) !==
      wire.ciphertext ||
    (wire.contentHint !== undefined &&
      !Number.isSafeInteger(wire.contentHint)) ||
    typeof wire.messageType !== "string" ||
    !Number.isSafeInteger(wire.timestamp) ||
    wire.version !== DELIVERY_WIRE_VERSION
  ) {
    throw new Error("Signal Protocol Relay mailbox envelope is invalid");
  }
  return wire as unknown as HostedDeliveryWireEnvelope;
}

export class HostedRelayHttpTransport
  implements SignalProtocolRelayServer, HostedRelayPushRuntime
{
  private readonly groups: HostedGroupServer;
  public readonly groupServer: RelayGroupServer;
  private readonly anonymousDelivery: HostedAnonymousDelivery;
  private refreshPromise?: Promise<void>;
  private readonly destinationGenerations = new Map<string, number>();
  private readonly ephemeralAcknowledgments = new Set<string>();
  private subscription?: MailboxSubscriptionHandle;

  public constructor(
    private readonly connection: HostedRelayConnection,
    private readonly storage: SignalProtocolLocalStore,
    private readonly deviceAuthentication: HostedRelayDeviceAuthentication,
    private session: StoredHostedRelaySession,
  ) {
    this.groups = new HostedGroupServer(connection);
    this.groupServer = {
      server: this.groups,
      issueAuthCredential: (userId, authorityKeyId) => this.issueAuthCredential(userId, authorityKeyId),
      issueProfileKeyCredential: (userId, request, authorityKeyId) => this.issueProfileKeyCredential(userId, request, authorityKeyId),
      setUnidentifiedAccessKey: (userId, accessKey) => this.setUnidentifiedAccessKey(userId, accessKey),
    };
    this.anonymousDelivery = new HostedAnonymousDelivery(
      connection,
      async (accountAddress, deviceId) => {
        const key = `${accountAddress}\0${deviceId}`;
        if (!this.destinationGenerations.has(key))
          await this.directory(accountAddress);
        const generation = this.destinationGenerations.get(key);
        if (generation === undefined)
          throw new Error("Signal Protocol Relay destination device does not exist");
        return { accountAddress, deviceId, generation };
      },
    );
  }

  public get accountId(): string {
    return this.session.canonicalAccountId;
  }

  public get deviceId(): number {
    return this.session.deviceId;
  }

  public readonly objectStore: SignalProtocolRemoteObjectStore = {
    createUpload: async (input) => {
      try {
        return await this.createObjectUpload(input);
      } catch (error) {
        throw this.uploadError(error, "admission");
      }
    },
    createDownload: async (input) => this.createObjectDownload(input),
    abandonUpload: async ({ requestId, preparedAt }) => {
      const result = await this.authenticatedPost("/objects/abandon-upload", {
        requestId,
        preparedAt,
        publishableKey: this.connection.publishableKey,
      });
      if (
        !record(result) ||
        result.abandoned !== true ||
        Object.keys(result).length !== 1
      )
        throw new Error("The upload abandonment receipt is invalid.");
    },
    completeUpload: async ({ objectId }) => {
      try {
        await this.commitObjectUpload(objectId);
      } catch (error) {
        throw this.uploadError(error, "settlement");
      }
    },
    reconcileUpload: async ({ objectId }) => {
      try {
        return await this.commitObjectUpload(objectId);
      } catch (error) {
        if (
          error instanceof HostedRelayHttpError &&
          error.code === "UPLOAD_INCOMPLETE"
        )
          return null;
        throw this.uploadError(error, "settlement");
      }
    },
    deleteObject: async ({ objectId }) => {
      await this.authenticatedPost("/objects/delete", {
        objectId,
        publishableKey: this.connection.publishableKey,
      });
    },
  };

  private uploadError(
    error: unknown,
    phase: "admission" | "settlement",
  ): unknown {
    if (!(error instanceof HostedRelayHttpError)) return error;
    switch (error.code) {
      case "UPLOAD_EXPIRED":
        return new RemoteObjectUploadError("upload-expired");
      case "UPLOAD_CLOCK_SKEW":
        return new RemoteObjectUploadError("upload-clock-skew");
      case "PERIOD_CLOSED":
        // Accepted work can still require settlement repair. Do not terminalize it here.
        return phase === "admission"
          ? new RemoteObjectUploadError("upload-admission-closed")
          : error;
      case "NOT_FOUND":
        return new RemoteObjectUploadError("upload-unavailable");
      case "RETRY_CONFLICT":
        return new RemoteObjectUploadError("upload-identity-conflict");
      case "AUTHORITY_OVERRIDE":
      case "AUTHORITY_DENIED":
      case "SCOPE_MISMATCH":
        return new RemoteObjectUploadError("upload-rejected");
      default:
        return error;
    }
  }

  private async persistSession(): Promise<void> {
    await this.storage.setMetadata(
      await sessionMetadataKey(this.connection),
      JSON.stringify(this.session),
    );
  }

  private async commitObjectUpload(
    objectId: string,
  ): Promise<RemoteObjectUploadReceipt> {
    const value = await this.authenticatedPost("/objects/commit-upload", {
      objectId,
      publishableKey: this.connection.publishableKey,
    });
    if (
      !record(value) ||
      value.available !== true ||
      value.objectId !== objectId
    ) {
      throw new Error("Signal Protocol Relay returned an invalid upload receipt");
    }
    const contentLength = requiredNumber(value, "contentLength");
    const digest = decodeBase64Url(
      requiredString(value, "digest"),
      "Attachment digest",
    );
    if (
      !Number.isSafeInteger(contentLength) ||
      contentLength < 0 ||
      digest.length !== 32
    ) {
      throw new Error("Signal Protocol Relay returned an invalid upload receipt");
    }
    return { objectId, contentLength, digest };
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
    const value = await postJson(this.connection, "/identity/token", {
      accountAddress: this.session.canonicalAccountId,
      deviceId: this.session.deviceId,
      deviceProof: bytesToBase64(proof),
      nonce: bytesToUrlSafeBase64(nonce),
      publishableKey: this.connection.publishableKey,
      requestedAtSeconds,
    });
    if (!record(value) || typeof value.deviceToken !== "string") {
      throw new Error("Signal Protocol Relay returned an invalid device token");
    }
    this.session = { ...this.session, deviceToken: value.deviceToken };
    if (
      tokenExpiration(this.session.deviceToken, this.session) <=
      requestedAtSeconds
    ) {
      throw new Error("Signal Protocol Relay returned an invalid device token");
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

  /** Verify that the stored device authority can get a current token. */
  public async ensureAuthenticated(force = false): Promise<void> {
    await this.token(force);
  }

  private async authenticatedPost(
    path: string,
    body: JsonRecord,
  ): Promise<unknown> {
    let token = await this.token();
    try {
      return await postJson(this.connection, path, body, token);
    } catch (error) {
      if (
        !(error instanceof HostedRelayHttpError) ||
        error.code !== "TOKEN_INVALID"
      ) {
        throw error;
      }
      token = await this.token(true);
      return postJson(this.connection, path, body, token);
    }
  }

  private assertCurrentIdentity(
    userId: string,
    deviceId: number,
    identityType: IdentityType = "aci",
  ): void {
    if (
      userId !== this.session.canonicalAccountId ||
      deviceId !== this.session.deviceId ||
      identityType !== "aci"
    ) {
      throw new Error(
        "Signal Protocol Relay operation crossed the current device authority",
      );
    }
  }

  private async directory(
    userId: string,
  ): Promise<readonly HostedDeviceDirectoryEntry[]> {
    const value = await this.authenticatedPost("/identity/devices", {
      accountAddress: userId,
      publishableKey: this.connection.publishableKey,
    });
    if (
      !record(value) ||
      value.accountAddress !== userId ||
      !Array.isArray(value.devices)
    ) {
      throw new Error("Signal Protocol Relay returned an invalid device directory");
    }
    return value.devices.map((candidate) => {
      if (!record(candidate))
        throw new Error("Signal Protocol Relay returned an invalid device directory");
      const device = {
        deviceId: requiredNumber(candidate, "deviceId"),
        generation: requiredNumber(candidate, "generation"),
        mailboxGeneration: requiredNumber(candidate, "mailboxGeneration"),
      };
      if (
        device.deviceId < 1 ||
        device.generation < 0 ||
        device.mailboxGeneration < 0
      ) {
        throw new Error("Signal Protocol Relay returned an invalid device directory");
      }
      this.destinationGenerations.set(
        `${userId}\0${String(device.deviceId)}`,
        device.mailboxGeneration,
      );
      return device;
    });
  }

  private async prekeyStatus(
    userId: string,
    deviceId: number,
    identityType: IdentityType = "aci",
  ): Promise<HostedPreKeyStatus> {
    if (identityType !== "aci") unsupported("PNI prekey authority");
    const value = await this.authenticatedPost("/prekeys/status", {
      accountAddress: userId,
      deviceId,
      identityType,
      publishableKey: this.connection.publishableKey,
    });
    return parseHostedPreKeyStatus(value);
  }

  private async currentIdentity(): Promise<{
    identity: CompositeIdentityV1;
    registrationId: number;
  }> {
    const identity = await this.storage.getIdentityKey("aci");
    if (!identity)
      throw new Error("Signal Protocol Relay local Signal identity is unavailable");
    return {
      identity: createCompositeIdentityV1(identity),
      registrationId: identity.registrationId,
    };
  }

  private async acceptPublicationStatus(
    status: HostedPreKeyStatus,
  ): Promise<void> {
    this.session.preKeyPublication = storedPublication(
      status.authorityGeneration,
      status.materialFingerprint,
      status.currentOperationId,
      status.publicationRevision,
      statusPreKeys(status),
    );
    this.session.pendingPreKeyPublication = null;
    await this.persistSession();
  }

  private async publishCurrentPrekeys(
    uploads: readonly PreKeyUpload[],
  ): Promise<void> {
    await hostedPreKeyPublicationLock.acquire(
      await sessionMetadataKey(this.connection),
      async () => {
        const current = await this.currentIdentity();
        let status = await this.prekeyStatus(
          this.session.canonicalAccountId,
          this.session.deviceId,
        );
        if (
          status.authorityGeneration !== this.session.generation ||
          status.registrationId !== current.registrationId ||
          !equalBytes(
            status.identityPublicMaterial,
            encodeCompositeIdentityV1(current.identity),
          )
        ) {
          throw new Error(
            "Signal Protocol Relay prekey publication authority does not match local state",
          );
        }
        const pending = this.session.pendingPreKeyPublication;
        let retryPending: StoredHostedPendingPreKeyPublication | undefined;
        if (pending !== null) {
          if (
            status.currentOperationId === pending.operationId &&
            status.materialFingerprint === pending.materialFingerprint &&
            status.publicationRevision === pending.predecessorRevision + 1
          ) {
            await this.acceptPublicationStatus(status);
          } else if (
            !publicationMatchesStatus(this.session.preKeyPublication, status) ||
            status.publicationRevision !== pending.predecessorRevision
          ) {
            throw new Error(
              "Signal Protocol Relay prekey publication state is newer than local state",
            );
          } else retryPending = pending;
        } else if (
          !publicationMatchesStatus(this.session.preKeyPublication, status)
        ) {
          throw new Error(
            "Signal Protocol Relay prekey publication state is newer than local state",
          );
        }

        const target =
          retryPending === undefined
            ? applyPreKeyUploads(statusPreKeys(status), uploads)
            : {
                oneTimePreKeys:
                  retryPending.oneTimePreKeys.map(registrationPreKey),
                signedPreKeys:
                  retryPending.signedPreKeys.map(registrationPreKey),
              };
        const fingerprint = await registrationMaterialFingerprint(
          current.identity,
          current.registrationId,
          target,
        );
        if (retryPending !== undefined) {
          const repeatedFingerprint = await registrationMaterialFingerprint(
            current.identity,
            current.registrationId,
            applyPreKeyUploads(target, uploads),
          );
          if (repeatedFingerprint !== retryPending.materialFingerprint) {
            throw new Error(
              "A different Signal Protocol Relay prekey publication is already pending",
            );
          }
        }
        if (fingerprint === status.materialFingerprint) {
          await this.acceptPublicationStatus(status);
          return;
        }
        if (
          retryPending !== undefined &&
          fingerprint !== retryPending.materialFingerprint
        ) {
          throw new Error("Stored Signal Protocol Relay prekey publication is invalid");
        }
        const operationId = retryPending?.operationId ?? fingerprint;
        const predecessorRevision =
          retryPending?.predecessorRevision ?? status.publicationRevision;
        this.session.pendingPreKeyPublication = {
          materialFingerprint: fingerprint,
          oneTimePreKeys: target.oneTimePreKeys.map(storedPreKey),
          operationId,
          predecessorRevision,
          signedPreKeys: target.signedPreKeys.map(storedPreKey),
        };
        await this.persistSession();
        const result = await this.authenticatedPost("/prekeys/publish", {
          operationId,
          predecessorRevision,
          publishableKey: this.connection.publishableKey,
          signalRegistration: signalRegistration(
            current.identity,
            current.registrationId,
            target,
          ),
        });
        if (
          !record(result) ||
          result.published !== true ||
          requiredNumber(result, "publicationRevision") !==
            predecessorRevision + 1
        ) {
          throw new Error(
            "Signal Protocol Relay returned an invalid prekey publication",
          );
        }
        status = await this.prekeyStatus(
          this.session.canonicalAccountId,
          this.session.deviceId,
        );
        if (
          status.currentOperationId !== operationId ||
          status.materialFingerprint !== fingerprint ||
          status.publicationRevision !== result.publicationRevision ||
          status.authorityGeneration !== this.session.generation
        ) {
          throw new Error(
            "Signal Protocol Relay returned an invalid prekey publication",
          );
        }
        await this.acceptPublicationStatus(status);
      },
    );
  }

  private async pullIncoming(): Promise<readonly IncomingEnvelope[]> {
    const value = await this.authenticatedPost("/mailbox/pull", {
      publishableKey: this.connection.publishableKey,
    });
    if (!record(value) || !Array.isArray(value.messages)) {
      throw new Error("Signal Protocol Relay returned an invalid mailbox page");
    }
    return value.messages.map((candidate) => this.incomingEnvelope(candidate));
  }

  /** One retained mailbox message, from a pull page or a `durable-message` frame. */
  private incomingEnvelope(candidate: unknown): IncomingEnvelope {
    if (!record(candidate) || !record(candidate.sender)) {
      throw new Error("Signal Protocol Relay returned an invalid mailbox message");
    }
    const decoded = this.decodeMailboxEnvelope(candidate);
    return {
      id: requiredString(candidate, "messageId"),
      ...decoded,
      serverTimestamp: requiredNumber(candidate, "enqueuedAt"),
    };
  }

  private decodeMailboxEnvelope(candidate: JsonRecord) {
    if (!record(candidate.sender))
      throw new Error("Signal Protocol Relay mailbox sender is invalid");
    const encoded = decodeCanonicalBase64(
      candidate.envelope,
      "Mailbox envelope",
    );
    const anonymous =
      candidate.sender.accountId === "" && candidate.sender.deviceId === 0;
    if (anonymous)
      return {
        ...decodeHostedAnonymousEnvelope(encoded),
        senderUserId: "",
        senderDeviceId: 0,
      };
    const senderDeviceId = requiredNumber(candidate.sender, "deviceId");
    if (senderDeviceId < 1)
      throw new Error("Signal Protocol Relay mailbox sender is invalid");
    return {
      ...decodeDeliveryWire(encoded),
      senderUserId: requiredString(candidate.sender, "accountId"),
      senderDeviceId,
    };
  }

  public async fetchSenderCertificate(deviceId: number): Promise<string> {
    this.assertCurrentIdentity(this.session.canonicalAccountId, deviceId);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const token = await this.token(attempt > 0);
      const claims: unknown = JSON.parse(
        new TextDecoder().decode(
          decodeBase64Url(token.split(".")[1]!, "Device token"),
        ),
      );
      if (
        !record(claims) ||
        typeof claims.jti !== "string" ||
        !claims.jti ||
        claims.jti.includes("\0")
      )
        throw new Error("Signal Protocol Relay certificate token is invalid");
      const nonce = bytesToUrlSafeBase64(
        crypto.getRandomValues(new Uint8Array(32)),
      );
      const proof = await this.deviceAuthentication.signCertificateRequest(
        claims.jti,
        nonce,
      );
      if (proof.byteLength !== 64)
        throw new Error("Signal Protocol Relay certificate proof is invalid");
      try {
        const result = await postJson(
          this.connection,
          "/certificates/issue",
          {
            publishableKey: this.connection.publishableKey,
            nonce,
            deviceProof: bytesToBase64(proof),
          },
          token,
        );
        if (
          !record(result) ||
          typeof result.senderCertificate !== "string" ||
          decodeCanonicalBase64(result.senderCertificate, "Sender certificate")
            .length === 0
        )
          throw new Error("Signal Protocol Relay certificate response is invalid");
        return result.senderCertificate;
      } catch (error) {
        if (
          attempt > 0 ||
          !(error instanceof HostedRelayHttpError) ||
          error.code !== "TOKEN_INVALID"
        )
          throw error;
      }
    }
    throw new Error("Signal Protocol Relay certificate request failed");
  }

  public async setUnidentifiedAccessKey(
    userId: string,
    accessKey: Uint8Array,
  ): Promise<void> {
    this.assertCurrentIdentity(userId, this.session.deviceId);
    if (accessKey.byteLength !== 16)
      throw new Error("Signal Protocol Relay access key is invalid");
    const value = await this.authenticatedPost("/anonymous/access-key", {
      publishableKey: this.connection.publishableKey,
      unidentifiedAccessKey: bytesToBase64(accessKey),
    });
    if (value !== undefined)
      throw new Error("Signal Protocol Relay access-key receipt is invalid");
  }

  public async sendMultiRecipientUnidentified(
    sentMessageBase64: string,
    auth: SealedSenderAuth,
    timestamp: number,
    deliveryClass: DeliveryClass,
    recipientUserIds?: string[],
    clientMessageId?: string,
  ) {
    return this.anonymousDelivery.send(
      sentMessageBase64,
      auth,
      timestamp,
      deliveryClass,
      recipientUserIds,
      clientMessageId,
    );
  }

  private async acknowledge(messageIds: readonly string[]): Promise<void> {
    const value = await this.authenticatedPost("/mailbox/acknowledge", {
      messageIds: [...messageIds],
      publishableKey: this.connection.publishableKey,
    });
    if (!record(value) || requiredNumber(value, "acknowledged") < 0) {
      throw new Error("Signal Protocol Relay returned an invalid acknowledgment");
    }
  }

  public async registerPush(
    registration: HostedRelayPushRegistration,
  ): Promise<void> {
    const value = await this.authenticatedPost("/push/register", {
      ...registration,
      publishableKey: this.connection.publishableKey,
    });
    if (value !== undefined) {
      throw new Error("Signal Protocol Relay returned an invalid push result");
    }
  }

  public async removePush(): Promise<void> {
    const value = await this.authenticatedPost("/push/remove", {
      publishableKey: this.connection.publishableKey,
    });
    if (value !== undefined) {
      throw new Error("Signal Protocol Relay returned an invalid push result");
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

  private async createObjectUpload(
    input: RemoteObjectUploadRequest,
  ): Promise<RemoteObjectUpload> {
    if (
      !(input.readCapabilityDigest instanceof Uint8Array) ||
      input.readCapabilityDigest.length !== 32
    )
      throw new Error(
        "The hosted attachment requires a read-capability commitment.",
      );
    const value = await this.authenticatedPost("/objects/authorize-upload", {
      contentLength: input.contentLength,
      digest: bytesToUrlSafeBase64(input.digest),
      readCapabilityDigest: bytesToUrlSafeBase64(input.readCapabilityDigest),
      publishableKey: this.connection.publishableKey,
      requestId: input.requestId,
      preparedAt: input.preparedAt,
    });
    if (!record(value) || !record(value.headers)) {
      throw new Error("Signal Protocol Relay returned an invalid upload grant");
    }
    return {
      expiresAt: requiredNumber(value, "expiresAt"),
      headers: Object.fromEntries(
        Object.entries(value.headers).map(([name, header]) => {
          if (typeof header !== "string")
            throw new Error("Signal Protocol Relay returned an invalid upload grant");
          return [name, header];
        }),
      ),
      objectId: requiredString(value, "objectId"),
      protocol: "put",
      uploadUrl: requiredString(value, "uploadUrl"),
    };
  }

  private async createObjectDownload(
    input: RemoteObjectDownloadRequest,
  ): Promise<RemoteObjectDownload> {
    if (
      input.readCapability === undefined ||
      !/^[A-Za-z0-9_-]{43}$/.test(input.readCapability)
    )
      throw new Error("The hosted attachment requires its read capability.");
    const token = await this.token();
    return {
      downloadUrl: `${identifiedEndpoint(this.connection)}/objects/download`,
      expiresAt: tokenExpiration(token, this.session) * 1_000,
      headers: {
        authorization: `Bearer ${token}`,
        "x-open-e2ee-publishable-key": this.connection.publishableKey,
        "x-open-e2ee-object-id": input.objectId,
        "x-open-e2ee-attachment-capability": input.readCapability,
      },
    };
  }

  public async send(
    envelope: Envelope,
  ): Promise<{ messageId: string; serverTimestamp: number }> {
    if (
      envelope.senderUserId !== this.session.canonicalAccountId ||
      envelope.senderDeviceId !== this.session.deviceId ||
      envelope.clientMessageId === ''
    ) {
      throw new Error(
        "Signal Protocol Relay send authority or operation ID is invalid",
      );
    }
    const messageId = envelope.clientMessageId ?? await generateUuidV4();
    const key = `${envelope.targetUserId}\0${String(envelope.targetDeviceId)}`;
    let generation = this.destinationGenerations.get(key);
    if (generation === undefined) {
      await this.directory(envelope.targetUserId);
      generation = this.destinationGenerations.get(key);
    }
    if (generation === undefined)
      throw new Error("Signal Protocol Relay destination device does not exist");
    let value: unknown;
    try {
      value = await this.authenticatedPost("/delivery/send", {
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
      if (
        error instanceof HostedRelayHttpError &&
        error.code === "STALE_DEVICE"
      ) {
        throw new HostedRelayHttpError(
          error.status,
          error.code,
          error.message,
          {
            code: "STALE_DEVICE",
            message: error.message,
            reason: "device_reinstalled",
            staleDevices: [envelope.targetDeviceId],
          },
        );
      }
      throw error;
    }
    if (!record(value) || requiredString(value, "messageId") !== messageId) {
      throw new Error("Signal Protocol Relay returned an invalid delivery receipt");
    }
    return {
      messageId,
      serverTimestamp:
        typeof value.enqueuedAt === "number"
          ? value.enqueuedAt
          : envelope.timestamp,
    };
  }

  public subscribe(
    userId: string,
    deviceId: number,
    onEnvelope: (envelope: Envelope) => void,
    options?: { onBatchStart?: () => void; onBatchEnd?: () => void },
  ): Unsubscribe {
    this.assertCurrentIdentity(userId, deviceId);
    const subscription = subscribeHostedMailbox({
      ...options,
      authenticate: async () => {
        const token = await this.token();
        const url = new URL(
          `${identifiedEndpoint(this.connection)}/mailbox/connect`,
        );
        url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
        url.searchParams.set("publishableKey", this.connection.publishableKey);
        return {
          url: url.toString(),
          token,
          renewAt:
            (tokenExpiration(token, this.session) -
              DEVICE_TOKEN_REFRESH_SECONDS) *
            1_000,
        };
      },
      decodeDurable: (message) => this.incomingEnvelope(message) as Envelope,
      pull: async () => (await this.pullIncoming()) as readonly Envelope[],
      acknowledge: (messageIds) => this.acknowledge(messageIds),
      receive: onEnvelope,
      receiveEphemeral: async (candidate, current) => {
        if (!record(candidate) || !record(candidate.sender))
          throw new Error("Invalid ephemeral mailbox message.");
        const wire = this.decodeMailboxEnvelope(candidate);
        const messageId = requiredString(candidate, "messageId");
        const envelope: Envelope = {
          ...wire,
          id: messageId,
          deliveryClass: "ephemeral",
          targetUserId: this.session.canonicalAccountId,
          targetDeviceId: this.session.deviceId,
        };
        if (!current()) return messageId;
        this.ephemeralAcknowledgments.add(messageId);
        try {
          await onEnvelope(envelope);
        } finally {
          this.ephemeralAcknowledgments.delete(messageId);
        }
        return messageId;
      },
    });
    this.subscription = subscription;
    return () => {
      if (this.subscription === subscription) this.subscription = undefined;
      subscription.unsubscribe();
    };
  }

  /**
   * Acknowledges over the live mailbox socket when one exists, in one frame per
   * drained burst, and over HTTP otherwise.
   */
  public async markDelivered(envelopeId: string): Promise<void> {
    if (this.ephemeralAcknowledgments.has(envelopeId)) return;
    if (this.subscription?.acknowledge(envelopeId) === true) return;
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

  public async provisionIdentityKey(
    request: AccountIdentityProvisioning,
  ): Promise<void> {
    this.assertCurrentIdentity(
      request.userId,
      request.deviceId,
      request.identityType,
    );
    const status = await this.prekeyStatus(
      request.userId,
      request.deviceId,
      request.identityType,
    );
    if (
      status.registrationId !== request.registrationId ||
      !equalBytes(
        status.identityPublicMaterial,
        encodeCompositeIdentityV1(request.identity),
      )
    ) {
      throw new Error(
        "Signal Protocol Relay canonical Signal identity does not match local state",
      );
    }
  }

  public async getIdentityKey(
    userId: string,
    identityType: IdentityType = "aci",
  ): Promise<CompositeIdentityV1 | null> {
    try {
      return decodeCompositeIdentityV1(
        (await this.prekeyStatus(userId, 1, identityType))
          .identityPublicMaterial,
      );
    } catch (error) {
      if (error instanceof HostedRelayHttpError && error.code === "NOT_FOUND")
        return null;
      throw error;
    }
  }

  public async uploadPreKeys(
    userId: string,
    deviceId: number,
    keys: PreKeyUpload[],
    identityType: IdentityType = "aci",
  ): Promise<void> {
    this.assertCurrentIdentity(userId, deviceId, identityType);
    await this.publishCurrentPrekeys(keys);
  }

  public async fetchPreKeyBundle(
    userId: string,
    deviceId: number,
    _fetcherUserId?: string,
    identityType: IdentityType = "aci",
  ): Promise<PreKeyBundle | null> {
    if (identityType !== "aci") unsupported("PNI prekey authority");
    let value: unknown;
    try {
      value = await this.authenticatedPost("/prekeys/consume", {
        accountAddress: userId,
        deviceId,
        identityType,
        publishableKey: this.connection.publishableKey,
      });
    } catch (error) {
      if (error instanceof HostedRelayHttpError && error.code === "NOT_FOUND")
        return null;
      throw error;
    }
    if (
      !record(value) ||
      !Array.isArray(value.signedPreKeys) ||
      !Array.isArray(value.oneTimePreKeys)
    ) {
      throw new Error("Signal Protocol Relay returned an invalid prekey bundle");
    }
    const signed = value.signedPreKeys.map((candidate) => {
      if (!record(candidate))
        throw new Error("Signal Protocol Relay returned an invalid prekey bundle");
      return {
        algorithm: requiredString(candidate, "algorithm"),
        keyId: requiredNumber(candidate, "keyId"),
        publicKey: requiredString(candidate, "publicKey"),
        signature: requiredString(candidate, "signature"),
      };
    });
    const oneTime = value.oneTimePreKeys.map((candidate) => {
      if (!record(candidate))
        throw new Error("Signal Protocol Relay returned an invalid prekey bundle");
      return {
        algorithm: requiredString(candidate, "algorithm"),
        keyId: requiredNumber(candidate, "keyId"),
        publicKey: requiredString(candidate, "publicKey"),
        ...(candidate.signature === undefined
          ? {}
          : { signature: requiredString(candidate, "signature") }),
      };
    });
    const ecSigned = signed.find((key) => key.algorithm === "ec-x25519");
    const kemSigned = signed.find((key) => key.algorithm === "kem-ml-kem-1024");
    if (!ecSigned || !kemSigned)
      throw new Error("Signal Protocol Relay returned an invalid prekey bundle");
    const ecOneTime = oneTime.find((key) => key.algorithm === "ec-x25519");
    const kemOneTime = oneTime.find(
      (key) => key.algorithm === "kem-ml-kem-1024",
    );
    return {
      deviceId,
      registrationId: requiredNumber(value, "registrationId"),
      identity: decodeCompositeIdentityV1(
        decodeCanonicalBase64(value.identityPublicMaterial, "Signal identity"),
      ),
      ecSignedPreKey: {
        keyId: ecSigned.keyId,
        publicKey: ecSigned.publicKey as PublicKey,
        signature: ecSigned.signature as Signature,
      },
      ecOneTimePreKey: ecOneTime
        ? {
            keyId: ecOneTime.keyId,
            publicKey: ecOneTime.publicKey as PublicKey,
          }
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

  public async getPreKeyInventory(
    userId: string,
    deviceId: number,
    identityType: IdentityType = "aci",
  ): Promise<PreKeyInventory> {
    const status = await this.prekeyStatus(userId, deviceId, identityType);
    const metadata = (algorithm: string) => {
      const key = status.signedPreKeys.find(
        (candidate) => candidate.algorithm === algorithm,
      );
      return key
        ? {
            keyId: key.keyId,
            createdAt: key.acceptedAtMilliseconds,
            expiresAt: key.acceptedAtMilliseconds + PREKEY_EXPIRY_MILLISECONDS,
            publicKey: bytesToBase64(key.publicKey),
          }
        : null;
    };
    return {
      ecSignedPreKey: metadata("ec-x25519"),
      kemLastResortPreKey: metadata("kem-ml-kem-1024"),
      ecOneTimePreKeyCount: status.oneTimePreKeyCounts["ec-x25519"] ?? 0,
      kemOneTimePreKeyCount: status.oneTimePreKeyCounts["kem-ml-kem-1024"] ?? 0,
    };
  }

  public async getPreKeyCount(
    userId: string,
    deviceId: number,
    type: "ec" | "kem",
    identityType: IdentityType = "aci",
  ): Promise<number> {
    const status = await this.prekeyStatus(userId, deviceId, identityType);
    return (
      status.oneTimePreKeyCounts[
        type === "ec" ? "ec-x25519" : "kem-ml-kem-1024"
      ] ?? 0
    );
  }

  public async getEcSignedPreKeyMetadata(
    userId: string,
    deviceId: number,
    identityType: IdentityType = "aci",
  ) {
    return (await this.getPreKeyInventory(userId, deviceId, identityType))
      .ecSignedPreKey;
  }

  public async getKemLastResortPreKeyMetadata(
    userId: string,
    deviceId: number,
    identityType: IdentityType = "aci",
  ) {
    return (await this.getPreKeyInventory(userId, deviceId, identityType))
      .kemLastResortPreKey;
  }

  public async clearStaleKemPreKeys(
    userId: string,
    deviceId: number,
    identityType: IdentityType = "aci",
  ): Promise<{ cleared: number }> {
    this.assertCurrentIdentity(userId, deviceId, identityType);
    const value = await this.authenticatedPost("/prekeys/clear-stale-kem", {
      publishableKey: this.connection.publishableKey,
    });
    if (!record(value))
      throw new Error("Signal Protocol Relay returned an invalid prekey result");
    return { cleared: requiredNumber(value, "cleared") };
  }

  public async uploadEcSignedPreKey(
    userId: string,
    key: EcSignedPreKeyUpload,
    identityType: IdentityType = "aci",
  ): Promise<void> {
    this.assertCurrentIdentity(userId, this.session.deviceId, identityType);
    await this.publishCurrentPrekeys([
      {
        keyId: key.keyId,
        publicKey: key.publicKey,
        signature: key.signature,
        type: "ecSignedPreKey",
      },
    ]);
  }

  public async uploadKemLastResortPreKey(
    userId: string,
    key: KemLastResortPreKeyUpload,
    identityType: IdentityType = "aci",
  ): Promise<void> {
    this.assertCurrentIdentity(userId, this.session.deviceId, identityType);
    await this.publishCurrentPrekeys([
      {
        keyId: key.keyId,
        publicKey: key.publicKey,
        signature: key.signature,
        type: "kemLastResortPreKey",
      },
    ]);
  }

  public async rotateIdentityKey(
    _request: AccountIdentityRotation,
  ): Promise<void> {
    unsupported("identity rotation outside the hosted recovery flow");
  }

  public async registerDevice(
    _userId: string,
    _device: DeviceRegistration,
  ): Promise<number> {
    unsupported("direct device registration");
  }
  public async removeDevice(_userId: string, _deviceId: number): Promise<void> {
    unsupported("direct device removal");
  }
  public async markDeviceConnected(_deviceId: number): Promise<void> {
    unsupported("connection presence");
  }
  public async markDeviceDisconnected(_deviceId: number): Promise<void> {
    unsupported("connection presence");
  }
  public async heartbeat(_deviceId: number): Promise<void> {
    unsupported("connection presence");
  }
  public async createProvisioningSession(
    _userId: string,
    _key: string,
  ): Promise<{ sessionId: string }> {
    unsupported("legacy provisioning sessions");
  }
  public async connectNewDevice(
    _sessionId: string,
    _key: string,
    _metadata: { platform?: string; appVersion?: string; osVersion?: string },
  ): Promise<void> {
    unsupported("legacy provisioning sessions");
  }
  public async sendProvisioningMessage(
    _sessionId: string,
    _message: string,
    _userId?: string,
  ): Promise<void> {
    unsupported("legacy provisioning sessions");
  }
  public async getProvisioningMessage(_sessionId: string): Promise<{
    status:
      | "waiting"
      | "connected"
      | "ready"
      | "linked_pending_ack"
      | "completed"
      | "rolled_back"
      | "expired";
    message: string | null;
    expiresAt: number | null;
  }> {
    unsupported("legacy provisioning sessions");
  }
  public async completeProvisioning(
    _sessionId: string,
    _metadata: {
      encryptedDeviceName: ArrayBuffer;
      platform?: string;
      appVersion?: string;
      osVersion?: string;
    },
  ): Promise<{ deviceId: number }> {
    unsupported("legacy provisioning sessions");
  }
  public async acknowledgeProvisioning(_sessionId: string): Promise<void> {
    unsupported("legacy provisioning sessions");
  }
  public async rollbackProvisioning(_sessionId: string): Promise<void> {
    unsupported("legacy provisioning sessions");
  }
  public async deleteProvisioningSession(
    _sessionId: string,
    _userId?: string,
  ): Promise<void> {
    unsupported("legacy provisioning sessions");
  }
  public async createGroupState(
    groupId: Uint8Array,
    state: Uint8Array,
    authorization: GroupAuthorization,
  ): Promise<void> {
    return this.groups.createGroup(groupId, state, authorization);
  }
  public async getGroupState(
    groupId: Uint8Array,
    authorization: GroupAuthorization,
    version?: number,
  ): Promise<{
    encryptedState: Uint8Array;
    version: number;
    baselineSignature: Uint8Array;
  } | null> {
    return this.groups.getGroup(groupId, authorization, version);
  }
  public async getGroupJoinInfo(
    groupId: Uint8Array,
    password: Uint8Array,
    authorization: GroupAuthorization,
  ): Promise<{ encryptedJoinInfo: Uint8Array; version: number } | null> {
    return this.groups.getGroupJoinInfo(groupId, password, authorization);
  }
  public async getGroupChanges(
    groupId: Uint8Array,
    fromVersion: number,
    authorization: GroupAuthorization,
  ): Promise<GroupChangePage> {
    return this.groups.getGroupChanges(groupId, fromVersion, authorization);
  }
  public async submitGroupChange(
    groupId: Uint8Array,
    expectedVersion: number,
    actions: Uint8Array,
    password: Uint8Array,
    authorization: GroupAuthorization,
  ): Promise<GroupChangeEntry> {
    if (arguments.length !== 5)
      throw new Error(
        "INVALID_REQUEST: Group change submission must not carry an epoch",
      );
    return this.groups.submitGroupChange(
      groupId,
      expectedVersion,
      actions,
      password,
      authorization,
    );
  }
  public async issueAuthCredential(userId: string, authorityKeyId?: string): Promise<Uint8Array> {
    this.assertCurrentIdentity(userId, this.session.deviceId);
    return this.groupCredential("auth", { authorityKeyId });
  }
  public async refreshGroupSendEndorsements(groupId: Uint8Array, authorization: GroupAuthorization): Promise<{ endorsements: Uint8Array; expiration: number }> {
    return this.groups.refreshGroupSendEndorsements(groupId, authorization);
  }
  public async issueProfileKeyCredential(userId: string, request: Uint8Array, authorityKeyId?: string): Promise<Uint8Array> {
    this.assertCurrentIdentity(userId, this.session.deviceId);
    if (request.byteLength !== 160) throw new Error("Invalid blinded profile credential request");
    return this.groupCredential("profile-key", { authorityKeyId, blindedRequest: bytesToBase64(request) });
  }
  private async groupCredential(kind: "auth" | "profile-key", request: JsonRecord): Promise<Uint8Array> {
    if (typeof request.authorityKeyId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(request.authorityKeyId))
      throw new Error("Managed group credentials require a verified authority selection");
    const value = await this.authenticatedPost(`/groups/credentials/${kind}`, {
      publishableKey: this.connection.publishableKey, ...request,
    });
    if (!record(value) || Object.keys(value).length !== 1 || typeof value.credential !== "string")
      throw new Error("Relay returned an invalid group credential");
    try {
      const credential = base64ToBytes(value.credential as Base64);
      if (credential.byteLength < 1 || credential.byteLength > 2048 || bytesToBase64(credential) !== value.credential)
        throw new Error("Invalid credential encoding");
      return credential;
    } catch {
      throw new Error("Relay returned an invalid group credential");
    }
  }
}

export async function bootstrapHostedRelayTransport(
  request: HostedRelayTransportBootstrapRequest,
): Promise<HostedRelayTransportResult> {
  const proof = await request.deviceAuthentication.signChallenge(
    await registrationChallenge(request),
  );
  const value = await postJson(
    request.connection,
    request.assertionPurpose === "recover"
      ? "/identity/recover"
      : "/identity/register",
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
  if (!record(value))
    throw new Error("Signal Protocol Relay returned an invalid registration");
  const materialFingerprint = await registrationMaterialFingerprint(
    request.signalIdentity,
    request.registrationId,
    request.registrationPreKeys,
  );
  const generation = requiredNumber(
    value,
    request.assertionPurpose === "recover"
      ? "deviceAuthorizationGeneration"
      : "generation",
  );
  const session: StoredHostedRelaySession = {
    canonicalAccountId: requiredString(value, "canonicalAccountId"),
    deviceId: requiredNumber(value, "deviceId"),
    deviceToken: requiredString(value, "deviceToken"),
    generation,
    mailboxGeneration: requiredNumber(value, "mailboxGeneration"),
    pendingPreKeyPublication: null,
    preKeyPublication: storedPublication(
      generation,
      materialFingerprint,
      request.operationId,
      0,
      request.registrationPreKeys,
    ),
    relayScopeId: requiredString(value, "relayScopeId"),
  };
  if (
    session.relayScopeId !== relayScopeId(request.connection) ||
    session.deviceId < 1 ||
    session.generation < 0 ||
    session.mailboxGeneration < 0 ||
    tokenExpiration(session.deviceToken, session) <=
      Math.floor(Date.now() / 1_000)
  ) {
    throw new Error("Signal Protocol Relay returned an invalid registration");
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
  readonly storage: SignalProtocolLocalStore;
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
