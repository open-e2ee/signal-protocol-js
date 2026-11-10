import { HostedSignalProtocolRelayResumeError } from './hosted-resume-error';
import { hostedAssertionIdentifier } from "./hosted-assertion-id";
import { HostedSignalProtocolRelayHttpError } from "./hosted-http-error";
import { submitHostedSignalProtocolRelayDeviceLink } from "./hosted-device-link-transport";
import { utf8Decode, websocketUrl } from "../internal/platform";
import type {
  AccountIdentityProvisioning,
  AccountIdentityRotation,
  ContentKind,
  DeliveryClass,
  DeviceInfo,
  DeviceRegistration,
  Envelope,
  GroupChangeEntry,
  GroupChangePage,
  GroupMemberDevice,
  SignalProtocolRelayServer,
  SignalProtocolRelayGroupServer,
  PreKeyBundle,
  PreKeyInventory,
  PreKeyPublicationPlan,
  PreKeyUpload,
  SignalProtocolRelayConnectionState,
  SealedSenderAuth,
  Unsubscribe,
} from "../remote/signal-relay/types";
import AsyncLock from "async-lock";
import type { GroupAuthorization } from "../internal/groups/manager";
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
  generateRandomBytes,
  generateUuidV4,
  sha256,
  stringToBytes,
  urlSafeToBase64,
} from "../internal/crypto";
import type { Base64, SignalProtocolLocalStore } from "../types";
import type { PublicKey, Signature } from "../keys";
import type { IncomingEnvelope } from "./types";
import type { HostedSignalProtocolRelayConnection } from "./hosted-connection";
import type {
  HostedSignalProtocolRelayDeviceAuthentication,
  HostedSignalProtocolRelayRegistrationPreKey,
  HostedSignalProtocolRelayRegistrationPreKeys,
  HostedSignalProtocolRelayManagedDeviceLinkRequest,
  HostedSignalProtocolRelayManagedDeviceLinkResult,
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
import { SignalProtocolRelayConnectionStateOwner } from "../remote/signal-relay/connection-state";
import type {
  HostedMailboxPage,
  HostedSignalProtocolRelayPushRegistration,
  HostedSignalProtocolRelayPushRuntime,
} from "./hosted-push";
import type { HostedSignalProtocolRelayPresenceRuntime } from "./hosted-presence";
import {
  presenceHttpBody,
  type HostedSignalProtocolRelayPresenceRequest,
} from "./hosted-presence-frames";
import {
  subscribeHostedMailbox,
  type MailboxAcknowledgment,
  type MailboxSubscriptionHandle,
  type PresenceSocketEvent,
} from "./hosted-mailbox-subscription";
import { HostedGroupServer } from "./hosted-groups";
import {
  RELAY_PROTOCOL_VERSION,
  markSignalProtocolRelayAnswerVersion,
  signalRelayProtocolHeadersFor,
  throwIfUpgradeRequired,
} from "./signal-relay-protocol";
import {
  HostedSignalProtocolRelayDeviceUnknownError,
  throwIfDeviceRevoked,
} from "./hosted-device-standing";
import {
  HostedAnonymousDelivery,
  HostedAnonymousDeliveryError,
  decodeHostedAnonymousEnvelope,
} from "./hosted-anonymous-delivery";
import { createAdapterSignalProtocolRelayFanOut, rethrowSignalProtocolRelayWorkStopped } from "./signal-relay-work";
import { withSignalProtocolRelayRequestDeadline } from "./signal-relay-request-deadline";
import type { BoundedFanOut } from "../utils/bounded-fan-out";
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
import {
  declareRefusesRemovedDevices,
  markSignalProtocolRelayDeviceRefusal,
} from "./signal-relay-device-refusal";
import { onePeriodClosedRetry } from "./signal-relay-period-close";
import {
  declareComparesDeviceSets,
  deviceSetRefusal,
  markDeviceSetRefusal,
  parseDeviceSetRefusal,
  type DeviceSetRefusal,
} from "../remote/signal-relay/device-set";
import {
  admitRepeatRequest,
  markAfterRepeatedRequest,
  type RepeatRequest,
} from "../remote/signal-relay/request-admission";
import {
  SignalProtocolRelayReceiptInbox,
  declareSignalProtocolRelayReceiptIntake,
  decodeSignalProtocolRelayDeliveryReceipts,
  type SignalProtocolRelayDeliveryReceipt,
} from "./signal-relay-receipt-intake";
import {
  SignalProtocolRelayReceiptJoin,
  declareSignalProtocolRelayReceiptJoin,
} from "./signal-relay-receipt-join";
import {
  hostedStoreRecordKey,
  readHostedStoreRecord,
  writeHostedStoreRecord,
  type HostedStoreRecordKey,
  type HostedStoreRecordPrefix,
} from "./hosted-store-records";

const SESSION_METADATA_PREFIX: HostedStoreRecordPrefix = {
  current: "signalRelay.session.v2:",
  earlier: "hostedRelay.session.v1:",
};
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

interface StoredHostedSignalProtocolRelaySession {
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
  /** Present only in the caller's own account listing. */
  lastSeenAt?: number | null;
}

/** The rotation inventory that one status read describes. */
function inventoryFromStatus(status: HostedPreKeyStatus): PreKeyInventory {
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

const hostedPreKeyPublicationLock = new AsyncLock({ maxPending: 100 });

interface HostedDeliveryWireEnvelope {
  ciphertext: string;
  contentHint?: number;
  messageType: Envelope["messageType"];
  timestamp: number;
  version: typeof DELIVERY_WIRE_VERSION;
}

export interface HostedSignalProtocolRelayTransportBootstrapRequest {
  readonly assertion: string;
  readonly assertionPurpose: "register" | "recover";
  readonly connection: HostedSignalProtocolRelayConnection;
  readonly deviceAuthentication: HostedSignalProtocolRelayDeviceAuthentication;
  readonly operationId: string;
  readonly registrationId: number;
  readonly registrationPreKeys: HostedSignalProtocolRelayRegistrationPreKeys;
  readonly signalIdentity: CompositeIdentityV1;
  readonly storage: SignalProtocolLocalStore;
}

export interface HostedSignalProtocolRelayTransportResult {
  readonly canonicalAccountId: string;
  readonly deviceId: number;
  /** @deprecated Use `relay`. SDK 15.0.0 removes this name. */
  readonly signalProtocolRelay: SignalProtocolRelayServer;
  readonly relay: SignalProtocolRelayServer;
  /** @deprecated Use `relayScopeId`. SDK 15.0.0 removes this name. */
  readonly signalProtocolRelayScopeId: Uint8Array;
  readonly relayScopeId: Uint8Array;
  readonly remoteObjectStore: SignalProtocolRemoteObjectStore;
  readonly transport: HostedSignalProtocolRelayHttpTransport;
}

/**
 * The Relay refusal codes that end a subscription when the Relay marks them
 * not retryable: a deleted account or device, a missing resource, and an
 * expired operation. The same request gets the same refusal again.
 */
const CONCLUSIVE_REFUSAL_CODES: ReadonlySet<string> = new Set([
  "AUTHORITY_DENIED",
  "NOT_FOUND",
  "OPERATION_EXPIRED",
]);

/**
 * Returns true for a Relay refusal that a retry gets again. A refusal that the
 * Relay marks `retryable`, for example a missing binding during a Relay
 * outage, is not conclusive.
 */
function isConclusiveRefusal(error: unknown): boolean {
  return (
    error instanceof HostedSignalProtocolRelayHttpError &&
    !error.retryable &&
    CONCLUSIVE_REFUSAL_CODES.has(error.code)
  );
}

/**
 * A durable delivery whose mailbox reset inside its acknowledgment hold
 * answers 503 `DELIVERY_UNCERTAIN`. The operation identifier makes a repeat
 * exact, so the transport sends the same request once more before it
 * surfaces the error. An ephemeral delivery is best-effort, so an uncertain
 * answer on that class is not repeated. When `beforeRepeat` rejects, no repeat
 * starts and the first `DELIVERY_UNCERTAIN` error is thrown.
 */
async function withOneUncertainRetry<T>(
  deliveryClass: DeliveryClass,
  post: () => Promise<T>,
  beforeRepeat?: () => Promise<void>,
): Promise<T> {
  try {
    return await post();
  } catch (error) {
    if (
      deliveryClass === "ephemeral" ||
      !(error instanceof HostedSignalProtocolRelayHttpError) ||
      error.code !== "DELIVERY_UNCERTAIN"
    ) {
      throw error;
    }
    try {
      await beforeRepeat?.();
    } catch {
      throw error;
    }
    return post();
  }
}

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The Relay takes at most this many ids in each HTTP acknowledgment list. */
const MAXIMUM_ACKNOWLEDGMENT_IDS = 100;

function strings(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((entry) => typeof entry === "string")
  );
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

function signalProtocolRelayScopeId(connection: HostedSignalProtocolRelayConnection): string {
  return bytesToUrlSafeBase64(connection.relayScopeId);
}

function identifiedEndpoint(connection: HostedSignalProtocolRelayConnection): string {
  return connection.protocolEndpoint.replace(/\/$/u, "");
}

/**
 * Read the body of a Relay answer. An error answer throws, and the error
 * records `signalRelayProtocolVersion`, the protocol version of the request that
 * it answers.
 */
async function parseResponse(
  response: Response,
  signalRelayProtocolVersion: number,
): Promise<unknown> {
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
    // `UPGRADE_REQUIRED` and `DEVICE_REVOKED` are terminal at any error
    // status, so `authenticatedPost` and every other retry, which matches only
    // a `HostedSignalProtocolRelayHttpError`, never repeat them. `PROTOCOL_UNSUPPORTED`
    // stays a `HostedSignalProtocolRelayHttpError` whose `retryable` is true: the Relay
    // sends it for a version above the newest one that it serves, which
    // happens only after a Relay rollback.
    throwIfUpgradeRequired(response.status, parsed, signalRelayProtocolVersion);
    throwIfDeviceRevoked(response.status, parsed);
    const error = record(parsed) && record(parsed.error) ? parsed.error : {};
    const code = typeof error.code === "string" ? error.code : "UNKNOWN";
    const message =
      typeof error.message === "string"
        ? error.message
        : "Signal Protocol Relay request failed";
    // A refused declared post names the devices of each account in
    // `details`. The error keeps them for the device-set reconciliation.
    throw markSignalProtocolRelayAnswerVersion(
      new HostedSignalProtocolRelayHttpError(response.status, code, message, {
        ...(record(error.details) ? { data: { details: error.details } } : {}),
        retryable: error.retryable === true,
      }),
      signalRelayProtocolVersion,
    );
  }
  return parsed;
}

/**
 * The device directory does not list the destination, so no mailbox
 * generation names it. The Relay refuses such a device as NOT_FOUND.
 */
function missingDestination(userId: string, deviceId: number): Error {
  return markSignalProtocolRelayDeviceRefusal(
    new Error("Signal Protocol Relay destination device does not exist"),
    { code: "NOT_FOUND", userId, deviceId },
  );
}

async function postJson(
  connection: HostedSignalProtocolRelayConnection,
  signalRelayProtocolVersion: number,
  path: string,
  body: JsonRecord,
  token?: string,
): Promise<unknown> {
  const headers = new Headers({
    accept: "application/json",
    "content-type": "application/json",
    ...signalRelayProtocolHeadersFor(signalRelayProtocolVersion),
  });
  if (token !== undefined) headers.set("authorization", `Bearer ${token}`);
  return withSignalProtocolRelayRequestDeadline(async (signal) => {
    let response: Response;
    try {
      response = await fetch(`${identifiedEndpoint(connection)}${path}`, {
        body: JSON.stringify(body),
        headers,
        method: "POST",
        credentials: "omit",
        redirect: "error",
        signal,
      });
    } catch (cause) {
      throw new Error("Signal Protocol Relay request could not be completed", { cause });
    }
    return parseResponse(response, signalRelayProtocolVersion);
  });
}

function serializedPreKey(prekey: HostedSignalProtocolRelayRegistrationPreKey): JsonRecord {
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
  prekeys: HostedSignalProtocolRelayRegistrationPreKeys,
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
  prekeys: HostedSignalProtocolRelayRegistrationPreKeys,
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
  request: HostedSignalProtocolRelayTransportBootstrapRequest,
): Promise<Uint8Array> {
  return sha256(
    concatBytes(
      request.assertionPurpose === "recover"
        ? RECOVERY_CHALLENGE_LABEL
        : REGISTRATION_CHALLENGE_LABEL,
      text(signalProtocolRelayScopeId(request.connection)),
      text(
        await hostedAssertionIdentifier(
          request.assertion,
          request.assertionPurpose,
          request.operationId,
        ),
      ),
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
  connection: HostedSignalProtocolRelayConnection,
): Promise<HostedStoreRecordKey> {
  return hostedStoreRecordKey(
    SESSION_METADATA_PREFIX,
    bytesToUrlSafeBase64(
      await sha256(
        concatBytes(
          stringToBytes(connection.publishableKey),
          new Uint8Array([0]),
          connection.relayScopeId,
        ),
      ),
    ),
  );
}

function parseSession(
  value: string,
  connection: HostedSignalProtocolRelayConnection,
): StoredHostedSignalProtocolRelaySession {
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
    parsed.relayScopeId !== signalProtocolRelayScopeId(connection)
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

/**
 * The scope claim of a device token. Protocol version 3 names the claim
 * `signal_relay_scope_id`, and protocol versions 1 and 2 name it
 * `relay_scope_id`. A token that carries both claims with different values
 * has no scope.
 */
function deviceTokenScopeId(claims: JsonRecord): unknown {
  const scope = claims.signal_relay_scope_id;
  const earlierScope = claims.relay_scope_id;
  if (scope === undefined) return earlierScope;
  return earlierScope === undefined || earlierScope === scope ? scope : undefined;
}

function tokenExpiration(
  token: string,
  session: StoredHostedSignalProtocolRelaySession,
): number {
  const parts = token.split(".");
  if (parts.length !== 3) return 0;
  try {
    const claims: unknown = JSON.parse(
      utf8Decode(decodeBase64Url(parts[1]!, "Device token")),
    );
    if (
      !record(claims) ||
      claims.account_id !== session.canonicalAccountId ||
      claims.device_id !== session.deviceId ||
      claims.generation !== session.generation ||
      claims.mailbox_generation !== session.mailboxGeneration ||
      deviceTokenScopeId(claims) !== session.relayScopeId ||
      !Number.isSafeInteger(claims.exp)
    ) {
      return 0;
    }
    return claims.exp as number;
  } catch {
    return 0;
  }
}

/**
 * The issuer and audience pairs of a device token. Protocol versions 1 and 2
 * issue the first pair, and protocol version 3 issues the second. The SDK
 * accepts each pair until the Relay retires versions 1 and 2.
 */
const SIGNAL_RELAY_DEVICE_TOKEN_ISSUERS = [
  { issuer: 'open-e2ee-relay', audience: 'open-e2ee-relay-device' },
  { issuer: 'signal-relay', audience: 'signal-relay-device' },
] as const;

function isSignalRelayDeviceTokenIssuer(issuer: unknown, audience: unknown): boolean {
  return SIGNAL_RELAY_DEVICE_TOKEN_ISSUERS.some(
    (pair) => pair.issuer === issuer && pair.audience === audience,
  );
}

function assertLinkToken(session: StoredHostedSignalProtocolRelaySession): void {
  const parts = session.deviceToken.split('.');
  if (parts.length !== 3) throw new Error('Signal Protocol Relay returned an invalid link token');
  const header: unknown = JSON.parse(utf8Decode(decodeBase64Url(parts[0]!, 'Device token header')));
  const claims: unknown = JSON.parse(utf8Decode(decodeBase64Url(parts[1]!, 'Device token claims')));
  if (!record(header) || Object.keys(header).sort().join(',') !== 'alg,kid,typ' ||
      header.alg !== 'EdDSA' || header.typ !== 'JWT' || typeof header.kid !== 'string' || !header.kid ||
      decodeBase64Url(parts[2]!, 'Device token signature').length !== 64 ||
      !record(claims) || typeof claims.jti !== 'string' || !claims.jti ||
      !isSignalRelayDeviceTokenIssuer(claims.iss, claims.aud) || claims.token_use !== 'device' ||
      typeof claims.account_state_id !== 'string' || !claims.account_state_id ||
      !Number.isSafeInteger(claims.iat) || (claims.iat as number) < 0 ||
      tokenExpiration(session.deviceToken, session) <= (claims.iat as number))
    throw new Error('Signal Protocol Relay returned an invalid link token');
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
    wire = JSON.parse(utf8Decode(value));
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
  // Only the fields that the sender encodes leave the wire. The Relay
  // message, not the wire, gives the envelope ID.
  return {
    ciphertext: wire.ciphertext,
    ...(wire.contentHint === undefined
      ? {}
      : { contentHint: wire.contentHint as number }),
    messageType: wire.messageType as Envelope["messageType"],
    timestamp: wire.timestamp as number,
    version: DELIVERY_WIRE_VERSION,
  };
}

export class HostedSignalProtocolRelayHttpTransport
  implements
    SignalProtocolRelayServer,
    HostedSignalProtocolRelayPushRuntime,
    HostedSignalProtocolRelayPresenceRuntime
{
  private readonly groups: HostedGroupServer;
  public readonly groupServer: SignalProtocolRelayGroupServer;
  private readonly anonymousDelivery: HostedAnonymousDelivery;
  // The relay request bound of the client that uses this transport
  private readonly fanOut: BoundedFanOut;
  private refreshPromise?: Promise<void>;
  private readonly destinationGenerations = new Map<string, number>();
  private readonly destinationLookups = new Map<string, Promise<unknown>>();
  private readonly ephemeralAcknowledgments = new Set<string>();
  private subscription?: MailboxSubscriptionHandle;
  private subscriptionGeneration = 0;
  private readonly connectionState = new SignalProtocolRelayConnectionStateOwner();
  private readonly presenceListeners = new Set<
    (event: PresenceSocketEvent) => void
  >();
  private readonly receiptInbox = new SignalProtocolRelayReceiptInbox();
  private readonly receiptJoin = new SignalProtocolRelayReceiptJoin();

  public constructor(
    private readonly connection: HostedSignalProtocolRelayConnection,
    private readonly storage: SignalProtocolLocalStore,
    private readonly deviceAuthentication: HostedSignalProtocolRelayDeviceAuthentication,
    private session: StoredHostedSignalProtocolRelaySession,
    private readonly persistRefreshedToken = true,
    /**
     * @internal The Relay protocol version of the client that owns this
     * transport. Every carrier of the client sends it.
     */
    public readonly signalRelayProtocolVersion: number = RELAY_PROTOCOL_VERSION,
  ) {
    // The Relay refuses a removed device's mailbox on every send path before
    // its device list shows the removal, so a direct send may post first.
    declareRefusesRemovedDevices(this);
    // The Relay compares a declared device set on every send route, and
    // answers a difference with DEVICE_SET_MISMATCH or a declared
    // STALE_DEVICE.
    declareComparesDeviceSets(this);
    // The Relay sends Relay delivery receipts to the sender, and replies to
    // each acknowledgment with the messages whose receipt it owns.
    declareSignalProtocolRelayReceiptIntake(this, this.receiptInbox);
    declareSignalProtocolRelayReceiptJoin(this, this.receiptJoin);
    this.groups = new HostedGroupServer(connection, signalRelayProtocolVersion);
    this.groupServer = {
      server: this.groups,
      issueAuthCredential: (userId, authorityKeyId) => this.issueAuthCredential(userId, authorityKeyId),
      issueProfileKeyCredential: (userId, request, authorityKeyId) => this.issueProfileKeyCredential(userId, request, authorityKeyId),
      setUnidentifiedAccessKey: (userId, accessKey) => this.setUnidentifiedAccessKey(userId, accessKey),
    };
    this.fanOut = createAdapterSignalProtocolRelayFanOut(this);
    this.anonymousDelivery = new HostedAnonymousDelivery(
      connection,
      this.fanOut,
      async (accountAddress, deviceId, declaredDeviceIds) => {
        const key = `${accountAddress}\0${deviceId}`;
        if (!this.destinationGenerations.has(key))
          await this.lookUpDestinations(accountAddress);
        const generation = this.destinationGenerations.get(key);
        // A declared post gets the refusal that the Relay would give, so
        // the send removes the device and posts again.
        if (generation === undefined && declaredDeviceIds !== undefined)
          throw markDeviceSetRefusal(
            new HostedAnonymousDeliveryError(409, "DEVICE_SET_MISMATCH"),
            this.directoryDeviceSetRefusal(accountAddress, declaredDeviceIds),
          );
        if (generation === undefined)
          throw missingDestination(accountAddress, deviceId);
        return { accountAddress, deviceId, generation };
      },
      (clientMessageId, request) =>
        admitRepeatRequest(this, clientMessageId, request),
      signalRelayProtocolVersion,
      ({ accountAddress, deviceId, generation }) =>
        this.destinationRecovered(accountAddress, deviceId, generation, true),
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
          error instanceof HostedSignalProtocolRelayHttpError &&
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
    if (!(error instanceof HostedSignalProtocolRelayHttpError)) return error;
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
    await writeHostedStoreRecord(
      this.storage,
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
    const nonce = await generateRandomBytes(32);
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
    let value: unknown;
    try {
      value = await postJson(this.connection, this.signalRelayProtocolVersion, "/identity/token", {
        accountAddress: this.session.canonicalAccountId,
        // The Relay checks this key against the keys that a recovery revoked.
        deviceAuthenticationPublicKey: bytesToBase64(
          this.deviceAuthentication.publicKey,
        ),
        deviceId: this.session.deviceId,
        deviceProof: bytesToBase64(proof),
        nonce: bytesToUrlSafeBase64(nonce),
        publishableKey: this.connection.publishableKey,
        requestedAtSeconds,
      });
    } catch (error) {
      // A token refusal names this device, so it is not a
      // `HostedSignalProtocolRelayHttpError`. A catch that reads `NOT_FOUND` as a missing
      // destination cannot take it.
      if (error instanceof HostedSignalProtocolRelayHttpError && error.code === "NOT_FOUND")
        throw new HostedSignalProtocolRelayDeviceUnknownError(error.status, error.message);
      throw error;
    }
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
    if (this.persistRefreshedToken) await this.persistSession();
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

  /** Private-package link capability. Detached active authority never persists. */
  public async linkDevice(
    request: HostedSignalProtocolRelayManagedDeviceLinkRequest,
    storage: SignalProtocolLocalStore,
  ): Promise<HostedSignalProtocolRelayTransportResult & HostedSignalProtocolRelayManagedDeviceLinkResult> {
    const materialFingerprint = await registrationMaterialFingerprint(
      request.signalIdentity, request.registrationId, request.registrationPreKeys,
    );
    const bodyFor = async (body: (tokenId: string) => Promise<JsonRecord>, token: string) => {
      const claims: unknown = JSON.parse(utf8Decode(decodeBase64Url(token.split('.')[1]!, 'Device token')));
      if (!record(claims) || typeof claims.jti !== 'string' || !claims.jti)
        throw new Error('Signal Protocol Relay returned an invalid device token');
      return body(claims.jti);
    };
    const value = await submitHostedSignalProtocolRelayDeviceLink(request, {
      relayScopeId: this.session.relayScopeId,
      materialFingerprint,
      signalRegistration: signalRegistration(request.signalIdentity, request.registrationId, request.registrationPreKeys),
      post: async (body) => {
        let token = await this.token();
        try {
          return await postJson(this.connection, this.signalRelayProtocolVersion, '/identity/devices/link', await bodyFor(body, token), token);
        } catch (error) {
          if (!(error instanceof HostedSignalProtocolRelayHttpError) || error.code !== 'TOKEN_INVALID') throw error;
          token = await this.token(true);
          return postJson(this.connection, this.signalRelayProtocolVersion, '/identity/devices/link', await bodyFor(body, token), token);
        }
      },
    });
    if (!record(value) || value.accountPreserved !== true || value.protocolStateCopied !== false)
      throw new Error('Signal Protocol Relay returned an invalid managed device link');
    const generation = requiredNumber(value, 'deviceAuthorizationGeneration');
    let session: StoredHostedSignalProtocolRelaySession = {
      canonicalAccountId: requiredString(value, 'canonicalAccountId'),
      deviceId: requiredNumber(value, 'deviceId'),
      deviceToken: requiredString(value, 'deviceToken'),
      generation,
      mailboxGeneration: requiredNumber(value, 'mailboxGeneration'),
      pendingPreKeyPublication: null,
      preKeyPublication: storedPublication(generation, materialFingerprint, request.operationId, 0, request.registrationPreKeys),
      relayScopeId: requiredString(value, 'relayScopeId'),
    };
    if (session.canonicalAccountId !== this.session.canonicalAccountId ||
        session.relayScopeId !== this.session.relayScopeId || session.deviceId < 1 ||
        session.deviceId === this.session.deviceId || generation < 0 || session.mailboxGeneration < 0 ||
        tokenExpiration(session.deviceToken, session) <= 0)
      throw new Error('Signal Protocol Relay returned an invalid managed device link');
    assertLinkToken(session);
    const key = await sessionMetadataKey(this.connection);
    const stored = await readHostedStoreRecord(storage, key);
    if (stored !== null) {
      const existing = parseSession(stored, this.connection);
      assertLinkToken(existing);
      if (existing.canonicalAccountId !== session.canonicalAccountId || existing.deviceId !== session.deviceId ||
          existing.generation !== generation || existing.mailboxGeneration !== session.mailboxGeneration ||
          tokenExpiration(existing.deviceToken, existing) <= 0 ||
          existing.preKeyPublication.authorityGeneration !== generation ||
          (existing.preKeyPublication.revision === 0 &&
            (existing.preKeyPublication.operationId !== request.operationId ||
             existing.preKeyPublication.materialFingerprint !== materialFingerprint)))
        throw new Error('Stored Signal Protocol Relay link session conflicts with the retained attempt');
      session = existing;
    }
    const transport = new HostedSignalProtocolRelayHttpTransport(this.connection, storage, request.newDeviceAuthentication, session, true, this.signalRelayProtocolVersion);
    // Persist the complete shape before synchronization or token renewal can fail.
    try {
      await writeHostedStoreRecord(storage, key, JSON.stringify(session));
      await transport.ensureAuthenticated();
    } catch (error) {
      // A renewal refusal cannot prove that the accepted link had no effect.
      if (error instanceof HostedSignalProtocolRelayHttpError && !error.retryable &&
          (error.code === 'KEY_PROOF_INVALID' || error.code === 'CONFLICT'))
        throw new Error('Signal Protocol Relay accepted the link but session adoption failed', { cause: error });
      throw error;
    }
    const scopeId = this.connection.relayScopeId.slice();
    return {
      canonicalAccountId: session.canonicalAccountId, deviceId: session.deviceId,
      signalProtocolRelayScopeId: scopeId, relayScopeId: scopeId,
      signalProtocolRelay: transport, relay: transport,
      remoteObjectStore: transport.objectStore, transport,
      accountPreserved: true, protocolStateCopied: false,
    };
  }

  /**
   * Post with the device token. On TOKEN_INVALID, get a new token and post
   * once more. When `beforeRepeat` rejects, no repeat starts and the
   * TOKEN_INVALID error is thrown.
   */
  private async authenticatedPost(
    path: string,
    body: JsonRecord,
    beforeRepeat?: () => Promise<void>,
  ): Promise<unknown> {
    let token = await this.token();
    try {
      return await postJson(this.connection, this.signalRelayProtocolVersion, path, body, token);
    } catch (error) {
      if (
        !(error instanceof HostedSignalProtocolRelayHttpError) ||
        error.code !== "TOKEN_INVALID"
      ) {
        throw error;
      }
      token = await this.token(true);
      try {
        await beforeRepeat?.();
      } catch {
        throw error;
      }
      return postJson(this.connection, this.signalRelayProtocolVersion, path, body, token);
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

  /**
   * One directory lookup for each account at a time. A destination whose
   * account a lookup already reads waits for that lookup.
   */
  private lookUpDestinations(accountAddress: string): Promise<unknown> {
    let lookup = this.destinationLookups.get(accountAddress);
    if (lookup === undefined) {
      lookup = this.fanOut
        .request(() => this.directory(accountAddress))
        .finally(() => this.destinationLookups.delete(accountAddress));
      this.destinationLookups.set(accountAddress, lookup);
    }
    return lookup;
  }

  /**
   * The Relay refused a post to this mailbox generation as NOT_FOUND. True
   * when a new read of the device directory lists the device at another
   * mailbox generation: a recovery replaced the device, so the refusal is
   * the stale-device refusal of the posted generation. False when the read
   * fails, or the directory does not list the device, or lists it at the
   * posted generation. The read refills the destination cache, so a repost
   * goes to the listed generation. An identified post runs in a slot of the
   * relay request bound, so it reads without a slot. A sealed post holds no
   * slot, so it reads under the bound.
   */
  private async destinationRecovered(
    userId: string,
    deviceId: number,
    postedGeneration: number,
    underBound: boolean,
  ): Promise<boolean> {
    try {
      await (underBound
        ? this.fanOut.request(() => this.directory(userId))
        : this.directory(userId));
    } catch (error) {
      rethrowSignalProtocolRelayWorkStopped(error);
      return false;
    }
    const listed = this.destinationGenerations.get(
      `${userId}\0${String(deviceId)}`,
    );
    return listed !== undefined && listed !== postedGeneration;
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
    for (const key of this.destinationGenerations.keys()) {
      if (key.startsWith(`${userId}\0`)) this.destinationGenerations.delete(key);
    }
    return value.devices.map((candidate) => {
      if (!record(candidate))
        throw new Error("Signal Protocol Relay returned an invalid device directory");
      const device: HostedDeviceDirectoryEntry = {
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
      if ("lastSeenAt" in candidate) {
        const lastSeenAt = candidate.lastSeenAt;
        if (lastSeenAt !== null && !Number.isSafeInteger(lastSeenAt)) {
          throw new Error("Signal Protocol Relay returned an invalid device directory");
        }
        device.lastSeenAt = lastSeenAt as number | null;
      }
      this.destinationGenerations.set(
        `${userId}\0${String(device.deviceId)}`,
        device.mailboxGeneration,
      );
      return device;
    });
  }

  /**
   * A prekey read addressed by the destination mailbox generation, because
   * the Relay names each device's prekey object by that generation. The own
   * device reads the session. Another device reads the directory cache and
   * fills it on a miss. A recovery moves a device to a new generation, so a
   * cached generation that the Relay no longer serves is read again from the
   * directory once.
   */
  private async prekeyPost(
    path: "/prekeys/consume" | "/prekeys/status",
    userId: string,
    deviceId: number,
    identityType: IdentityType,
  ): Promise<unknown> {
    const own =
      userId === this.session.canonicalAccountId &&
      deviceId === this.session.deviceId;
    const key = `${userId}\0${String(deviceId)}`;
    const cached = !own && this.destinationGenerations.has(key);
    const post = async (): Promise<unknown> => {
      if (!own && !this.destinationGenerations.has(key))
        await this.directory(userId);
      const generation = own
        ? this.session.mailboxGeneration
        : this.destinationGenerations.get(key);
      if (generation === undefined) {
        throw new HostedSignalProtocolRelayHttpError(
          404,
          "NOT_FOUND",
          "Signal Protocol Relay destination device does not exist",
        );
      }
      return this.authenticatedPost(path, {
        accountAddress: userId,
        deviceId,
        identityType,
        mailboxGeneration: generation,
        publishableKey: this.connection.publishableKey,
      });
    };
    try {
      return await post();
    } catch (error) {
      if (
        !cached ||
        !(error instanceof HostedSignalProtocolRelayHttpError) ||
        error.code !== "NOT_FOUND"
      ) {
        throw error;
      }
      this.destinationGenerations.delete(key);
      return post();
    }
  }

  private async prekeyStatus(
    userId: string,
    deviceId: number,
    identityType: IdentityType = "aci",
  ): Promise<HostedPreKeyStatus> {
    if (identityType !== "aci") unsupported("PNI prekey authority");
    return parseHostedPreKeyStatus(
      await this.prekeyPost("/prekeys/status", userId, deviceId, identityType),
    );
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

  /**
   * One publication under the account's publication fence. The plan sees the
   * inventory from the status read that opens the fence, so its decision and
   * the publication share one observation. An empty plan with no pending
   * publication returns after that one read.
   */
  private async publishCurrentPrekeys(
    plan: PreKeyPublicationPlan,
  ): Promise<void> {
    await hostedPreKeyPublicationLock.acquire(
      (await sessionMetadataKey(this.connection)).current,
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

        const uploads = await plan(inventoryFromStatus(status));
        if (uploads.length === 0 && retryPending === undefined) return;
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

  /**
   * One mailbox page. Its `relayReceipts` holds for this pull only: a page
   * carries `receipts` only when it is true. With `cursor`, the page starts
   * after the last message of the page that issued it. The cursor is opaque.
   * A page without `retainedWork` comes from a Relay that does not report
   * it, so the retained work after the page is unknown. A page without
   * `failedEntries` comes from a Relay that does not report the messages that
   * it could not serve.
   */
  private async pullIncoming(cursor?: string): Promise<HostedMailboxPage> {
    const value = await this.authenticatedPost("/mailbox/pull", {
      publishableKey: this.connection.publishableKey,
      ...(cursor === undefined ? {} : { cursor }),
    });
    if (
      !record(value) ||
      !Array.isArray(value.messages) ||
      (value.relayReceipts !== undefined &&
        typeof value.relayReceipts !== "boolean") ||
      (value.receipts !== undefined && value.relayReceipts !== true) ||
      (value.nextCursor !== undefined &&
        (typeof value.nextCursor !== "string" || value.nextCursor === "")) ||
      (value.retainedWork !== undefined &&
        typeof value.retainedWork !== "boolean") ||
      (value.failedEntries !== undefined &&
        (!Array.isArray(value.failedEntries) ||
          !value.failedEntries.every(
            (entry) =>
              record(entry) &&
              typeof entry.messageId === "string" &&
              entry.messageId !== "" &&
              typeof entry.reason === "string",
          )))
    ) {
      throw new Error("Signal Protocol Relay returned an invalid mailbox page");
    }
    return {
      messages: value.messages.map((candidate) =>
        this.incomingEnvelope(candidate),
      ),
      receipts:
        value.receipts === undefined
          ? []
          : decodeSignalProtocolRelayDeliveryReceipts(value.receipts),
      ...(value.nextCursor === undefined
        ? {}
        : { nextCursor: value.nextCursor }),
      ...(value.retainedWork === undefined
        ? {}
        : { retainedWork: value.retainedWork }),
      ...(value.failedEntries === undefined
        ? {}
        : {
            failedEntries: (value.failedEntries as Record<string, unknown>[]).map(
              ({ messageId, reason }) => ({
                messageId: messageId as string,
                reason: reason as string,
              }),
            ),
          }),
    };
  }

  /** One retained mailbox message, from a pull page or a `durable-message` frame. */
  private incomingEnvelope(candidate: unknown): IncomingEnvelope {
    if (!record(candidate) || !record(candidate.sender)) {
      throw new Error("Signal Protocol Relay returned an invalid mailbox message");
    }
    const decoded = this.decodeMailboxEnvelope(candidate);
    const messageId = requiredString(candidate, "messageId");
    // The Relay message ID is the client message ID of the sender, and it
    // is the ID of the envelope. The decoded wire never sets either.
    return {
      ...decoded,
      id: messageId,
      clientMessageId: messageId,
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
        utf8Decode(
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
      const nonce = bytesToUrlSafeBase64(await generateRandomBytes(32));
      const proof = await this.deviceAuthentication.signCertificateRequest(
        claims.jti,
        nonce,
      );
      if (proof.byteLength !== 64)
        throw new Error("Signal Protocol Relay certificate proof is invalid");
      try {
        const result = await postJson(
          this.connection,
          this.signalRelayProtocolVersion,
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
          !(error instanceof HostedSignalProtocolRelayHttpError) ||
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
    operationEpochMilliseconds?: number,
    contentKind?: ContentKind,
    deviceSets?: readonly { userId: string; deviceIds: readonly number[] }[],
  ) {
    try {
      return await this.anonymousDelivery.send(
        sentMessageBase64,
        auth,
        timestamp,
        deliveryClass,
        recipientUserIds,
        clientMessageId,
        operationEpochMilliseconds,
        contentKind,
        deviceSets,
      );
    } catch (error) {
      // A refused declared post can name a re-registered device, so the
      // next post reads each named account's mailbox generations again.
      const refusal = deviceSetRefusal(error);
      if (refusal !== undefined)
        this.forgetDestinationGenerations(refusal.accounts);
      throw error;
    }
  }

  /** Drops the cached mailbox generations of each named account. */
  private forgetDestinationGenerations(
    accounts: readonly { readonly userId: string }[],
  ): void {
    for (const { userId } of accounts) {
      for (const key of this.destinationGenerations.keys()) {
        if (key.startsWith(`${userId}\0`)) this.destinationGenerations.delete(key);
      }
    }
  }

  /**
   * The refusal that the Relay would give a declared post whose device the
   * directory does not list: the declared set differs from the directory.
   * The directory read just before it filled the cache for the account.
   */
  private directoryDeviceSetRefusal(
    userId: string,
    declaredDeviceIds: readonly number[],
  ): DeviceSetRefusal {
    const listed = new Set<number>();
    for (const key of this.destinationGenerations.keys()) {
      if (!key.startsWith(`${userId}\0`)) continue;
      const deviceId = Number(key.slice(userId.length + 1));
      if (
        userId === this.session.canonicalAccountId &&
        deviceId === this.session.deviceId
      )
        continue;
      listed.add(deviceId);
    }
    const declared = new Set(declaredDeviceIds);
    return {
      kind: "mismatch",
      accounts: [
        {
          userId,
          missingDeviceIds: [...listed]
            .filter((id) => !declared.has(id))
            .sort((a, b) => a - b),
          extraDeviceIds: [...declared]
            .filter((id) => !listed.has(id))
            .sort((a, b) => a - b),
        },
      ],
    };
  }

  /**
   * Acknowledges messages and Relay receipts over HTTP. The response lists,
   * in `receipted`, each message whose delivery receipt the Relay owns.
   */
  private async acknowledge(
    messageIds: readonly string[],
    receiptIds: readonly string[] = [],
  ): Promise<MailboxAcknowledgment> {
    const value = await this.authenticatedPost("/mailbox/acknowledge", {
      messageIds: [...messageIds],
      ...(receiptIds.length === 0 ? {} : { receiptIds: [...receiptIds] }),
      publishableKey: this.connection.publishableKey,
    });
    if (
      !record(value) ||
      requiredNumber(value, "acknowledged") < 0 ||
      (value.receipted !== undefined && !strings(value.receipted)) ||
      (value.receiptsAcknowledged !== undefined &&
        (!Number.isSafeInteger(value.receiptsAcknowledged) ||
          (value.receiptsAcknowledged as number) < 0))
    ) {
      throw new Error("Signal Protocol Relay returned an invalid acknowledgment");
    }
    return {
      receipted: (value.receipted as string[] | undefined) ?? [],
      acknowledged: value.acknowledged as number,
      receiptsAcknowledged: (value.receiptsAcknowledged as number | undefined) ?? 0,
    };
  }

  /**
   * Acknowledges over HTTP, and gives each message the reply: the response,
   * or a failed acknowledgment when the request fails.
   */
  private async acknowledgeAndAnswer(
    messageIds: readonly string[],
    receiptIds: readonly string[] = [],
  ): Promise<void> {
    let receipted: readonly string[];
    try {
      ({ receipted } = await this.acknowledge(messageIds, receiptIds));
    } catch (error) {
      for (const messageId of messageIds)
        this.receiptJoin.settle(messageId, false);
      throw error;
    }
    for (const messageId of messageIds)
      this.receiptJoin.settle(messageId, receipted.includes(messageId));
  }

  public async registerPush(
    registration: HostedSignalProtocolRelayPushRegistration,
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

  public get presenceScope(): string {
    return this.session.relayScopeId;
  }

  public get presenceStore(): Pick<
    SignalProtocolLocalStore,
    "getMetadata" | "setMetadata"
  > {
    return this.storage;
  }

  /** The live mailbox socket, or `undefined` while no subscription runs. */
  public get presenceSocket(): MailboxSubscriptionHandle | undefined {
    return this.subscription;
  }

  /** Receives the presence events of the newest subscription's socket. */
  public subscribePresenceSocket(
    listener: (event: PresenceSocketEvent) => void,
  ): Unsubscribe {
    this.presenceListeners.add(listener);
    return () => {
      this.presenceListeners.delete(listener);
    };
  }

  /** Posts one presence request, for a wake client with no socket. */
  public postPresence(request: HostedSignalProtocolRelayPresenceRequest): Promise<unknown> {
    return this.authenticatedPost(
      "/presence",
      presenceHttpBody(this.connection.publishableKey, request),
    );
  }

  public async pullMailbox(cursor?: string): Promise<HostedMailboxPage> {
    return this.pullIncoming(cursor);
  }

  /**
   * Acknowledges one pull page. The Relay takes at most 100 ids in each list,
   * so receipt ids past the first 100 leave in further requests.
   */
  public async acknowledgeMailbox(
    messageIds: readonly string[],
    receiptIds: readonly string[],
  ): Promise<void> {
    await this.acknowledgeAndAnswer(
      messageIds,
      receiptIds.slice(0, MAXIMUM_ACKNOWLEDGMENT_IDS),
    );
    for (
      let start = MAXIMUM_ACKNOWLEDGMENT_IDS;
      start < receiptIds.length;
      start += MAXIMUM_ACKNOWLEDGMENT_IDS
    )
      await this.acknowledge(
        [],
        receiptIds.slice(start, start + MAXIMUM_ACKNOWLEDGMENT_IDS),
      );
  }

  public receiveSignalProtocolRelayReceipt(receipt: SignalProtocolRelayDeliveryReceipt): Promise<void> {
    return this.receiptInbox.handOff(receipt);
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
        ...signalRelayProtocolHeadersFor(this.signalRelayProtocolVersion),
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
    if (generation === undefined && envelope.declaredDeviceIds !== undefined) {
      throw markDeviceSetRefusal(
        new HostedSignalProtocolRelayHttpError(
          409,
          "DEVICE_SET_MISMATCH",
          "The declared device set differs from the device directory",
        ),
        this.directoryDeviceSetRefusal(
          envelope.targetUserId,
          envelope.declaredDeviceIds,
        ),
      );
    }
    if (generation === undefined)
      throw missingDestination(envelope.targetUserId, envelope.targetDeviceId);
    const deviceSets =
      envelope.declaredDeviceIds === undefined
        ? undefined
        : [
            {
              accountAddress: envelope.targetUserId,
              deviceIds: [...envelope.declaredDeviceIds],
            },
          ];
    let value: unknown;
    let uncertainRepeat = false;
    // Each repeat request meets the checks that the owner of the post
    // registered under its message ID, and names its device and the answer
    // that it follows.
    const beforeRepeat = (after: RepeatRequest["after"]) => () =>
      admitRepeatRequest(this, messageId, {
        userId: envelope.targetUserId,
        deviceId: envelope.targetDeviceId,
        after,
      });
    const repeatAfterUncertain = async (): Promise<void> => {
      await beforeRepeat("uncertain")();
      uncertainRepeat = true;
    };
    // A PERIOD_CLOSED answer proves that the Relay stored nothing, so the
    // same request goes once more, in the next period.
    const periodClosedRetry = onePeriodClosedRetry();
    try {
      value = await withOneUncertainRetry(envelope.deliveryClass, () =>
        periodClosedRetry(() => this.authenticatedPost("/delivery/send", {
          contentKind: envelope.contentKind ?? "message",
          deliveryClass: envelope.deliveryClass,
          destination: {
            accountAddress: envelope.targetUserId,
            deviceId: envelope.targetDeviceId,
            generation,
          },
          envelope: bytesToBase64(encodeDeliveryWire(envelope)),
          messageId,
          operationEpochMilliseconds:
            envelope.operationEpochMilliseconds ?? envelope.timestamp,
          publishableKey: this.connection.publishableKey,
          ...(envelope.recipientRegistrationId === undefined
            ? {}
            : { recipientRegistrationId: envelope.recipientRegistrationId }),
          ...(deviceSets === undefined ? {} : { deviceSets }),
        }, beforeRepeat("token")), beforeRepeat("period-closed")),
      repeatAfterUncertain);
    } catch (error) {
      // After an uncertain answer, the first request can have stored the
      // copy, so the answer to the repeat tells nothing about the post.
      const answer = <T>(failure: T): T =>
        uncertainRepeat ? markAfterRepeatedRequest(failure) : failure;
      const device = {
        userId: envelope.targetUserId,
        deviceId: envelope.targetDeviceId,
      };
      if (deviceSets !== undefined && error instanceof HostedSignalProtocolRelayHttpError) {
        const refusal = parseDeviceSetRefusal(error.code, error.data?.details);
        if (refusal !== undefined) {
          this.forgetDestinationGenerations(refusal.accounts);
          throw answer(markDeviceSetRefusal(error, refusal));
        }
      }
      const staleDevice = (stale: HostedSignalProtocolRelayHttpError) =>
        answer(
          markSignalProtocolRelayDeviceRefusal(
            new HostedSignalProtocolRelayHttpError(stale.status, "STALE_DEVICE", stale.message, {
              data: {
                code: "STALE_DEVICE",
                message: stale.message,
                reason: "device_reinstalled",
                staleDevices: [envelope.targetDeviceId],
              },
              retryable: stale.retryable,
            }),
            { code: "STALE_DEVICE", ...device },
          ),
        );
      if (
        error instanceof HostedSignalProtocolRelayHttpError &&
        error.code === "STALE_DEVICE"
      ) {
        throw staleDevice(error);
      }
      // Only the Relay's own error body names NOT_FOUND. A 404 without it
      // fails to parse or carries no code, so it is not a device refusal.
      if (error instanceof HostedSignalProtocolRelayHttpError && error.code === "NOT_FOUND") {
        // A recovery retired the posted generation. As for a stale device,
        // the send archives the session and posts to the recovered device.
        // A declared post gets the declared STALE_DEVICE that the Relay
        // gives for a changed registration.
        if (
          await this.destinationRecovered(
            envelope.targetUserId,
            envelope.targetDeviceId,
            generation,
            false,
          )
        ) {
          const stale = staleDevice(error);
          throw deviceSets === undefined
            ? stale
            : markDeviceSetRefusal(stale, {
                kind: "stale",
                accounts: [
                  {
                    userId: envelope.targetUserId,
                    staleDeviceIds: [envelope.targetDeviceId],
                  },
                ],
              });
        }
        throw answer(
          markSignalProtocolRelayDeviceRefusal(error, { code: "NOT_FOUND", ...device }),
        );
      }
      throw answer(error);
    }
    if (
      !record(value) ||
      requiredString(value, "messageId") !== messageId ||
      (value.duplicate !== undefined && typeof value.duplicate !== "boolean") ||
      (value.expiresAt !== undefined &&
        (!Number.isSafeInteger(value.expiresAt) ||
          (value.expiresAt as number) <= 0)) ||
      (value.deviceSetChecked !== undefined &&
        value.deviceSetChecked !== true) ||
      (value.needsSync !== undefined && typeof value.needsSync !== "boolean")
    ) {
      throw new Error("Signal Protocol Relay returned an invalid delivery receipt");
    }
    // An ephemeral receipt carries neither field, so each one is optional.
    // After an uncertain answer, the first request can have stored the copy
    // that the repeat finds, so the repeat's duplicate tells nothing.
    return {
      messageId,
      serverTimestamp:
        typeof value.enqueuedAt === "number"
          ? value.enqueuedAt
          : envelope.timestamp,
      ...(typeof value.duplicate === "boolean" && !uncertainRepeat
        ? { duplicate: value.duplicate }
        : {}),
      ...(typeof value.expiresAt === "number"
        ? { expiresAt: value.expiresAt }
        : {}),
      ...(value.deviceSetChecked === true ? { deviceSetChecked: true } : {}),
      ...(typeof value.needsSync === "boolean"
        ? { needsSync: value.needsSync }
        : {}),
    };
  }

  public subscribe(
    userId: string,
    deviceId: number,
    onEnvelope: (envelope: Envelope) => void | Promise<void>,
    options?: { onBatchStart?: () => void; onBatchEnd?: () => void },
  ): Unsubscribe {
    this.assertCurrentIdentity(userId, deviceId);
    // Only the newest subscription reports the connection state.
    const generation = ++this.subscriptionGeneration;
    const subscription = subscribeHostedMailbox({
      ...options,
      signalRelayProtocolVersion: this.signalRelayProtocolVersion,
      onConnectionState: (state, reason) => {
        if (generation === this.subscriptionGeneration)
          this.connectionState.move(state, reason);
      },
      onPresence: (event) => {
        if (generation !== this.subscriptionGeneration) return;
        // A listener that throws does not reach the socket's frame handling.
        for (const listener of [...this.presenceListeners]) {
          try {
            listener(event);
          } catch (error) {
            queueMicrotask(() => {
              throw error;
            });
          }
        }
      },
      authenticate: async () => {
        const previous = this.session.deviceToken;
        const token = await this.token();
        const url = websocketUrl(
          `${identifiedEndpoint(this.connection)}/mailbox/connect`,
          [["publishableKey", this.connection.publishableKey]],
        );
        return { url, token, refreshed: token !== previous };
      },
      isConclusiveRefusal,
      decodeDurable: (message) => this.incomingEnvelope(message) as Envelope,
      pull: async (cursor) => {
        const { messages, receipts, nextCursor, retainedWork, failedEntries } =
          await this.pullIncoming(cursor);
        return {
          messages: messages as readonly Envelope[],
          receipts,
          ...(nextCursor === undefined ? {} : { nextCursor }),
          ...(retainedWork === undefined ? {} : { retainedWork }),
          ...(failedEntries === undefined ? {} : { failedEntries }),
        };
      },
      acknowledge: (messageIds, receiptIds) =>
        this.acknowledge(messageIds, receiptIds),
      receive: onEnvelope,
      receiveReceipt: (receipt) => this.receiptInbox.handOff(receipt),
      onAcknowledgmentReply: (messageId, receipted) =>
        this.receiptJoin.settle(messageId, receipted),
      receiveEphemeral: async (candidate, current) => {
        if (!record(candidate) || !record(candidate.sender))
          throw new Error("Invalid ephemeral mailbox message.");
        const wire = this.decodeMailboxEnvelope(candidate);
        const messageId = requiredString(candidate, "messageId");
        const envelope: Envelope = {
          ...wire,
          id: messageId,
          clientMessageId: messageId,
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

  /** @deprecated Use `relayConnectionState`. SDK 15.0.0 removes this name. */
  public get signalProtocolRelayConnectionState(): SignalProtocolRelayConnectionState {
    return this.connectionState.current;
  }

  /** @deprecated Use `subscribeRelayConnectionState`. SDK 15.0.0 removes this name. */
  public subscribeSignalProtocolRelayConnectionState(
    listener: (state: SignalProtocolRelayConnectionState) => void,
  ): Unsubscribe {
    return this.connectionState.subscribe(listener);
  }

  public get relayConnectionState(): SignalProtocolRelayConnectionState {
    return this.signalProtocolRelayConnectionState;
  }

  public subscribeRelayConnectionState(
    listener: (state: SignalProtocolRelayConnectionState) => void,
  ): Unsubscribe {
    return this.subscribeSignalProtocolRelayConnectionState(listener);
  }

  /**
   * Acknowledges over the live mailbox socket when one exists, in one frame per
   * drained burst, and over HTTP otherwise.
   */
  public async markDelivered(envelopeId: string): Promise<void> {
    if (this.ephemeralAcknowledgments.has(envelopeId)) return;
    const subscription = this.subscription;
    if (subscription?.acknowledge(envelopeId) === true) return;
    const send = () => this.acknowledgeAndAnswer([envelopeId]);
    await (subscription === undefined
      ? send()
      : subscription.acknowledgeOverHttp(send));
  }

  public async getDevices(userId: string): Promise<DeviceInfo[]> {
    return (await this.directory(userId)).map((device) => ({
      deviceId: device.deviceId,
      registered: true,
      linked: device.deviceId > 1,
      enabled: true,
      ...(device.lastSeenAt === undefined ? {} : { lastSeenAt: device.lastSeenAt }),
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
      if (error instanceof HostedSignalProtocolRelayHttpError && error.code === "NOT_FOUND")
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
    await this.publishCurrentPrekeys(async () => keys);
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
      value = await this.prekeyPost(
        "/prekeys/consume",
        userId,
        deviceId,
        identityType,
      );
    } catch (error) {
      if (error instanceof HostedSignalProtocolRelayHttpError && error.code === "NOT_FOUND")
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
    return inventoryFromStatus(
      await this.prekeyStatus(userId, deviceId, identityType),
    );
  }

  public async publishPlannedPreKeys(
    userId: string,
    deviceId: number,
    plan: PreKeyPublicationPlan,
    identityType: IdentityType = "aci",
  ): Promise<void> {
    this.assertCurrentIdentity(userId, deviceId, identityType);
    await this.publishCurrentPrekeys(plan);
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

export async function bootstrapHostedSignalProtocolRelayTransport(
  request: HostedSignalProtocolRelayTransportBootstrapRequest,
): Promise<HostedSignalProtocolRelayTransportResult> {
  const proof = await request.deviceAuthentication.signChallenge(
    await registrationChallenge(request),
  );
  // A new client starts at the default version, which the transport built
  // below also takes.
  const value = await postJson(
    request.connection,
    RELAY_PROTOCOL_VERSION,
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
  const session: StoredHostedSignalProtocolRelaySession = {
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
    session.relayScopeId !== signalProtocolRelayScopeId(request.connection) ||
    session.deviceId < 1 ||
    session.generation < 0 ||
    session.mailboxGeneration < 0 ||
    tokenExpiration(session.deviceToken, session) <=
      Math.floor(Date.now() / 1_000)
  ) {
    throw new Error("Signal Protocol Relay returned an invalid registration");
  }
  await writeHostedStoreRecord(
    request.storage,
    await sessionMetadataKey(request.connection),
    JSON.stringify(session),
  );
  const transport = new HostedSignalProtocolRelayHttpTransport(
    request.connection,
    request.storage,
    request.deviceAuthentication,
    session,
  );
  const scopeId = request.connection.relayScopeId.slice();
  return {
    canonicalAccountId: session.canonicalAccountId,
    deviceId: session.deviceId,
    signalProtocolRelay: transport,
    relay: transport,
    signalProtocolRelayScopeId: scopeId,
    relayScopeId: scopeId,
    remoteObjectStore: transport.objectStore,
    transport,
  };
}

export async function resumeHostedSignalProtocolRelayTransport(options: {
  readonly connection: HostedSignalProtocolRelayConnection;
  readonly deviceAuthentication: HostedSignalProtocolRelayDeviceAuthentication;
  readonly storage: SignalProtocolLocalStore;
  /** @internal Strict resume refuses absence before any authentication. */
  readonly requireExisting?: boolean;
  /** @internal Reports actual entry into authentication, after local validation. */
  readonly onAuthenticating?: () => void;
}): Promise<HostedSignalProtocolRelayTransportResult | undefined> {
  let stored: string | null;
  try {
    stored = await readHostedStoreRecord(options.storage, await sessionMetadataKey(options.connection));
  } catch (cause) {
    if (options.requireExisting) {
      throw new HostedSignalProtocolRelayResumeError(
        'RETAINED_STATE_UNREADABLE', 'reading-local-state', { cause }
      );
    }
    throw cause;
  }
  if (!stored) {
    if (options.requireExisting) {
      throw new HostedSignalProtocolRelayResumeError('RETAINED_SESSION_UNAVAILABLE', 'reading-local-state');
    }
    return undefined;
  }
  let session: StoredHostedSignalProtocolRelaySession;
  try {
    session = parseSession(stored, options.connection);
  } catch (cause) {
    if (options.requireExisting) {
      throw new HostedSignalProtocolRelayResumeError(
        'RETAINED_SESSION_UNAVAILABLE', 'reading-local-state', { cause }
      );
    }
    throw cause;
  }
  const transport = new HostedSignalProtocolRelayHttpTransport(
    options.connection,
    options.storage,
    options.deviceAuthentication,
    session,
  );
  options.onAuthenticating?.();
  await transport.ensureAuthenticated(true);
  const scopeId = options.connection.relayScopeId.slice();
  return {
    canonicalAccountId: session.canonicalAccountId,
    deviceId: session.deviceId,
    signalProtocolRelay: transport,
    relay: transport,
    signalProtocolRelayScopeId: scopeId,
    relayScopeId: scopeId,
    remoteObjectStore: transport.objectStore,
    transport,
  };
}

/** Compose a link using a detached active session without publication writes. */
export async function linkHostedSignalProtocolRelayTransport(options: {
  readonly connection: HostedSignalProtocolRelayConnection;
  readonly activeStorage: SignalProtocolLocalStore;
  readonly storage: SignalProtocolLocalStore;
  readonly request: HostedSignalProtocolRelayManagedDeviceLinkRequest;
}): Promise<HostedSignalProtocolRelayTransportResult & HostedSignalProtocolRelayManagedDeviceLinkResult> {
  const stored = await readHostedStoreRecord(options.activeStorage, await sessionMetadataKey(options.connection));
  if (!stored) throw new Error('Signal Protocol Relay device link requires an active hosted session');
  const active = new HostedSignalProtocolRelayHttpTransport(
    options.connection, options.activeStorage, options.request.activeDeviceAuthentication,
    parseSession(stored, options.connection), false,
  );
  return active.linkDevice(options.request, options.storage);
}
