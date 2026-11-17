/**
 * The join of a new device to a hosted account through a device link (wire
 * contract sections 3.2, 3.6, 4, 8, 11, and 11.1).
 *
 * The new device shows a link code, receives the account identity in an
 * envelope from the primary device, and redeems the link token for its own
 * device session. A join marker in the store records the phase of the join,
 * so a call after a crash continues the join and opens no new channel.
 */
import {
  bytesToBase64,
  bytesToUrlSafeBase64,
  concatBytes,
  secureZeroBytes,
  sha256,
  stringToBytes,
} from "../internal/crypto";
import type { GroupStateStore } from "../internal/groups/manager";
import { SignalProtocolGroupStateStore } from "../internal/groups/sdk-store";
import { generateRegistrationId } from "../keys";
import { createCompositeIdentityV1 } from "../keys/identity";
import type { IdentityKeyPair } from "../keys/types";
import type { SignalProtocolLocalStore } from "../types";
import type { DefaultSignalProtocolClient } from "./client";
import type { HostedSignalProtocolRelayFirstSyncCallback } from "./first-sync-bundle";
import type { SignalProtocolClientCompositionOptions } from "./compose";
import type { SealedSenderAccessMode } from "./config";
import {
  DEVICE_LINK_ENCRYPTED_DEVICE_NAME_MAX_BYTES,
  decodeDeviceLinkPlaintext,
  encodeDeviceLinkPlaintext,
  openDeviceLinkEnvelope,
  type DeviceLinkIdentityKeyPair,
  type DeviceLinkPlaintext,
} from "./device-link-envelope";
import { createClientFromHostedResult } from "./hosted-client-composition";
import { getOrCreateDeviceAuthentication } from "./hosted-device-authentication";
import {
  createHostedClientWithFirstSync,
  getOrCreateRegistrationSnapshot,
  type HostedSignalProtocolRelayDeviceAuthentication,
  type HostedSignalProtocolRelayIdentityProgressCallback,
} from "./hosted";
import {
  resolveHostedSignalProtocolRelayConnection,
  type HostedSignalProtocolRelayConnection,
} from "./hosted-connection";
import {
  assertHostedDeviceName,
  deviceLinkTokenHash,
  encryptHostedDeviceName,
  rethrowDeviceLinkRefusal,
  watchHostedSignalProtocolRelayOwnDevices,
  type HostedSignalProtocolRelayOwnDevicesChangedCallback,
} from "./hosted-device-management";
import { clearHostedDeviceLinkIntent } from "./hosted-device-link";
import { HostedSignalProtocolRelayDeviceProvisioningError } from "./hosted-device-provisioning-error";
import type { HostedGroupOptions } from "./hosted-group-authority";
import { HostedSignalProtocolRelayHttpError } from "./hosted-http-error";
import {
  assertHostedSignalProtocolRelayProfileKeys,
  type HostedSignalProtocolRelayProfileKeys,
} from "./hosted-profile-keys";
import {
  DEVICE_LINK_PROTOCOL_VERSION,
  deviceLinkCancelled,
  probeHostedSignalProtocolRelayProvisioning,
  raceDeviceLinkCancel,
  receiveHostedDeviceLinkEnvelope,
  throwIfDeviceLinkCancelled,
  waitForDeviceLink,
  zeroDeviceLinkReceiverKeys,
} from "./hosted-provisioning-channel";
import {
  canonicalBase64,
  decodeCanonicalBase64,
  lengthPrefixed,
  registrationMaterialFingerprint,
  signalProtocolRelayScopeId,
  signalRegistration,
  text,
} from "./hosted-registration-material";
import { adoptRedeemedHostedSignalProtocolRelayDevice } from "./hosted-transport";
import { type JsonRecord, postJson } from "./signal-relay-http";
import { isSignalProtocolRelayRequestNotCompleted } from "./signal-relay-request-deadline";
import { SignalRelayProtocolOffer } from "./signal-relay-protocol";

/** The options of a join. The store of `adapters.storage` must be empty. */
export interface HostedSignalProtocolRelayJoinOptions
  extends Omit<SignalProtocolClientCompositionOptions, "adapters" | "identity" | "sealedSender" | "groups"> {
  readonly groups?: HostedGroupOptions;
  /**
   * `storage` must be empty, or hold the marker of a join that did not
   * finish. A store with an identity and no such marker gives
   * `STORE_NOT_EMPTY`.
   */
  readonly adapters: Omit<
    SignalProtocolClientCompositionOptions["adapters"],
    "relay" | "signalProtocolRelay" | "remoteObjectStore"
  >;
  readonly hosted: {
    /** The public environment-scoped Signal Protocol Relay connection URL. */
    readonly relayUrl: string;
    /**
     * Called with each new link code. Show it to the user of the primary
     * device, for example as a QR code. A code is valid for 90 s, and then
     * the join calls this callback again with a new code.
     */
    readonly onLinkCode: (code: string) => void;
    readonly onProgress?: HostedSignalProtocolRelayIdentityProgressCallback;
    readonly sealedSenderAccessMode?: SealedSenderAccessMode;
    /**
     * The profile keys of the account. The join binds them before it
     * resolves. On a new device, `getOwnProfileKey` returns null until the
     * application stores the key that `applicationData` brings.
     */
    readonly profileKeys?: HostedSignalProtocolRelayProfileKeys;
    /** Called when a read of the own device list finds an added or a removed own device. */
    readonly onOwnDevicesChanged?: HostedSignalProtocolRelayOwnDevicesChangedCallback;
    /**
     * Applies a first-sync bundle that device 1 sends with
     * `sendHostedSignalProtocolRelayFirstSync`. The client binds it before
     * its first receive, so a bundle that waits in the mailbox of this
     * device arrives at it. The device writes the apply-once record of the
     * bundle after the callback resolves. When the callback throws, the
     * durable local receive queue gives the bundle again, also after a
     * restart. Without it, the device consumes each first sync and logs
     * the warning `FIRST_SYNC_UNHANDLED`.
     */
    readonly onFirstSync?: HostedSignalProtocolRelayFirstSyncCallback;
    /**
     * The name of this device, 1 to 50 UTF-16 code units. The join does not
     * truncate a name. It encrypts the name to the account identity key of
     * the envelope, so each device of the account can read it and the Relay
     * cannot. The join state keeps the encrypted name, so a continued join
     * sends the same name. With no name, the device has no name until
     * `renameHostedSignalProtocolRelayDevice` sets one.
     */
    readonly deviceName?: string;
    /**
     * Called after the envelope opens and before the redeem, with the
     * account address of the envelope. Return false to stop the join with
     * `CANCELLED`. The join then redeems nothing and writes nothing.
     */
    readonly confirmAccount?: (account: { readonly accountAddress: string }) => boolean | Promise<boolean>;
  };
  /** Stops the join with `CANCELLED`. */
  readonly signal?: AbortSignal;
}

/** The result of a join. */
export interface HostedSignalProtocolRelayJoinResult {
  /** The started client of the new device. */
  readonly client: DefaultSignalProtocolClient;
  /** The device ID of the new device. */
  readonly deviceId: number;
  /** The `applicationData` of the approval, when the primary device sent it. */
  readonly applicationData?: Uint8Array;
}

/** The join marker key. */
const JOIN_MARKER_METADATA_KEY = "hosted-join:v1";
/** The label of the redeem challenge (wire contract section 8). */
const REDEEM_CHALLENGE_LABEL = stringToBytes("signal-relay-device-link-redeem-challenge-v1\0");
const REDEEM_PATH = "/identity/devices/link/redeem";
/**
 * The wait before each repeat of a redeem, in milliseconds. One redeem
 * request goes out, then one repeat after each wait.
 */
const REDEEM_RETRY_DELAYS_MILLISECONDS = [250, 1_000] as const;

type JoinPhase = "provisioned" | "registering" | "complete";

/**
 * The join marker.
 *
 * - `provisioned`: the envelope opened. The identity writes can be partial.
 * - `registering`: the identities and the groups are in the store. The
 *   redeem can have reached the Relay.
 * - `complete`: the join finished. The store belongs to the joined device.
 *
 * `plaintext` holds the encoded envelope plaintext until the join finishes,
 * so a continued join redeems the same link token.
 */
interface JoinMarker {
  readonly version: 1;
  readonly phase: JoinPhase;
  readonly registrationId: number;
  readonly pniRegistrationId?: number;
  readonly plaintext?: string;
  /** The canonical base64 of the encrypted device name of the redeem. */
  readonly encryptedDeviceName?: string;
  /** True after the first redeem `CONFLICT`. */
  readonly conflictRetried?: boolean;
  readonly deviceId?: number;
}

function provisioningError(
  code: HostedSignalProtocolRelayDeviceProvisioningError["code"],
  message: string,
  cause?: unknown,
): HostedSignalProtocolRelayDeviceProvisioningError {
  return new HostedSignalProtocolRelayDeviceProvisioningError(
    code,
    message,
    cause === undefined ? undefined : { cause },
  );
}

function invalidMarker(): Error {
  return new Error("Stored Signal Protocol Relay device join state is invalid");
}

function isRegistrationId(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 1 && (value as number) <= 0x3fff;
}

function isEncryptedDeviceName(value: unknown): boolean {
  let bytes: Uint8Array;
  try {
    bytes = decodeCanonicalBase64(value, "Stored Signal Protocol Relay device join state");
  } catch {
    return false;
  }
  return bytes.length >= 1 && bytes.length <= DEVICE_LINK_ENCRYPTED_DEVICE_NAME_MAX_BYTES;
}

async function readJoinMarker(storage: SignalProtocolLocalStore): Promise<JoinMarker | null> {
  const stored = await storage.getMetadata(JOIN_MARKER_METADATA_KEY);
  if (stored === null || stored === undefined) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(stored);
  } catch {
    throw invalidMarker();
  }
  if (typeof parsed !== "object" || parsed === null) throw invalidMarker();
  const marker = parsed as Record<string, unknown>;
  const phase = marker.phase;
  if (
    marker.version !== 1 ||
    (phase !== "provisioned" && phase !== "registering" && phase !== "complete") ||
    !isRegistrationId(marker.registrationId) ||
    (marker.pniRegistrationId !== undefined && !isRegistrationId(marker.pniRegistrationId)) ||
    (phase !== "complete" && typeof marker.plaintext !== "string") ||
    (marker.encryptedDeviceName !== undefined && !isEncryptedDeviceName(marker.encryptedDeviceName)) ||
    (marker.conflictRetried !== undefined && typeof marker.conflictRetried !== "boolean")
  ) {
    throw invalidMarker();
  }
  return marker as unknown as JoinMarker;
}

async function writeJoinMarker(storage: SignalProtocolLocalStore, marker: JoinMarker): Promise<void> {
  await storage.setMetadata(JOIN_MARKER_METADATA_KEY, JSON.stringify(marker));
}

function zeroPlaintext(plaintext: DeviceLinkPlaintext | undefined): void {
  if (plaintext === undefined) return;
  secureZeroBytes(plaintext.aci.dhPrivateKey);
  secureZeroBytes(plaintext.aci.signingPrivateKey);
  if (plaintext.pni !== undefined) {
    secureZeroBytes(plaintext.pni.dhPrivateKey);
    secureZeroBytes(plaintext.pni.signingPrivateKey);
  }
}

function storedIdentity(identity: DeviceLinkIdentityKeyPair, registrationId: number): IdentityKeyPair {
  return {
    dhKey: {
      publicKey: bytesToBase64(identity.dhPublicKey),
      privateKey: bytesToBase64(identity.dhPrivateKey),
    },
    signingKey: {
      publicKey: bytesToBase64(identity.signingPublicKey),
      privateKey: bytesToBase64(identity.signingPrivateKey),
    },
    registrationId,
  } as IdentityKeyPair;
}

/** Writes the identities of the plaintext with the registration IDs of the marker. */
async function storeJoinedIdentities(
  storage: SignalProtocolLocalStore,
  plaintext: DeviceLinkPlaintext,
  marker: JoinMarker,
): Promise<void> {
  await storage.storeIdentityKey(storedIdentity(plaintext.aci, marker.registrationId), "aci");
  await storage.setLocalRegistrationId(marker.registrationId, "aci");
  if (plaintext.pni === undefined || marker.pniRegistrationId === undefined) return;
  await storage.storeIdentityKey(storedIdentity(plaintext.pni, marker.pniRegistrationId), "pni");
  await storage.setLocalRegistrationId(marker.pniRegistrationId, "pni");
}

async function newRegistrationId(excluded: readonly (number | undefined)[]): Promise<number> {
  let registrationId: number;
  do {
    registrationId = await generateRegistrationId();
  } while (excluded.includes(registrationId));
  return registrationId;
}

/**
 * Receives the envelope, asks the application to confirm the account, and
 * writes the `provisioned` marker. Nothing is written before the marker.
 * The marker keeps the device name, encrypted to the account identity key
 * of the envelope.
 */
async function provisionJoin(
  options: HostedSignalProtocolRelayJoinOptions,
  connection: HostedSignalProtocolRelayConnection,
): Promise<JoinMarker> {
  const { hosted, signal } = options;
  // A network failure of the probe continues: the channel open gives the
  // answer, and only the probe can tell a Relay without the route.
  await raceDeviceLinkCancel(probeHostedSignalProtocolRelayProvisioning(connection), signal);
  const delivery = await receiveHostedDeviceLinkEnvelope({
    connection,
    onLinkCode: hosted.onLinkCode,
    ...(signal === undefined ? {} : { signal }),
  });
  let plaintext: DeviceLinkPlaintext;
  try {
    plaintext = await openDeviceLinkEnvelope(delivery.envelope, delivery);
  } finally {
    zeroDeviceLinkReceiverKeys(delivery.keys);
  }
  try {
    throwIfDeviceLinkCancelled(signal);
    if (hosted.confirmAccount !== undefined) {
      let confirmed: boolean;
      try {
        confirmed = await hosted.confirmAccount({ accountAddress: plaintext.accountAddress });
      } catch (error) {
        throw provisioningError("CANCELLED", "The device link was cancelled", error);
      }
      if (confirmed !== true) throw deviceLinkCancelled();
    }
    throwIfDeviceLinkCancelled(signal);
    const registrationId = await newRegistrationId([]);
    const pniRegistrationId =
      plaintext.pni === undefined ? undefined : await newRegistrationId([registrationId]);
    const encryptedDeviceName =
      hosted.deviceName === undefined
        ? undefined
        : await encryptHostedDeviceName(hosted.deviceName, bytesToBase64(plaintext.aci.dhPublicKey));
    const marker: JoinMarker = {
      version: 1,
      phase: "provisioned",
      registrationId,
      ...(pniRegistrationId === undefined ? {} : { pniRegistrationId }),
      plaintext: canonicalBase64(encodeDeviceLinkPlaintext(plaintext)),
      ...(encryptedDeviceName === undefined ? {} : { encryptedDeviceName: canonicalBase64(encryptedDeviceName) }),
    };
    await writeJoinMarker(options.adapters.storage, marker);
    return marker;
  } finally {
    zeroPlaintext(plaintext);
  }
}

/** The redeem challenge (wire contract section 8). */
async function redeemChallenge(
  connection: HostedSignalProtocolRelayConnection,
  linkToken: string,
  operationId: string,
  materialFingerprint: string,
  newDeviceAuthenticationPublicKey: Uint8Array,
): Promise<Uint8Array> {
  const tokenHash = await deviceLinkTokenHash(linkToken);
  return sha256(
    concatBytes(
      REDEEM_CHALLENGE_LABEL,
      text(signalProtocolRelayScopeId(connection)),
      text(bytesToUrlSafeBase64(tokenHash)),
      text(operationId),
      text(materialFingerprint),
      lengthPrefixed(newDeviceAuthenticationPublicKey),
    ),
  );
}

/** Removes the join state: the groups, the identities, and the marker. */
async function discardJoin(
  storage: SignalProtocolLocalStore,
  groupStore: GroupStateStore,
  plaintext: DeviceLinkPlaintext,
): Promise<void> {
  await clearHostedDeviceLinkIntent(
    groupStore,
    plaintext.groups.map((group) => group.groupId),
  );
  await storage.clearAllKeys();
  await storage.deleteMetadata(JOIN_MARKER_METADATA_KEY);
}

/**
 * True for a redeem failure that the same request can pass: a request with
 * no answer, a 5xx answer, or a retryable answer other than 429. The Relay
 * can have made the device before the failure, and a repeat of the same
 * request returns that device (wire contract section 3.6, check 9).
 */
function isRepeatableRedeemFailure(error: unknown): boolean {
  if (error instanceof HostedSignalProtocolRelayHttpError) {
    return error.status !== 429 && (error.status >= 500 || error.retryable);
  }
  return isSignalProtocolRelayRequestNotCompleted(error);
}

/**
 * Sends one redeem body. After a failure that the same request can pass,
 * it sends the same body again, up to `REDEEM_RETRY_DELAYS_MILLISECONDS`
 * times. Then it throws the last failure.
 */
async function postRedeem(
  connection: HostedSignalProtocolRelayConnection,
  body: JsonRecord,
  signal: AbortSignal | undefined,
): Promise<unknown> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await raceDeviceLinkCancel(
        postJson(connection, new SignalRelayProtocolOffer(DEVICE_LINK_PROTOCOL_VERSION), REDEEM_PATH, body),
        signal,
      );
    } catch (error) {
      const delay = REDEEM_RETRY_DELAYS_MILLISECONDS[attempt];
      if (delay === undefined || !isRepeatableRedeemFailure(error)) throw error;
      await waitForDeviceLink(delay, signal);
    }
  }
}

/**
 * Throws a redeem refusal as its SDK result (wire contract section 11.1).
 * A refusal that the same request gets again discards the join state, so
 * the next join opens a new channel. Every other failure keeps the state.
 *
 * - `KEY_PROOF_INVALID` and a second `CONFLICT` come before the Relay binds
 *   the token, so no device holds the link.
 * - `TOKEN_INVALID` and `RETRY_CONFLICT` can come after the Relay made the
 *   device. The Relay answers a repeat of a completed redeem until the token
 *   cleanup, 24 hours after the link token expires. After the cleanup, a
 *   removal, a recovery, or an identity-mode migration, the repeat gets
 *   `TOKEN_INVALID`. A device that the Relay made can then have no owner:
 *   the primary device lists it and can remove it.
 */
async function rethrowRedeemRefusal(
  error: unknown,
  storage: SignalProtocolLocalStore,
  groupStore: GroupStateStore,
  plaintext: DeviceLinkPlaintext,
): Promise<never> {
  if (error instanceof HostedSignalProtocolRelayHttpError) {
    if (error.code === "KEY_PROOF_INVALID") {
      await discardJoin(storage, groupStore, plaintext);
      throw provisioningError("ENVELOPE_INVALID", "The Relay refused the identity of the device link", error);
    }
    if (error.code === "TOKEN_INVALID" || error.code === "RETRY_CONFLICT" || error.code === "CONFLICT") {
      await discardJoin(storage, groupStore, plaintext);
      throw provisioningError("LINK_TOKEN_REJECTED", "The Relay refused the link token", error);
    }
  }
  return rethrowDeviceLinkRefusal(error, "SIGNAL_RELAY_UNSUPPORTED");
}

/**
 * Join this device to the account of a primary device.
 *
 * The call shows a link code through `hosted.onLinkCode`. The user approves
 * the code on the primary device with
 * `approveHostedSignalProtocolRelayDeviceLink`. The call then receives the
 * account identity and the groups through the provisioning channel, which
 * the Relay cannot read, and registers this device with its own device ID,
 * registration ID, prekeys, and device key.
 *
 * The store keeps the state of the join. After a failure, call again with
 * the same store: a join that received its envelope continues with the same
 * link token and opens no new channel. A redeem that gets no answer, a 5xx
 * answer, or another retryable answer than 429 is sent again with the same
 * body, two times at most. Then the call throws and keeps the join state.
 * A refusal of the redeem that the same request gets again
 * (`ENVELOPE_INVALID` or `LINK_TOKEN_REJECTED`) removes the join state, so
 * the next call shows a new link code.
 *
 * The Relay can make the device and then lose its answer. A later call that
 * repeats the redeem gets the same answer until the token cleanup, 24 hours
 * after the link token expires. When the device token of that answer has
 * expired, the call gets a new device token with the device proof. After the
 * cleanup, the call gives `LINK_TOKEN_REJECTED`, and the device that the
 * Relay made has no owner. The primary device lists it with
 * `listHostedSignalProtocolRelayDevices` and removes it with
 * `removeHostedSignalProtocolRelayDevice`.
 *
 * @throws HostedSignalProtocolRelayDeviceProvisioningError for a refusal of
 * the link (wire contract section 11.1).
 * @throws HostedSignalProtocolRelayHttpError for another Relay refusal. The
 * join state stays.
 */
export async function joinHostedSignalProtocolRelayAccount(
  options: HostedSignalProtocolRelayJoinOptions,
): Promise<HostedSignalProtocolRelayJoinResult> {
  const { adapters, hosted, signal, ...clientOptions } = options;
  if (typeof hosted.onLinkCode !== "function") {
    throw new TypeError("joinHostedSignalProtocolRelayAccount requires hosted.onLinkCode");
  }
  if (hosted.profileKeys !== undefined) assertHostedSignalProtocolRelayProfileKeys(hosted.profileKeys);
  if (hosted.deviceName !== undefined) assertHostedDeviceName(hosted.deviceName);
  throwIfDeviceLinkCancelled(signal);
  const storage = adapters.storage;
  const groupStore = clientOptions.groups?.store ?? new SignalProtocolGroupStateStore(storage);
  const connection = await resolveHostedSignalProtocolRelayConnection(hosted.relayUrl);
  const progress = (phase: "preparing-linked-device" | "copying" | "submitting") =>
    hosted.onProgress?.({ operation: "device-link", phase });
  progress("preparing-linked-device");

  let marker = await readJoinMarker(storage);
  if (
    marker?.phase === "complete" ||
    (marker === null &&
      ((await storage.getIdentityKey("aci")) !== null || (await storage.getIdentityKey("pni")) !== null))
  ) {
    throw provisioningError("STORE_NOT_EMPTY", "The store of the new device already holds an identity");
  }
  marker ??= await provisionJoin(options, connection);

  const plaintext = decodeDeviceLinkPlaintext(
    decodeCanonicalBase64(marker.plaintext, "Stored Signal Protocol Relay device join state"),
  );
  try {
    if (marker.phase === "provisioned") {
      progress("copying");
      await storeJoinedIdentities(storage, plaintext, marker);
      for (const group of plaintext.groups) await groupStore.storeMasterKey(group.groupId, group.masterKey);
      marker = { ...marker, phase: "registering" };
      await writeJoinMarker(storage, marker);
    }
    throwIfDeviceLinkCancelled(signal);

    const { publishableKey } = connection;
    const deviceAuthentication = await getOrCreateDeviceAuthentication(storage, publishableKey);
    progress("submitting");
    const redeemed = await redeemJoin({
      connection,
      storage,
      groupStore,
      plaintext,
      marker,
      deviceAuthentication,
      ...(signal === undefined ? {} : { signal }),
    });
    marker = redeemed.marker;
    const result = await adoptRedeemedHostedSignalProtocolRelayDevice({
      connection,
      storage,
      deviceAuthentication,
      value: redeemed.value,
      operationId: redeemed.operationId,
      materialFingerprint: redeemed.materialFingerprint,
      registrationPreKeys: redeemed.registrationPreKeys,
      accountId: plaintext.accountAddress,
    });
    const client = await createClientFromHostedResult(
      result,
      connection,
      adapters,
      clientOptions,
      hosted.sealedSenderAccessMode,
      result.remoteObjectStore,
      result.transport,
      hosted.profileKeys,
      createHostedClientWithFirstSync(hosted.onFirstSync),
    );
    try {
      if (client.syncStatus === "failed") {
        throw new Error("OpenE2EE Signal Protocol Relay initial synchronization failed");
      }
      await watchHostedSignalProtocolRelayOwnDevices(client, hosted.onOwnDevicesChanged, { joined: true });
      await writeJoinMarker(storage, {
        version: 1,
        phase: "complete",
        registrationId: marker.registrationId,
        ...(marker.pniRegistrationId === undefined ? {} : { pniRegistrationId: marker.pniRegistrationId }),
        deviceId: result.deviceId,
      });
    } catch (error) {
      await client.stop();
      throw error;
    }
    hosted.onProgress?.({ operation: "device-link", phase: "complete", deviceId: result.deviceId });
    return {
      client,
      deviceId: result.deviceId,
      ...(plaintext.applicationData === undefined
        ? {}
        : { applicationData: plaintext.applicationData.slice() }),
    };
  } finally {
    zeroPlaintext(plaintext);
  }
}

/**
 * Redeems the link token. A request with no answer, or a retryable answer,
 * repeats with the same body (`postRedeem`). The first `CONFLICT` gives the
 * device a new registration ID, and so a new snapshot and operation ID, and
 * the redeem runs once more.
 */
async function redeemJoin(options: {
  readonly connection: HostedSignalProtocolRelayConnection;
  readonly storage: SignalProtocolLocalStore;
  readonly groupStore: GroupStateStore;
  readonly plaintext: DeviceLinkPlaintext;
  readonly marker: JoinMarker;
  readonly deviceAuthentication: HostedSignalProtocolRelayDeviceAuthentication;
  readonly signal?: AbortSignal;
}): Promise<{
  readonly value: unknown;
  readonly marker: JoinMarker;
  readonly operationId: string;
  readonly materialFingerprint: string;
  readonly registrationPreKeys: Awaited<ReturnType<typeof getOrCreateRegistrationSnapshot>>["registrationPreKeys"];
}> {
  const { connection, storage, groupStore, plaintext, deviceAuthentication, signal } = options;
  const { publishableKey } = connection;
  let marker = options.marker;
  for (;;) {
    const identity = await storage.getIdentityKey("aci");
    if (identity === null) throw invalidMarker();
    const signalIdentity = createCompositeIdentityV1(identity);
    const { registrationId } = marker;
    const { operationId, registrationPreKeys } = await getOrCreateRegistrationSnapshot(
      storage,
      publishableKey,
      signalIdentity,
      registrationId,
      { ...identity, registrationId },
    );
    const materialFingerprint = await registrationMaterialFingerprint(
      signalIdentity,
      registrationId,
      registrationPreKeys,
    );
    const challenge = await redeemChallenge(
      connection,
      plaintext.linkToken,
      operationId,
      materialFingerprint,
      deviceAuthentication.publicKey,
    );
    const proof = await deviceAuthentication.signChallenge(challenge, DEVICE_LINK_PROTOCOL_VERSION);
    try {
      const value = await postRedeem(
        connection,
        {
          publishableKey,
          linkToken: plaintext.linkToken,
          operationId,
          signalRegistration: signalRegistration(signalIdentity, registrationId, registrationPreKeys),
          newDeviceAuthenticationPublicKey: canonicalBase64(deviceAuthentication.publicKey),
          newDeviceProof: canonicalBase64(proof),
          // The name comes only from the join state. The join ignores a name
          // in the envelope plaintext (field 7), which only an earlier SDK
          // on the primary device writes.
          ...(marker.encryptedDeviceName === undefined ? {} : { encryptedDeviceName: marker.encryptedDeviceName }),
        },
        signal,
      );
      return { value, marker, operationId, materialFingerprint, registrationPreKeys };
    } catch (error) {
      if (
        error instanceof HostedSignalProtocolRelayHttpError &&
        error.code === "CONFLICT" &&
        marker.conflictRetried !== true
      ) {
        // The slot refuses the registration ID of an earlier device in it.
        const next = await newRegistrationId([registrationId, marker.pniRegistrationId]);
        marker = { ...marker, registrationId: next, conflictRetried: true };
        await writeJoinMarker(storage, marker);
        await storage.storeIdentityKey({ ...identity, registrationId: next }, "aci");
        await storage.setLocalRegistrationId(next, "aci");
        continue;
      }
      return rethrowRedeemRefusal(error, storage, groupStore, plaintext);
    }
  }
}
