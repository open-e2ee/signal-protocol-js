/**
 * The own devices of a hosted account: approve a device link on the primary
 * device, list the devices, rename a device, remove a device, and report
 * changes to the device list (wire contract sections 3.3 to 3.8, 3.11,
 * 3.12, 11, 11.2, and 11.3).
 */
import { decryptDeviceName, encryptDeviceName } from "../device/device-name-crypto";
import {
  base64ToBytes,
  bytesToHex,
  bytesToUrlSafeBase64,
  generateUuidV4,
  secureZeroBytes,
  sha256,
} from "../internal/crypto";
import type { GroupStateStore } from "../internal/groups/manager";
import { SignalProtocolGroupStateStore } from "../internal/groups/sdk-store";
import { deriveGroupSecretParams } from "../internal/protocol/zk/groups";
import type { IdentityKeyPair } from "../keys/types";
import type { Logger } from "../logger";
import { estimateServerTimestamp } from "../server-clock";
import type { SignalProtocolLocalStore } from "../types";
import type { Base64 } from "../types/utils";
import type { DefaultSignalProtocolClient } from "./client";
import {
  DEVICE_LINK_APPLICATION_DATA_MAX_BYTES,
  DEVICE_LINK_ENCRYPTED_DEVICE_NAME_MAX_BYTES,
  parseDeviceLinkCode,
  sealDeviceLinkEnvelope,
  verifyDeviceLinkKemPublicKey,
  type DeviceLinkGroup,
  type DeviceLinkIdentityKeyPair,
} from "./device-link-envelope";
import type { HostedSignalProtocolRelayConnection } from "./hosted-connection";
import {
  HostedSignalProtocolRelayDeviceProvisioningError,
  type HostedSignalProtocolRelayDeviceProvisioningErrorCode,
} from "./hosted-device-provisioning-error";
import { HostedSignalProtocolRelayHttpError } from "./hosted-http-error";
import {
  deviceLinkUnsupported,
  probeHostedSignalProtocolRelayProvisioning,
  raceDeviceLinkCancel,
  throwIfDeviceLinkCancelled,
  waitForDeviceLink,
} from "./hosted-provisioning-channel";
import { canonicalBase64, decodeBase64Url, decodeCanonicalBase64 } from "./hosted-registration-material";
import type { HostedSignalProtocolRelayHttpTransport } from "./hosted-transport";
import { record } from "./signal-relay-http";
import { isSignalProtocolRelayRequestNotCompleted } from "./signal-relay-request-deadline";

/** The highest device ID of an account. */
const MAXIMUM_DEVICE_ID = 5;
/** The form of a link token: `<64 hex>.<43 b64url>` (wire contract section 7.1). */
const LINK_TOKEN_PATTERN = /^[0-9a-f]{64}\.[A-Za-z0-9_-]{43}$/u;
/** The largest device name, in UTF-16 code units (wire contract section 11.3). */
const DEVICE_NAME_MAX_UNITS = 50;
/** The first wait between two link status reads. Each wait doubles it. */
const LINK_STATUS_FIRST_WAIT_MILLISECONDS = 500;
/** The longest wait between two link status reads. */
const LINK_STATUS_MAXIMUM_WAIT_MILLISECONDS = 5_000;
/**
 * The time after the token expiry, by the estimated Relay clock
 * (`estimateServerTimestamp()`), in which a `pending` status still continues
 * the wait. It covers an error in that estimate. The Relay `expired` status
 * stops the wait at once.
 */
const LINK_STATUS_CLOCK_GRACE_MILLISECONDS = 60_000;

export interface HostedSignalProtocolRelayDeviceLinkApprovalOptions {
  /**
   * @deprecated This option does nothing. The new device names itself with
   * `hosted.deviceName` of `joinHostedSignalProtocolRelayAccount`. A later
   * major version removes this option.
   */
  readonly deviceName?: string;
  /**
   * Application bytes for the new device, 16,384 bytes or less. The join
   * returns them in `applicationData`.
   */
  readonly applicationData?: Uint8Array;
  /** Stops the approval with `CANCELLED`. */
  readonly signal?: AbortSignal;
}

/** A device of the own account. */
export interface HostedSignalProtocolRelayOwnDevice {
  readonly deviceId: number;
  /** True for device 1, the device that approves links. */
  readonly isPrimary: boolean;
  /** True for the device of this client. */
  readonly isCurrent: boolean;
  /** The device name, when the device has one that this client can read. */
  readonly name?: string;
  /** The time of the link, for a device that a link made. */
  readonly linkedAt?: Date;
}

/**
 * Called when a read of the own device list finds a change. `added` holds
 * the new own devices other than this device. `removed` holds the own
 * devices that the account no longer lists.
 */
export type HostedSignalProtocolRelayOwnDevicesChangedCallback = (change: {
  readonly added: readonly number[];
  readonly removed: readonly number[];
}) => void;

interface DeviceManagementRuntime {
  readonly transport: HostedSignalProtocolRelayHttpTransport;
  readonly connection: HostedSignalProtocolRelayConnection;
  readonly storage: SignalProtocolLocalStore;
  readonly groupStore: GroupStateStore;
  readonly logger: Required<Logger>;
}

const runtimes = new WeakMap<object, DeviceManagementRuntime>();

/** @internal Bind the SDK-owned transport of a hosted client to the device calls. */
export function bindHostedSignalProtocolRelayDeviceManagementRuntime(
  client: DefaultSignalProtocolClient,
  runtime: {
    readonly transport: HostedSignalProtocolRelayHttpTransport;
    readonly connection: HostedSignalProtocolRelayConnection;
    readonly storage: SignalProtocolLocalStore;
    readonly groupStore?: GroupStateStore;
    readonly logger: Required<Logger>;
  },
): void {
  runtimes.set(client, {
    ...runtime,
    groupStore: runtime.groupStore ?? new SignalProtocolGroupStateStore(runtime.storage),
  });
}

/**
 * @internal Throw when the client has no hosted device management runtime,
 * because it is not connected to the Relay.
 */
export function assertHostedSignalProtocolRelayDeviceManagement(client: DefaultSignalProtocolClient): void {
  deviceManagementRuntime(client);
}

function deviceManagementRuntime(client: DefaultSignalProtocolClient): DeviceManagementRuntime {
  const runtime = runtimes.get(client);
  if (runtime === undefined) {
    throw new Error("The client is not connected to the OpenE2EE Signal Protocol Relay");
  }
  return runtime;
}

function provisioningError(
  code: HostedSignalProtocolRelayDeviceProvisioningErrorCode,
  message: string,
  cause?: unknown,
): HostedSignalProtocolRelayDeviceProvisioningError {
  return new HostedSignalProtocolRelayDeviceProvisioningError(
    code,
    message,
    cause === undefined ? undefined : { cause },
  );
}

/**
 * @internal Throw a Relay refusal of a device link route as its
 * provisioning code (wire contract section 11.1). `notFound` is the code of
 * a 404. Every other error is thrown as it is.
 */
export function rethrowDeviceLinkRefusal(
  error: unknown,
  notFound: HostedSignalProtocolRelayDeviceProvisioningErrorCode,
): never {
  if (error instanceof HostedSignalProtocolRelayHttpError) {
    if (error.status === 404) {
      throw notFound === "SIGNAL_RELAY_UNSUPPORTED"
        ? deviceLinkUnsupported(error)
        : provisioningError(notFound, "The device link code expired", error);
    }
    if (error.code === "NOT_PRIMARY") {
      throw provisioningError("NOT_PRIMARY", "Only the primary device can do this", error);
    }
    if (error.code === "DEVICE_LIMIT_REACHED") {
      throw provisioningError("DEVICE_LIMIT_REACHED", "The account has no free device slot", error);
    }
    if (error.status === 413) {
      throw provisioningError("ENVELOPE_TOO_LARGE", "The device link envelope is too large", error);
    }
  }
  throw error;
}

/**
 * @internal The link token hash of wire contract section 7.1: SHA-256 of the
 * decoded secret after the `.` of the token.
 */
export async function deviceLinkTokenHash(linkToken: string): Promise<Uint8Array> {
  const secret = linkToken.slice(linkToken.indexOf(".") + 1);
  return sha256(decodeBase64Url(secret, "Signal Protocol Relay link token"));
}

/**
 * @internal Refuse a device name that is not 1 to 50 UTF-16 code units
 * (wire contract section 11.3). The SDK does not truncate a name.
 */
export function assertHostedDeviceName(name: unknown): asserts name is string {
  if (typeof name !== "string") throw new TypeError("The device name must be a string");
  if (name.length < 1 || name.length > DEVICE_NAME_MAX_UNITS) {
    throw new RangeError(`The device name must be 1 to ${DEVICE_NAME_MAX_UNITS} UTF-16 code units`);
  }
}

/**
 * @internal Encrypt a device name to the account identity key, so that each
 * device of the account can read it and the Relay cannot.
 */
export async function encryptHostedDeviceName(name: string, identityPublicKey: Base64): Promise<Uint8Array> {
  const encrypted = new Uint8Array(await encryptDeviceName(name, identityPublicKey));
  if (encrypted.length < 1 || encrypted.length > DEVICE_LINK_ENCRYPTED_DEVICE_NAME_MAX_BYTES) {
    throw new RangeError(
      `The encrypted device name must be 1 to ${DEVICE_LINK_ENCRYPTED_DEVICE_NAME_MAX_BYTES} bytes`,
    );
  }
  return encrypted;
}

function identityBytes(identity: IdentityKeyPair): DeviceLinkIdentityKeyPair {
  return {
    dhPublicKey: base64ToBytes(identity.dhKey.publicKey),
    dhPrivateKey: base64ToBytes(identity.dhKey.privateKey),
    signingPublicKey: base64ToBytes(identity.signingKey.publicKey),
    signingPrivateKey: base64ToBytes(identity.signingKey.privateKey),
  };
}

function zeroIdentity(identity: DeviceLinkIdentityKeyPair | undefined): void {
  if (identity === undefined) return;
  secureZeroBytes(identity.dhPrivateKey);
  secureZeroBytes(identity.signingPrivateKey);
}

/**
 * The groups that the new device gets: each group that the store lists, with
 * a master key whose derived group ID is the listed ID. A group whose record
 * has no master key, or a key of another group, stays on this device.
 */
async function linkedGroups(groupStore: GroupStateStore): Promise<DeviceLinkGroup[]> {
  const groups: DeviceLinkGroup[] = [];
  for (const groupId of await groupStore.listGroupReceiveRecords()) {
    const masterKey = await groupStore.getMasterKey(groupId);
    if (masterKey === null) continue;
    if (bytesToHex(deriveGroupSecretParams(masterKey).groupId) !== groupId) continue;
    groups.push({ groupId, masterKey });
  }
  return groups;
}

/**
 * Approve the device link of `linkCode` on the primary device. The client
 * sends the account identity, the groups, and `applicationData` to the new
 * device through the provisioning channel. The Relay cannot read them. The
 * new device joins with `joinHostedSignalProtocolRelayAccount`, and sets its
 * own name with `hosted.deviceName` of that call.
 *
 * The call resolves only after the new device has linked: the Relay has a
 * device from the redeem of the link token that this call issued. The call
 * reads the link status with a wait of 500 ms that doubles to 5 s. It
 * resolves with the device ID of the linked device. The Relay keeps the
 * `linked` status of the token after a later removal of the device, so a
 * resolved call does not prove that the device is still on the account. To
 * see the current devices, use `listHostedSignalProtocolRelayDevices` or
 * `hosted.onOwnDevicesChanged`.
 *
 * @throws RangeError when `applicationData` is above 16,384 bytes. The call
 * then sends no request.
 * @throws HostedSignalProtocolRelayDeviceProvisioningError for a refusal of
 * the link (wire contract section 11.1): `LINK_CODE_EXPIRED` when the link
 * code expires before the delivery, or the link token expires before the new
 * device links, and `CANCELLED` when `signal` fires.
 */
export async function approveHostedSignalProtocolRelayDeviceLink(
  client: DefaultSignalProtocolClient,
  linkCode: string,
  options: HostedSignalProtocolRelayDeviceLinkApprovalOptions = {},
): Promise<{ readonly deviceId: number }> {
  const { transport, connection, storage, groupStore } = deviceManagementRuntime(client);
  const { applicationData, signal } = options;
  if (applicationData !== undefined && applicationData.length > DEVICE_LINK_APPLICATION_DATA_MAX_BYTES) {
    throw new RangeError(
      `The device link application data is above ${DEVICE_LINK_APPLICATION_DATA_MAX_BYTES} bytes`,
    );
  }
  throwIfDeviceLinkCancelled(signal);
  const code = parseDeviceLinkCode(linkCode);
  const aciIdentity = await storage.getIdentityKey("aci");
  if (aciIdentity === null) {
    throw new Error("The device link requires the account identity of this device");
  }
  const pniIdentity = await storage.getIdentityKey("pni");

  const publishableKey = connection.publishableKey;
  const address = bytesToUrlSafeBase64(code.address);
  await raceDeviceLinkCancel(probeHostedSignalProtocolRelayProvisioning(connection), signal);
  const keyAnswer = await raceDeviceLinkCancel(
    transport
      .postSignalRelayDeviceLink("/provisioning/key", { publishableKey, address })
      .catch((error: unknown) => rethrowDeviceLinkRefusal(error, "LINK_CODE_EXPIRED")),
    signal,
  );
  if (!record(keyAnswer)) throw new Error("Signal Protocol Relay returned an invalid KEM key");
  const kemPublicKey = decodeCanonicalBase64(keyAnswer.publicKey, "Signal Protocol Relay KEM key");
  await verifyDeviceLinkKemPublicKey(code, kemPublicKey);

  const tokenAnswer = await raceDeviceLinkCancel(
    transport
      .postSignalRelayDeviceLink("/identity/devices/link-tokens", { publishableKey })
      .catch((error: unknown) => rethrowDeviceLinkRefusal(error, "SIGNAL_RELAY_UNSUPPORTED")),
    signal,
  );
  if (
    !record(tokenAnswer) ||
    typeof tokenAnswer.linkToken !== "string" ||
    !LINK_TOKEN_PATTERN.test(tokenAnswer.linkToken) ||
    !isLinkedDeviceId(tokenAnswer.deviceId) ||
    !Number.isSafeInteger(tokenAnswer.expiresAt)
  ) {
    throw new Error("Signal Protocol Relay returned an invalid link token");
  }
  const linkToken = tokenAnswer.linkToken;
  const expiresAt = tokenAnswer.expiresAt as number;

  const aci = identityBytes(aciIdentity);
  const pni = pniIdentity === null ? undefined : identityBytes(pniIdentity);
  let envelope: Uint8Array;
  try {
    envelope = await sealDeviceLinkEnvelope({
      linkCode: code,
      kemPublicKey,
      plaintext: {
        aci,
        ...(pni === undefined ? {} : { pni }),
        accountAddress: transport.accountId,
        linkToken,
        groups: await linkedGroups(groupStore),
        ...(applicationData === undefined ? {} : { applicationData }),
        createdAtMs: Date.now(),
      },
    });
  } finally {
    zeroIdentity(aci);
    zeroIdentity(pni);
  }
  throwIfDeviceLinkCancelled(signal);
  await transport
    .postSignalRelayDeviceLink("/provisioning/deliver", {
      publishableKey,
      address,
      envelope: canonicalBase64(envelope),
    })
    .catch((error: unknown) => rethrowDeviceLinkRefusal(error, "LINK_CODE_EXPIRED"));
  return { deviceId: await waitForLink(transport, publishableKey, linkToken, expiresAt, signal) };
}

function isLinkedDeviceId(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 2 && (value as number) <= MAXIMUM_DEVICE_ID;
}

/**
 * True for a status read failure that a later read can pass: a request with
 * no answer, a 5xx answer, or a retryable answer.
 */
function isTransientStatusFailure(error: unknown): boolean {
  if (error instanceof HostedSignalProtocolRelayHttpError) return error.status >= 500 || error.retryable;
  return isSignalProtocolRelayRequestNotCompleted(error);
}

/**
 * Read the link status of `linkToken` until the new device links (wire
 * contract sections 3.12 and 11.3), and return its device ID.
 *
 * - `linked` returns the device ID of the answer.
 * - `expired` rejects with `LINK_CODE_EXPIRED`.
 * - `pending` waits 500 ms, then twice the last wait, up to 5 s. A wait that
 *   starts before `expiresAt` ends 1 ms after it at the latest, so the last
 *   read comes after the expiry. After the expiry plus the clock grace, a
 *   `pending` answer rejects with `LINK_CODE_EXPIRED`.
 *
 * A transient failure waits and reads again until the clock grace ends.
 */
async function waitForLink(
  transport: HostedSignalProtocolRelayHttpTransport,
  publishableKey: string,
  linkToken: string,
  expiresAt: number,
  signal: AbortSignal | undefined,
): Promise<number> {
  const linkTokenHash = bytesToUrlSafeBase64(await deviceLinkTokenHash(linkToken));
  const expired = () =>
    provisioningError("LINK_CODE_EXPIRED", "The link token expired before the new device linked");
  let wait = LINK_STATUS_FIRST_WAIT_MILLISECONDS;
  for (;;) {
    throwIfDeviceLinkCancelled(signal);
    let answer: unknown;
    try {
      answer = await raceDeviceLinkCancel(
        transport.postSignalRelayDeviceLink("/identity/devices/link-tokens/status", {
          publishableKey,
          linkTokenHash,
        }),
        signal,
      );
    } catch (error) {
      const late = estimateServerTimestamp() > expiresAt + LINK_STATUS_CLOCK_GRACE_MILLISECONDS;
      if (late || !isTransientStatusFailure(error)) rethrowDeviceLinkRefusal(error, "SIGNAL_RELAY_UNSUPPORTED");
      answer = undefined;
    }
    if (answer !== undefined) {
      if (!record(answer)) throw new Error("Signal Protocol Relay returned an invalid link status");
      if (answer.state === "linked") {
        if (!isLinkedDeviceId(answer.deviceId)) {
          throw new Error("Signal Protocol Relay returned an invalid link status");
        }
        return answer.deviceId;
      }
      if (answer.state === "expired") throw expired();
      if (answer.state !== "pending") throw new Error("Signal Protocol Relay returned an invalid link status");
    }
    const now = estimateServerTimestamp();
    if (answer !== undefined && now > expiresAt + LINK_STATUS_CLOCK_GRACE_MILLISECONDS) throw expired();
    const remaining = expiresAt - now;
    await waitForDeviceLink(remaining >= 0 ? Math.min(wait, remaining + 1) : wait, signal);
    wait = Math.min(wait * 2, LINK_STATUS_MAXIMUM_WAIT_MILLISECONDS);
  }
}

/**
 * List the devices of the own account. A device name that this client
 * cannot decrypt stays absent.
 */
export async function listHostedSignalProtocolRelayDevices(
  client: DefaultSignalProtocolClient,
): Promise<readonly HostedSignalProtocolRelayOwnDevice[]> {
  const { transport, storage } = deviceManagementRuntime(client);
  const devices = await transport.listOwnDevices();
  const identity = devices.some((device) => device.encryptedName !== undefined)
    ? await storage.getIdentityKey("aci")
    : null;
  const currentDeviceId = transport.deviceId;
  return Promise.all(
    devices.map(async (device): Promise<HostedSignalProtocolRelayOwnDevice> => {
      let name: string | undefined;
      if (device.encryptedName !== undefined && identity !== null) {
        try {
          name = await decryptDeviceName(device.encryptedName.slice().buffer, identity.dhKey.privateKey);
        } catch {
          // A name of another identity key, or a damaged name, stays absent.
        }
      }
      return {
        deviceId: device.deviceId,
        isPrimary: device.deviceId === 1,
        isCurrent: device.deviceId === currentDeviceId,
        ...(name === undefined ? {} : { name }),
        ...(device.linkedAt === undefined ? {} : { linkedAt: new Date(device.linkedAt) }),
      };
    }),
  );
}

/**
 * Remove a device from the own account. The primary device can remove each
 * other device, and each device can remove itself. A removed client stops
 * with `HostedSignalProtocolRelayDeviceRevokedError`.
 *
 * A device ID that holds no device resolves, because the account is then in
 * the requested state.
 *
 * @throws RangeError for device 1 or an ID that is not an integer. The call
 * then sends no request.
 * @throws HostedSignalProtocolRelayDeviceProvisioningError `NOT_PRIMARY` or
 * `SIGNAL_RELAY_UNSUPPORTED`.
 */
export async function removeHostedSignalProtocolRelayDevice(
  client: DefaultSignalProtocolClient,
  deviceId: number,
): Promise<void> {
  if (!Number.isSafeInteger(deviceId) || deviceId < 2) {
    throw new RangeError("The device ID must be an integer of 2 or more. Device 1 cannot be removed.");
  }
  const { transport, connection, logger } = deviceManagementRuntime(client);
  await transport
    .postSignalRelayDeviceLink("/identity/devices/remove", {
      publishableKey: connection.publishableKey,
      targetDeviceId: deviceId,
      operationId: await generateUuidV4(),
    })
    .catch((error: unknown) => rethrowDeviceLinkRefusal(error, "SIGNAL_RELAY_UNSUPPORTED"));
  if (deviceId === transport.deviceId) return;
  try {
    await client.refreshOwnDeviceList();
  } catch (error) {
    logger.warn("Could not read the own device list after a device removal", {
      category: "E2EE",
      error: error as Error,
    });
  }
}

/**
 * Rename a device of the own account. The client encrypts `name` to the
 * account identity key, so each device of the account can read it, and the
 * Relay cannot. `listHostedSignalProtocolRelayDevices` shows the new name.
 *
 * Device 1 can rename each device from 1 to 5. A linked device can rename
 * only itself.
 *
 * @throws RangeError for a device ID that is not an integer from 1 to 5, or
 * a name that is not 1 to 50 UTF-16 code units. The call does not truncate a
 * name, and then sends no request.
 * @throws HostedSignalProtocolRelayDeviceProvisioningError `NOT_PRIMARY`
 * when a linked device renames another device, `DEVICE_NOT_FOUND` when the
 * slot holds no device, or `SIGNAL_RELAY_UNSUPPORTED`.
 */
export async function renameHostedSignalProtocolRelayDevice(
  client: DefaultSignalProtocolClient,
  deviceId: number,
  name: string,
): Promise<void> {
  if (!Number.isSafeInteger(deviceId) || deviceId < 1 || deviceId > MAXIMUM_DEVICE_ID) {
    throw new RangeError(`The device ID must be an integer from 1 to ${MAXIMUM_DEVICE_ID}`);
  }
  assertHostedDeviceName(name);
  const { transport, connection, storage, logger } = deviceManagementRuntime(client);
  const identity = await storage.getIdentityKey("aci");
  if (identity === null) throw new Error("The device rename requires the account identity of this device");
  const encryptedName = await encryptHostedDeviceName(name, identity.dhKey.publicKey);
  await transport
    .postSignalRelayDeviceLink("/identity/devices/name", {
      publishableKey: connection.publishableKey,
      targetDeviceId: deviceId,
      encryptedName: canonicalBase64(encryptedName),
    })
    .catch((error: unknown) => {
      if (error instanceof HostedSignalProtocolRelayHttpError && error.status === 409) {
        throw provisioningError("DEVICE_NOT_FOUND", "The device slot holds no device", error);
      }
      return rethrowDeviceLinkRefusal(error, "SIGNAL_RELAY_UNSUPPORTED");
    });
  try {
    await client.refreshOwnDeviceList();
  } catch (error) {
    logger.warn("Could not read the own device list after a device rename", {
      category: "E2EE",
      error: error as Error,
    });
  }
}

/**
 * @internal Call `callback` for each change to the own device list. The
 * client reads the list now and each time its Relay connection moves to
 * connected. A device that `joined` just now reads the list first and sets
 * the listener after that read, so the first read sets the baseline.
 */
export async function watchHostedSignalProtocolRelayOwnDevices(
  client: DefaultSignalProtocolClient,
  callback: HostedSignalProtocolRelayOwnDevicesChangedCallback | undefined,
  options: { readonly joined?: boolean } = {},
): Promise<void> {
  if (callback === undefined) return;
  const { logger } = deviceManagementRuntime(client);
  const refresh = async () => {
    try {
      await client.refreshOwnDeviceList();
    } catch (error) {
      logger.warn("Could not read the own device list", {
        category: "E2EE",
        error: error as Error,
      });
    }
  };
  const listener = (change: { readonly added: readonly number[]; readonly removed: readonly number[] }) =>
    callback({ added: change.added, removed: change.removed });
  if (options.joined === true) await refresh();
  client.setOwnDeviceListListener(listener);
  client.subscribeRelayConnectionState((state) => {
    if (state.state === "connected") void refresh();
  });
  if (options.joined !== true) await refresh();
}
