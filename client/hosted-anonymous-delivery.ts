import { utf8Decode } from "../internal/platform";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToUrlSafeBase64,
  concatBytes,
} from "../internal/crypto";
import {
  deserializeReceivedMessage,
  deserializeSentMessage,
  serializeReceivedMessage,
  serviceIdToBytes,
} from "../internal/protocol/sealed-sender/multi-recipient-message";
import type {
  ContentKind,
  DeliveryClass,
  SealedSenderAuth,
} from "../remote/relay/types";
import type { Base64 } from "../types";
import { SealedSenderAuthError } from "../types/errors";
import { FanOutError, type BoundedFanOut } from "../utils/bounded-fan-out";
import type { HostedRelayConnection } from "./hosted-connection";
import { aggregateRelayAcceptance } from "./relay-acceptance";
import { markRelayDeviceRefusal } from "./relay-device-refusal";
import {
  deviceSetRefusal,
  markDeviceSetRefusal,
  parseDeviceSetRefusal,
  type DeviceSetMismatchAccount,
} from "../remote/relay/device-set";
import {
  markGroupRouteFallback,
  takesDirectSealedRoute,
} from "./relay-sealed-route";
import { relayProtocolHeaders, throwIfUpgradeRequired } from "./relay-protocol";
import { withRelayRequestDeadline } from "./relay-request-deadline";

const FRAME_VERSION = 1;
const FRAME_HEADER_BYTES = 9;
const GROUP_BODY_BYTES = 96 * 1024;
const DIRECT_BODY_BYTES = 256 * 1024;
type JsonRecord = Record<string, unknown>;
type Destination = {
  accountAddress: string;
  deviceId: number;
  generation: number;
};
/**
 * One destination of a post, with the registration ID that the body names
 * for its device. The Relay refuses the device as stale when its current
 * registration differs. A body device with registration 0 names none.
 */
type ResolvedDestination = Destination & {
  recipientPrefix: string;
  recipientRegistrationId?: number;
};
type AnonymousReceipt = {
  messageId: string;
  serverTimestamp: number;
  uuids404: string[];
  duplicate?: boolean;
  expiresAt?: number;
  refusedDestinationCount?: number;
  deviceSetChecked?: boolean;
  refusals?: { userId: string; deviceId: number; code: string }[];
};
/** The device set of one account, as the wire names it. */
type WireDeviceSet = { accountAddress: string; deviceIds: number[] };
type SendOperation = {
  messageCiphertext: Uint8Array;
  deliveryClass: DeliveryClass;
  clientMessageId: string;
  operationEpochMilliseconds: number;
  contentKind: ContentKind;
  timestamp: number;
  deviceSets?: WireDeviceSet[];
};

function record(value: unknown): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function bytes(value: string): Uint8Array {
  const decoded = base64ToBytes(value as Base64);
  if (bytesToBase64(decoded) !== value)
    throw new Error("Anonymous delivery encoding is invalid");
  return decoded;
}

function timestampHeader(timestamp: number): Uint8Array {
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0)
    throw new Error("Anonymous delivery timestamp is invalid");
  const header = new Uint8Array(FRAME_HEADER_BYTES);
  header[0] = FRAME_VERSION;
  new DataView(header.buffer).setBigUint64(1, BigInt(timestamp));
  return header;
}

/** The Relay frame adds only the original timestamp to the existing sealed envelope. */
export function decodeHostedAnonymousEnvelope(value: Uint8Array): {
  ciphertext: string;
  messageType: "unidentified_sender";
  timestamp: number;
} {
  if (value.length <= FRAME_HEADER_BYTES || value[0] !== FRAME_VERSION)
    throw new Error("Anonymous mailbox envelope is invalid");
  const timestamp = Number(
    new DataView(value.buffer, value.byteOffset, value.byteLength).getBigUint64(
      1,
    ),
  );
  timestampHeader(timestamp);
  const received = value.subarray(FRAME_HEADER_BYTES);
  if (deserializeReceivedMessage(received).messageCiphertext.length === 0)
    throw new Error("Anonymous mailbox envelope is invalid");
  return {
    ciphertext: bytesToBase64(received),
    messageType: "unidentified_sender",
    timestamp,
  };
}

export class HostedAnonymousDeliveryError extends Error {
  public constructor(
    public readonly status: number,
    public readonly code: string,
    /**
     * The `details` object of the Relay's answer. For a refused declared
     * post, it names the missing and extra devices of each account for
     * `DEVICE_SET_MISMATCH`, or the stale devices for `STALE_DEVICE`. Absent
     * when the answer has no `details` object.
     */
    public readonly data?: Readonly<{ details: Readonly<Record<string, unknown>> }>,
  ) {
    super("Anonymous Relay delivery failed");
    this.name = "HostedAnonymousDeliveryError";
  }
}

/**
 * Mark a NOT_FOUND or STALE_DEVICE answer to one direct post as the Relay's
 * refusal of the device that the post names. The code comes only from the
 * Relay's error body, so a 404 without that body is not a device refusal.
 */
function markDestinationRefusal(
  error: unknown,
  destination: Destination,
): unknown {
  if (
    error instanceof HostedAnonymousDeliveryError &&
    (error.code === "NOT_FOUND" || error.code === "STALE_DEVICE")
  )
    markRelayDeviceRefusal(error, {
      code: error.code,
      userId: destination.accountAddress,
      deviceId: destination.deviceId,
    });
  return error;
}

/**
 * The Relay refused a group endorsement on the direct route as an unknown
 * authorization. The post did not start, so it can go on the group route.
 */
class DirectRouteRefusedError extends Error {
  public constructor() {
    super("Anonymous direct delivery refused the group endorsement");
    this.name = "DirectRouteRefusedError";
  }
}

async function responseObject(response: Response): Promise<JsonRecord> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Anonymous delivery receipt is invalid");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > 1024 * 1024) {
        await reader.cancel();
        throw new Error("Anonymous delivery receipt exceeds its limit");
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  const value: unknown = JSON.parse(
    utf8Decode(concatBytes(...chunks)),
  );
  if (!record(value)) throw new Error("Anonymous delivery receipt is invalid");
  return value;
}

/** Anonymous requests never carry the authenticated transport's token or cookies. */
export class HostedAnonymousDelivery {
  public constructor(
    private readonly connection: HostedRelayConnection,
    private readonly fanOut: BoundedFanOut,
    /**
     * The destination of one device. `declaredDeviceIds` is the declared
     * set of the account, given only for a declared post. For such a post, a
     * device that the directory does not list gets the device-set refusal
     * that the Relay would give: the device is extra.
     */
    private readonly resolveDestination: (
      account: string,
      deviceId: number,
      declaredDeviceIds?: readonly number[],
    ) => Promise<Destination>,
  ) {}

  /**
   * Run task for each item at the same time. After every item settles, a
   * failure rejects with the error of the first failed item in input order,
   * because callers match its type.
   */
  private async each<T, R>(
    items: readonly T[],
    task: (item: T) => Promise<R>,
  ): Promise<R[]> {
    try {
      return await this.fanOut.all(items, task);
    } catch (error) {
      throw error instanceof FanOutError ? error.errors[0] : error;
    }
  }

  /**
   * Resolve each destination as `each` does. When every failed destination
   * has a device-set refusal, the send fails with one refusal that names
   * each refused account, as the Relay's answer to the whole post does.
   */
  private async resolveAll<T>(
    items: readonly T[],
    task: (item: T) => Promise<ResolvedDestination>,
  ): Promise<ResolvedDestination[]> {
    try {
      return await this.fanOut.all(items, task);
    } catch (error) {
      if (!(error instanceof FanOutError)) throw error;
      const first: unknown = error.errors[0];
      const refusals = error.errors.map(deviceSetRefusal);
      if (
        !(first instanceof Error) ||
        !refusals.every((refusal) => refusal?.kind === "mismatch")
      )
        throw first;
      const accounts = new Map<string, DeviceSetMismatchAccount>();
      for (const refusal of refusals) {
        for (const account of refusal!.accounts as DeviceSetMismatchAccount[])
          if (!accounts.has(account.userId)) accounts.set(account.userId, account);
      }
      throw markDeviceSetRefusal(first, {
        kind: "mismatch",
        accounts: [...accounts.values()],
      });
    }
  }

  private post(path: string, body: JsonRecord): Promise<JsonRecord> {
    return withRelayRequestDeadline(async (signal) => {
      let response: Response;
      try {
        response = await fetch(
          `${this.connection.protocolEndpoint.replace(/\/$/u, "")}/anonymous${path}`,
          {
            method: "POST",
            credentials: "omit",
            redirect: "error",
            headers: {
              accept: "application/json",
              "content-type": "application/json",
              ...relayProtocolHeaders(),
            },
            body: JSON.stringify({
              ...body,
              publishableKey: this.connection.publishableKey,
            }),
            signal,
          },
        );
      } catch (cause) {
        throw new Error("Signal Protocol Relay request could not be completed", {
          cause,
        });
      }
      const value = await responseObject(response);
      if (!response.ok) {
        throwIfUpgradeRequired(response.status, value);
        const code = record(value.error) ? value.error.code : undefined;
        // Each route answers a rejected credential with the code of its
        // type. A Relay without the endorsement on the direct route answers
        // ANONYMOUS_AUTH_REJECTED for it.
        const groupCredential =
          record(body.auth) && body.auth.type === "groupSendToken";
        if (response.status === 401) {
          if (
            code ===
            (groupCredential
              ? "GROUP_CREDENTIAL_REJECTED"
              : "ANONYMOUS_AUTH_REJECTED")
          )
            throw new SealedSenderAuthError();
          if (
            groupCredential &&
            path === "/delivery/send" &&
            code === "ANONYMOUS_AUTH_REJECTED"
          )
            throw new DirectRouteRefusedError();
        }
        const safeCodes = [
          "NOT_FOUND",
          "STALE_DEVICE",
          "RETRY_CONFLICT",
          "OPERATION_EXPIRED",
          "DELIVERY_UNCERTAIN",
          "DEVICE_SET_MISMATCH",
        ];
        const safeCode =
          typeof code === "string" && safeCodes.includes(code)
            ? code
            : "DELIVERY_FAILED";
        const details =
          record(value.error) && record(value.error.details)
            ? value.error.details
            : undefined;
        const error = new HostedAnonymousDeliveryError(
          response.status,
          safeCode,
          details === undefined ? undefined : { details },
        );
        // Only a declared post gets a device-set refusal.
        const refusal =
          body.deviceSets === undefined
            ? undefined
            : parseDeviceSetRefusal(safeCode, details);
        throw refusal === undefined
          ? error
          : markDeviceSetRefusal(error, refusal);
      }
      return value;
    });
  }

  public async send(
    sentMessageBase64: string,
    auth: SealedSenderAuth,
    timestamp: number,
    deliveryClass: DeliveryClass,
    recipientUserIds?: string[],
    clientMessageId?: string,
    operationEpochMilliseconds = timestamp,
    contentKind: ContentKind = "message",
    declaredDeviceSets?: readonly {
      userId: string;
      deviceIds: readonly number[];
    }[],
  ): Promise<AnonymousReceipt> {
    const header = timestampHeader(timestamp);
    if (
      !clientMessageId ||
      clientMessageId.length > 128 ||
      !["user-visible", "background-sync", "ephemeral"].includes(deliveryClass) ||
      !["message", "receipt"].includes(contentKind)
    )
      throw new Error("Anonymous delivery operation is invalid");
    const parsed = deserializeSentMessage(bytes(sentMessageBase64));
    if (
      !parsed.recipients.length ||
      parsed.recipients.length > 1_000 ||
      !parsed.messageCiphertext.length ||
      (recipientUserIds !== undefined &&
        recipientUserIds.length !== parsed.recipients.length)
    )
      throw new Error("Anonymous delivery recipients are invalid");
    if (auth.type === "accessKey") {
      if (
        bytes(auth.unidentifiedAccessKey).length !== 16 ||
        parsed.recipients.length !== 1
      )
        throw new Error("Anonymous access-key delivery requires one account");
    } else if (auth.type === "groupSendToken") {
      if (
        auth.groupSendToken.length !== 24 ||
        deliveryClass === "ephemeral" ||
        parsed.messageCiphertext.length > GROUP_BODY_BYTES
      )
        throw new Error("Anonymous group delivery is invalid");
    } else throw new Error("Anonymous delivery authorization is invalid");

    const accounts = new Set<string>();
    const recipients = parsed.recipients.map((entry, index) => {
      const aci = serviceIdToBytes(entry.serviceId);
      const accountAddress = bytesToUrlSafeBase64(aci);
      if (
        aci.every((value) => value === 0) ||
        accounts.has(accountAddress) ||
        (recipientUserIds !== undefined &&
          recipientUserIds[index] !== accountAddress) ||
        entry.devices.length < 1 ||
        entry.devices.length > 5 ||
        new Set(entry.devices.map((device) => device.deviceId)).size !==
          entry.devices.length ||
        entry.devices.some(
          (device) => device.deviceId < 1 || device.deviceId > 5,
        )
      )
        throw new Error("Anonymous delivery recipients are invalid");
      accounts.add(accountAddress);
      if (auth.type === "groupSendToken") {
        const claimed = auth.recipientAciBytes.get(accountAddress);
        if (!claimed || bytesToUrlSafeBase64(claimed) !== accountAddress)
          throw new SealedSenderAuthError();
      }
      const prefix = concatBytes(
        header,
        serializeReceivedMessage(
          entry.encryptedMessageKey,
          entry.authenticationTag,
          parsed.ephemeralPublic,
          new Uint8Array(),
        ),
      );
      if (
        auth.type === "accessKey" &&
        prefix.length + parsed.messageCiphertext.length > DIRECT_BODY_BYTES
      )
        throw new Error("Anonymous delivery envelope exceeds its limit");
      return { accountAddress, devices: entry.devices, prefix };
    });
    if (
      auth.type === "groupSendToken" &&
      auth.recipientAciBytes.size !== accounts.size
    )
      throw new SealedSenderAuthError();

    // Every destination resolves at the same time. The resolver sends one
    // lookup for each account. Each destination names the registration that
    // the body gives its device. The Relay compares it with the device's
    // current one. The field names only the recipient.
    const declared = new Map(
      declaredDeviceSets?.map(({ userId, deviceIds }) => [userId, deviceIds]),
    );
    const destinations = await this.resolveAll(
      recipients.flatMap((entry) =>
        entry.devices.map((device) => ({ entry, device })),
      ),
      async ({ entry, device }): Promise<ResolvedDestination> => ({
        ...(await this.resolveDestination(
          entry.accountAddress,
          device.deviceId,
          declaredDeviceSets === undefined
            ? undefined
            : declared.get(entry.accountAddress),
        )),
        recipientPrefix: bytesToBase64(entry.prefix),
        ...(device.registrationId !== 0 && {
          recipientRegistrationId: device.registrationId,
        }),
      }),
    );
    const deviceSets = declaredDeviceSets?.map(
      ({ userId, deviceIds }): WireDeviceSet => ({
        accountAddress: userId,
        deviceIds: [...deviceIds],
      }),
    );
    if (
      deviceSets !== undefined &&
      (deviceSets.length !== accounts.size ||
        deviceSets.some(({ accountAddress }) => !accounts.has(accountAddress)))
    )
      throw new Error("Anonymous delivery device sets are invalid");
    const operation: SendOperation = {
      messageCiphertext: parsed.messageCiphertext,
      deliveryClass,
      clientMessageId,
      operationEpochMilliseconds,
      contentKind,
      timestamp,
      ...(deviceSets !== undefined && { deviceSets }),
    };
    if (auth.type === "accessKey")
      return this.sendDirect(auth, destinations, operation);
    const groupSendToken = bytesToBase64(auth.groupSendToken);
    // The endorsement of one destination device takes the direct route, as
    // an access key does. The Relay checks that the endorsement is for the
    // destination account alone.
    if (takesDirectSealedRoute(auth) && destinations.length === 1) {
      try {
        return await this.sendDirect(
          { type: auth.type, groupSendToken },
          destinations,
          operation,
        );
      } catch (error) {
        if (!(error instanceof DirectRouteRefusedError)) throw error;
      }
      // The Relay refused the endorsement on the direct route before the
      // post started. The same post goes once on the group route.
      return markGroupRouteFallback(
        await this.sendGroup(groupSendToken, destinations, operation),
      );
    }
    return this.sendGroup(groupSendToken, destinations, operation);
  }

  /** One fan-out post of the shared body to every destination. */
  private async sendGroup(
    groupSendToken: string,
    destinations: readonly ResolvedDestination[],
    operation: SendOperation,
  ): Promise<AnonymousReceipt> {
    const { clientMessageId } = operation;
    const result = await this.fanOut.request(() =>
      this.post("/groups/send", {
        auth: { type: "groupSendToken", groupSendToken },
        body: bytesToBase64(operation.messageCiphertext),
        destinations,
        contentKind: operation.contentKind,
        deliveryClass: operation.deliveryClass,
        logicalSendId: clientMessageId,
        operationEpochMilliseconds: operation.operationEpochMilliseconds,
        ...(operation.deviceSets !== undefined && {
          deviceSets: operation.deviceSets,
        }),
      }),
    );
    if (
      result.logicalSendId !== clientMessageId ||
      result.replayable !== true ||
      typeof result.duplicate !== "boolean" ||
      !Number.isSafeInteger(result.acceptedDestinations) ||
      (result.acceptedDestinations as number) < 0 ||
      (result.acceptedDestinations as number) > destinations.length ||
      (result.deviceSetChecked !== undefined &&
        result.deviceSetChecked !== true)
    )
      throw new Error("Anonymous group receipt is invalid");
    const refusals = groupRefusals(result.refusals, destinations);
    // On a first acceptance, NOT_FOUND names an account that the Relay
    // does not know. On a duplicate receipt it can also name a delivery
    // that the Relay ended after acceptance, so no account leaves the send.
    const uuids404 =
      refusals === undefined || result.duplicate === true
        ? []
        : [
            ...new Set(
              refusals.flatMap((refusal) =>
                refusal.code === "NOT_FOUND" ? [refusal.userId] : [],
              ),
            ),
          ];
    // Fan-out acceptance has no recipient enqueue time. Keep the original
    // message time. A duplicate fan-out is one that the Relay had already
    // accepted; it does not tell that each destination stored a copy. The
    // refused count is the Relay's answer at acceptance. A destination that
    // the fan-out refuses later is not counted, and the SDK reads no
    // fan-out status.
    return {
      messageId: clientMessageId,
      serverTimestamp: operation.timestamp,
      uuids404,
      duplicate: result.duplicate as boolean,
      refusedDestinationCount:
        destinations.length - (result.acceptedDestinations as number),
      ...(result.deviceSetChecked === true && { deviceSetChecked: true }),
      ...(refusals !== undefined && { refusals }),
    };
  }

  /** One direct post of each destination's envelope. */
  private async sendDirect(
    auth: JsonRecord,
    destinations: readonly ResolvedDestination[],
    operation: SendOperation,
  ): Promise<AnonymousReceipt> {
    const { clientMessageId, deliveryClass } = operation;
    // Every device is sent at the same time. A failure for one device does
    // not stop the send to another.
    const receipts = await this.each(
      destinations,
      async ({ recipientPrefix, recipientRegistrationId, ...destination }) => {
        // The direct body names the registration of its one destination
        // beside the destination.
        const body = {
          auth,
          destination,
          contentKind: operation.contentKind,
          deliveryClass,
          messageId: clientMessageId,
          operationEpochMilliseconds: operation.operationEpochMilliseconds,
          envelope: bytesToBase64(
            concatBytes(bytes(recipientPrefix), operation.messageCiphertext),
          ),
          ...(recipientRegistrationId !== undefined && {
            recipientRegistrationId,
          }),
          ...(operation.deviceSets !== undefined && {
            deviceSets: operation.deviceSets,
          }),
        };
        const deliver = () =>
          this.fanOut.request(() => this.post("/delivery/send", body));
        let result: JsonRecord;
        let repeated = false;
        try {
          result = await deliver();
        } catch (error) {
          // A mailbox reset inside the durable acknowledgment hold answers
          // 503 DELIVERY_UNCERTAIN. The operation identifier makes one repeat
          // exact; a second uncertain answer reaches the caller. The repeat
          // is a new request with its own slot.
          if (
            deliveryClass === "ephemeral" ||
            !(error instanceof HostedAnonymousDeliveryError) ||
            error.code !== "DELIVERY_UNCERTAIN"
          )
            throw markDestinationRefusal(error, destination);
          repeated = true;
          result = await deliver().catch((repeatError: unknown) => {
            // The first request can have stored the copy, so a refused
            // repeat does not move the post to another route.
            if (repeatError instanceof DirectRouteRefusedError)
              throw new HostedAnonymousDeliveryError(401, "DELIVERY_FAILED");
            throw markDestinationRefusal(repeatError, destination);
          });
        }
        if (
          result.messageId !== clientMessageId ||
          (result.enqueuedAt !== undefined &&
            (!Number.isSafeInteger(result.enqueuedAt) ||
              (result.enqueuedAt as number) <= 0)) ||
          (result.duplicate !== undefined &&
            typeof result.duplicate !== "boolean") ||
          (result.expiresAt !== undefined &&
            (!Number.isSafeInteger(result.expiresAt) ||
              (result.expiresAt as number) <= 0)) ||
          (result.deviceSetChecked !== undefined &&
            result.deviceSetChecked !== true)
        )
          throw new Error("Anonymous delivery receipt is invalid");
        return {
          deviceSetChecked: result.deviceSetChecked === true,
          enqueuedAt: result.enqueuedAt as number | undefined,
          // The uncertain first request can have stored the copy that the
          // repeat finds, so the repeat's duplicate tells nothing.
          duplicate: repeated
            ? undefined
            : (result.duplicate as boolean | undefined),
          expiresAt: result.expiresAt as number | undefined,
        };
      },
    );
    return {
      messageId: clientMessageId,
      // The last destination in input order gives the server timestamp.
      serverTimestamp:
        receipts[receipts.length - 1]?.enqueuedAt ?? operation.timestamp,
      uuids404: [],
      ...aggregateRelayAcceptance(receipts),
      ...(receipts.length > 0 &&
        receipts.every((receipt) => receipt.deviceSetChecked) && {
          deviceSetChecked: true,
        }),
    };
  }
}

/**
 * The refused destinations of a declared group receipt. Each wire refusal
 * names a destination by its index in the posted list and gives the
 * Relay's result code.
 */
function groupRefusals(
  value: unknown,
  destinations: readonly ResolvedDestination[],
): { userId: string; deviceId: number; code: string }[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value))
    throw new Error("Anonymous group receipt is invalid");
  const seen = new Set<number>();
  return value.map((entry: unknown) => {
    if (
      !record(entry) ||
      !Number.isSafeInteger(entry.sequence) ||
      typeof entry.code !== "string" ||
      entry.code.length === 0 ||
      seen.has(entry.sequence as number)
    )
      throw new Error("Anonymous group receipt is invalid");
    const destination = destinations[entry.sequence as number];
    if (destination === undefined)
      throw new Error("Anonymous group receipt is invalid");
    seen.add(entry.sequence as number);
    return {
      userId: destination.accountAddress,
      deviceId: destination.deviceId,
      code: entry.code,
    };
  });
}
