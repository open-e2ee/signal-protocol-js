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
import type { DeliveryClass, SealedSenderAuth } from "../remote/relay/types";
import type { Base64 } from "../types";
import { SealedSenderAuthError } from "../types/errors";
import { FanOutError, type BoundedFanOut } from "../utils/bounded-fan-out";
import type { HostedRelayConnection } from "./hosted-connection";
import { aggregateRelayAcceptance } from "./relay-acceptance";
import { markRelayDeviceRefusal } from "./relay-device-refusal";
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
    private readonly resolveDestination: (
      account: string,
      deviceId: number,
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
        const code = record(value.error) ? value.error.code : undefined;
        const authenticationCode =
          path === "/delivery/send"
            ? "ANONYMOUS_AUTH_REJECTED"
            : "GROUP_CREDENTIAL_REJECTED";
        if (response.status === 401 && code === authenticationCode)
          throw new SealedSenderAuthError();
        const safeCodes = [
          "NOT_FOUND",
          "STALE_DEVICE",
          "RETRY_CONFLICT",
          "OPERATION_EXPIRED",
          "DELIVERY_UNCERTAIN",
        ];
        throw new HostedAnonymousDeliveryError(
          response.status,
          typeof code === "string" && safeCodes.includes(code)
            ? code
            : "DELIVERY_FAILED",
        );
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
  ): Promise<{
    messageId: string;
    serverTimestamp: number;
    uuids404: string[];
    duplicate?: boolean;
    expiresAt?: number;
  }> {
    const header = timestampHeader(timestamp);
    if (
      !clientMessageId ||
      clientMessageId.length > 128 ||
      !["user-visible", "background-sync", "ephemeral"].includes(deliveryClass)
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
    // lookup for each account.
    const destinations = await this.each(
      recipients.flatMap((entry) =>
        entry.devices.map((device) => ({ entry, deviceId: device.deviceId })),
      ),
      async ({ entry, deviceId }) => ({
        ...(await this.resolveDestination(entry.accountAddress, deviceId)),
        recipientPrefix: bytesToBase64(entry.prefix),
      }),
    );
    if (auth.type === "groupSendToken") {
      const result = await this.fanOut.request(() =>
        this.post("/groups/send", {
          auth: {
            type: auth.type,
            groupSendToken: bytesToBase64(auth.groupSendToken),
          },
          body: bytesToBase64(parsed.messageCiphertext),
          destinations,
          deliveryClass,
          logicalSendId: clientMessageId,
          operationEpochMilliseconds,
        }),
      );
      if (
        result.logicalSendId !== clientMessageId ||
        result.replayable !== true ||
        typeof result.duplicate !== "boolean" ||
        !Number.isSafeInteger(result.acceptedDestinations) ||
        (result.acceptedDestinations as number) < 0 ||
        (result.acceptedDestinations as number) > destinations.length
      )
        throw new Error("Anonymous group receipt is invalid");
      // Fan-out acceptance has no recipient enqueue time. Keep the original
      // message time. A duplicate fan-out is one that the Relay had already
      // accepted; it does not tell that each destination stored a copy.
      return {
        messageId: clientMessageId,
        serverTimestamp: timestamp,
        uuids404: [],
        duplicate: result.duplicate as boolean,
      };
    }
    // Every device is sent at the same time. A failure for one device does
    // not stop the send to another.
    const receipts = await this.each(
      destinations,
      async ({ recipientPrefix, ...destination }) => {
        const body = {
          auth,
          destination,
          deliveryClass,
          messageId: clientMessageId,
          operationEpochMilliseconds,
          envelope: bytesToBase64(
            concatBytes(bytes(recipientPrefix), parsed.messageCiphertext),
          ),
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
              (result.expiresAt as number) <= 0))
        )
          throw new Error("Anonymous delivery receipt is invalid");
        return {
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
      serverTimestamp: receipts[receipts.length - 1]?.enqueuedAt ?? timestamp,
      uuids404: [],
      ...aggregateRelayAcceptance(receipts),
    };
  }
}
