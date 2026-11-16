/**
 * The first sync of a device link (wire contract section 11.4): device 1
 * sends one snapshot of account state to a newly linked own device.
 */
import type { StoredOutgoingDeviceMessage } from "../local/store/reliability";
import type { DefaultSignalProtocolClient } from "./client";
import {
  checkFirstSyncBundle,
  FIRST_SYNC_CONTENT_MAXIMUM_BYTES,
  FIRST_SYNC_DELIVERY_WIRE_MAXIMUM_BYTES,
  FIRST_SYNC_DOCUMENTED_CONTENT_BYTES,
  firstSyncBundleOf,
  newFirstSyncBundleId,
  type HostedSignalProtocolRelayFirstSyncBundle,
} from "./first-sync-bundle";
import { assertHostedSignalProtocolRelayDeviceManagement } from "./hosted-device-management";
import { HostedSignalProtocolRelayDeviceProvisioningError } from "./hosted-device-provisioning-error";
import { encodeDeliveryWire } from "./hosted-transport";
import { RelayWorkStopped } from "./signal-relay-work";

export type {
  HostedSignalProtocolRelayFirstSyncBundle,
  HostedSignalProtocolRelayFirstSyncCallback,
  HostedSignalProtocolRelayFirstSyncContact,
} from "./first-sync-bundle";

/** The device ID of the primary device, the only sender of a first sync. */
const PRIMARY_DEVICE_ID = 1;

function bytes(length: number): string {
  return `${length.toLocaleString("en-US")} bytes`;
}

/** The guidance that each size refusal gives. */
const FIRST_SYNC_SIZE_GUIDANCE =
  `Serialized content of ${bytes(FIRST_SYNC_DOCUMENTED_CONTENT_BYTES)} or less always fits. ` +
  "Send a smaller bundle.";

export interface HostedSignalProtocolRelayFirstSyncOptions {
  /**
   * Stops the send. The call then rejects with `CANCELLED`. A signal that
   * fires after the Relay accepted the copy does not stop the delivery.
   */
  readonly signal?: AbortSignal;
}

/**
 * @internal Throw a `RangeError` for a first-sync copy whose delivery wire
 * is larger than the inline payload limit of the Relay.
 */
export function checkFirstSyncDeliveryWire(
  copy: Pick<StoredOutgoingDeviceMessage, "ciphertext" | "messageType" | "timestamp">,
): void {
  const length = encodeDeliveryWire({
    ciphertext: copy.ciphertext,
    messageType: copy.messageType,
    timestamp: copy.timestamp,
  }).length;
  if (length > FIRST_SYNC_DELIVERY_WIRE_MAXIMUM_BYTES) {
    throw new RangeError(
      `The encrypted first sync has a delivery wire of ${bytes(length)}. ` +
        `The Relay accepts a delivery wire of ${bytes(FIRST_SYNC_DELIVERY_WIRE_MAXIMUM_BYTES)} or less. ` +
        FIRST_SYNC_SIZE_GUIDANCE,
    );
  }
}

function provisioningError(
  code: "NOT_PRIMARY" | "DEVICE_NOT_FOUND" | "CANCELLED",
  message: string,
  cause?: unknown,
): HostedSignalProtocolRelayDeviceProvisioningError {
  return new HostedSignalProtocolRelayDeviceProvisioningError(
    code,
    message,
    cause === undefined ? undefined : { cause },
  );
}

function cancelled(cause?: unknown): HostedSignalProtocolRelayDeviceProvisioningError {
  return provisioningError("CANCELLED", "The first sync was cancelled", cause);
}

/**
 * Send a first-sync bundle from device 1 to a newly linked own device
 * (wire contract section 11.4). Call it after the new device joined, for
 * example when `hosted.onOwnDevicesChanged` reports the device as added.
 * The new device gets the bundle in `hosted.onFirstSync`.
 *
 * The call encrypts one copy for the device. On a Relay that compares
 * device sets, the copy declares each own device. The Relay meters the
 * accepted copy as one message.
 *
 * Serialized content of 140,000 bytes or less fits in the copy, also in
 * the first message to the new device, which carries the PQXDH material.
 * The encrypted copy is about 1.8 times the serialized content. Larger
 * content can fail with a `RangeError` after the encryption.
 *
 * The call is not idempotent. Each call gives a new bundle ID, and the new
 * device applies each new bundle that is not older than the newest bundle
 * that it applied.
 *
 * @param client - The client of device 1
 * @param deviceId - The device ID of the new device. A safe integer of 2 or
 *   more.
 * @param bundle - The snapshot. It has at least one part.
 * @returns The ID of the bundle: 16 random bytes, as base64url with no
 *   padding
 * @throws HostedSignalProtocolRelayDeviceProvisioningError `NOT_PRIMARY`
 *   when the client is not device 1, `DEVICE_NOT_FOUND` when the own device
 *   list does not hold the device or the Relay accepted no copy for it, and
 *   `CANCELLED` when the signal fires or the client stops before the Relay
 *   accepted the copy
 * @throws TypeError for a bundle value of the wrong type, or for a content
 *   adapter with no `serializeFirstSync`. Each type check runs before each
 *   range check.
 * @throws RangeError for a device ID that is not a safe integer of 2 or
 *   more, for a bundle value out of range, for serialized content larger
 *   than 196,608 bytes, and for an encrypted copy whose delivery wire is
 *   larger than 262,144 bytes. The content check is an early check before
 *   the encryption, so content of 196,608 bytes or less can still fail the
 *   wire check. The wire check runs after the encryption and before the
 *   post.
 */
export async function sendHostedSignalProtocolRelayFirstSync(
  client: DefaultSignalProtocolClient,
  deviceId: number,
  bundle: HostedSignalProtocolRelayFirstSyncBundle,
  options: HostedSignalProtocolRelayFirstSyncOptions = {},
): Promise<{ readonly bundleId: string }> {
  assertHostedSignalProtocolRelayDeviceManagement(client);
  if (client.deviceId !== PRIMARY_DEVICE_ID) {
    throw provisioningError("NOT_PRIMARY", "Only device 1 can send a first sync");
  }
  // Each TypeError comes before each RangeError.
  const serialize = client.firstSyncSerializer();
  if (serialize === undefined) {
    throw new TypeError("The content adapter has no serializeFirstSync, so it cannot send a first sync.");
  }
  checkFirstSyncBundle(bundle);
  if (!Number.isSafeInteger(deviceId) || deviceId < 2) {
    throw new RangeError("The first-sync device ID must be a safe integer of 2 or more.");
  }
  if (options.signal?.aborted) throw cancelled(options.signal.reason);

  const bundleId = newFirstSyncBundleId();
  const createdAt = Date.now();
  const content = serialize({ version: 1, bundleId, createdAt, ...firstSyncBundleOf(bundle) });
  if (content.length > FIRST_SYNC_CONTENT_MAXIMUM_BYTES) {
    throw new RangeError(
      `The serialized first sync is ${bytes(content.length)}. ` +
        "The early check before the encryption refuses serialized content above " +
        `${bytes(FIRST_SYNC_CONTENT_MAXIMUM_BYTES)}. ` +
        FIRST_SYNC_SIZE_GUIDANCE,
    );
  }

  let result: Awaited<ReturnType<DefaultSignalProtocolClient["sendFirstSyncToOwnDevice"]>>;
  try {
    result = await client.sendFirstSyncToOwnDevice(content, deviceId, createdAt, {
      ...(options.signal && { signal: options.signal }),
      checkCopy: checkFirstSyncDeliveryWire,
    });
  } catch (error) {
    if (error instanceof RelayWorkStopped) throw cancelled(options.signal?.reason);
    throw error;
  }
  if (result !== "accepted") {
    throw provisioningError(
      "DEVICE_NOT_FOUND",
      result === "unlisted"
        ? `The own device list holds no device ${deviceId}`
        : `The Relay accepted no first-sync copy for device ${deviceId}`,
    );
  }
  return { bundleId };
}
