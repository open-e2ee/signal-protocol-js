/**
 * The provisioning channel of a device link: the capability probe, and the
 * socket on which the new device receives the envelope (wire contract
 * sections 3.2 and 4).
 *
 * A channel lives for 90 s. The Relay closes it with 4408 at the expiry, and
 * the new device then opens a new channel with new receiver keys and shows a
 * new link code. The client has no renewal timer of its own.
 */
import { secureZeroBytes } from "../internal/crypto";
import { websocketUrl } from "../internal/platform";
import type { HostedSignalProtocolRelayConnection } from "./hosted-connection";
import { HostedSignalProtocolRelayDeviceProvisioningError } from "./hosted-device-provisioning-error";
import { HostedSignalProtocolRelayHttpError } from "./hosted-http-error";
import {
  DEVICE_LINK_ADDRESS_BYTES,
  DEVICE_LINK_BODY_MAX_BYTES,
  formatDeviceLinkCode,
  generateDeviceLinkReceiverKeys,
  type DeviceLinkReceiverKeys,
} from "./device-link-envelope";
import { canonicalBase64, decodeBase64Url, decodeCanonicalBase64 } from "./hosted-registration-material";
import { getJson, identifiedEndpoint, record } from "./signal-relay-http";
import {
  HostedSignalProtocolRelayUpgradeRequiredError,
  SIGNAL_RELAY_PROTOCOL_TOKEN,
  signalRelayUpgradeRequired,
} from "./signal-relay-protocol";

/** The provisioning version that this SDK speaks. */
const PROVISIONING_VERSION = 1;
/** The largest Relay frame: an envelope frame of the largest body. */
const MAXIMUM_FRAME_CHARACTERS = 350_000;
/** The time from the socket open to the address frame. */
const HANDSHAKE_MILLISECONDS = 10_000;

/** @internal The `CANCELLED` refusal of a device link call. */
export function deviceLinkCancelled(): HostedSignalProtocolRelayDeviceProvisioningError {
  return new HostedSignalProtocolRelayDeviceProvisioningError(
    "CANCELLED",
    "The device link was cancelled",
  );
}

/** @internal Throw `CANCELLED` when `signal` fired. */
export function throwIfDeviceLinkCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) throw deviceLinkCancelled();
}

/**
 * @internal Settle with `promise`, or reject with `CANCELLED` when `signal`
 * fires first. The work of `promise` continues, so a request that the Relay
 * already received can still take effect.
 */
export async function raceDeviceLinkCancel<T>(
  promise: Promise<T>,
  signal: AbortSignal | undefined,
): Promise<T> {
  if (signal === undefined) return promise;
  throwIfDeviceLinkCancelled(signal);
  let onAbort: (() => void) | undefined;
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(deviceLinkCancelled());
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    return await Promise.race([promise, aborted]);
  } finally {
    signal.removeEventListener("abort", onAbort!);
  }
}

/** @internal Wait `milliseconds`, or reject with `CANCELLED` when `signal` fires. */
export async function waitForDeviceLink(milliseconds: number, signal: AbortSignal | undefined): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await raceDeviceLinkCancel(
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, milliseconds);
      }),
      signal,
    );
  } finally {
    clearTimeout(timer);
  }
}

/** @internal The `SIGNAL_RELAY_UNSUPPORTED` refusal of a device link call. */
export function deviceLinkUnsupported(cause?: unknown): HostedSignalProtocolRelayDeviceProvisioningError {
  return new HostedSignalProtocolRelayDeviceProvisioningError(
    "SIGNAL_RELAY_UNSUPPORTED",
    "The Signal Protocol Relay has no device link provisioning channel",
    cause === undefined ? undefined : { cause },
  );
}

/**
 * @internal Ask the Relay whether it serves the provisioning channel.
 *
 * - `available`: the Relay serves provisioning version 1.
 * - `unknown`: the request failed on the network. The caller continues, and
 *   the next route gives the answer.
 *
 * A 404, or a provisioning version other than 1, throws
 * `SIGNAL_RELAY_UNSUPPORTED`. A 426 throws
 * `HostedSignalProtocolRelayUpgradeRequiredError`, and a 429 throws a
 * retryable `HostedSignalProtocolRelayHttpError`.
 */
export async function probeHostedSignalProtocolRelayProvisioning(
  connection: HostedSignalProtocolRelayConnection,
): Promise<"available" | "unknown"> {
  let answer: unknown;
  try {
    answer = await getJson(
      connection,
      `/provisioning/connect?publishableKey=${encodeURIComponent(connection.publishableKey)}`,
    );
  } catch (error) {
    if (error instanceof HostedSignalProtocolRelayHttpError) {
      if (error.status === 404) throw deviceLinkUnsupported(error);
      throw error;
    }
    if (error instanceof HostedSignalProtocolRelayUpgradeRequiredError) throw error;
    return "unknown";
  }
  if (!record(answer) || answer.provisioningVersion !== PROVISIONING_VERSION) {
    throw deviceLinkUnsupported();
  }
  return "available";
}

/** The envelope that one provisioning channel delivered. */
export interface HostedDeviceLinkDelivery {
  /** The envelope body. */
  readonly envelope: Uint8Array;
  /** The channel address `A`, 16 bytes. */
  readonly address: Uint8Array;
  /** The receiver keys of the channel. The caller zeroes them after the open. */
  readonly keys: DeviceLinkReceiverKeys;
}

/** @internal Zero the private values of receiver keys. */
export function zeroDeviceLinkReceiverKeys(keys: DeviceLinkReceiverKeys): void {
  secureZeroBytes(keys.x25519PrivateKey);
  secureZeroBytes(keys.kemSecretKey);
}

/**
 * @internal Receive one device link envelope. Each channel gets new receiver
 * keys, and `onLinkCode` gets the code of each channel after its `ready`
 * frame. A 4408 close opens the next channel.
 */
export async function receiveHostedDeviceLinkEnvelope(options: {
  readonly connection: HostedSignalProtocolRelayConnection;
  readonly onLinkCode: (code: string) => void;
  readonly signal?: AbortSignal;
}): Promise<HostedDeviceLinkDelivery> {
  for (;;) {
    throwIfDeviceLinkCancelled(options.signal);
    const keys = await generateDeviceLinkReceiverKeys();
    let delivery: { readonly envelope: Uint8Array; readonly address: Uint8Array } | undefined;
    try {
      delivery = await openChannel(options, keys);
    } catch (error) {
      zeroDeviceLinkReceiverKeys(keys);
      throw error;
    }
    if (delivery !== undefined) return { ...delivery, keys };
    zeroDeviceLinkReceiverKeys(keys);
  }
}

function networkFailure(cause: unknown): Error {
  return new Error("Signal Protocol Relay request could not be completed", { cause });
}

function invalidFrame(): Error {
  return new Error("Signal Protocol Relay sent an invalid provisioning frame");
}

/** The error of a close before the envelope. */
function closeError(code: number, reason: string): Error {
  switch (code) {
    case 4400:
    case 4404:
      return deviceLinkUnsupported();
    case 4426:
      return signalRelayUpgradeRequired(426);
    case 4429:
      return new HostedSignalProtocolRelayHttpError(
        429,
        "QUOTA_EXCEEDED",
        "The Signal Protocol Relay refused the provisioning channel",
        { retryable: true },
      );
    case 4403:
    case 4422:
      return new HostedSignalProtocolRelayHttpError(
        code - 4000,
        reason === "" ? "UNKNOWN" : reason,
        "The Signal Protocol Relay closed the provisioning channel",
      );
    default:
      // 1011 and every other close, for example a lost connection, is a
      // network failure that the caller can retry.
      return networkFailure({ code, reason });
  }
}

/**
 * Open one channel. It resolves with the delivery, or with `undefined` when
 * the channel expired.
 */
function openChannel(
  options: {
    readonly connection: HostedSignalProtocolRelayConnection;
    readonly onLinkCode: (code: string) => void;
    readonly signal?: AbortSignal;
  },
  keys: DeviceLinkReceiverKeys,
): Promise<{ readonly envelope: Uint8Array; readonly address: Uint8Array } | undefined> {
  const { connection, onLinkCode, signal } = options;
  return new Promise((resolve, reject) => {
    const protocolToken = SIGNAL_RELAY_PROTOCOL_TOKEN;
    const url = websocketUrl(`${identifiedEndpoint(connection)}/provisioning/connect`, [
      ["publishableKey", connection.publishableKey],
    ]);
    let socket: WebSocket;
    try {
      socket = new WebSocket(url, [protocolToken]);
    } catch (cause) {
      reject(networkFailure(cause));
      return;
    }
    let phase: "opening" | "open" | "address" | "ready" = "opening";
    let address: Uint8Array | undefined;
    let settled = false;
    const onAbort = () => fail(deviceLinkCancelled());
    const handshake = setTimeout(() => fail(networkFailure("handshake")), HANDSHAKE_MILLISECONDS);
    const settle = (finish: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(handshake);
      signal?.removeEventListener("abort", onAbort);
      finish();
    };
    function fail(error: unknown): void {
      settle(() => reject(error));
      try {
        socket.close(1000);
      } catch {
        // The socket is already closed.
      }
    }
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted === true) {
      onAbort();
      return;
    }

    socket.addEventListener("open", () => {
      if (settled) return;
      if (socket.protocol !== protocolToken) {
        fail(networkFailure("protocol"));
        return;
      }
      phase = "open";
    });
    socket.addEventListener("message", (event: MessageEvent) => {
      if (settled) return;
      try {
        if (typeof event.data !== "string" || event.data.length > MAXIMUM_FRAME_CHARACTERS) {
          throw invalidFrame();
        }
        const frame: unknown = JSON.parse(event.data);
        if (!record(frame)) throw invalidFrame();
        if (frame.type === "address" && phase === "open") {
          if (typeof frame.address !== "string" || !Number.isSafeInteger(frame.expiresAt)) {
            throw invalidFrame();
          }
          address = decodeBase64Url(frame.address, "Signal Protocol Relay provisioning address");
          if (address.length !== DEVICE_LINK_ADDRESS_BYTES) throw invalidFrame();
          clearTimeout(handshake);
          phase = "address";
          socket.send(JSON.stringify({ type: "kem", publicKey: canonicalBase64(keys.kemPublicKey) }));
          return;
        }
        if (frame.type === "ready" && phase === "address") {
          phase = "ready";
          const channelAddress = address!;
          void formatDeviceLinkCode(channelAddress, keys).then(
            (code) => {
              if (settled) return;
              try {
                onLinkCode(code);
              } catch (error) {
                fail(error);
              }
            },
            fail,
          );
          return;
        }
        if (frame.type === "envelope" && phase === "ready") {
          const envelope = decodeCanonicalBase64(frame.envelope, "Signal Protocol Relay provisioning envelope");
          if (envelope.length > DEVICE_LINK_BODY_MAX_BYTES) throw invalidFrame();
          const channelAddress = address!;
          settle(() => resolve({ envelope, address: channelAddress }));
          try {
            socket.close(1000);
          } catch {
            // The Relay closes the socket after the envelope.
          }
          return;
        }
        throw invalidFrame();
      } catch (error) {
        fail(error instanceof SyntaxError ? invalidFrame() : error);
      }
    });
    socket.addEventListener("close", (event: CloseEvent) => {
      if (settled) return;
      if (event.code === 4408) {
        settle(() => resolve(undefined));
        return;
      }
      fail(closeError(event.code, event.reason));
    });
  });
}
