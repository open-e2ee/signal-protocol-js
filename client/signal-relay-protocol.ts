/**
 * The Relay protocol version that this SDK speaks, and its carriers.
 *
 * The mailbox socket offers the version as a subprotocol token, because a
 * browser `WebSocket` cannot set headers, and the Relay must echo it. Each
 * public HTTP route except the connection document carries the version in a
 * header. The header is `x-signal-relay-protocol`, the token is
 * `signal-relay.v<N>`, and the device token entry is `signal-relay.auth.`.
 *
 * A Relay that no longer serves the version refuses it with
 * `UPGRADE_REQUIRED`: close code 4426 on the socket, and the body code on
 * HTTP. That refusal is terminal for this SDK. A Relay that does not serve
 * the version yet refuses it with the retryable `PROTOCOL_UNSUPPORTED`:
 * close code 4400 on the socket, and the body code on HTTP. The Relay
 * refuses the version before it reads the request, so the refused request
 * had no effect.
 *
 * The SDK offers only `RELAY_PROTOCOL_VERSION`. It does not offer another
 * version after a refusal.
 */
import { stringToBytes } from "../internal/crypto";
import { HostedSignalProtocolRelayHttpError } from "./hosted-http-error";

/**
 * The Relay protocol version that this SDK speaks. Each request and each
 * socket of a client offers it.
 *
 * Version 2 added `DELIVERY_ALREADY_ACCEPTED`: the Relay refuses a post
 * before it stores anything, because it already holds an accepted post
 * under the message ID. Version 3 keeps that behavior and uses the
 * signal prefix names: its carriers, the labels of its signed proofs, the
 * response fields `signalRelayScopeId` and `signalRelayReceipts`, and the
 * device token issuer and audience.
 */
export const RELAY_PROTOCOL_VERSION = 3;

/**
 * The first Relay protocol version. A request without the header is this
 * version. This SDK does not speak it.
 */
const FIRST_RELAY_PROTOCOL_VERSION = 1;

/** The subprotocol token that the socket offers and the Relay must echo. */
export const SIGNAL_RELAY_PROTOCOL_TOKEN = `signal-relay.v${RELAY_PROTOCOL_VERSION}`;

/** The prefix of the subprotocol entry that carries the device token. */
export const SIGNAL_RELAY_AUTH_PROTOCOL_PREFIX = "signal-relay.auth.";

/** The HTTP header that carries the version. */
const SIGNAL_RELAY_PROTOCOL_HEADER = "x-signal-relay-protocol";

/** The headers that put the protocol version on an HTTP request. */
export function signalRelayProtocolHeaders(): Record<string, string> {
  return { [SIGNAL_RELAY_PROTOCOL_HEADER]: String(RELAY_PROTOCOL_VERSION) };
}

/**
 * The labels of the device proofs that the SDK signs. Each label ends in a
 * NUL byte.
 */
export interface SignalRelayProofLabels {
  /** Prefixes each device challenge that the device key signs. */
  readonly deviceAuthentication: Uint8Array;
  /** Starts the challenge of a device link. */
  readonly deviceLinkChallenge: Uint8Array;
  /** Starts the challenge of a device token renewal. */
  readonly deviceTokenRefreshChallenge: Uint8Array;
  /** Starts the challenge of a recovery. */
  readonly recoveryChallenge: Uint8Array;
  /** Starts the challenge of a registration. */
  readonly registrationChallenge: Uint8Array;
  /** Prefixes a sender certificate request that the device key signs. */
  readonly senderCertificateRequest: Uint8Array;
}

/** The proof labels of `RELAY_PROTOCOL_VERSION`. */
export const SIGNAL_RELAY_PROOF_LABELS: SignalRelayProofLabels = {
  deviceAuthentication: stringToBytes("signal-relay-device-authentication-v2\0"),
  deviceLinkChallenge: stringToBytes("signal-relay-device-link-challenge-v2\0"),
  deviceTokenRefreshChallenge: stringToBytes(
    "signal-relay-device-token-refresh-challenge-v2\0",
  ),
  recoveryChallenge: stringToBytes("signal-relay-recovery-challenge-v2\0"),
  registrationChallenge: stringToBytes("signal-relay-registration-challenge-v2\0"),
  senderCertificateRequest: stringToBytes(
    "signal-relay-sender-certificate-request-v2\0",
  ),
};

/**
 * The Relay no longer serves the protocol version of this SDK. The same
 * request fails again until the application ships a newer SDK, so the SDK
 * does not retry it. The mailbox subscription stops with the reason
 * `upgrade-required` for the same refusal on its socket.
 */
export class HostedSignalProtocolRelayUpgradeRequiredError extends Error {
  /** The optional reference of the HTTP response that refused this request. */
  declare public readonly requestId?: string;
  public readonly code = "UPGRADE_REQUIRED";
  /** The HTTP status of the refusal, 426 from a current Relay. */
  public readonly status: number;
  /** Always false: only a newer SDK can send the request again. */
  public readonly retryable = false;

  /**
   * @param status - The HTTP status of the refusal.
   * @param version - The Relay protocol version that the client sent. The
   * message names it. Without it, the message names version 1.
   */
  public constructor(status: number, version?: number) {
    super(
      `The Relay no longer accepts Relay protocol version ${version ?? FIRST_RELAY_PROTOCOL_VERSION}. Update the SDK.`,
    );
    this.name = "HostedSignalProtocolRelayUpgradeRequiredError";
    this.status = status;
  }
}

/**
 * The refusal of `RELAY_PROTOCOL_VERSION`, the version that each request of
 * this SDK sends, at the HTTP `status`.
 */
export function signalRelayUpgradeRequired(
  status: number,
): HostedSignalProtocolRelayUpgradeRequiredError {
  return new HostedSignalProtocolRelayUpgradeRequiredError(status, RELAY_PROTOCOL_VERSION);
}

/**
 * Throws `HostedSignalProtocolRelayUpgradeRequiredError` when a Relay error body has the
 * code `UPGRADE_REQUIRED`, at any error status. The body code is the
 * contract, not the status. The error names `RELAY_PROTOCOL_VERSION`, the
 * protocol version that the request sent.
 */
export function throwIfUpgradeRequired(status: number, body: unknown): void {
  if (
    typeof body === "object" &&
    body !== null &&
    "error" in body &&
    typeof body.error === "object" &&
    body.error !== null &&
    "code" in body.error &&
    body.error.code === "UPGRADE_REQUIRED"
  )
    throw signalRelayUpgradeRequired(status);
}

/**
 * Throws the retryable `HostedSignalProtocolRelayHttpError` with the code
 * `PROTOCOL_UNSUPPORTED` when a Relay error body has that code. It is the
 * error that an identified HTTP route gives for the same answer. The Relay
 * sends it for a version above the newest one that it serves, and it can
 * serve the version later, so the refusal is always retryable.
 */
export function throwIfProtocolUnsupported(status: number, body: unknown): void {
  if (
    typeof body !== "object" ||
    body === null ||
    !("error" in body) ||
    typeof body.error !== "object" ||
    body.error === null ||
    !("code" in body.error) ||
    body.error.code !== "PROTOCOL_UNSUPPORTED"
  )
    return;
  const message =
    "message" in body.error && typeof body.error.message === "string"
      ? body.error.message
      : "Signal Protocol Relay request failed";
  throw markSignalProtocolRelayAnswerVersion(
    new HostedSignalProtocolRelayHttpError(status, "PROTOCOL_UNSUPPORTED", message, {
      retryable: true,
    }),
  );
}

/** The protocol version of the request that each Relay error answers. */
const answerVersions = new WeakMap<object, number>();

/**
 * Record that `error` is the Relay's answer to a request that sent protocol
 * `version`, which is `RELAY_PROTOCOL_VERSION` by default. The meaning of
 * some codes depends on that version. Returns the same error.
 */
export function markSignalProtocolRelayAnswerVersion<T extends object>(
  error: T,
  version: number = RELAY_PROTOCOL_VERSION,
): T {
  answerVersions.set(error, version);
  return error;
}

/**
 * The protocol version of the request that a Relay error answers, or
 * undefined when no hosted carrier marked the error. A custom relay marks
 * no error.
 */
export function signalRelayAnswerVersion(error: unknown): number | undefined {
  return error !== null && typeof error === "object"
    ? answerVersions.get(error)
    : undefined;
}
