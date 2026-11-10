/**
 * The Relay protocol version that this SDK speaks, and its carriers.
 *
 * The mailbox socket offers the version as a subprotocol token, because a
 * browser `WebSocket` cannot set headers, and the Relay must echo it. Each
 * public HTTP route except the connection document carries the version in a
 * header. Versions 1 and 2 use the header `x-open-e2ee-relay-protocol`, the
 * token `open-e2ee-relay.v<N>`, and the device token entry
 * `open-e2ee-relay.auth.`. Version 3 and later use the header
 * `x-signal-relay-protocol`, the token `signal-relay.v<N>`, and the entry
 * `signal-relay.auth.`. Each version rides only on its own carrier.
 *
 * A Relay that no longer serves the version refuses it with
 * `UPGRADE_REQUIRED`: close code 4426 on the socket, and the body code on
 * HTTP. That refusal is terminal for this SDK. A Relay that does not serve
 * the version yet refuses it with the retryable `PROTOCOL_UNSUPPORTED`:
 * close code 4400 on the socket, and the body code on HTTP. The Relay
 * refuses the version before it reads the request, so the refused request
 * had no effect.
 *
 * A client offers version 3 first. When the Relay refuses version 3 with
 * `PROTOCOL_UNSUPPORTED`, the client offers version 2 from then on and sends
 * the refused request again. A client whose version the caller selected
 * never offers another version.
 */
import { stringToBytes } from "../internal/crypto";

/**
 * The Relay protocol version that this SDK speaks by default. Each client
 * holds its own version, which starts at this one.
 *
 * Version 2 adds `DELIVERY_ALREADY_ACCEPTED`: the Relay refuses a post
 * before it stores anything, because it already holds an accepted post
 * under the message ID. Under version 1 the Relay sends RETRY_CONFLICT for
 * the same refusal. Version 3 keeps the behavior of version 2 and uses the
 * signal prefix names: its carriers, the labels of its signed proofs, the
 * response fields `signalRelayScopeId` and `signalRelayReceipts`, and the
 * device token issuer and audience.
 */
export const RELAY_PROTOCOL_VERSION = 3;

/** The first Relay protocol version. A request without the header is this version. */
const FIRST_RELAY_PROTOCOL_VERSION = 1;

/** The first version that uses the signal prefix names. */
const SIGNAL_RELAY_PROTOCOL_V3 = 3;

/** The version that a client offers after the Relay refuses version 3. */
const SIGNAL_RELAY_PROTOCOL_FALLBACK = 2;

/** The prefix of a version 1 or 2 token. The version number follows it. */
const RELAY_PROTOCOL_TOKEN_PREFIX = "open-e2ee-relay.v";

/** The prefix of a version 3 or later token. The version number follows it. */
const SIGNAL_RELAY_PROTOCOL_TOKEN_PREFIX = "signal-relay.v";

/**
 * The prefix of the subprotocol entry that carries the device token on
 * versions 1 and 2.
 */
export const RELAY_AUTH_PROTOCOL_PREFIX = "open-e2ee-relay.auth.";

/** The prefix of the device token entry on version 3 and later. */
const SIGNAL_RELAY_AUTH_PROTOCOL_PREFIX = "signal-relay.auth.";

/** The HTTP header that carries versions 1 and 2. */
export const RELAY_PROTOCOL_HEADER = "x-open-e2ee-relay-protocol";

/** The HTTP header that carries version 3 and later. */
const SIGNAL_RELAY_PROTOCOL_HEADER = "x-signal-relay-protocol";

/** True when a version uses the signal prefix names. */
function usesSignalRelayNames(version: number): boolean {
  return version >= SIGNAL_RELAY_PROTOCOL_V3;
}

/**
 * The subprotocol token of a protocol version, on the carrier of that
 * version: `open-e2ee-relay.v2` or `signal-relay.v3`.
 */
export function signalRelayProtocolToken(version: number): string {
  return `${
    usesSignalRelayNames(version)
      ? SIGNAL_RELAY_PROTOCOL_TOKEN_PREFIX
      : RELAY_PROTOCOL_TOKEN_PREFIX
  }${version}`;
}

/** The prefix of the subprotocol entry that carries the device token for a version. */
export function signalRelayAuthProtocolPrefix(version: number): string {
  return usesSignalRelayNames(version)
    ? SIGNAL_RELAY_AUTH_PROTOCOL_PREFIX
    : RELAY_AUTH_PROTOCOL_PREFIX;
}

/** The headers that put a protocol version on an HTTP request, on the carrier of that version. */
export function signalRelayProtocolHeadersFor(version: number): Record<string, string> {
  return {
    [usesSignalRelayNames(version)
      ? SIGNAL_RELAY_PROTOCOL_HEADER
      : RELAY_PROTOCOL_HEADER]: String(version),
  };
}

/** The headers that put this SDK's default protocol version on an HTTP request. */
export function signalRelayProtocolHeaders(): Record<string, string> {
  return signalRelayProtocolHeadersFor(RELAY_PROTOCOL_VERSION);
}

/**
 * The labels of the device proofs that a protocol version signs. Each label
 * ends in a NUL byte. Each version frames the payload after the label in the
 * same way.
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

/**
 * The labels of versions 1 and 2. They are historical constants: a Relay
 * verifies their exact bytes until it retires both versions.
 */
const SIGNAL_RELAY_V1_PROOF_LABELS: SignalRelayProofLabels = {
  deviceAuthentication: stringToBytes("OpenE2EE Relay device authentication v1\0"),
  deviceLinkChallenge: stringToBytes("OpenE2EE Relay device link challenge v1\0"),
  deviceTokenRefreshChallenge: stringToBytes(
    "OpenE2EE Relay device token refresh challenge v1\0",
  ),
  recoveryChallenge: stringToBytes("OpenE2EE Relay recovery challenge v1\0"),
  registrationChallenge: stringToBytes("OpenE2EE Relay registration challenge v1\0"),
  senderCertificateRequest: stringToBytes(
    "OpenE2EE Relay sender certificate request v1\0",
  ),
};

/** The labels of version 3 and later. */
const SIGNAL_RELAY_V3_PROOF_LABELS: SignalRelayProofLabels = {
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
 * The proof labels of a protocol version. Without a version, the labels of
 * version 1, which a Relay also reads for a request without a version.
 */
export function signalRelayProofLabels(
  version: number = FIRST_RELAY_PROTOCOL_VERSION,
): SignalRelayProofLabels {
  return usesSignalRelayNames(version)
    ? SIGNAL_RELAY_V3_PROOF_LABELS
    : SIGNAL_RELAY_V1_PROOF_LABELS;
}

/**
 * The protocol version that one client offers. Every carrier of the client
 * reads it for each request. An unselected offer starts at
 * `RELAY_PROTOCOL_VERSION` and moves to version 2 after the Relay refuses
 * version 3 with `PROTOCOL_UNSUPPORTED`. It stays at version 2 for the
 * life of the client. A selected offer keeps its version.
 */
export class SignalRelayProtocolOffer {
  #version: number;
  readonly #selected: boolean;

  /** @param version - The selected version. Without it, the offer can fall back. */
  public constructor(version?: number) {
    this.#selected = version !== undefined;
    this.#version = version ?? RELAY_PROTOCOL_VERSION;
  }

  /** The version that the next request offers. */
  public get version(): number {
    return this.#version;
  }

  /**
   * Records that the Relay refused `sent` with `PROTOCOL_UNSUPPORTED`.
   * Returns true when the client now offers version 2 in place of the
   * refused version, so the caller sends the request again.
   */
  public refused(sent: number): boolean {
    if (this.#selected || !usesSignalRelayNames(sent)) return false;
    this.#version = SIGNAL_RELAY_PROTOCOL_FALLBACK;
    return true;
  }
}

/** The offer of `value`, or a new unselected offer when `value` is undefined. */
export function signalRelayProtocolOffer(
  value?: number | SignalRelayProtocolOffer,
): SignalRelayProtocolOffer {
  return value instanceof SignalRelayProtocolOffer
    ? value
    : new SignalRelayProtocolOffer(value);
}

/** The request offered a version that the client no longer offers. */
class SignalRelayProtocolFallBack extends Error {
  public constructor() {
    super("The Relay does not serve the offered protocol version.");
    this.name = "SignalRelayProtocolFallBack";
  }
}

/** True when a Relay error body has the code `PROTOCOL_UNSUPPORTED`. */
function protocolUnsupported(body: unknown): boolean {
  return (
    typeof body === "object" &&
    body !== null &&
    "error" in body &&
    typeof body.error === "object" &&
    body.error !== null &&
    "code" in body.error &&
    body.error.code === "PROTOCOL_UNSUPPORTED"
  );
}

/**
 * Throws inside `sendOnSignalRelayProtocol` when a Relay error body refuses
 * `sent` with `PROTOCOL_UNSUPPORTED` and `offer` falls back. Otherwise the
 * caller handles the error body as before.
 */
export function throwIfProtocolFallBack(
  offer: SignalRelayProtocolOffer,
  sent: number,
  body: unknown,
): void {
  if (protocolUnsupported(body) && offer.refused(sent))
    throw new SignalRelayProtocolFallBack();
}

/**
 * Sends one request with the version that `offer` holds. The request gets
 * the version and builds its headers and its signed fields from it. When the
 * Relay refuses version 3 and the offer falls back, the request runs once
 * more with version 2.
 */
export async function sendOnSignalRelayProtocol<T>(
  offer: SignalRelayProtocolOffer,
  send: (version: number) => Promise<T>,
): Promise<T> {
  try {
    return await send(offer.version);
  } catch (error) {
    if (!(error instanceof SignalRelayProtocolFallBack)) throw error;
    return send(offer.version);
  }
}

/**
 * The value of a response field that version 3 renamed. Version 3 sends the
 * field under `current`, and versions 1 and 2 send it under `earlier`. The
 * result is undefined when neither name is present. Two different values
 * under the two names throw an error with the message `invalid`.
 */
export function signalRelayRenamedField(
  value: Readonly<Record<string, unknown>>,
  current: string,
  earlier: string,
  invalid: string,
): unknown {
  const named = value[current];
  const earlierNamed = value[earlier];
  if (named !== undefined && earlierNamed !== undefined && named !== earlierNamed)
    throw new Error(invalid);
  return named ?? earlierNamed;
}

/**
 * The Relay no longer serves the protocol version of this SDK. The same
 * request fails again until the application ships a newer SDK, so the SDK
 * does not retry it. The mailbox subscription stops with the reason
 * `upgrade-required` for the same refusal on its socket.
 */
export class HostedSignalProtocolRelayUpgradeRequiredError extends Error {
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
    this.name = "HostedRelayUpgradeRequiredError";
    this.status = status;
  }
}

/**
 * Throws `HostedSignalProtocolRelayUpgradeRequiredError` when a Relay error body has the
 * code `UPGRADE_REQUIRED`, at any error status. The body code is the
 * contract, not the status. The error names `version`, the protocol version
 * that the request sent.
 */
export function throwIfUpgradeRequired(
  status: number,
  body: unknown,
  version?: number,
): void {
  if (
    typeof body === "object" &&
    body !== null &&
    "error" in body &&
    typeof body.error === "object" &&
    body.error !== null &&
    "code" in body.error &&
    body.error.code === "UPGRADE_REQUIRED"
  )
    throw new HostedSignalProtocolRelayUpgradeRequiredError(status, version);
}

/** The protocol version of the request that each Relay error answers. */
const answerVersions = new WeakMap<object, number>();

/**
 * Record that `error` is the Relay's answer to a request that sent protocol
 * `version`. The meaning of some codes depends on that version. Returns
 * the same error.
 */
export function markSignalProtocolRelayAnswerVersion<T extends object>(error: T, version: number): T {
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

// Names before the Signal Protocol Relay rename. SDK 15.0.0 removes them.
/** @deprecated Use `HostedSignalProtocolRelayUpgradeRequiredError`. SDK 15.0.0 removes this name. */
export const HostedRelayUpgradeRequiredError = HostedSignalProtocolRelayUpgradeRequiredError;
/** @deprecated Use `HostedSignalProtocolRelayUpgradeRequiredError`. SDK 15.0.0 removes this name. */
export type HostedRelayUpgradeRequiredError = HostedSignalProtocolRelayUpgradeRequiredError;
