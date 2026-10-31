/**
 * The Relay protocol version that this SDK speaks, and its carriers.
 *
 * The mailbox socket offers the version as a subprotocol token, because a
 * browser `WebSocket` cannot set headers, and the Relay must echo it. Each
 * public HTTP route except the connection document carries the version in
 * the `x-open-e2ee-relay-protocol` header. A Relay that no longer serves the
 * version refuses it with `UPGRADE_REQUIRED`: close code 4426 on the socket,
 * and the body code on HTTP. That refusal is terminal for this SDK. A Relay
 * that does not serve the version yet refuses it with the retryable
 * `PROTOCOL_UNSUPPORTED`. The SDK never sends an older version in its place.
 */

/**
 * The Relay protocol version that this SDK speaks by default. Each client
 * holds its own version, which starts at this one.
 *
 * Version 2 adds `DELIVERY_ALREADY_ACCEPTED`: the Relay refuses a post
 * before it stores anything, because it already holds an accepted post
 * under the message ID. Under version 1 the Relay sends RETRY_CONFLICT for
 * the same refusal.
 */
export const RELAY_PROTOCOL_VERSION = 2;

/** The first Relay protocol version. A request without the header is this version. */
const FIRST_RELAY_PROTOCOL_VERSION = 1;

/** The prefix of a protocol version token. The version number follows it. */
const RELAY_PROTOCOL_TOKEN_PREFIX = "open-e2ee-relay.v";

/** The prefix of the subprotocol token that carries the device token. */
export const RELAY_AUTH_PROTOCOL_PREFIX = "open-e2ee-relay.auth.";

/** The HTTP header that carries the protocol version. */
export const RELAY_PROTOCOL_HEADER = "x-open-e2ee-relay-protocol";

/** The subprotocol token of a protocol version, for example `open-e2ee-relay.v1`. */
export function relayProtocolToken(version: number): string {
  return `${RELAY_PROTOCOL_TOKEN_PREFIX}${version}`;
}

/** The headers that put a protocol version on an HTTP request. */
export function relayProtocolHeadersFor(version: number): Record<string, string> {
  return { [RELAY_PROTOCOL_HEADER]: String(version) };
}

/** The headers that put this SDK's default protocol version on an HTTP request. */
export function relayProtocolHeaders(): Record<string, string> {
  return relayProtocolHeadersFor(RELAY_PROTOCOL_VERSION);
}

/**
 * The Relay no longer serves the protocol version of this SDK. The same
 * request fails again until the application ships a newer SDK, so the SDK
 * does not retry it. The mailbox subscription stops with the reason
 * `upgrade-required` for the same refusal on its socket.
 */
export class HostedRelayUpgradeRequiredError extends Error {
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
 * Throws `HostedRelayUpgradeRequiredError` when a Relay error body has the
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
    throw new HostedRelayUpgradeRequiredError(status, version);
}

/** The protocol version of the request that each Relay error answers. */
const answerVersions = new WeakMap<object, number>();

/**
 * Record that `error` is the Relay's answer to a request that sent protocol
 * `version`. The meaning of some codes depends on that version. Returns
 * the same error.
 */
export function markRelayAnswerVersion<T extends object>(error: T, version: number): T {
  answerVersions.set(error, version);
  return error;
}

/**
 * The protocol version of the request that a Relay error answers, or
 * undefined when no hosted carrier marked the error. A custom relay marks
 * no error.
 */
export function relayAnswerVersion(error: unknown): number | undefined {
  return error !== null && typeof error === "object"
    ? answerVersions.get(error)
    : undefined;
}
