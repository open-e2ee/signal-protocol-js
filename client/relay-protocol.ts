/**
 * The Relay protocol version that this SDK speaks, and its carriers.
 *
 * The mailbox socket offers the version as a subprotocol token, because a
 * browser `WebSocket` cannot set headers, and the Relay must echo it. Each
 * public HTTP route except the connection document carries the version in
 * the `x-open-e2ee-relay-protocol` header. A Relay that no longer serves the
 * version refuses it with `UPGRADE_REQUIRED`: close code 4426 on the socket,
 * and the body code on HTTP. That refusal is terminal for this SDK.
 */

/** The Relay protocol version that this SDK speaks. */
export const RELAY_PROTOCOL_VERSION = 1;

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

/** The headers that put this SDK's protocol version on an HTTP request. */
export function relayProtocolHeaders(): Record<string, string> {
  return { [RELAY_PROTOCOL_HEADER]: String(RELAY_PROTOCOL_VERSION) };
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

  public constructor(status: number) {
    super(
      `The Relay no longer accepts Relay protocol version ${RELAY_PROTOCOL_VERSION}. Update the SDK.`,
    );
    this.name = "HostedRelayUpgradeRequiredError";
    this.status = status;
  }
}

/**
 * Throws `HostedRelayUpgradeRequiredError` when a Relay error body has the
 * code `UPGRADE_REQUIRED`, at any error status. The body code is the
 * contract, not the status.
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
    throw new HostedRelayUpgradeRequiredError(status);
}
