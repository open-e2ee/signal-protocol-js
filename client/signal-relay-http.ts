import type { HostedSignalProtocolRelayConnection } from "./hosted-connection";
import { HostedSignalProtocolRelayHttpError } from "./hosted-http-error";
import { throwIfDeviceRevoked } from "./hosted-device-standing";
import {
  markSignalProtocolRelayAnswerVersion,
  sendOnSignalRelayProtocol,
  signalRelayProtocolHeadersFor,
  throwIfProtocolFallBack,
  throwIfUpgradeRequired,
  type SignalRelayProtocolOffer,
} from "./signal-relay-protocol";
import {
  signalProtocolRelayRequestNotCompleted,
  withSignalProtocolRelayRequestDeadline,
} from "./signal-relay-request-deadline";

const MAXIMUM_RESPONSE_BYTES = 1024 * 1024;

export type JsonRecord = Record<string, unknown>;

export function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function identifiedEndpoint(connection: HostedSignalProtocolRelayConnection): string {
  return connection.protocolEndpoint.replace(/\/$/u, "");
}

/**
 * Read the body of a Relay answer. An error answer throws, and the error
 * records `signalRelayProtocolVersion`, the protocol version of the request that
 * it answers. When the Relay refuses that version and `offer` falls back,
 * the answer throws for `sendOnSignalRelayProtocol`, which sends the request
 * again.
 */
export async function parseResponse(
  response: Response,
  signalRelayProtocolVersion: number,
  offer: SignalRelayProtocolOffer,
): Promise<unknown> {
  const body = await response.text();
  if (body.length > MAXIMUM_RESPONSE_BYTES) {
    throw new Error("Signal Protocol Relay response is too large");
  }
  if (response.ok && response.status === 204) {
    if (body.length !== 0) {
      throw new Error("Signal Protocol Relay returned an invalid response");
    }
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error("Signal Protocol Relay returned invalid JSON");
  }
  if (!response.ok) {
    // `UPGRADE_REQUIRED` and `DEVICE_REVOKED` are terminal at any error
    // status, so `authenticatedPost` and every other retry, which matches only
    // a `HostedSignalProtocolRelayHttpError`, never repeat them. A refused
    // version 3 moves the offer to version 2. Any other `PROTOCOL_UNSUPPORTED`
    // stays a `HostedSignalProtocolRelayHttpError` whose `retryable` is true: the Relay
    // sends it for a version above the newest one that it serves, which
    // happens only after a Relay rollback.
    throwIfProtocolFallBack(offer, signalRelayProtocolVersion, parsed);
    throwIfUpgradeRequired(response.status, parsed, signalRelayProtocolVersion);
    throwIfDeviceRevoked(response.status, parsed);
    const error = record(parsed) && record(parsed.error) ? parsed.error : {};
    const code = typeof error.code === "string" ? error.code : "UNKNOWN";
    const message =
      typeof error.message === "string"
        ? error.message
        : "Signal Protocol Relay request failed";
    // A refused declared post names the devices of each account in
    // `details`. The error keeps them for the device-set reconciliation.
    throw markSignalProtocolRelayAnswerVersion(
      new HostedSignalProtocolRelayHttpError(response.status, code, message, {
        ...(record(error.details) ? { data: { details: error.details } } : {}),
        retryable: error.retryable === true,
      }),
      signalRelayProtocolVersion,
    );
  }
  return parsed;
}

/**
 * Send one request with the version that `offer` holds and read its answer.
 * A fetch failure throws an error whose cause is the fetch error.
 */
async function send(
  connection: HostedSignalProtocolRelayConnection,
  offer: SignalRelayProtocolOffer,
  path: string,
  request: (signalRelayProtocolVersion: number) => Promise<RequestInit>,
): Promise<unknown> {
  return sendOnSignalRelayProtocol(offer, async (signalRelayProtocolVersion) => {
    const init = await request(signalRelayProtocolVersion);
    return withSignalProtocolRelayRequestDeadline(async (signal) => {
      let response: Response;
      try {
        response = await fetch(`${identifiedEndpoint(connection)}${path}`, {
          ...init,
          credentials: "omit",
          redirect: "error",
          signal,
        });
      } catch (cause) {
        throw signalProtocolRelayRequestNotCompleted(cause);
      }
      return parseResponse(response, signalRelayProtocolVersion, offer);
    });
  });
}

/**
 * Post a JSON body with the version that `offer` holds. A body that signs
 * a proof is a function of the version, because each version signs its own
 * labels. When the Relay refuses version 3, the post runs once more with
 * version 2.
 */
export async function postJson(
  connection: HostedSignalProtocolRelayConnection,
  offer: SignalRelayProtocolOffer,
  path: string,
  body: JsonRecord | ((signalRelayProtocolVersion: number) => Promise<JsonRecord>),
  token?: string,
): Promise<unknown> {
  return send(connection, offer, path, async (signalRelayProtocolVersion) => {
    const headers = new Headers({
      accept: "application/json",
      "content-type": "application/json",
      ...signalRelayProtocolHeadersFor(signalRelayProtocolVersion),
    });
    if (token !== undefined) headers.set("authorization", `Bearer ${token}`);
    const json = JSON.stringify(
      typeof body === "function" ? await body(signalRelayProtocolVersion) : body,
    );
    return { body: json, headers, method: "POST" };
  });
}

/** Get a JSON answer with the version that `offer` holds, with no credential. */
export async function getJson(
  connection: HostedSignalProtocolRelayConnection,
  offer: SignalRelayProtocolOffer,
  path: string,
): Promise<unknown> {
  return send(connection, offer, path, async (signalRelayProtocolVersion) => ({
    headers: new Headers({
      accept: "application/json",
      ...signalRelayProtocolHeadersFor(signalRelayProtocolVersion),
    }),
    method: "GET",
  }));
}
