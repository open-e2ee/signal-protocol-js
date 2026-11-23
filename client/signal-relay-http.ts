import type { HostedSignalProtocolRelayConnection } from "./hosted-connection";
import { HostedSignalProtocolRelayHttpError } from "./hosted-http-error";
import { throwIfDeviceRevoked } from "./hosted-device-standing";
import { readSignalProtocolRelayResponse } from "./signal-relay-response-reference";
import {
  markSignalProtocolRelayAnswerVersion,
  signalRelayProtocolHeaders,
  throwIfUpgradeRequired,
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
 * records the protocol version of the request that it answers.
 */
export async function parseResponse(response: Response): Promise<unknown> {
  const body = await response.text();
  return readSignalProtocolRelayResponse(response, () => {
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
      // a `HostedSignalProtocolRelayHttpError`, never repeat them.
      // `PROTOCOL_UNSUPPORTED` stays a `HostedSignalProtocolRelayHttpError` whose
      // `retryable` is true: the Relay sends it for a version above the newest
      // one that it serves. The SDK does not offer another version.
      throwIfUpgradeRequired(response.status, parsed);
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
      );
    }
    return parsed;
  });
}

/**
 * Checks one Relay answer after the protocol handling of `parseResponse`.
 * It gets the response and, for an error answer, the error that the answer
 * throws. An upgrade refusal and a device revocation never reach it. It throws to refuse the answer.
 */
export type SignalRelayAnswerCheck = (
  response: Response,
  refusal?: HostedSignalProtocolRelayHttpError,
) => void;

/**
 * Send one request and read its answer. A fetch failure throws an error whose
 * cause is the fetch error.
 */
async function send<T = unknown>(
  connection: HostedSignalProtocolRelayConnection,
  path: string,
  request: () => Promise<RequestInit>,
  answerHandling: SignalRelayAnswerHandling<T> = {},
): Promise<T> {
  const { checkAnswer, decode } = answerHandling;
  const init = await request();
  const answer = await withSignalProtocolRelayRequestDeadline(async (signal) => {
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
    let value: unknown;
    try {
      value = await parseResponse(response);
    } catch (error) {
      if (error instanceof HostedSignalProtocolRelayHttpError) checkAnswer?.(response, error);
      throw error;
    }
    checkAnswer?.(response);
    return { value, response };
  });
  return decode === undefined ? answer.value as T : decode(answer.value, answer.response);
}

/**
 * How `send` treats an answer after the protocol handling. `checkAnswer`
 * runs on each answer that the protocol handling does not consume, inside
 * the request deadline. `decode` then reads the accepted answer and its
 * response.
 */
type SignalRelayAnswerHandling<T> = {
  readonly checkAnswer?: SignalRelayAnswerCheck;
  readonly decode?: (value: unknown, response: Response) => T | Promise<T>;
};

/**
 * Post a JSON body. A body that signs a proof is a function, so that the post
 * signs it just before it sends it. `answerHandling` checks and decodes each
 * answer.
 */
export async function postJson<T = unknown>(
  connection: HostedSignalProtocolRelayConnection,
  path: string,
  body: JsonRecord | (() => Promise<JsonRecord>),
  token?: string,
  answerHandling: SignalRelayAnswerHandling<T> = {},
): Promise<T> {
  return send(connection, path, async () => {
    const headers = new Headers({
      accept: "application/json",
      "content-type": "application/json",
      ...signalRelayProtocolHeaders(),
    });
    if (token !== undefined) headers.set("authorization", `Bearer ${token}`);
    const json = JSON.stringify(typeof body === "function" ? await body() : body);
    return { body: json, headers, method: "POST" };
  }, answerHandling);
}

/** Get a JSON answer with no credential. */
export async function getJson(
  connection: HostedSignalProtocolRelayConnection,
  path: string,
): Promise<unknown> {
  return send(connection, path, async () => ({
    headers: new Headers({
      accept: "application/json",
      ...signalRelayProtocolHeaders(),
    }),
    method: "GET",
  }));
}
