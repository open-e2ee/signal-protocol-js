/**
 * The presence wire contract of the hosted Relay, version 1.
 *
 * A device with a mailbox socket sends each presence request as one text frame
 * on that socket. The frame carries `type`, `version`, and an `id` that the
 * Relay echoes in its one answer: a `presence-result` or a `presence-error`
 * frame. The Relay closes the socket with code 1008 on a frame type or a
 * version that it does not accept, as it does for every other unknown frame.
 * The SDK has no fallback for that close. It rejects the pending requests
 * with `FRAME_REJECTED`.
 *
 * A wake client has no socket. It sends the same request body, without `id`
 * and with `publishableKey`, as an authenticated `POST /presence`, and the
 * response body is the `result` object of the same request type.
 */
import {
  base64ToBytes,
  bytesToUrlSafeBase64,
  urlSafeToBase64,
} from "../internal/crypto";
import type { Base64 } from "../types";

/** The version that every presence request and answer carries. */
export const PRESENCE_FRAME_VERSION = 1;

/** The Relay refuses a presence read with more accounts. */
export const PRESENCE_READ_LIMIT = 100;

/** A presence key is 16 bytes, sent as 22 canonical base64url characters. */
const PRESENCE_KEY_BYTES = 16;
const PRESENCE_KEY_CHARACTERS = 22;
const MAXIMUM_ACCOUNT_CHARACTERS = 256;
const MAXIMUM_ERROR_CODE_CHARACTERS = 64;
const MAXIMUM_ERROR_MESSAGE_CHARACTERS = 1_024;
const REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/u;
const ERROR_CODE = /^[A-Z][A-Z0-9_]*$/u;

/** Who controls presence in the project. */
export type HostedRelayPresenceMode =
  | "off"
  | "default-on"
  | "default-off"
  | "forced";

/** Who can read an account's presence. */
export type HostedRelayPresenceAudience = "contacts" | "project";

/** How much of the last-seen time a reader gets. */
export type HostedRelayPresenceLastSeenPolicy =
  | "exact"
  | "approximate"
  | "hidden";

/** The project's presence policy, as the Relay resolves it. */
export interface HostedRelayPresencePolicy {
  readonly audience: HostedRelayPresenceAudience;
  readonly lastSeen: HostedRelayPresenceLastSeenPolicy;
  readonly mode: HostedRelayPresenceMode;
  /** A hidden account reads no other account's presence. */
  readonly reciprocal: boolean;
}

/** An account's own choice. `unset` takes the project default. */
export type HostedRelayPresenceSetting = "unset" | "visible" | "hidden";

/** The choice that an account can write. */
export type HostedRelayPresenceVisibility = "visible" | "hidden";

/** The local account's presence state in its project. */
export interface HostedRelayPresenceAccount {
  /** The visibility that applies after the project mode. */
  readonly effective: HostedRelayPresenceVisibility;
  /** True when the account registered a presence key. */
  readonly keyRegistered: boolean;
  readonly mode: HostedRelayPresenceMode;
  readonly setting: HostedRelayPresenceSetting;
}

/** A last-seen time that the `approximate` policy rounds to a range. */
export type HostedRelayPresenceApproximateLastSeen =
  | "recently"
  | "within-week"
  | "within-month"
  | "long-ago";

/** One account's presence, as its reader may see it. */
export interface HostedRelayPresenceStatus {
  /**
   * Milliseconds since the epoch under the `exact` policy, a range under
   * `approximate`, and null under `hidden` or when no device was seen.
   */
  readonly lastSeen: number | HostedRelayPresenceApproximateLastSeen | null;
  readonly online: boolean;
}

/** One account in a presence read. */
export interface HostedRelayPresenceTarget {
  readonly account: string;
  /** The account's presence key. The `contacts` audience requires it. */
  readonly presenceKey?: string;
}

/** The request of each presence frame type. */
export type HostedRelayPresenceRequest =
  | { readonly type: "presence-policy" }
  | { readonly type: "presence-account" }
  | {
      readonly type: "presence-setting";
      readonly setting: HostedRelayPresenceVisibility;
    }
  | { readonly type: "presence-key"; readonly presenceKey: string }
  | {
      readonly type: "presence-read";
      readonly accounts: readonly HostedRelayPresenceTarget[];
    };

/** The decoded result of each presence request type. */
export interface HostedRelayPresenceResults {
  readonly "presence-policy": HostedRelayPresencePolicy;
  readonly "presence-account": HostedRelayPresenceAccount;
  readonly "presence-setting": HostedRelayPresenceAccount;
  readonly "presence-key": undefined;
  readonly "presence-read": readonly (HostedRelayPresenceStatus | null)[];
}

/**
 * A presence error code. The Relay sends its own codes, for example
 * `PRESENCE_SETTING_FORCED` for a setting write under the `forced` mode,
 * `INVALID_TRANSITION` for a write under the `off` mode, and
 * `QUOTA_EXCEEDED` for too many reads. The SDK adds four codes:
 * `NOT_CONNECTED` when no mailbox socket is live or the socket left before
 * the answer, `TIMEOUT` when no answer arrives in 10 s, `BUSY` when too many
 * requests wait for an answer, and `FRAME_REJECTED` when the Relay closed the
 * socket with 1008 because it does not accept presence frames.
 */
export type HostedRelayPresenceErrorCode =
  | "PRESENCE_SETTING_FORCED"
  | "INVALID_TRANSITION"
  | "QUOTA_EXCEEDED"
  | "NOT_CONNECTED"
  | "TIMEOUT"
  | "BUSY"
  | "FRAME_REJECTED"
  | (string & {});

/** A presence request that the Relay refused or that got no answer. */
export class HostedRelayPresenceError extends Error {
  public readonly code: HostedRelayPresenceErrorCode;
  /** True when the same request can be sent again later. */
  public readonly retryable: boolean;

  public constructor(
    code: HostedRelayPresenceErrorCode,
    message: string,
    retryable: boolean,
  ) {
    super(message);
    this.name = "HostedRelayPresenceError";
    this.code = code;
    this.retryable = retryable;
  }
}

type JsonRecord = Record<string, unknown>;

function record(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: JsonRecord, keys: readonly string[]): boolean {
  const present = Object.keys(value);
  return (
    present.length === keys.length && keys.every((key) => key in value)
  );
}

function invalidResult(): Error {
  return new Error("Signal Protocol Relay returned an invalid presence result");
}

/** Throws unless the account is a Relay account address of 1-256 characters. */
export function assertPresenceAccount(account: unknown): string {
  if (
    typeof account !== "string" ||
    account.length === 0 ||
    account.length > MAXIMUM_ACCOUNT_CHARACTERS
  )
    throw new Error("Signal Protocol Relay presence account is invalid");
  return account;
}

/** Throws unless the key is exactly 16 bytes of canonical base64url. */
export function assertPresenceKey(presenceKey: unknown): string {
  if (
    typeof presenceKey !== "string" ||
    presenceKey.length !== PRESENCE_KEY_CHARACTERS
  )
    throw new Error("Signal Protocol Relay presence key is invalid");
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(urlSafeToBase64(presenceKey) as Base64);
  } catch {
    throw new Error("Signal Protocol Relay presence key is invalid");
  }
  if (
    bytes.length !== PRESENCE_KEY_BYTES ||
    bytesToUrlSafeBase64(bytes) !== presenceKey
  )
    throw new Error("Signal Protocol Relay presence key is invalid");
  return presenceKey;
}

/** The request fields after `type` and `version`, in their wire order. */
function requestFields(request: HostedRelayPresenceRequest): JsonRecord {
  switch (request.type) {
    case "presence-policy":
    case "presence-account":
      return {};
    case "presence-setting":
      if (request.setting !== "visible" && request.setting !== "hidden")
        throw new Error("Signal Protocol Relay presence setting is invalid");
      return { setting: request.setting };
    case "presence-key":
      return { presenceKey: assertPresenceKey(request.presenceKey) };
    case "presence-read":
      if (
        !Array.isArray(request.accounts) ||
        request.accounts.length === 0 ||
        request.accounts.length > PRESENCE_READ_LIMIT
      )
        throw new Error("Signal Protocol Relay presence read is invalid");
      return {
        accounts: request.accounts.map((target) =>
          target.presenceKey === undefined
            ? { account: assertPresenceAccount(target.account) }
            : {
                account: assertPresenceAccount(target.account),
                presenceKey: assertPresenceKey(target.presenceKey),
              },
        ),
      };
    default:
      throw new Error("Signal Protocol Relay presence request is invalid");
  }
}

/** The socket frame of one presence request. */
export function encodePresenceFrame(
  id: string,
  request: HostedRelayPresenceRequest,
): string {
  if (!REQUEST_ID.test(id))
    throw new Error("Signal Protocol Relay presence request id is invalid");
  return JSON.stringify({
    type: request.type,
    version: PRESENCE_FRAME_VERSION,
    id,
    ...requestFields(request),
  });
}

/** The HTTP body of one presence request from a client with no socket. */
export function presenceHttpBody(
  publishableKey: string,
  request: HostedRelayPresenceRequest,
): JsonRecord {
  return {
    type: request.type,
    version: PRESENCE_FRAME_VERSION,
    ...requestFields(request),
    publishableKey,
  };
}

/** True for the frame types that answer a presence request. */
export function isPresenceAnswerType(type: unknown): boolean {
  return type === "presence-result" || type === "presence-error";
}

/** One decoded answer frame. */
export type PresenceAnswer =
  | { readonly id: string; readonly result: unknown }
  | { readonly id: string; readonly error: HostedRelayPresenceError };

/**
 * Decodes a `presence-result` or `presence-error` frame. A malformed answer
 * throws, and the subscription treats it as an invalid frame.
 */
export function decodePresenceAnswer(frame: JsonRecord): PresenceAnswer {
  if (
    frame.version !== PRESENCE_FRAME_VERSION ||
    typeof frame.id !== "string" ||
    !REQUEST_ID.test(frame.id)
  )
    throw new Error("Invalid presence frame.");
  if (frame.type === "presence-result") {
    if (!exactKeys(frame, ["type", "version", "id", "result"]))
      throw new Error("Invalid presence frame.");
    return { id: frame.id, result: frame.result };
  }
  if (
    frame.type !== "presence-error" ||
    !exactKeys(frame, ["type", "version", "id", "code", "message", "retryable"]) ||
    typeof frame.code !== "string" ||
    frame.code.length > MAXIMUM_ERROR_CODE_CHARACTERS ||
    !ERROR_CODE.test(frame.code) ||
    typeof frame.message !== "string" ||
    frame.message.length > MAXIMUM_ERROR_MESSAGE_CHARACTERS ||
    typeof frame.retryable !== "boolean"
  )
    throw new Error("Invalid presence frame.");
  return {
    id: frame.id,
    error: new HostedRelayPresenceError(
      frame.code,
      frame.message,
      frame.retryable,
    ),
  };
}

const MODES: readonly unknown[] = ["off", "default-on", "default-off", "forced"];
const AUDIENCES: readonly unknown[] = ["contacts", "project"];
const LAST_SEEN_POLICIES: readonly unknown[] = [
  "exact",
  "approximate",
  "hidden",
];
const SETTINGS: readonly unknown[] = ["unset", "visible", "hidden"];
const VISIBILITIES: readonly unknown[] = ["visible", "hidden"];
const APPROXIMATE_LAST_SEEN: readonly unknown[] = [
  "recently",
  "within-week",
  "within-month",
  "long-ago",
];

function decodePolicy(value: unknown): HostedRelayPresencePolicy {
  if (
    !record(value) ||
    !exactKeys(value, ["audience", "lastSeen", "mode", "reciprocal"]) ||
    !AUDIENCES.includes(value.audience) ||
    !LAST_SEEN_POLICIES.includes(value.lastSeen) ||
    !MODES.includes(value.mode) ||
    typeof value.reciprocal !== "boolean"
  )
    throw invalidResult();
  return {
    audience: value.audience as HostedRelayPresenceAudience,
    lastSeen: value.lastSeen as HostedRelayPresenceLastSeenPolicy,
    mode: value.mode as HostedRelayPresenceMode,
    reciprocal: value.reciprocal,
  };
}

function decodeAccount(value: unknown): HostedRelayPresenceAccount {
  if (
    !record(value) ||
    !exactKeys(value, ["effective", "keyRegistered", "mode", "setting"]) ||
    !VISIBILITIES.includes(value.effective) ||
    typeof value.keyRegistered !== "boolean" ||
    !MODES.includes(value.mode) ||
    !SETTINGS.includes(value.setting)
  )
    throw invalidResult();
  return {
    effective: value.effective as HostedRelayPresenceVisibility,
    keyRegistered: value.keyRegistered,
    mode: value.mode as HostedRelayPresenceMode,
    setting: value.setting as HostedRelayPresenceSetting,
  };
}

function decodeStatus(value: unknown): HostedRelayPresenceStatus | null {
  if (value === null) return null;
  if (
    !record(value) ||
    !exactKeys(value, ["lastSeen", "online"]) ||
    typeof value.online !== "boolean" ||
    !(
      value.lastSeen === null ||
      APPROXIMATE_LAST_SEEN.includes(value.lastSeen) ||
      (typeof value.lastSeen === "number" &&
        Number.isSafeInteger(value.lastSeen) &&
        value.lastSeen >= 0)
    )
  )
    throw invalidResult();
  return {
    lastSeen: value.lastSeen as HostedRelayPresenceStatus["lastSeen"],
    online: value.online,
  };
}

/** Decodes the `result` of one request, and throws on any other shape. */
export function decodePresenceResult<
  Request extends HostedRelayPresenceRequest,
>(
  request: Request,
  value: unknown,
): HostedRelayPresenceResults[Request["type"]] {
  type Result = HostedRelayPresenceResults[Request["type"]];
  switch (request.type) {
    case "presence-policy":
      return decodePolicy(value) as Result;
    case "presence-account":
    case "presence-setting":
      return decodeAccount(value) as Result;
    case "presence-key":
      if (!record(value) || Object.keys(value).length !== 0)
        throw invalidResult();
      return undefined as Result;
    case "presence-read": {
      if (
        !record(value) ||
        !exactKeys(value, ["results"]) ||
        !Array.isArray(value.results) ||
        value.results.length !== request.accounts.length
      )
        throw invalidResult();
      const results: HostedRelayPresenceResults["presence-read"] =
        value.results.map(decodeStatus);
      return results as unknown as Result;
    }
    default:
      throw invalidResult();
  }
}
