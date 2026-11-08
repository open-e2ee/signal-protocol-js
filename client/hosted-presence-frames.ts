/**
 * The presence wire contract of the OpenE2EE Signal Protocol Relay, version 1.
 *
 * A device with a mailbox socket sends each presence request as one text frame
 * on that socket. The frame carries `type`, `version`, and an `id` that the
 * Relay echoes in its one answer: a `presence-result` or a `presence-error`
 * frame. The Relay closes the socket with code 1008 on a frame type or a
 * version that it does not accept, as it does for every other unknown frame.
 * The SDK has no fallback for that close. It rejects the pending requests
 * with `FRAME_REJECTED`.
 *
 * On the socket only, a `presence-watch` request registers the device's
 * whole watch set. After its answer, the Relay pushes one `presence-update`
 * frame for each socket edge of a watched account. That frame has no `id`,
 * because it answers no request.
 *
 * A wake client has no socket. It sends the same request body, without `id`
 * and with `publishableKey`, as an authenticated `POST /presence`, and the
 * response body is the `result` object of the same request type. The HTTP
 * carrier has no watch.
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

/** The Relay refuses a presence watch with more accounts. */
export const PRESENCE_WATCH_LIMIT = 16;

/** A presence key is 16 bytes, sent as 22 canonical base64url characters. */
const PRESENCE_KEY_BYTES = 16;
const PRESENCE_KEY_CHARACTERS = 22;
const MAXIMUM_ACCOUNT_CHARACTERS = 256;
const MAXIMUM_ERROR_CODE_CHARACTERS = 64;
const MAXIMUM_ERROR_MESSAGE_CHARACTERS = 1_024;
const REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/u;
const ERROR_CODE = /^[A-Z][A-Z0-9_]*$/u;

/** Who controls presence in the project. */
export type HostedSignalProtocolRelayPresenceMode =
  | "off"
  | "default-on"
  | "default-off"
  | "forced";

/** Who can read an account's presence. */
export type HostedSignalProtocolRelayPresenceAudience = "contacts" | "project";

/** How much of the last-seen time a reader gets. */
export type HostedSignalProtocolRelayPresenceLastSeenPolicy =
  | "exact"
  | "approximate"
  | "hidden";

/** The project's presence policy, as the Relay resolves it. */
export interface HostedSignalProtocolRelayPresencePolicy {
  readonly audience: HostedSignalProtocolRelayPresenceAudience;
  readonly lastSeen: HostedSignalProtocolRelayPresenceLastSeenPolicy;
  readonly mode: HostedSignalProtocolRelayPresenceMode;
  /** A hidden account reads no other account's presence. */
  readonly reciprocal: boolean;
}

/** An account's own choice. `unset` takes the project default. */
export type HostedSignalProtocolRelayPresenceSetting = "unset" | "visible" | "hidden";

/** The choice that an account can write. */
export type HostedSignalProtocolRelayPresenceVisibility = "visible" | "hidden";

/** The local account's presence state in its project. */
export interface HostedSignalProtocolRelayPresenceAccount {
  /** The visibility that applies after the project mode. */
  readonly effective: HostedSignalProtocolRelayPresenceVisibility;
  /** True when the account registered a presence key. */
  readonly keyRegistered: boolean;
  readonly mode: HostedSignalProtocolRelayPresenceMode;
  readonly setting: HostedSignalProtocolRelayPresenceSetting;
}

/** A last-seen time that the `approximate` policy rounds to a range. */
export type HostedSignalProtocolRelayPresenceApproximateLastSeen =
  | "recently"
  | "within-week"
  | "within-month"
  | "long-ago";

/** One account's presence, as its reader may see it. */
export interface HostedSignalProtocolRelayPresenceStatus {
  /**
   * Milliseconds since the epoch under the `exact` policy, a range under
   * `approximate`, and null under `hidden` or when no device was seen.
   */
  readonly lastSeen: number | HostedSignalProtocolRelayPresenceApproximateLastSeen | null;
  readonly online: boolean;
}

/** One account in a presence read. */
export interface HostedSignalProtocolRelayPresenceTarget {
  readonly account: string;
  /** The account's presence key. The `contacts` audience requires it. */
  readonly presenceKey?: string;
}

/** The request of each presence frame type. */
export type HostedSignalProtocolRelayPresenceRequest =
  | { readonly type: "presence-policy" }
  | { readonly type: "presence-account" }
  | {
      readonly type: "presence-setting";
      readonly setting: HostedSignalProtocolRelayPresenceVisibility;
    }
  | { readonly type: "presence-key"; readonly presenceKey: string }
  | {
      readonly type: "presence-read";
      readonly accounts: readonly HostedSignalProtocolRelayPresenceTarget[];
    }
  | {
      /** The whole watch set of the device. No account stops the watch. */
      readonly type: "presence-watch";
      readonly accounts: readonly HostedSignalProtocolRelayPresenceTarget[];
    };

/** The decoded result of each presence request type. */
export interface HostedSignalProtocolRelayPresenceResults {
  readonly "presence-policy": HostedSignalProtocolRelayPresencePolicy;
  readonly "presence-account": HostedSignalProtocolRelayPresenceAccount;
  readonly "presence-setting": HostedSignalProtocolRelayPresenceAccount;
  readonly "presence-key": undefined;
  readonly "presence-read": readonly (HostedSignalProtocolRelayPresenceStatus | null)[];
  readonly "presence-watch": readonly (HostedSignalProtocolRelayPresenceStatus | null)[];
}

/** One pushed socket edge of a watched account. */
export interface HostedSignalProtocolRelayPresenceUpdate {
  /** The account address, as the watch sent it. */
  readonly account: string;
  readonly presence: HostedSignalProtocolRelayPresenceStatus;
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
export type HostedSignalProtocolRelayPresenceErrorCode =
  | "PRESENCE_SETTING_FORCED"
  | "INVALID_TRANSITION"
  | "QUOTA_EXCEEDED"
  | "NOT_CONNECTED"
  | "TIMEOUT"
  | "BUSY"
  | "FRAME_REJECTED"
  | (string & {});

/** A presence request that the Relay refused or that got no answer. */
export class HostedSignalProtocolRelayPresenceError extends Error {
  public readonly code: HostedSignalProtocolRelayPresenceErrorCode;
  /** True when the same request can be sent again later. */
  public readonly retryable: boolean;

  public constructor(
    code: HostedSignalProtocolRelayPresenceErrorCode,
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

function targetFields(
  targets: readonly HostedSignalProtocolRelayPresenceTarget[],
): JsonRecord[] {
  return targets.map((target) =>
    target.presenceKey === undefined
      ? { account: assertPresenceAccount(target.account) }
      : {
          account: assertPresenceAccount(target.account),
          presenceKey: assertPresenceKey(target.presenceKey),
        },
  );
}

/** The request fields after `type` and `version`, in their wire order. */
function requestFields(request: HostedSignalProtocolRelayPresenceRequest): JsonRecord {
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
      return { accounts: targetFields(request.accounts) };
    case "presence-watch":
      if (
        !Array.isArray(request.accounts) ||
        request.accounts.length > PRESENCE_WATCH_LIMIT
      )
        throw new Error("Signal Protocol Relay presence watch is invalid");
      return { accounts: targetFields(request.accounts) };
    default:
      throw new Error("Signal Protocol Relay presence request is invalid");
  }
}

/** The socket frame of one presence request. */
export function encodePresenceFrame(
  id: string,
  request: HostedSignalProtocolRelayPresenceRequest,
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

/**
 * The HTTP body of one presence request from a client with no socket. A watch
 * exists only on the socket, so this carrier refuses it.
 */
export function presenceHttpBody(
  publishableKey: string,
  request: HostedSignalProtocolRelayPresenceRequest,
): JsonRecord {
  if (request.type === "presence-watch")
    throw new Error(
      "Signal Protocol Relay presence watch needs the mailbox socket",
    );
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
  | { readonly id: string; readonly error: HostedSignalProtocolRelayPresenceError };

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
    error: new HostedSignalProtocolRelayPresenceError(
      frame.code,
      frame.message,
      frame.retryable,
    ),
  };
}

/** True for the frame type of a pushed presence edge. */
export function isPresenceUpdateType(type: unknown): boolean {
  return type === "presence-update";
}

/**
 * Decodes a `presence-update` frame. A malformed frame throws, and the
 * subscription treats it as an invalid frame. The Relay never pushes `null`.
 */
export function decodePresenceUpdate(
  frame: JsonRecord,
): HostedSignalProtocolRelayPresenceUpdate {
  if (
    frame.type !== "presence-update" ||
    frame.version !== PRESENCE_FRAME_VERSION ||
    !exactKeys(frame, ["type", "version", "account", "presence"]) ||
    typeof frame.account !== "string" ||
    frame.account.length === 0 ||
    frame.account.length > MAXIMUM_ACCOUNT_CHARACTERS
  )
    throw new Error("Invalid presence frame.");
  let presence: HostedSignalProtocolRelayPresenceStatus | null;
  try {
    presence = decodeStatus(frame.presence);
  } catch {
    throw new Error("Invalid presence frame.");
  }
  if (presence === null) throw new Error("Invalid presence frame.");
  return { account: frame.account, presence };
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

function decodePolicy(value: unknown): HostedSignalProtocolRelayPresencePolicy {
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
    audience: value.audience as HostedSignalProtocolRelayPresenceAudience,
    lastSeen: value.lastSeen as HostedSignalProtocolRelayPresenceLastSeenPolicy,
    mode: value.mode as HostedSignalProtocolRelayPresenceMode,
    reciprocal: value.reciprocal,
  };
}

function decodeAccount(value: unknown): HostedSignalProtocolRelayPresenceAccount {
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
    effective: value.effective as HostedSignalProtocolRelayPresenceVisibility,
    keyRegistered: value.keyRegistered,
    mode: value.mode as HostedSignalProtocolRelayPresenceMode,
    setting: value.setting as HostedSignalProtocolRelayPresenceSetting,
  };
}

function decodeStatus(value: unknown): HostedSignalProtocolRelayPresenceStatus | null {
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
    lastSeen: value.lastSeen as HostedSignalProtocolRelayPresenceStatus["lastSeen"],
    online: value.online,
  };
}

/** Decodes the `result` of one request, and throws on any other shape. */
export function decodePresenceResult<
  Request extends HostedSignalProtocolRelayPresenceRequest,
>(
  request: Request,
  value: unknown,
): HostedSignalProtocolRelayPresenceResults[Request["type"]] {
  type Result = HostedSignalProtocolRelayPresenceResults[Request["type"]];
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
    case "presence-read":
    case "presence-watch": {
      if (
        !record(value) ||
        !exactKeys(value, ["results"]) ||
        !Array.isArray(value.results) ||
        value.results.length !== request.accounts.length
      )
        throw invalidResult();
      const results: readonly (HostedSignalProtocolRelayPresenceStatus | null)[] =
        value.results.map(decodeStatus);
      return results as unknown as Result;
    }
    default:
      throw invalidResult();
  }
}

// Names before the Signal Protocol Relay rename. SDK 15.0.0 removes them.
/** @deprecated Use `HostedSignalProtocolRelayPresenceAccount`. SDK 15.0.0 removes this name. */
export type HostedRelayPresenceAccount = HostedSignalProtocolRelayPresenceAccount;
/** @deprecated Use `HostedSignalProtocolRelayPresenceApproximateLastSeen`. SDK 15.0.0 removes this name. */
export type HostedRelayPresenceApproximateLastSeen = HostedSignalProtocolRelayPresenceApproximateLastSeen;
/** @deprecated Use `HostedSignalProtocolRelayPresenceAudience`. SDK 15.0.0 removes this name. */
export type HostedRelayPresenceAudience = HostedSignalProtocolRelayPresenceAudience;
/** @deprecated Use `HostedSignalProtocolRelayPresenceError`. SDK 15.0.0 removes this name. */
export const HostedRelayPresenceError = HostedSignalProtocolRelayPresenceError;
/** @deprecated Use `HostedSignalProtocolRelayPresenceError`. SDK 15.0.0 removes this name. */
export type HostedRelayPresenceError = HostedSignalProtocolRelayPresenceError;
/** @deprecated Use `HostedSignalProtocolRelayPresenceErrorCode`. SDK 15.0.0 removes this name. */
export type HostedRelayPresenceErrorCode = HostedSignalProtocolRelayPresenceErrorCode;
/** @deprecated Use `HostedSignalProtocolRelayPresenceLastSeenPolicy`. SDK 15.0.0 removes this name. */
export type HostedRelayPresenceLastSeenPolicy = HostedSignalProtocolRelayPresenceLastSeenPolicy;
/** @deprecated Use `HostedSignalProtocolRelayPresenceMode`. SDK 15.0.0 removes this name. */
export type HostedRelayPresenceMode = HostedSignalProtocolRelayPresenceMode;
/** @deprecated Use `HostedSignalProtocolRelayPresencePolicy`. SDK 15.0.0 removes this name. */
export type HostedRelayPresencePolicy = HostedSignalProtocolRelayPresencePolicy;
/** @deprecated Use `HostedSignalProtocolRelayPresenceSetting`. SDK 15.0.0 removes this name. */
export type HostedRelayPresenceSetting = HostedSignalProtocolRelayPresenceSetting;
/** @deprecated Use `HostedSignalProtocolRelayPresenceStatus`. SDK 15.0.0 removes this name. */
export type HostedRelayPresenceStatus = HostedSignalProtocolRelayPresenceStatus;
/** @deprecated Use `HostedSignalProtocolRelayPresenceVisibility`. SDK 15.0.0 removes this name. */
export type HostedRelayPresenceVisibility = HostedSignalProtocolRelayPresenceVisibility;
