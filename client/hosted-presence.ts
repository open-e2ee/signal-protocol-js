/**
 * Presence for a hosted client: the project policy, the account's own
 * setting, batch reads, a watch for an open chat, and the presence key
 * operations. With `hosted.profileKeys`, the SDK carries the key in its own
 * end-to-end encrypted 1:1 messages and calls `accessKey()` and `grant()`.
 *
 * A client with a mailbox subscription sends every request over its socket.
 * A wake client, which has no socket, sends them over HTTP. The two are
 * separate entry points, and neither falls back to the other.
 *
 * The SDK reports no presence state. The Relay records the socket edges, and
 * the lifecycle binding closes the socket in the background.
 */
import { bytesToUrlSafeBase64, hkdf, stringToBytes } from "../internal/crypto";
import type { SignalProtocolLocalStore } from "../types";
import type {
  RelayConnectionState,
  Unsubscribe,
} from "../remote/relay/types";
import type { DefaultSignalProtocolClient } from "./client";
import type { MailboxSubscriptionHandle } from "./hosted-mailbox-subscription";
import type { HostedRelayWakeClient } from "./hosted-push";
import { HostedRelayHttpError } from "./hosted-transport";
import {
  HostedRelayPresenceError,
  PRESENCE_READ_LIMIT,
  assertPresenceAccount,
  assertPresenceKey,
  decodePresenceResult,
  type HostedRelayPresenceAccount,
  type HostedRelayPresencePolicy,
  type HostedRelayPresenceRequest,
  type HostedRelayPresenceResults,
  type HostedRelayPresenceStatus,
  type HostedRelayPresenceTarget,
  type HostedRelayPresenceVisibility,
} from "./hosted-presence-frames";

export {
  HostedRelayPresenceError,
  type HostedRelayPresenceAccount,
  type HostedRelayPresenceApproximateLastSeen,
  type HostedRelayPresenceAudience,
  type HostedRelayPresenceErrorCode,
  type HostedRelayPresenceLastSeenPolicy,
  type HostedRelayPresenceMode,
  type HostedRelayPresencePolicy,
  type HostedRelayPresenceSetting,
  type HostedRelayPresenceStatus,
  type HostedRelayPresenceVisibility,
} from "./hosted-presence-frames";

/** The interval of the `watch()` poll while the mailbox socket is connected. */
export const PRESENCE_WATCH_POLL_MILLISECONDS = 30_000;

/** The HKDF info of the presence key. No other key uses this label. */
const PRESENCE_KEY_INFO = stringToBytes("open-e2ee-presence-key-v1");
const PRESENCE_KEY_BYTES = 16;
const PROFILE_KEY_BYTES = 32;
const PRESENCE_GRANT_METADATA_PREFIX = "hostedRelay.presenceGrant.v1:";

/**
 * The presence of a hosted client with a mailbox subscription. Each request
 * needs a connected socket and otherwise fails with `NOT_CONNECTED`.
 */
export interface HostedRelayPresence {
  /** The project's presence policy, so the app can show or disable its toggle. */
  policy(): Promise<HostedRelayPresencePolicy>;
  /** The local account's setting and the visibility that applies. */
  setting(): Promise<HostedRelayPresenceAccount>;
  /**
   * Writes the local account's setting. It fails with
   * `PRESENCE_SETTING_FORCED` under the `forced` mode and with
   * `INVALID_TRANSITION` under the `off` mode.
   */
  setVisibility(
    visibility: HostedRelayPresenceVisibility,
  ): Promise<HostedRelayPresenceAccount>;
  /**
   * Reads the presence of each account, in the order given. A null result is
   * the same for a hidden account, an unknown account, a missing or wrong
   * key, and a project with presence off. The read sends the key that
   * `grant()` stored for each account.
   */
  read(
    accounts: readonly string[],
  ): Promise<(HostedRelayPresenceStatus | null)[]>;
  /**
   * Calls `onChange` with the account's presence, then again after each
   * change. It reads every 30 s while the mailbox socket is connected, and at
   * once when the socket connects. A failed read keeps the last value. After
   * a `FRAME_REJECTED` read, it waits 30 s after the reconnect.
   */
  watch(
    account: string,
    onChange: (status: HostedRelayPresenceStatus | null) => void,
  ): Unsubscribe;
  /**
   * Derives this account's presence key from its 32-byte profile key,
   * registers the key with the Relay, and returns it. A new profile key
   * revokes every old holder. With `hosted.profileKeys`, the SDK calls it
   * when the profile key changes.
   */
  accessKey(profileKey: Uint8Array): Promise<string>;
  /**
   * Stores the presence key that a contact sent, for later reads. With
   * `hosted.profileKeys`, the SDK calls it for each contact profile key that
   * it receives.
   */
  grant(account: string, presenceKey: string): Promise<void>;
}

/**
 * The presence of a wake client: a hosted client in a push handler, a
 * notification service extension, or a background task, which pulls its
 * mailbox without a subscription. Each request is one authenticated HTTP
 * request. A wake client has no `watch()`.
 */
export type HostedRelayWakePresence = Omit<HostedRelayPresence, "watch">;

/** @internal SDK-owned transport for one authenticated hosted client. */
export interface HostedRelayPresenceRuntime {
  /** The Relay scope that owns the account's stored grants. */
  readonly presenceScope: string;
  readonly presenceStore: Pick<
    SignalProtocolLocalStore,
    "getMetadata" | "setMetadata"
  >;
  /** The live mailbox socket, or `undefined` while no subscription runs. */
  readonly presenceSocket:
    | Pick<MailboxSubscriptionHandle, "presence">
    | undefined;
  /** Sends one request as an authenticated HTTP request. */
  postPresence(request: HostedRelayPresenceRequest): Promise<unknown>;
  readonly relayConnectionState: RelayConnectionState;
  subscribeRelayConnectionState(
    listener: (state: RelayConnectionState) => void,
  ): Unsubscribe;
}

const runtimes = new WeakMap<object, HostedRelayPresenceRuntime>();
const presences = new WeakMap<object, HostedRelayPresence>();

/** @internal Bind the SDK-owned transport to the client that uses it. */
export function bindHostedRelayPresenceRuntime(
  client: object,
  runtime: HostedRelayPresenceRuntime,
): void {
  runtimes.set(client, runtime);
  presences.delete(client);
}

function presenceRuntime(client: object): HostedRelayPresenceRuntime {
  const runtime = runtimes.get(client);
  if (runtime === undefined)
    throw new Error(
      "The client is not connected to the OpenE2EE Signal Protocol Relay",
    );
  return runtime;
}

/** @internal HKDF-SHA-256 over the profile key, with an empty salt, 16 bytes out. */
export async function derivePresenceKey(profileKey: Uint8Array): Promise<string> {
  if (
    !(profileKey instanceof Uint8Array) ||
    profileKey.length !== PROFILE_KEY_BYTES
  )
    throw new Error("Signal Protocol Relay profile key is invalid");
  return bytesToUrlSafeBase64(
    await hkdf(profileKey, new Uint8Array(0), PRESENCE_KEY_INFO, PRESENCE_KEY_BYTES),
  );
}

function grantMetadataKey(
  runtime: HostedRelayPresenceRuntime,
  account: string,
): string {
  return `${PRESENCE_GRANT_METADATA_PREFIX}${runtime.presenceScope}:${account}`;
}

function presenceOperations(
  runtime: HostedRelayPresenceRuntime,
  send: (request: HostedRelayPresenceRequest) => Promise<unknown>,
): HostedRelayWakePresence {
  const request = async <Request extends HostedRelayPresenceRequest>(
    value: Request,
  ): Promise<HostedRelayPresenceResults[Request["type"]]> =>
    decodePresenceResult(value, await send(value));

  const target = async (
    account: string,
  ): Promise<HostedRelayPresenceTarget> => {
    const stored = await runtime.presenceStore.getMetadata(
      grantMetadataKey(runtime, account),
    );
    return stored === null
      ? { account }
      : { account, presenceKey: assertPresenceKey(stored) };
  };

  return {
    policy: () => request({ type: "presence-policy" }),
    setting: () => request({ type: "presence-account" }),
    setVisibility: (visibility) =>
      request({ type: "presence-setting", setting: visibility }),
    read: async (accounts) => {
      if (!Array.isArray(accounts))
        throw new Error("Signal Protocol Relay presence read is invalid");
      accounts.forEach(assertPresenceAccount);
      const targets = await Promise.all(accounts.map(target));
      const results: (HostedRelayPresenceStatus | null)[] = [];
      for (let start = 0; start < targets.length; start += PRESENCE_READ_LIMIT)
        results.push(
          ...(await request({
            type: "presence-read",
            accounts: targets.slice(start, start + PRESENCE_READ_LIMIT),
          })),
        );
      return results;
    },
    accessKey: async (profileKey) => {
      const presenceKey = await derivePresenceKey(profileKey);
      await request({ type: "presence-key", presenceKey });
      return presenceKey;
    },
    grant: async (account, presenceKey) => {
      await runtime.presenceStore.setMetadata(
        grantMetadataKey(runtime, assertPresenceAccount(account)),
        assertPresenceKey(presenceKey),
      );
    },
  };
}

function sameStatus(
  left: HostedRelayPresenceStatus | null,
  right: HostedRelayPresenceStatus | null,
): boolean {
  if (left === null || right === null) return left === right;
  return left.online === right.online && left.lastSeen === right.lastSeen;
}

type WatchListener = (status: HostedRelayPresenceStatus | null) => void;

interface WatchedAccount {
  readonly listeners: Set<WatchListener>;
  known: boolean;
  status: HostedRelayPresenceStatus | null;
}

/**
 * One poll for every watched account of a client. It runs only while the
 * mailbox socket is connected, which the lifecycle binding limits to the
 * foreground.
 */
class PresenceWatch {
  private readonly watched = new Map<string, WatchedAccount>();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private polling = false;
  private pollAgain = false;
  /**
   * The Signal Protocol Relay closed the socket on the last read frame. The
   * next read waits one full interval after the reconnect, so a Relay without
   * presence frames does not see a reconnect loop.
   */
  private rejected = false;
  private stopStateListener: Unsubscribe | undefined;

  public constructor(
    private readonly runtime: HostedRelayPresenceRuntime,
    private readonly read: HostedRelayPresence["read"],
  ) {}

  public watch(account: string, onChange: WatchListener): Unsubscribe {
    assertPresenceAccount(account);
    if (typeof onChange !== "function")
      throw new Error("Signal Protocol Relay presence listener is invalid");
    let entry = this.watched.get(account);
    if (entry === undefined) {
      entry = { listeners: new Set(), known: false, status: null };
      this.watched.set(account, entry);
    }
    const watchedEntry = entry;
    // Each call owns its own listener, so one callback can watch twice.
    const listener: WatchListener = (status) => onChange(status);
    watchedEntry.listeners.add(listener);
    this.stopStateListener ??= this.runtime.subscribeRelayConnectionState(
      (state) => {
        if (state.state !== "connected") this.cancel();
        else if (this.rejected) this.schedule(PRESENCE_WATCH_POLL_MILLISECONDS);
        else this.pollSoon();
      },
    );
    if (watchedEntry.known) {
      queueMicrotask(() => {
        if (watchedEntry.listeners.has(listener))
          notify(listener, watchedEntry.status);
      });
    } else this.pollSoon();
    return () => {
      if (!watchedEntry.listeners.delete(listener)) return;
      if (
        watchedEntry.listeners.size === 0 &&
        this.watched.get(account) === watchedEntry
      )
        this.watched.delete(account);
      if (this.watched.size > 0) return;
      this.cancel();
      this.stopStateListener?.();
      this.stopStateListener = undefined;
    };
  }

  private connected(): boolean {
    return this.runtime.relayConnectionState.state === "connected";
  }

  private cancel(): void {
    clearTimeout(this.timer);
    this.timer = undefined;
  }

  private schedule(milliseconds: number): void {
    this.cancel();
    this.timer = setTimeout(() => {
      this.timer = undefined;
      void this.poll();
    }, milliseconds);
  }

  /** Reads at the next turn, so watches that start together share one read. */
  private pollSoon(): void {
    if (!this.connected() || this.watched.size === 0) return;
    if (this.polling) this.pollAgain = true;
    else this.schedule(0);
  }

  private async poll(): Promise<void> {
    if (this.polling || !this.connected() || this.watched.size === 0) return;
    this.polling = true;
    this.pollAgain = false;
    const accounts = [...this.watched.keys()];
    try {
      const results = await this.read(accounts);
      this.rejected = false;
      accounts.forEach((account, index) => {
        const entry = this.watched.get(account);
        const status = results[index] ?? null;
        if (entry === undefined || (entry.known && sameStatus(entry.status, status)))
          return;
        entry.known = true;
        entry.status = status;
        for (const listener of [...entry.listeners]) notify(listener, status);
      });
    } catch (error) {
      // A failed read keeps the last value. The next poll reads again.
      if (
        error instanceof HostedRelayPresenceError &&
        error.code === "FRAME_REJECTED"
      )
        this.rejected = true;
    } finally {
      this.polling = false;
      if (this.connected() && this.watched.size > 0)
        this.schedule(this.pollAgain ? 0 : PRESENCE_WATCH_POLL_MILLISECONDS);
    }
  }
}

/** A listener that throws does not stop the others or the poll. */
function notify(
  listener: WatchListener,
  status: HostedRelayPresenceStatus | null,
): void {
  try {
    listener(status);
  } catch (error) {
    queueMicrotask(() => {
      throw error;
    });
  }
}

/**
 * The presence of a hosted client with a mailbox subscription. Every request
 * goes over the socket, so start the subscription first. Each client has one
 * presence object, and its watches share one poll.
 */
export function hostedRelayPresence(
  client: DefaultSignalProtocolClient,
): HostedRelayPresence {
  const existing = presences.get(client);
  if (existing !== undefined) return existing;
  const runtime = presenceRuntime(client);
  // Every request goes over the socket, never over HTTP.
  const operations = presenceOperations(runtime, async (request) => {
    const socket = runtime.presenceSocket;
    if (socket === undefined)
      throw new HostedRelayPresenceError(
        "NOT_CONNECTED",
        "The mailbox subscription is not running",
        true,
      );
    return socket.presence(request);
  });
  const watch = new PresenceWatch(runtime, operations.read);
  const presence: HostedRelayPresence = {
    ...operations,
    watch: (account, onChange) => watch.watch(account, onChange),
  };
  presences.set(client, presence);
  return presence;
}

/**
 * The presence of a wake client, over HTTP. Use it only where the client runs
 * no mailbox subscription, for example beside `pullHostedRelayAfterWake()`.
 */
export function hostedRelayWakePresence(
  client: HostedRelayWakeClient,
): HostedRelayWakePresence {
  const runtime = presenceRuntime(client);
  return presenceOperations(runtime, async (request) => {
    try {
      return await runtime.postPresence(request);
    } catch (error) {
      if (!(error instanceof HostedRelayHttpError)) throw error;
      throw new HostedRelayPresenceError(
        error.code,
        error.message,
        error.retryable,
      );
    }
  });
}
