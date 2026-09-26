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
import type {
  MailboxSubscriptionHandle,
  PresenceSocketEvent,
} from "./hosted-mailbox-subscription";
import type { HostedRelayWakeClient } from "./hosted-push";
import { HostedRelayHttpError } from "./hosted-transport";
import {
  HostedRelayPresenceError,
  PRESENCE_READ_LIMIT,
  PRESENCE_WATCH_LIMIT,
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

/**
 * The interval of the `watch()` poll. It reads only the accounts that no
 * answered presence watch covers.
 */
export const PRESENCE_WATCH_POLL_MILLISECONDS = 30_000;

/**
 * The interval of the `watch()` renewal. Each renewal sends the whole watch
 * set again, and its answer is the read of the watched accounts. The Relay
 * drops a watch that is not renewed in two intervals.
 */
export const PRESENCE_WATCH_RENEWAL_MILLISECONDS = 120_000;

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
   * change. While the mailbox socket is connected, the client registers one
   * presence watch for the first 16 watched accounts. It registers at once,
   * at each change of that set, at each new socket, and again every 120 s.
   * The Relay then pushes each change. The client reads the other accounts
   * every 30 s. After a failed watch, or when no answer arrives in 10 s, it
   * reads every account every 30 s and tries the watch again 120 s later. A
   * failed read keeps the last value. After a `FRAME_REJECTED` request, it
   * waits 30 s after the reconnect to read and 120 s to watch.
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
  /** Receives each new mailbox socket and each pushed presence edge. */
  subscribePresenceSocket(
    listener: (event: PresenceSocketEvent) => void,
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

/** The account with the key that `grant()` stored for it, if any. */
async function presenceTarget(
  runtime: HostedRelayPresenceRuntime,
  account: string,
): Promise<HostedRelayPresenceTarget> {
  const stored = await runtime.presenceStore.getMetadata(
    grantMetadataKey(runtime, account),
  );
  return stored === null
    ? { account }
    : { account, presenceKey: assertPresenceKey(stored) };
}

type PresenceSend = (request: HostedRelayPresenceRequest) => Promise<unknown>;

function presenceOperations(
  runtime: HostedRelayPresenceRuntime,
  send: PresenceSend,
): HostedRelayWakePresence {
  const request = async <Request extends HostedRelayPresenceRequest>(
    value: Request,
  ): Promise<HostedRelayPresenceResults[Request["type"]]> =>
    decodePresenceResult(value, await send(value));

  const target = (account: string) => presenceTarget(runtime, account);

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

function sameAccounts(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return (
    left.length === right.length &&
    left.every((account, index) => account === right[index])
  );
}

function refused(error: unknown): boolean {
  return (
    error instanceof HostedRelayPresenceError && error.code === "FRAME_REJECTED"
  );
}

/**
 * The presence watch of a client, shared by all its `watch()` calls. It runs
 * only while the mailbox socket is connected, which the lifecycle binding
 * limits to the foreground.
 *
 * The first PRESENCE_WATCH_LIMIT watched accounts, in watch order, are the
 * watch set. One `presence-watch` request registers that set on the socket.
 * Its answer is the read of those accounts, and the Relay then pushes each
 * change as a `presence-update` frame. The client sends the set again at each
 * change of the set, at each new socket, and every
 * PRESENCE_WATCH_RENEWAL_MILLISECONDS. The Relay drops a watch that is not
 * renewed, and it can lose a watch without a signal, so the renewal is also
 * the bound of a lost watch.
 *
 * The poll reads the accounts past the watch set, and every account while no
 * answered watch covers the set: after a failed watch, until a watch answers
 * again.
 */
class PresenceWatch {
  private readonly watched = new Map<string, WatchedAccount>();
  /** The next registration: at once, or the renewal of the last one. */
  private registerTimer: ReturnType<typeof setTimeout> | undefined;
  private registering = false;
  private registerAgain = false;
  /**
   * The accounts of the last watch request on this socket. An empty list
   * means that the socket holds no watch, so an empty set sends nothing.
   */
  private requested: readonly string[] = [];
  /** The presence keys of the last watch request, for each account. */
  private requestedKeys = new Map<string, string | undefined>();
  /** The last watch request on this socket was answered. */
  private confirmed = false;
  private pollTimer: ReturnType<typeof setTimeout> | undefined;
  private polling = false;
  private pollAgain = false;
  /**
   * The Signal Protocol Relay closed the socket on the last presence frame.
   * After the reconnect, the client reads one full poll interval later and
   * watches one full renewal interval later, so a Relay without these frames
   * does not see a reconnect loop.
   */
  private rejected = false;
  private stopListeners: Unsubscribe | undefined;

  public constructor(
    private readonly runtime: HostedRelayPresenceRuntime,
    private readonly read: HostedRelayPresence["read"],
    private readonly target: (
      account: string,
    ) => Promise<HostedRelayPresenceTarget>,
    private readonly send: PresenceSend,
  ) {}

  public watch(account: string, onChange: WatchListener): Unsubscribe {
    assertPresenceAccount(account);
    if (typeof onChange !== "function")
      throw new Error("Signal Protocol Relay presence listener is invalid");
    let entry = this.watched.get(account);
    const added = entry === undefined;
    if (entry === undefined) {
      entry = { listeners: new Set(), known: false, status: null };
      this.watched.set(account, entry);
    }
    const watchedEntry = entry;
    // Each call owns its own listener, so one callback can watch twice.
    const listener: WatchListener = (status) => onChange(status);
    watchedEntry.listeners.add(listener);
    this.listen();
    if (watchedEntry.known) {
      queueMicrotask(() => {
        if (watchedEntry.listeners.has(listener))
          notify(listener, watchedEntry.status);
      });
    }
    if (added) this.changed();
    return () => {
      if (!watchedEntry.listeners.delete(listener)) return;
      if (
        watchedEntry.listeners.size === 0 &&
        this.watched.get(account) === watchedEntry
      ) {
        this.watched.delete(account);
        this.changed();
      }
      this.release();
    };
  }

  /** A new key for a watched account goes to the Relay with the watch. */
  public granted(account: string, presenceKey: string): void {
    if (
      this.connected() &&
      this.watchSet().includes(account) &&
      this.requestedKeys.get(account) !== presenceKey
    )
      this.registerSoon();
  }

  private listen(): void {
    if (this.stopListeners !== undefined) return;
    const stopState = this.runtime.subscribeRelayConnectionState((state) => {
      if (state.state === "connected") return;
      // A closed socket holds no watch. A new socket registers again.
      this.cancel();
      this.requested = [];
      this.confirmed = false;
      this.release();
    });
    const stopSocket = this.runtime.subscribePresenceSocket((event) => {
      if (event.type === "update") {
        this.apply(event.update.account, event.update.presence);
        return;
      }
      this.cancel();
      this.requested = [];
      this.confirmed = false;
      if (this.watched.size === 0) return;
      if (!this.rejected) {
        this.changed();
        return;
      }
      this.schedulePoll(PRESENCE_WATCH_POLL_MILLISECONDS);
      this.registerTimer = setTimeout(
        () => void this.register(),
        PRESENCE_WATCH_RENEWAL_MILLISECONDS,
      );
    });
    this.stopListeners = () => {
      stopState();
      stopSocket();
    };
  }

  /** Stops listening when nothing is watched and no request waits. */
  private release(): void {
    if (
      this.watched.size > 0 ||
      this.registering ||
      this.registerTimer !== undefined
    )
      return;
    clearTimeout(this.pollTimer);
    this.pollTimer = undefined;
    this.stopListeners?.();
    this.stopListeners = undefined;
  }

  private connected(): boolean {
    return this.runtime.relayConnectionState.state === "connected";
  }

  private cancel(): void {
    clearTimeout(this.registerTimer);
    this.registerTimer = undefined;
    clearTimeout(this.pollTimer);
    this.pollTimer = undefined;
  }

  private watchSet(): string[] {
    return [...this.watched.keys()].slice(0, PRESENCE_WATCH_LIMIT);
  }

  /** The accounts that the poll reads. */
  private pollSet(): string[] {
    const accounts = [...this.watched.keys()];
    return this.registering || this.confirmed
      ? accounts.slice(PRESENCE_WATCH_LIMIT)
      : accounts;
  }

  /** Registers when the watch set changed, and reads a new account past it. */
  private changed(): void {
    if (!this.connected()) return;
    if (!sameAccounts(this.watchSet(), this.requested)) this.registerSoon();
    const unknown = [...this.watched.values()]
      .slice(PRESENCE_WATCH_LIMIT)
      .some((entry) => !entry.known);
    if (unknown) this.pollSoon();
  }

  /** Registers at the next turn, so watches that start together share one. */
  private registerSoon(): void {
    if (!this.connected()) return;
    if (this.registering) {
      this.registerAgain = true;
      return;
    }
    clearTimeout(this.registerTimer);
    this.registerTimer = setTimeout(() => void this.register(), 0);
  }

  private async register(): Promise<void> {
    this.registerTimer = undefined;
    if (this.registering || !this.connected()) return;
    const accounts = this.watchSet();
    if (accounts.length === 0 && this.requested.length === 0) {
      this.release();
      return;
    }
    this.registering = true;
    this.registerAgain = false;
    this.requested = accounts;
    try {
      const targets = await Promise.all(accounts.map(this.target));
      this.requestedKeys = new Map(
        targets.map((target) => [target.account, target.presenceKey]),
      );
      const request = { type: "presence-watch", accounts: targets } as const;
      const results = decodePresenceResult(request, await this.send(request));
      this.rejected = false;
      this.confirmed = true;
      accounts.forEach((account, index) =>
        this.apply(account, results[index] ?? null),
      );
    } catch (error) {
      // The Relay can hold the new set or the old one. The poll reads every
      // account until a watch answers again.
      this.confirmed = false;
      if (refused(error)) this.rejected = true;
    } finally {
      this.registering = false;
      if (this.connected()) {
        if (this.registerAgain) this.registerSoon();
        else if (this.watched.size > 0)
          this.registerTimer = setTimeout(
            () => void this.register(),
            PRESENCE_WATCH_RENEWAL_MILLISECONDS,
          );
        this.schedulePoll(PRESENCE_WATCH_POLL_MILLISECONDS);
      }
      this.release();
    }
  }

  /**
   * Starts the poll when it has accounts to read, and stops it when it has
   * none. A running poll keeps its interval.
   */
  private schedulePoll(milliseconds: number): void {
    if (this.pollSet().length === 0) {
      clearTimeout(this.pollTimer);
      this.pollTimer = undefined;
      return;
    }
    if (this.pollTimer !== undefined && milliseconds > 0) return;
    clearTimeout(this.pollTimer);
    this.pollTimer = setTimeout(() => {
      this.pollTimer = undefined;
      void this.poll();
    }, milliseconds);
  }

  /** Reads at the next turn, so watches that start together share one read. */
  private pollSoon(): void {
    if (!this.connected()) return;
    if (this.polling) this.pollAgain = true;
    else this.schedulePoll(0);
  }

  private async poll(): Promise<void> {
    if (this.polling || !this.connected()) return;
    const accounts = this.pollSet();
    if (accounts.length === 0) return;
    this.polling = true;
    this.pollAgain = false;
    try {
      const results = await this.read(accounts);
      this.rejected = false;
      accounts.forEach((account, index) =>
        this.apply(account, results[index] ?? null),
      );
    } catch (error) {
      // A failed read keeps the last value. The next poll reads again.
      if (refused(error)) this.rejected = true;
    } finally {
      this.polling = false;
      if (this.connected())
        this.schedulePoll(this.pollAgain ? 0 : PRESENCE_WATCH_POLL_MILLISECONDS);
    }
  }

  /** Notifies the listeners of a watched account when its presence changed. */
  private apply(
    account: string,
    status: HostedRelayPresenceStatus | null,
  ): void {
    const entry = this.watched.get(account);
    if (entry === undefined || (entry.known && sameStatus(entry.status, status)))
      return;
    entry.known = true;
    entry.status = status;
    for (const listener of [...entry.listeners]) notify(listener, status);
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
 * presence object, and its watches share one presence watch and one poll.
 */
export function hostedRelayPresence(
  client: DefaultSignalProtocolClient,
): HostedRelayPresence {
  const existing = presences.get(client);
  if (existing !== undefined) return existing;
  const runtime = presenceRuntime(client);
  // Every request goes over the socket, never over HTTP.
  const send: PresenceSend = async (request) => {
    const socket = runtime.presenceSocket;
    if (socket === undefined)
      throw new HostedRelayPresenceError(
        "NOT_CONNECTED",
        "The mailbox subscription is not running",
        true,
      );
    return socket.presence(request);
  };
  const operations = presenceOperations(runtime, send);
  const watch = new PresenceWatch(
    runtime,
    operations.read,
    (account) => presenceTarget(runtime, account),
    send,
  );
  const presence: HostedRelayPresence = {
    ...operations,
    grant: async (account, presenceKey) => {
      await operations.grant(account, presenceKey);
      watch.granted(account, presenceKey);
    },
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
