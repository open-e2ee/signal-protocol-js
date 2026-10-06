import type {
  Envelope,
  RelayConnectionReason,
  RelayConnectionState,
  Unsubscribe,
} from "../remote/relay/types";
import {
  HostedRelayPresenceError,
  decodePresenceAnswer,
  decodePresenceUpdate,
  encodePresenceFrame,
  isPresenceAnswerType,
  isPresenceUpdateType,
  type HostedRelayPresenceRequest,
  type HostedRelayPresenceUpdate,
} from "./hosted-presence-frames";

const MAILBOX_PROTOCOL = "open-e2ee-relay.v1";
const AUTH_PROTOCOL_PREFIX = "open-e2ee-relay.auth.";
/**
 * The recovery pull waits a random time from half to one and a half of this
 * value after the call that asks for it, so clients that lose their sockets
 * together do not pull together. A pending pull is replaced only by a pull
 * that starts sooner, so many calls can bring the pull near the 1 s floor.
 * The floor is the bound: the recovery timers fire at least 1 s apart, so a
 * failing pull does not loop fast.
 */
const RECOVERY_MILLISECONDS = 2_000;
/**
 * The recovery pull after failed work starts at `RECOVERY_MILLISECONDS` and
 * doubles each time it schedules a pull for failed work, from a socket batch,
 * a recovery page, or a socket open, up to this value. A recovery page that
 * leaves no failed message, and a new socket, start it again at
 * `RECOVERY_MILLISECONDS`. The same random factor applies.
 */
const MAXIMUM_RECOVERY_MILLISECONDS = 64_000;
/**
 * A recovery page that is not full shows a failed message gone when the page
 * does not hold it. The message must also have first failed longer than this
 * before the pull of the page started. Then the message expired or was
 * acknowledged elsewhere. A newer failed message can still wait in the
 * Relay's 1.5 s hot delivery window, which a pull page does not show.
 */
const FAILED_MESSAGE_GONE_MILLISECONDS = 5_000;
/**
 * The reconnect ceiling starts at 1 s and doubles to 30 s. Each wait is a
 * random time from zero up to the ceiling (full jitter), the first one too, so
 * clients that lose their sockets together, for example in a Relay deploy, do
 * not reconnect together. The ceiling starts again at 1 s when the Relay
 * answers a ping, 30 s after the socket opens. A socket that closes sooner,
 * for example on a frame that the client refuses on each connect, keeps the
 * ceiling growing, so a loop of short connections backs off to 30 s.
 */
const FIRST_RECONNECT_MILLISECONDS = 1_000;
const MAXIMUM_RECONNECT_MILLISECONDS = 30_000;
/** The Relay answers each `ping` text frame with `pong` without waking the mailbox. */
const PING_MILLISECONDS = 30_000;
/**
 * The tick that would send this many unanswered pings closes the socket
 * instead. That is 60 s after the last answered ping. The Relay closes a socket
 * whose last answered ping is 75 s old, so the client gives up first.
 */
const MAXIMUM_UNANSWERED_PINGS = 2;
const MAXIMUM_FRAME_CHARACTERS = 1024 * 1024;
const MAXIMUM_PENDING_FRAMES = 100;
/** The Relay refuses an acknowledgment frame that carries more ids. */
const MAXIMUM_ACKNOWLEDGMENT_IDS = 100;
/** A presence request fails with `BUSY` while this many wait for an answer. */
const MAXIMUM_PENDING_PRESENCE_REQUESTS = 16;
/** A presence request fails with `TIMEOUT` when its answer takes longer. */
const PRESENCE_ANSWER_MILLISECONDS = 10_000;
/** The Relay closes the socket with this code on a frame that it refuses. */
const POLICY_VIOLATION_CLOSE_CODE = 1008;

/**
 * A presence event of the live socket: `open` when a new socket opens, which
 * holds no presence watch, and `update` for each pushed presence edge.
 */
export type PresenceSocketEvent =
  | { readonly type: "open" }
  | { readonly type: "update"; readonly update: HostedRelayPresenceUpdate };

interface MailboxSubscription {
  authenticate(): Promise<{ url: string; token: string; renewAt: number }>;
  /** Decodes the `message` of a `durable-message` frame. */
  decodeDurable(message: unknown): Envelope;
  /** Recovers retained messages over HTTP while no socket delivers them. */
  pull(): Promise<readonly Envelope[]>;
  /** Acknowledges over HTTP when queued socket acknowledgments lose their socket. */
  acknowledge(messageIds: readonly string[]): Promise<void>;
  receive(envelope: Envelope): void | Promise<void>;
  receiveEphemeral(message: unknown, current: () => boolean): Promise<string>;
  onBatchStart?(): void;
  onBatchEnd?(): void;
  /**
   * Receives each connection transition. The subscription starts at
   * `connecting` and ends at `stopped`. A token renewal on a live socket is not
   * a transition.
   */
  onConnectionState(
    state: RelayConnectionState["state"],
    reason?: RelayConnectionReason,
  ): void;
  /**
   * Receives each presence event. A token renewal opens a new socket without
   * a connection transition, and the new socket holds no watch.
   */
  onPresence?(event: PresenceSocketEvent): void;
}

export interface MailboxSubscriptionHandle {
  readonly unsubscribe: Unsubscribe;
  /**
   * Queues a socket acknowledgment and returns true while a socket is live.
   * Queued ids leave in one frame when the delivered frames are drained.
   */
  acknowledge(messageId: string): boolean;
  /**
   * Sends one presence request frame on the live socket and resolves with the
   * `result` of its answer. It rejects with a `HostedRelayPresenceError`: the
   * Relay's error, or `NOT_CONNECTED`, `TIMEOUT`, `BUSY`, or
   * `FRAME_REJECTED`. There is no HTTP fallback.
   */
  presence(request: HostedRelayPresenceRequest): Promise<unknown>;
}

interface PendingPresence {
  readonly resolve: (result: unknown) => void;
  readonly reject: (error: HostedRelayPresenceError) => void;
  readonly timer: ReturnType<typeof setTimeout>;
}

function notConnected(): HostedRelayPresenceError {
  return new HostedRelayPresenceError(
    "NOT_CONNECTED",
    "The mailbox socket is not connected",
    true,
  );
}

/**
 * Delivers durable and ephemeral frames from the mailbox socket and acknowledges
 * durable frames over the same socket. HTTP pull recovers retained messages
 * only while the socket is down or after a handler failure.
 */
export function subscribeHostedMailbox(
  options: MailboxSubscription,
): MailboxSubscriptionHandle {
  let active = true;
  let socket: WebSocket | undefined;
  let connectionGeneration = 0;
  let reconnectDelay = FIRST_RECONNECT_MILLISECONDS;
  let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  let handshakeTimer: ReturnType<typeof setTimeout> | undefined;
  let renewalTimer: ReturnType<typeof setTimeout> | undefined;
  let recoveryTimer: ReturnType<typeof setTimeout> | undefined;
  /** The `Date.now()` time at which the pending recovery pull starts. */
  let recoveryDue = 0;
  let failedWorkRecoveryDelay = RECOVERY_MILLISECONDS;
  /**
   * The id of each message whose work failed, with the `Date.now()` time of
   * its first failure. An id leaves when its work succeeds or when a recovery
   * page shows that the message is gone.
   */
  const failedMessages = new Map<string, number>();
  /** The acknowledgments that `handle.acknowledge` received. */
  let acknowledgmentCount = 0;
  let pingTimer: ReturnType<typeof setTimeout> | undefined;
  let unansweredPings = 0;
  let acknowledgmentTimer: ReturnType<typeof setTimeout> | undefined;
  let draining = false;
  let pullRequested = false;
  const ephemeral: { socket: WebSocket; message: unknown }[] = [];
  const durable: Envelope[] = [];
  const acknowledgments: string[] = [];
  const presenceRequests = new Map<string, PendingPresence>();
  let presenceSequence = 0;

  const liveSocket = () =>
    active && socket?.readyState === 1 ? socket : undefined;

  /** Settles every pending presence request with one error. */
  const rejectPresence = (error: HostedRelayPresenceError) => {
    const pending = [...presenceRequests.values()];
    presenceRequests.clear();
    for (const request of pending) {
      clearTimeout(request.timer);
      request.reject(error);
    }
  };

  const answerPresence = (frame: Record<string, unknown>) => {
    const answer = decodePresenceAnswer(frame);
    const request = presenceRequests.get(answer.id);
    // An answer after its timeout has nothing to settle.
    if (request === undefined) return;
    presenceRequests.delete(answer.id);
    clearTimeout(request.timer);
    if ("error" in answer) request.reject(answer.error);
    else request.resolve(answer.result);
  };

  const flushAcknowledgments = () => {
    clearTimeout(acknowledgmentTimer);
    acknowledgmentTimer = undefined;
    while (acknowledgments.length > 0) {
      const messageIds = acknowledgments.splice(
        0,
        MAXIMUM_ACKNOWLEDGMENT_IDS,
      );
      const live = socket?.readyState === 1 ? socket : undefined;
      if (live !== undefined) {
        live.send(JSON.stringify({ type: "acknowledge", messageIds }));
        continue;
      }
      // The socket left after delivery. Reconnect redelivery re-acknowledges
      // anything this request loses.
      options.acknowledge(messageIds).catch(() => undefined);
    }
  };

  /**
   * Schedules one recovery pull. A pending pull that starts sooner stays, and
   * a pending pull that starts later is replaced, so a longer wait for failed
   * work does not delay the pull of a reconnect attempt or of a full page.
   * Returns false when the pending pull stays or the subscription stopped.
   */
  const recoverLater = (delay = RECOVERY_MILLISECONDS) => {
    if (!active) return false;
    const wait = delay * (0.5 + Math.random());
    const due = Date.now() + wait;
    if (recoveryTimer !== undefined) {
      if (due >= recoveryDue) return false;
      clearTimeout(recoveryTimer);
    }
    recoveryDue = due;
    recoveryTimer = setTimeout(() => {
      recoveryTimer = undefined;
      requestPull();
    }, wait);
    return true;
  };

  /** Schedules the recovery pull for failed work, and doubles its next wait. */
  const recoverFailedWork = () => {
    if (recoverLater(failedWorkRecoveryDelay))
      failedWorkRecoveryDelay = Math.min(
        MAXIMUM_RECOVERY_MILLISECONDS,
        failedWorkRecoveryDelay * 2,
      );
  };

  /**
   * Receives each message in mailbox order. A message whose work fails stays
   * in the mailbox, and the next recovery pull or socket replay gives it
   * again. The batch continues with the next message at once, whatever its
   * sender, so the order is not kept across a failed message. Resolves with
   * `failed` true when the work of a message failed, and with the number of
   * acknowledgments made during the batch. A message that resolves without an
   * acknowledgment, as an unhandled duplicate or a failed retry-request send
   * does, is not counted.
   */
  const receiveBatch = async (messages: readonly Envelope[]) => {
    if (!active || messages.length === 0)
      return { failed: false, acknowledged: 0 };
    let failed = false;
    const acknowledgmentsBefore = acknowledgmentCount;
    options.onBatchStart?.();
    try {
      for (const message of messages) {
        if (!active) break;
        try {
          await options.receive(message);
          if (message.id !== undefined) failedMessages.delete(message.id);
        } catch {
          failed = true;
          if (message.id !== undefined && !failedMessages.has(message.id))
            failedMessages.set(message.id, Date.now());
        }
      }
    } finally {
      options.onBatchEnd?.();
    }
    return {
      failed,
      acknowledged: acknowledgmentCount - acknowledgmentsBefore,
    };
  };

  /**
   * Forgets each failed message that a recovery page shows to be gone. A page
   * that is not full holds every retained message, except a message in the
   * Relay's hot delivery window. Such a page shows a failed message gone when
   * the page does not hold it. The message must also have first failed more
   * than `FAILED_MESSAGE_GONE_MILLISECONDS` before `pulledAt`. `pulledAt` is
   * the `Date.now()` time at which the pull of the page started. Then the
   * message expired or was acknowledged elsewhere. A slow batch does not make
   * a failure older than its page.
   */
  const forgetGoneFailures = (page: readonly Envelope[], pulledAt: number) => {
    if (page.length >= MAXIMUM_PENDING_FRAMES) return;
    const held = new Set(page.map((message) => message.id));
    const gone = pulledAt - FAILED_MESSAGE_GONE_MILLISECONDS;
    for (const [messageId, failedAt] of failedMessages)
      if (failedAt < gone && !held.has(messageId))
        failedMessages.delete(messageId);
  };

  const drain = async () => {
    if (draining || !active) return;
    draining = true;
    try {
      while (
        active &&
        (pullRequested || ephemeral.length > 0 || durable.length > 0)
      ) {
        const live = ephemeral.shift();
        if (live !== undefined) {
          const current = () =>
            active && socket === live.socket && live.socket.readyState === 1;
          if (!current()) continue;
          const messageId = await options.receiveEphemeral(
            live.message,
            current,
          );
          if (current())
            live.socket.send(
              JSON.stringify({ type: "ephemeral-accepted", messageId }),
            );
          continue;
        }
        if (durable.length > 0) {
          const { failed } = await receiveBatch(durable.splice(0));
          if (failed) recoverFailedWork();
          // One frame acknowledges the whole burst once nothing is queued.
          if (durable.length === 0) flushAcknowledgments();
          continue;
        }
        pullRequested = false;
        flushAcknowledgments();
        const pulledAt = Date.now();
        const messages = await options.pull();
        const { failed, acknowledged } = await receiveBatch(messages);
        flushAcknowledgments();
        // A failed message can be missing from the page while it waits in the
        // Relay's hot delivery window, so a pull follows while one remains.
        forgetGoneFailures(messages, pulledAt);
        if (failed || failedMessages.size > 0) recoverFailedWork();
        else failedWorkRecoveryDelay = RECOVERY_MILLISECONDS;
        // A full page can leave more retained work behind it. A full recovery
        // page whose batch acknowledged a message pulls the next page after a
        // random wait from 1 s to 3 s. A full page that acknowledged nothing
        // pulls again only while a failed message remains, after the
        // failed-work wait.
        if (messages.length >= MAXIMUM_PENDING_FRAMES && acknowledged > 0)
          recoverLater();
      }
    } catch {
      // A pull, an ephemeral message, or a batch callback failed. Retained
      // durable work stays in the mailbox. Ephemeral work can be lost.
      recoverLater();
    } finally {
      draining = false;
      if (
        active &&
        (pullRequested || ephemeral.length > 0 || durable.length > 0)
      )
        void drain();
      else flushAcknowledgments();
    }
  };

  const requestPull = () => {
    if (!active) return;
    pullRequested = true;
    void drain();
  };

  const disconnect = () => {
    const previous = socket;
    socket = undefined;
    connectionGeneration++;
    ephemeral.length = 0;
    durable.length = 0;
    clearTimeout(handshakeTimer);
    clearTimeout(renewalTimer);
    clearTimeout(pingTimer);
    unansweredPings = 0;
    // An answer can arrive only on the socket that carried the request.
    rejectPresence(notConnected());
    try {
      previous?.close(1000, "Subscription connection ended.");
    } catch {
      /* Already closed. */
    }
  };

  const retryConnection = (reason: RelayConnectionReason) => {
    if (!active || reconnectTimer !== undefined) return;
    disconnect();
    options.onConnectionState("reconnecting", reason);
    // One recovery pull per reconnect attempt, paced by the reconnect backoff.
    recoverLater();
    const delay = Math.floor(Math.random() * reconnectDelay);
    reconnectDelay = Math.min(MAXIMUM_RECONNECT_MILLISECONDS, reconnectDelay * 2);
    reconnectTimer = setTimeout(() => {
      reconnectTimer = undefined;
      void connect();
    }, delay);
  };

  const queueDurable = (candidate: WebSocket, message: unknown) => {
    const envelope = options.decodeDurable(message);
    if (durable.length >= MAXIMUM_PENDING_FRAMES) {
      // The frame stays retained in the mailbox; the recovery pull collects it.
      recoverLater();
      return;
    }
    if (socket === candidate) durable.push(envelope);
    void drain();
  };

  const connect = async () => {
    const generation = ++connectionGeneration;
    let authenticated = false;
    try {
      const authority = await options.authenticate();
      authenticated = true;
      if (!active || generation !== connectionGeneration) return;
      const candidate = new WebSocket(authority.url, [
        MAILBOX_PROTOCOL,
        `${AUTH_PROTOCOL_PREFIX}${authority.token}`,
      ]);
      socket = candidate;
      const current = () => active && socket === candidate;
      handshakeTimer = setTimeout(() => {
        if (current()) retryConnection("handshake");
      }, 10_000);
      candidate.addEventListener("open", () => {
        if (!current()) return;
        if (candidate.protocol !== MAILBOX_PROTOCOL) {
          retryConnection("protocol");
          return;
        }
        clearTimeout(handshakeTimer);
        // The Relay replays retained messages over the socket on connect,
        // oldest first, so the replay replaces the pending recovery pull and
        // the failed-work wait starts again. The replay can miss a failed
        // message, because the Relay stores a message from its hot delivery
        // window without a second frame. So a failed-work pull follows while
        // a failed message remains. This pull is scheduled before the replay
        // arrives, so it can find an empty page when the replay handles the
        // last failed message.
        clearTimeout(recoveryTimer);
        recoveryTimer = undefined;
        failedWorkRecoveryDelay = RECOVERY_MILLISECONDS;
        if (failedMessages.size > 0) recoverFailedWork();
        options.onConnectionState("connected");
        options.onPresence?.({ type: "open" });
        const schedulePing = () => {
          pingTimer = setTimeout(() => {
            if (!current()) return;
            if (unansweredPings + 1 >= MAXIMUM_UNANSWERED_PINGS) {
              retryConnection("silent");
              return;
            }
            // Count the ping first: a pong can arrive during `send`.
            unansweredPings++;
            try {
              candidate.send("ping");
            } catch {
              retryConnection("error");
              return;
            }
            schedulePing();
          }, PING_MILLISECONDS);
        };
        schedulePing();
        renewalTimer = setTimeout(
          () => {
            if (!current()) return;
            disconnect();
            void connect();
          },
          Math.max(
            1_000,
            Math.min(2_147_483_647, authority.renewAt - Date.now()),
          ),
        );
      });
      candidate.addEventListener("message", (event: MessageEvent) => {
        if (!current()) return;
        try {
          if (
            typeof event.data !== "string" ||
            event.data.length > MAXIMUM_FRAME_CHARACTERS
          )
            throw new Error("Invalid mailbox frame.");
          if (event.data === "pong") {
            unansweredPings = 0;
            // The socket stayed open and the Relay answers it.
            reconnectDelay = FIRST_RECONNECT_MILLISECONDS;
            return;
          }
          const frame: unknown = JSON.parse(event.data);
          if (
            typeof frame !== "object" ||
            frame === null ||
            !("type" in frame) ||
            typeof frame.type !== "string"
          )
            throw new Error("Invalid mailbox frame.");
          if (isPresenceAnswerType(frame.type))
            answerPresence(frame as Record<string, unknown>);
          else if (isPresenceUpdateType(frame.type)) {
            const update = decodePresenceUpdate(
              frame as Record<string, unknown>,
            );
            options.onPresence?.({ type: "update", update });
          } else if (frame.type === "durable-message") {
            if (!("message" in frame))
              throw new Error("Invalid mailbox frame.");
            queueDurable(candidate, frame.message);
          } else if (frame.type === "ephemeral-message") {
            if (!("message" in frame))
              throw new Error("Invalid mailbox frame.");
            if (ephemeral.length >= MAXIMUM_PENDING_FRAMES)
              throw new Error("Mailbox frame queue is full.");
            ephemeral.push({ socket: candidate, message: frame.message });
            void drain();
          }
          // A newer Relay can send a frame type that this client does not
          // know. The client ignores it and keeps the socket.
        } catch {
          retryConnection("frame");
        }
      });
      candidate.addEventListener("close", (event: CloseEvent) => {
        if (!current()) return;
        if (event.code === POLICY_VIOLATION_CLOSE_CODE)
          rejectPresence(
            new HostedRelayPresenceError(
              "FRAME_REJECTED",
              "The Relay closed the mailbox socket on a refused frame",
              false,
            ),
          );
        retryConnection("closed");
      });
      candidate.addEventListener("error", () => {
        if (current()) retryConnection("error");
      });
    } catch {
      if (active && generation === connectionGeneration)
        retryConnection(authenticated ? "error" : "authentication");
    }
  };

  options.onConnectionState("connecting");
  void connect();
  return {
    acknowledge: (messageId) => {
      // The transport acknowledges over HTTP when this returns false, so the
      // count includes that acknowledgment too.
      acknowledgmentCount++;
      if (liveSocket() === undefined) return false;
      acknowledgments.push(messageId);
      if (acknowledgments.length >= MAXIMUM_ACKNOWLEDGMENT_IDS)
        flushAcknowledgments();
      else if (!draining && acknowledgmentTimer === undefined)
        // An acknowledgment outside a delivery batch leaves on its own.
        acknowledgmentTimer = setTimeout(flushAcknowledgments, 0);
      return true;
    },
    presence: (request) => {
      const live = liveSocket();
      if (live === undefined) return Promise.reject(notConnected());
      if (presenceRequests.size >= MAXIMUM_PENDING_PRESENCE_REQUESTS)
        return Promise.reject(
          new HostedRelayPresenceError(
            "BUSY",
            "Too many presence requests wait for an answer",
            true,
          ),
        );
      presenceSequence += 1;
      const id = presenceSequence.toString(36);
      let frame: string;
      try {
        frame = encodePresenceFrame(id, request);
      } catch (error) {
        return Promise.reject(error);
      }
      return new Promise<unknown>((resolve, reject) => {
        const timer = setTimeout(() => {
          if (!presenceRequests.delete(id)) return;
          reject(
            new HostedRelayPresenceError(
              "TIMEOUT",
              "The Relay did not answer the presence request",
              true,
            ),
          );
        }, PRESENCE_ANSWER_MILLISECONDS);
        presenceRequests.set(id, { resolve, reject, timer });
        try {
          live.send(frame);
        } catch {
          presenceRequests.delete(id);
          clearTimeout(timer);
          reject(notConnected());
          retryConnection("error");
        }
      });
    },
    unsubscribe: () => {
      if (!active) return;
      flushAcknowledgments();
      active = false;
      clearTimeout(reconnectTimer);
      clearTimeout(recoveryTimer);
      disconnect();
      options.onConnectionState("stopped");
    },
  };
}
