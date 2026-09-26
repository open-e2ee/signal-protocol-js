import type {
  Envelope,
  RelayConnectionReason,
  RelayConnectionState,
  Unsubscribe,
} from "../remote/relay/types";
import {
  HostedRelayPresenceError,
  decodePresenceAnswer,
  encodePresenceFrame,
  isPresenceAnswerType,
  type HostedRelayPresenceRequest,
} from "./hosted-presence-frames";

const MAILBOX_PROTOCOL = "open-e2ee-relay.v1";
const AUTH_PROTOCOL_PREFIX = "open-e2ee-relay.auth.";
const RECOVERY_MILLISECONDS = 2_000;
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
  let reconnectDelay = 1_000;
  let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  let handshakeTimer: ReturnType<typeof setTimeout> | undefined;
  let renewalTimer: ReturnType<typeof setTimeout> | undefined;
  let recoveryTimer: ReturnType<typeof setTimeout> | undefined;
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

  const recoverLater = () => {
    if (!active || recoveryTimer !== undefined) return;
    recoveryTimer = setTimeout(() => {
      recoveryTimer = undefined;
      requestPull();
    }, RECOVERY_MILLISECONDS);
  };

  const receiveBatch = async (messages: readonly Envelope[]) => {
    if (!active || messages.length === 0) return;
    options.onBatchStart?.();
    try {
      for (const message of messages) {
        if (!active) break;
        await options.receive(message);
      }
    } finally {
      options.onBatchEnd?.();
    }
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
          await receiveBatch(durable.splice(0));
          // One frame acknowledges the whole burst once nothing is queued.
          if (durable.length === 0) flushAcknowledgments();
          continue;
        }
        pullRequested = false;
        flushAcknowledgments();
        const messages = await options.pull();
        await receiveBatch(messages);
        flushAcknowledgments();
        // A full page can leave more retained work behind it.
        if (messages.length >= MAXIMUM_PENDING_FRAMES) recoverLater();
      }
    } catch {
      // Failed durable work stays in the mailbox. Ephemeral work can be lost.
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
    const delay = reconnectDelay;
    reconnectDelay = Math.min(30_000, reconnectDelay * 2);
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
        // The Relay replays retained messages over the socket on connect.
        clearTimeout(recoveryTimer);
        recoveryTimer = undefined;
        reconnectDelay = 1_000;
        options.onConnectionState("connected");
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
            return;
          }
          const frame: unknown = JSON.parse(event.data);
          if (typeof frame !== "object" || frame === null || !("type" in frame))
            throw new Error("Invalid mailbox frame.");
          if (isPresenceAnswerType(frame.type))
            answerPresence(frame as Record<string, unknown>);
          else if (frame.type === "durable-message" && "message" in frame)
            queueDurable(candidate, frame.message);
          else if (frame.type === "ephemeral-message" && "message" in frame) {
            if (ephemeral.length >= MAXIMUM_PENDING_FRAMES)
              throw new Error("Mailbox frame queue is full.");
            ephemeral.push({ socket: candidate, message: frame.message });
            void drain();
          } else if (frame.type !== "acknowledged")
            throw new Error("Invalid mailbox frame.");
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
