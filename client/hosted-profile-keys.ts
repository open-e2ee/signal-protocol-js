/**
 * The presence key exchange of a hosted client. The client carries this
 * account's profile key in its end-to-end encrypted 1:1 content, in the Signal
 * `DataMessage.profileKey` shape. The receiving client keeps the key in the
 * contact profile store, derives the sender's presence key from it, and
 * grants that key. When the profile key changes, the client registers the new
 * presence key, and the Relay revokes the old one.
 *
 * The profile key goes only in encrypted content. The presence key goes only
 * in the `presence-key` frame and the `presence-read` frame.
 */
import { base64ToBytes, bytesToBase64 } from "../internal/crypto";
import type { Logger } from "../logger";
import {
  storeReceivedProfileKey,
  type MutableContactProfileStateStore,
} from "../profile/contact-state";
import { asBase64 } from "../types/utils";
import type { DefaultSignalProtocolClient } from "./client";
import {
  HostedRelayPresenceError,
  derivePresenceKey,
  hostedRelayPresence,
  type HostedRelayPresenceRuntime,
} from "./hosted-presence";
import {
  PROFILE_KEY_UPDATE_FLAG,
  bindProfileKeyExchange,
} from "./profile-key-exchange";

/** The profile keys that a hosted client carries in its 1:1 messages. */
export interface HostedRelayProfileKeys {
  /**
   * Returns this account's 32-byte profile key, or null when it has none. The
   * SDK reads it before each 1:1 send and when the mailbox socket connects,
   * so a new key takes effect at the next of these. Each device of the
   * account must return the same key.
   */
  getOwnProfileKey(): Promise<Uint8Array | null>;
  /** Keeps the profile key that each contact sent. */
  readonly contacts: MutableContactProfileStateStore;
}

const DELIVERED_METADATA_PREFIX = "hostedRelay.profileKeyDelivered.v1:";

interface OwnProfileKey {
  readonly bytes: Uint8Array;
  /** Standard base64, the `DataMessage.profileKey` encoding. */
  readonly profileKey: string;
  readonly presenceKey: string;
}

/** @internal Throws unless the option has the members that the SDK calls. */
export function assertHostedRelayProfileKeys(keys: HostedRelayProfileKeys): void {
  if (
    typeof keys?.getOwnProfileKey !== "function" ||
    typeof keys.contacts?.storeContactProfileKey !== "function" ||
    typeof keys.contacts.updateUnidentifiedAccessMode !== "function"
  )
    throw new Error("Signal Protocol Relay profile keys are invalid");
}

/** @internal Bind the presence key exchange of a hosted client. */
export function bindHostedRelayProfileKeys(
  client: DefaultSignalProtocolClient,
  runtime: HostedRelayPresenceRuntime,
  keys: HostedRelayProfileKeys,
  logger: Required<Logger>,
): void {
  assertHostedRelayProfileKeys(keys);
  const presence = hostedRelayPresence(client);
  /** The presence key that the Relay holds from this client. */
  let registered: string | undefined;
  /** A presence key that the Relay refused. The client does not send it again. */
  let refused: string | undefined;
  let registering: Promise<void> | undefined;
  const offers = new Map<string, Promise<void>>();

  const warn = (message: string, error: unknown): void =>
    logger.warn(message, {
      category: "E2EE",
      data: { error: error instanceof Error ? error.message : String(error) },
    });

  /** Reads this account's profile key. It throws unless the key has 32 bytes. */
  const own = async (): Promise<OwnProfileKey | undefined> => {
    const bytes = await keys.getOwnProfileKey();
    if (bytes === null) return undefined;
    const presenceKey = await derivePresenceKey(bytes);
    return { bytes, profileKey: bytesToBase64(bytes), presenceKey };
  };

  const deliveredMetadataKey = (recipient: string): string =>
    `${DELIVERED_METADATA_PREFIX}${runtime.presenceScope}:${recipient}`;

  /**
   * Registers the presence key once for each client and again after each
   * profile key change. A later send or connect retries a retryable failure.
   */
  const register = (key: OwnProfileKey): void => {
    if (
      registering !== undefined ||
      key.presenceKey === registered ||
      key.presenceKey === refused ||
      runtime.relayConnectionState.state !== "connected"
    )
      return;
    registering = presence
      .accessKey(key.bytes)
      .then(
        () => {
          registered = key.presenceKey;
        },
        (error: unknown) => {
          if (!(error instanceof HostedRelayPresenceError) || !error.retryable)
            refused = key.presenceKey;
          warn("Signal Protocol Relay presence key registration failed", error);
        },
      )
      .finally(() => {
        registering = undefined;
      });
  };

  runtime.subscribeRelayConnectionState((state) => {
    if (state.state !== "connected") return;
    own().then(
      (key) => {
        if (key !== undefined) register(key);
      },
      (error: unknown) => warn("Signal Protocol profile key is invalid", error),
    );
  });

  bindProfileKeyExchange(client, {
    outgoing: async () => {
      try {
        const key = await own();
        if (key === undefined) return undefined;
        register(key);
        return key.profileKey;
      } catch (error) {
        warn("Signal Protocol profile key is invalid", error);
        return undefined;
      }
    },
    delivered: async (recipient, profileKey) => {
      try {
        const presenceKey = await derivePresenceKey(
          base64ToBytes(asBase64(profileKey)),
        );
        const metadataKey = deliveredMetadataKey(recipient);
        if ((await runtime.presenceStore.getMetadata(metadataKey)) !== presenceKey)
          await runtime.presenceStore.setMetadata(metadataKey, presenceKey);
      } catch (error) {
        warn("Signal Protocol profile key delivery was not recorded", error);
      }
    },
    offer: (recipient) => {
      const pending = offers.get(recipient);
      if (pending !== undefined) return pending;
      const offer = (async () => {
        const key = await own();
        if (key === undefined) return;
        register(key);
        const delivered = await runtime.presenceStore.getMetadata(
          deliveredMetadataKey(recipient),
        );
        if (delivered === key.presenceKey) return;
        // The DataMessage path adds the profile key and records the delivery.
        await client.send(recipient, { flags: PROFILE_KEY_UPDATE_FLAG });
      })()
        .catch((error: unknown) =>
          warn("Signal Protocol profile key update was not sent", error),
        )
        .finally(() => {
          offers.delete(recipient);
        });
      offers.set(recipient, offer);
      return offer;
    },
    incoming: async (sender, profileKey) => {
      try {
        const bytes = base64ToBytes(asBase64(profileKey));
        const presenceKey = await derivePresenceKey(bytes);
        await storeReceivedProfileKey(
          sender,
          bytesToBase64(bytes),
          keys.contacts,
          logger,
        );
        await presence.grant(sender, presenceKey);
      } catch (error) {
        warn("Signal Protocol contact profile key was not kept", error);
      }
    },
  });
}
