/**
 * The seam through which a client carries this account's profile key in its
 * 1:1 content, in the Signal `DataMessage.profileKey` shape, and accepts the
 * profile key that a peer sent. A hosted client binds one. The client knows
 * only this seam, so the hosted presence code stays out of the core client.
 */

/**
 * The Signal `DataMessage.Flags.PROFILE_KEY_UPDATE` bit. A DataMessage with
 * this flag carries only a profile key. The receiving SDK consumes it and does
 * not give it to the application.
 */
export const PROFILE_KEY_UPDATE_FLAG = 4;

/**
 * @internal The profile key exchange of one client. No member throws. Each
 * member logs a failure, so a send or a receive always continues.
 */
export interface ProfileKeyExchange {
  /**
   * This account's profile key as standard base64 for the `profileKey` field
   * of a 1:1 DataMessage, or `undefined` when the account has none.
   */
  outgoing(): Promise<string | undefined>;
  /** Records that `recipient` got `profileKey` in a sent DataMessage. */
  delivered(recipient: string, profileKey: string): Promise<void>;
  /**
   * Before 1:1 content that has no `profileKey` field, sends a key-update
   * DataMessage to a recipient that does not have the current key.
   */
  offer(recipient: string): Promise<void>;
  /** Keeps the profile key that `sender` sent in authenticated 1:1 content. */
  incoming(sender: string, profileKey: string): Promise<void>;
}

const exchanges = new WeakMap<object, ProfileKeyExchange>();

/** @internal Bind the profile key exchange to the client that uses it. */
export function bindProfileKeyExchange(
  client: object,
  exchange: ProfileKeyExchange
): void {
  exchanges.set(client, exchange);
}

/** @internal The client's profile key exchange, or `undefined` when none is bound. */
export function profileKeyExchange(client: object): ProfileKeyExchange | undefined {
  return exchanges.get(client);
}
