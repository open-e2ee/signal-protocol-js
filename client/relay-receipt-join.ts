/**
 * Relay receipt join: the `'auto'` decision whether an arrival's E2EE
 * delivery receipt is needed, joined with the Relay's reply to the
 * acknowledgment of that arrival.
 *
 * A relay that can send a Relay delivery receipt for an acknowledged message
 * declares its join here. The reply to an acknowledgment lists, in
 * `receipted`, each message for which the Relay owns the delivery receipt.
 * The gate decision and the reply come in either order, so the join keeps
 * each one for its message until the other one comes.
 *
 * The join fails closed. The Relay owns the receipt only when the reply
 * lists the message. A reply that omits it, a failed acknowledgment, a socket
 * that closes before the reply, and no reply within `RELAY_RECEIPT_REPLY_MS`
 * all leave the receipt to the client.
 *
 * No package entry exports this module. The declaration is internal to the
 * SDK, so no public type carries it.
 *
 * @internal
 */

/**
 * The longest wait for the reply to an acknowledgment. It equals the
 * longest wait of a batched E2EE delivery receipt.
 */
export const RELAY_RECEIPT_REPLY_MS = 30_000;
/** The join keeps no more replies that wait for their gate than this. */
const MAXIMUM_WAITING_REPLIES = 1_000;

/** Receives true when the Relay owns the delivery receipt of the message. */
export type RelayReceiptDecision = (relayOwnsReceipt: boolean) => void;

export class RelayReceiptJoin {
  /** Each gate that waits for its reply, by message ID. */
  private readonly gates = new Map<
    string,
    { readonly decide: RelayReceiptDecision[]; readonly timer: ReturnType<typeof setTimeout> }
  >();
  /** Each reply that waits for its gate, by message ID, oldest first. */
  private readonly replies = new Map<string, { readonly owned: boolean; readonly at: number }>();

  /**
   * Calls `decide` once with the reply for this message: at once when the
   * reply came first, and otherwise when it comes. Without a reply within
   * `RELAY_RECEIPT_REPLY_MS`, `decide` receives false.
   */
  public await(messageId: string, decide: RelayReceiptDecision): void {
    this.forgetOldReplies();
    const reply = this.replies.get(messageId);
    if (reply !== undefined) {
      this.replies.delete(messageId);
      decide(reply.owned);
      return;
    }
    const gate = this.gates.get(messageId);
    if (gate !== undefined) {
      gate.decide.push(decide);
      return;
    }
    const timer = setTimeout(() => this.decide(messageId, false), RELAY_RECEIPT_REPLY_MS);
    this.gates.set(messageId, { decide: [decide], timer });
  }

  /**
   * Records the reply for one acknowledged message. `owned` is true only when
   * the reply lists the message in `receipted`.
   */
  public settle(messageId: string, owned: boolean): void {
    if (this.decide(messageId, owned)) return;
    this.forgetOldReplies();
    this.replies.delete(messageId);
    this.replies.set(messageId, { owned, at: Date.now() });
    if (this.replies.size > MAXIMUM_WAITING_REPLIES) {
      const oldest = this.replies.keys().next().value;
      if (oldest !== undefined) this.replies.delete(oldest);
    }
  }

  /** Every waiting gate receives false, and every waiting reply is dropped. */
  public release(): void {
    this.replies.clear();
    for (const messageId of [...this.gates.keys()]) this.decide(messageId, false);
  }

  private decide(messageId: string, owned: boolean): boolean {
    const gate = this.gates.get(messageId);
    if (gate === undefined) return false;
    this.gates.delete(messageId);
    clearTimeout(gate.timer);
    for (const decide of gate.decide) decide(owned);
    return true;
  }

  /** A reply older than the reply bound waits for a gate that does not come. */
  private forgetOldReplies(): void {
    const oldest = Date.now() - RELAY_RECEIPT_REPLY_MS;
    for (const [messageId, reply] of this.replies) {
      if (reply.at > oldest) break;
      this.replies.delete(messageId);
    }
  }
}

const joins = new WeakMap<object, RelayReceiptJoin>();

/** Declare the receipt join of this relay. */
export function declareRelayReceiptJoin(relay: object, join: RelayReceiptJoin): void {
  joins.set(relay, join);
}

/** The receipt join that this relay object declared. A wrapper declares none. */
export function relayReceiptJoinOf(relay: object): RelayReceiptJoin | undefined {
  return joins.get(relay);
}
