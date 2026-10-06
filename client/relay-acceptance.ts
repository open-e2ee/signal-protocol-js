/** What the relay reports about one post that it accepted. */
export interface RelayPostAcceptance {
  messageId: string;
  serverTimestamp: number;
  /** True when the relay had already accepted this exact post. */
  duplicate?: boolean;
  /** The time at which the relay drops the copy that a device has not acknowledged. */
  expiresAt?: number;
}

/**
 * The acceptance of a whole send from the acceptance of each of its posts.
 *
 * The send is a duplicate only when the relay had already accepted every
 * post, and the earliest expiry bounds the whole send. A field is present only
 * when every post reported it, so a send with no post has neither field.
 */
export function aggregateRelayAcceptance(
  posts: readonly Pick<RelayPostAcceptance, 'duplicate' | 'expiresAt'>[]
): { duplicate?: boolean; expiresAt?: number } {
  if (posts.length === 0) return {};
  const duplicates = posts.map((post) => post.duplicate);
  const expiries = posts.map((post) => post.expiresAt);
  return {
    ...(duplicates.every((duplicate) => duplicate !== undefined) && {
      duplicate: duplicates.every(Boolean),
    }),
    ...(expiries.every((expiry) => expiry !== undefined) && {
      expiresAt: Math.min(...(expiries as number[])),
    }),
  };
}
