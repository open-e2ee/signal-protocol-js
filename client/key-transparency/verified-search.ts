/**
 * One verified identity log search, with the head chain of the client.
 *
 * 1. Read the last verified head L from the store.
 * 2. Search for the account address and the identity, with the size of L.
 *    The result has the head S and, when 0 < L.treeSize < S.treeSize, the
 *    consistency proof from L to S.
 * 3. Verify the search result against L (`verifyIdentityLogSearch`).
 * 4. When the head to keep is not L, write it, compare-and-set against the L
 *    that step 1 read. When another client changed the head first, the
 *    search runs again from step 1, at most 3 times in all.
 *
 * A network error, a store error, or a third race gives `unavailable`. A
 * result that the client cannot accept gives `failure` with the error. The
 * head is written only after each step passed.
 */
import { equalBytes } from '@noble/curves/utils.js';

import { KeyTransparencyVerificationError } from '../../internal/protocol/key-transparency/errors';
import type { IdentityLogEntry } from '../../internal/protocol/key-transparency/entry';
import {
  verifyIdentityLogSearch,
  type IdentityLogTrust,
} from '../../internal/protocol/key-transparency/search-verification';
import type { IdentityLogHead } from '../../internal/protocol/key-transparency/tree-head';
import {
  readVerifiedHead,
  writeVerifiedHead,
  type KeyTransparencyRecordKeys,
  type KeyTransparencyStore,
} from './state';
import { decodeIdentityLogSearch, identityLogSearchBody, IDENTITY_LOG_SEARCH_PATH } from './wire';

/** Posts one identity log read to the Relay and returns the parsed body. */
export type IdentityLogPost = (path: string, body: Record<string, unknown>) => Promise<unknown>;

/** What one verified search needs. */
export interface IdentityLogSearchContext {
  readonly trust: IdentityLogTrust;
  /** The project scope string that the head signature covers. */
  readonly scope: string;
  readonly store: KeyTransparencyStore;
  readonly keys: KeyTransparencyRecordKeys;
  readonly post: IdentityLogPost;
  /** The local clock, Unix milliseconds. */
  readonly now: () => number;
}

/** Why a search gave no result. The reason holds no address and no key. */
export type IdentityLogUnavailableReason = 'transport' | 'store' | 'race';

/** The result of one verified search. */
export type IdentityLogSearchCheck =
  | { readonly kind: 'logged'; readonly entry: IdentityLogEntry }
  | { readonly kind: 'not-logged'; readonly appendPending: boolean }
  | { readonly kind: 'mismatch' }
  | { readonly kind: 'unavailable'; readonly reason: IdentityLogUnavailableReason }
  | { readonly kind: 'failure'; readonly error: KeyTransparencyVerificationError };

const ATTEMPTS = 3;

class Unavailable {
  constructor(readonly reason: IdentityLogUnavailableReason) {}
}

async function read<T>(reason: IdentityLogUnavailableReason, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch {
    throw new Unavailable(reason);
  }
}

function sameHead(a: IdentityLogHead, b: IdentityLogHead): boolean {
  return a.treeSize === b.treeSize && a.timestamp === b.timestamp && equalBytes(a.root, b.root);
}

async function searchOnce(
  context: IdentityLogSearchContext,
  accountAddress: string,
  identity: Uint8Array
): Promise<IdentityLogSearchCheck | 'again'> {
  const { store, keys, post } = context;
  const stored = await read('store', () => readVerifiedHead(store, keys));
  const last = stored.value;
  const result = decodeIdentityLogSearch(
    await read('transport', () =>
      post(
        IDENTITY_LOG_SEARCH_PATH,
        identityLogSearchBody(accountAddress, identity, last?.treeSize)
      )
    )
  );
  const verified = verifyIdentityLogSearch({
    trust: context.trust,
    scope: context.scope,
    searchKey: new TextEncoder().encode(accountAddress),
    result,
    lastHead: last,
    now: context.now(),
  });
  if (
    (last === undefined || !sameHead(last, verified.head)) &&
    !(await read('store', () => writeVerifiedHead(store, keys, stored.raw, verified.head)))
  ) {
    return 'again';
  }
  switch (verified.kind) {
    case 'logged':
      return { kind: 'logged', entry: verified.entry };
    case 'not-logged':
      return { kind: 'not-logged', appendPending: verified.appendPending };
    case 'mismatch':
      return { kind: 'mismatch' };
  }
}

/**
 * Searches the identity log for an account address and the encoded
 * identity `identity`, and verifies the result.
 */
export async function searchVerifiedIdentityLog(
  context: IdentityLogSearchContext,
  accountAddress: string,
  identity: Uint8Array
): Promise<IdentityLogSearchCheck> {
  try {
    for (let attempt = 0; attempt < ATTEMPTS; attempt += 1) {
      const check = await searchOnce(context, accountAddress, identity);
      if (check !== 'again') return check;
    }
    return { kind: 'unavailable', reason: 'race' };
  } catch (error) {
    if (error instanceof KeyTransparencyVerificationError) return { kind: 'failure', error };
    if (error instanceof Unavailable) return { kind: 'unavailable', reason: error.reason };
    throw error;
  }
}

/**
 * Why a key transparency check gave no result. The reason holds no address
 * and no key.
 *
 * - `transport`: a network error or a Relay error status, also a 429.
 * - `store`: a local store read or write failed.
 * - `race`: other clients on the store changed the verified head three times.
 * - `not-pinned`: the client has no pinned identity log keys, so it runs no
 *   check.
 * - `stopped`: the client is not started, or it stopped.
 * - `not-a-contact`: the user is the own account, or the store has no pinned
 *   identity for the user.
 * - `self-check-failing`: the self-check of the own identity is failing.
 * - `rate-limited`: the cap of requested checks is full. Try again later.
 *
 * The background checks give only `transport`, `store`, and `race`.
 */
export type KeyTransparencyUnavailableReason =
  | 'transport'
  | 'store'
  | 'race'
  | 'not-pinned'
  | 'stopped'
  | 'not-a-contact'
  | 'self-check-failing'
  | 'rate-limited';

/**
 * The outcome of one identity check against the log.
 *
 * - `pass`: the latest log entry of the account is a key entry with the
 *   identity.
 * - `not-logged`: the log has no entry for the account. `appendPending` is
 *   true when the Relay says that the append waits.
 * - `unavailable`: the check gave no result.
 * - `failure`: the log or a proof contradicts the identity. `error.code`
 *   names the check.
 */
export type KeyTransparencyCheckOutcome =
  | { readonly kind: 'pass' }
  | { readonly kind: 'not-logged'; readonly appendPending: boolean }
  | { readonly kind: 'unavailable'; readonly reason: KeyTransparencyUnavailableReason }
  | { readonly kind: 'failure'; readonly error: KeyTransparencyVerificationError };

const keyMismatch = (): KeyTransparencyCheckOutcome => ({
  kind: 'failure',
  error: new KeyTransparencyVerificationError(
    'LOGGED_KEY_MISMATCH',
    'The latest logged key of the account is not the expected identity'
  ),
});

/**
 * Checks that the latest log entry of an account is a key entry with the
 * encoded identity `identity`. A `mismatch` result or a logged entry with a
 * different key gives `LOGGED_KEY_MISMATCH`. A logged deletion gives
 * `LOGGED_TOMBSTONE`.
 */
export async function checkLoggedIdentity(
  context: IdentityLogSearchContext,
  accountAddress: string,
  identity: Uint8Array
): Promise<KeyTransparencyCheckOutcome> {
  const check = await searchVerifiedIdentityLog(context, accountAddress, identity);
  if (check.kind === 'mismatch') return keyMismatch();
  if (check.kind !== 'logged') return check;
  if (check.entry.kind === 'tombstone') {
    return {
      kind: 'failure',
      error: new KeyTransparencyVerificationError(
        'LOGGED_TOMBSTONE',
        'The latest identity log entry of the account is a deletion'
      ),
    };
  }
  if (!equalBytes(check.entry.identity, identity)) return keyMismatch();
  return { kind: 'pass' };
}
