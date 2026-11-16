/**
 * Verifies the result of an identity log search for one account address.
 *
 * The steps run in this order, and the first failure throws:
 *
 * 1. VRF: the proof is valid for the pinned VRF key and the search key. The
 *    index is the first 32 bytes of the VRF output.
 * 2. Position: the entry position is inside the tree of the head.
 * 3. Inclusion: the commitment of the opened value, after the index, is a
 *    leaf that the inclusion path places at the position under the head
 *    root. A wrong opening or value fails here.
 * 4. Head: consistency with the last verified head, the signature of a
 *    pinned head key, and the time against the local clock.
 * 5. Entry: the opened value decodes as an entry.
 *
 * A not-logged result and a mismatch result have no inclusion claim. Their
 * VRF proof and their head still pass steps 1 and 4.
 *
 * An inclusion proof shows that the entry is in the log. It does not show
 * that the entry is the latest entry of the account.
 */
import { decodeIdentityLogEntry, type IdentityLogEntry } from './entry';
import { commitIdentityLogValue } from './commitment';
import { KeyTransparencyVerificationError } from './errors';
import { retainedIdentityLogHead, verifyIdentityLogHeadConsistency } from './head-consistency';
import { leafHash, verifyInclusion } from './merkle';
import {
  verifyIdentityLogHeadFreshness,
  verifyIdentityLogHeadSignature,
  type IdentityLogHead,
  type SignedIdentityLogHead,
} from './tree-head';
import { verifyVrfProof } from './vrf';

/** The bytes of a VRF index. */
export const IDENTITY_LOG_INDEX_BYTES = 32;

/** The pinned keys of one identity log. */
export interface IdentityLogTrust {
  readonly vrfPublicKey: Uint8Array;
  readonly headPublicKeys: readonly Uint8Array[];
}

/**
 * A search result as the Relay gives it, after the wire decode. An absent
 * consistency proof decodes as an empty proof.
 *
 * - `logged`: the latest entry of the account, with its inclusion proof.
 * - `not-logged`: the log has no entry for the account and the key. The
 *   Relay sets `appendPending` when the append of the key waits. The field
 *   is not signed, and the client uses it only to schedule a new check.
 * - `mismatch`: the latest key entry of the account has another key.
 */
export type IdentityLogSearchResult =
  | {
      readonly kind: 'logged';
      readonly vrfProof: Uint8Array;
      readonly position: number;
      readonly opening: Uint8Array;
      readonly value: Uint8Array;
      readonly inclusionPath: readonly Uint8Array[];
      readonly signedHead: SignedIdentityLogHead;
      readonly consistencyProof: readonly Uint8Array[];
    }
  | {
      readonly kind: 'not-logged';
      readonly vrfProof: Uint8Array;
      readonly signedHead: SignedIdentityLogHead;
      readonly consistencyProof: readonly Uint8Array[];
      readonly appendPending: boolean;
    }
  | {
      readonly kind: 'mismatch';
      readonly vrfProof: Uint8Array;
      readonly signedHead: SignedIdentityLogHead;
      readonly consistencyProof: readonly Uint8Array[];
    };

/** The input of one search verification. */
export interface IdentityLogSearchVerification {
  readonly trust: IdentityLogTrust;
  /** The project scope string that the head signature covers. */
  readonly scope: string;
  /** The UTF-8 account address. */
  readonly searchKey: Uint8Array;
  readonly result: IdentityLogSearchResult;
  /** The last head that the client verified, if any. */
  readonly lastHead: IdentityLogHead | undefined;
  /** The local clock, Unix milliseconds. */
  readonly now: number;
}

/**
 * A verified search, and the head to keep. At the same size the kept head
 * is the head with the later time, so it can be `lastHead`.
 */
export type VerifiedIdentityLogSearch =
  | { readonly kind: 'logged'; readonly entry: IdentityLogEntry; readonly head: IdentityLogHead }
  | { readonly kind: 'not-logged'; readonly appendPending: boolean; readonly head: IdentityLogHead }
  | { readonly kind: 'mismatch'; readonly head: IdentityLogHead };

function verifyHead(input: IdentityLogSearchVerification): IdentityLogHead {
  const { signedHead, consistencyProof } = input.result;
  verifyIdentityLogHeadConsistency(input.lastHead, signedHead, consistencyProof);
  verifyIdentityLogHeadSignature(input.trust.headPublicKeys, input.scope, signedHead);
  verifyIdentityLogHeadFreshness(signedHead, input.now);
  return retainedIdentityLogHead(input.lastHead, {
    treeSize: signedHead.treeSize,
    root: signedHead.root.slice(),
    timestamp: signedHead.timestamp,
  });
}

/** Verifies a search result. Throws `KeyTransparencyVerificationError`. */
export function verifyIdentityLogSearch(
  input: IdentityLogSearchVerification
): VerifiedIdentityLogSearch {
  const { result } = input;
  const output = verifyVrfProof(input.trust.vrfPublicKey, input.searchKey, result.vrfProof);
  if (output === null) {
    throw new KeyTransparencyVerificationError(
      'VRF_PROOF_INVALID',
      'The VRF proof of the identity log index is not valid'
    );
  }
  if (result.kind === 'not-logged') {
    return { kind: 'not-logged', appendPending: result.appendPending, head: verifyHead(input) };
  }
  if (result.kind === 'mismatch') {
    return { kind: 'mismatch', head: verifyHead(input) };
  }
  const { signedHead } = result;
  if (!Number.isSafeInteger(result.position) || result.position < 0 || result.position >= signedHead.treeSize) {
    throw new KeyTransparencyVerificationError(
      'SEARCH_POSITION_INVALID',
      'The identity log entry position is outside the tree'
    );
  }
  const commitment = commitIdentityLogValue(input.searchKey, result.value, result.opening);
  const included =
    commitment !== null &&
    verifyInclusion(
      result.position,
      signedHead.treeSize,
      leafHash(Uint8Array.from([...output.subarray(0, IDENTITY_LOG_INDEX_BYTES), ...commitment])),
      result.inclusionPath,
      signedHead.root
    );
  if (!included) {
    throw new KeyTransparencyVerificationError(
      'INCLUSION_PROOF_INVALID',
      'The identity log entry is not included under the head root'
    );
  }
  const head = verifyHead(input);
  const entry = decodeIdentityLogEntry(result.value);
  if (entry === null) {
    throw new KeyTransparencyVerificationError(
      'MALFORMED_RESPONSE',
      'The identity log entry value does not decode'
    );
  }
  return { kind: 'logged', entry, head };
}
