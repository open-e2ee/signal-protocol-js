/**
 * The Relay identity log reads: the request paths, the request bodies, and
 * the decode of each response. This is the only file that reads a wire
 * field of the identity log.
 *
 * Bytes are unpadded URL-safe base64 (RFC 4648 section 5). Sizes, positions,
 * and times are safe integers. Each object must have its required fields and
 * no field that its kind does not allow. A response that breaks a rule gives
 * `MALFORMED_RESPONSE`.
 *
 * - Search gives one of three objects. `result` names the kind:
 *   - `logged`: `{result, vrfProof, signedHead, position, opening, value,
 *     inclusionPath, consistencyProof?}`.
 *   - `notLogged`: `{result, vrfProof, signedHead, consistencyProof?,
 *     appendPending?}`. `appendPending` is `true` when present.
 *   - `mismatch`: `{result, vrfProof, signedHead, consistencyProof?}`.
 * - Monitor gives `{signedHead, consistencyProof?}`.
 * - `signedHead` is `{treeSize, root, timestampMilliseconds, signature}`.
 *
 * An absent `consistencyProof` decodes as an empty proof. The Relay omits it
 * when the request has no last size, a last size of 0, or a last size larger
 * than the head size. The head checks refuse each of those cases that needs
 * a proof.
 */
import { base64ToBytes, bytesToUrlSafeBase64, urlSafeToBase64 } from '../../internal/crypto';
import { COMMITMENT_OPENING_BYTES } from '../../internal/protocol/key-transparency/commitment';
import { KeyTransparencyVerificationError } from '../../internal/protocol/key-transparency/errors';
import { LOG_HASH_BYTES } from '../../internal/protocol/key-transparency/merkle';
import type { IdentityLogSearchResult } from '../../internal/protocol/key-transparency/search-verification';
import {
  TREE_HEAD_SIGNATURE_BYTES,
  type SignedIdentityLogHead,
} from '../../internal/protocol/key-transparency/tree-head';
import { VRF_PROOF_BYTES } from '../../internal/protocol/key-transparency/vrf';
import type { Base64 } from '../../types';

/** The path of the search read. */
export const IDENTITY_LOG_SEARCH_PATH = '/key-transparency/search';
/** The path of the monitor read. */
export const IDENTITY_LOG_MONITOR_PATH = '/key-transparency/monitor';

/** The most hashes that a proof can have. A tree of 2^62 entries needs 62. */
const MAXIMUM_PROOF_HASHES = 64;
/** The most bytes that an entry value can have. */
const MAXIMUM_VALUE_BYTES = 4_096;

/** The required and the optional fields of one object kind. */
interface Shape {
  readonly required: readonly string[];
  readonly optional: readonly string[];
}

const LOGGED: Shape = {
  required: ['inclusionPath', 'opening', 'position', 'result', 'signedHead', 'value', 'vrfProof'],
  optional: ['consistencyProof'],
};
const NOT_LOGGED: Shape = {
  required: ['result', 'signedHead', 'vrfProof'],
  optional: ['appendPending', 'consistencyProof'],
};
const MISMATCH: Shape = {
  required: ['result', 'signedHead', 'vrfProof'],
  optional: ['consistencyProof'],
};
const MONITOR: Shape = { required: ['signedHead'], optional: ['consistencyProof'] };
const HEAD: Shape = {
  required: ['root', 'signature', 'timestampMilliseconds', 'treeSize'],
  optional: [],
};

/** A monitor response after the decode. */
export interface IdentityLogMonitorResult {
  readonly signedHead: SignedIdentityLogHead;
  readonly consistencyProof: readonly Uint8Array[];
}

/** The body of a search request, without the publishable key. */
export type IdentityLogSearchBody = {
  readonly accountAddress: string;
  /** The encoded identity that the client checks, unpadded URL-safe base64. */
  readonly identityKey: string;
  /** The size of the last verified head, when the client has one. */
  readonly lastTreeSize?: number;
};

/**
 * The body of a search request, without the publishable key. `lastTreeSize`
 * is the size of the last verified head, or `undefined` when the client has
 * no head.
 */
export function identityLogSearchBody(
  accountAddress: string,
  identity: Uint8Array,
  lastTreeSize: number | undefined
): IdentityLogSearchBody {
  return {
    accountAddress,
    identityKey: bytesToUrlSafeBase64(identity),
    ...(lastTreeSize === undefined ? {} : { lastTreeSize }),
  };
}

/** The body of a monitor request, without the publishable key. */
export function identityLogMonitorBody(fromTreeSize: number): { fromTreeSize: number } {
  return { fromTreeSize };
}

function malformed(): KeyTransparencyVerificationError {
  return new KeyTransparencyVerificationError(
    'MALFORMED_RESPONSE',
    'The Relay returned an invalid identity log response'
  );
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw malformed();
  return value as Record<string, unknown>;
}

function fields(value: unknown, shape: Shape): Record<string, unknown> {
  const result = object(value);
  const names = Object.keys(result);
  if (
    shape.required.some((name) => !names.includes(name)) ||
    names.some((name) => !shape.required.includes(name) && !shape.optional.includes(name))
  ) {
    throw malformed();
  }
  return result;
}

function bytes(value: unknown, minimum: number, maximum = minimum): Uint8Array {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/u.test(value)) throw malformed();
  let decoded: Uint8Array;
  try {
    decoded = base64ToBytes(urlSafeToBase64(value) as Base64);
  } catch {
    throw malformed();
  }
  if (
    decoded.length < minimum ||
    decoded.length > maximum ||
    bytesToUrlSafeBase64(decoded) !== value
  ) {
    throw malformed();
  }
  return decoded;
}

function integer(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw malformed();
  return value;
}

function hashes(value: unknown): Uint8Array[] {
  if (!Array.isArray(value) || value.length > MAXIMUM_PROOF_HASHES) throw malformed();
  return value.map((hash) => bytes(hash, LOG_HASH_BYTES));
}

function consistencyProof(result: Record<string, unknown>): Uint8Array[] {
  return 'consistencyProof' in result ? hashes(result.consistencyProof) : [];
}

function signedHead(value: unknown): SignedIdentityLogHead {
  const head = fields(value, HEAD);
  return {
    treeSize: integer(head.treeSize),
    root: bytes(head.root, LOG_HASH_BYTES),
    timestamp: integer(head.timestampMilliseconds),
    signature: bytes(head.signature, TREE_HEAD_SIGNATURE_BYTES),
  };
}

/** Decodes a search response. Throws `MALFORMED_RESPONSE`. */
export function decodeIdentityLogSearch(value: unknown): IdentityLogSearchResult {
  switch (object(value).result) {
    case 'logged': {
      const result = fields(value, LOGGED);
      return {
        kind: 'logged',
        vrfProof: bytes(result.vrfProof, VRF_PROOF_BYTES),
        position: integer(result.position),
        opening: bytes(result.opening, COMMITMENT_OPENING_BYTES),
        value: bytes(result.value, 1, MAXIMUM_VALUE_BYTES),
        inclusionPath: hashes(result.inclusionPath),
        signedHead: signedHead(result.signedHead),
        consistencyProof: consistencyProof(result),
      };
    }
    case 'notLogged': {
      const result = fields(value, NOT_LOGGED);
      if ('appendPending' in result && result.appendPending !== true) throw malformed();
      return {
        kind: 'not-logged',
        vrfProof: bytes(result.vrfProof, VRF_PROOF_BYTES),
        signedHead: signedHead(result.signedHead),
        consistencyProof: consistencyProof(result),
        appendPending: result.appendPending === true,
      };
    }
    case 'mismatch': {
      const result = fields(value, MISMATCH);
      return {
        kind: 'mismatch',
        vrfProof: bytes(result.vrfProof, VRF_PROOF_BYTES),
        signedHead: signedHead(result.signedHead),
        consistencyProof: consistencyProof(result),
      };
    }
    default:
      throw malformed();
  }
}

/** Decodes a monitor response. Throws `MALFORMED_RESPONSE`. */
export function decodeIdentityLogMonitor(value: unknown): IdentityLogMonitorResult {
  const result = fields(value, MONITOR);
  return {
    signedHead: signedHead(result.signedHead),
    consistencyProof: consistencyProof(result),
  };
}
