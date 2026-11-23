/**
 * Reads of a stored value that has a role name, such as `relayOwnsReceipt`,
 * and a `signalProtocolRelay*` name, such as `signalProtocolRelayOwnsReceipt`.
 *
 * SDK 14.2.0 added the `signalProtocolRelay*` names after the role names, so
 * this module calls the `signalProtocolRelay*` name the new name and the role
 * name the earlier name. SDK 15.0.0 removed these names from members and
 * options. A stored receive record can still hold both names, so the store
 * reads both.
 *
 * The module is not in a package entry point.
 */

import { SignalProtocolRelayNameConflictError } from './errors';

/** The two names of one member, and the operation that reads it. */
export interface RenamedMember {
  /** The `signalProtocolRelay*` name. */
  readonly newName: string;
  /** The role name. */
  readonly earlierName: string;
  readonly operation: string;
}

function sameValue(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) return true;
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) {
    return false;
  }
  return a.every((byte, index) => byte === b[index]);
}

/**
 * Returns the value that a stored record holds under either name.
 *
 * The new name wins. Two values with the same identity, or two byte arrays
 * with the same bytes, are the same value. Undefined means not set.
 *
 * @throws SignalProtocolRelayNameConflictError when both names hold values
 *   that are not the same.
 */
export function readRenamedOption<T>(
  newValue: T | undefined,
  earlierValue: T | undefined,
  member: RenamedMember
): T | undefined {
  if (newValue !== undefined && earlierValue !== undefined && !sameValue(newValue, earlierValue)) {
    throw new SignalProtocolRelayNameConflictError(
      member.newName,
      member.earlierName,
      member.operation
    );
  }
  return newValue !== undefined ? newValue : earlierValue;
}
