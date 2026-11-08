/**
 * Reads of a member that has a Signal Protocol Relay name and a deprecated
 * earlier name.
 *
 * SDK 14 accepts the earlier name of each such option and member. An option
 * read takes the new name first and the earlier name second. A member read
 * takes the name that the nearest level of the object defines, so a subclass
 * override of either name wins. SDK 15.0.0 removes the earlier names and this
 * module.
 *
 * The module is not in a package entry point.
 */

import { SignalProtocolRelayNameConflictError } from './errors';

/** The two names of one member, and the operation that reads it. */
export interface RenamedMember {
  readonly newName: string;
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
 * Returns the value of an option that the caller sets by either name.
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

/**
 * Returns the name that the nearest level of an object defines, where a
 * level is the object itself or one of its prototypes. The new name wins
 * when one level defines both names.
 */
function nearestRenamedName<T extends object>(
  source: T,
  newName: keyof T,
  earlierName: keyof T
): keyof T {
  for (
    let level: object | null = source;
    level !== null && level !== Object.prototype;
    level = Object.getPrototypeOf(level) as object | null
  ) {
    if (Object.prototype.hasOwnProperty.call(level, newName)) return newName;
    if (Object.prototype.hasOwnProperty.call(level, earlierName)) return earlierName;
  }
  return newName;
}

/**
 * Returns the member of an object that the caller implements under either
 * name, such as a `SignalProtocolRelayServer`.
 *
 * The name that the nearest level of the object defines wins, and the new
 * name wins when one level defines both. An SDK class defines both names, so
 * a subclass that overrides only one name gives its override. When the
 * chosen name holds no value, the read takes the other name. A method comes
 * back bound to its object. The read does not compare the two members,
 * because an SDK class keeps one name as a forward to the other.
 */
export function readRenamedImplementation<T extends object, K extends keyof T, E extends keyof T>(
  source: T,
  newName: K,
  earlierName: E
): NonNullable<T[K]> | NonNullable<T[E]> | undefined {
  const first = nearestRenamedName(source, newName, earlierName);
  const second = first === newName ? earlierName : newName;
  const member = source[first] ?? source[second];
  if (member === undefined || member === null) return undefined;
  if (typeof member === 'function') {
    return (member as (...args: unknown[]) => unknown).bind(source) as NonNullable<T[K]> | NonNullable<T[E]>;
  }
  return member as NonNullable<T[K]> | NonNullable<T[E]>;
}
