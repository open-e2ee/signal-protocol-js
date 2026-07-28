/**
 * Group ID Utilities
 *
 * @module groups/group-id
 *
 * Adds and validates the package's group-ID prefix.
 *
 */
export {};
declare const __brand_groupId: unique symbol;

/**
 * Branded type for prefixed group IDs
 *
 * Ensures compile-time safety for group ID handling.
 * A GroupId is always a string with the OpenE2EE group prefix.
 *
 * @example
 * ```typescript
 * const groupId: GroupId = createGroupId('abc123');
 * // groupId is 'open-e2ee:group:abc123' with GroupId type
 * ```
 */
export type GroupId = string & { readonly [__brand_groupId]: true };

/**
 * Canonical prefix for group identifiers.
 */
export const GROUP_ID_PREFIX = 'open-e2ee:group:';

/**
 * Check if an ID is a group ID (has group prefix)
 *
 * Type guard that narrows string to GroupId.
 *
 * @param id - Recipient ID to check
 * @returns True if this is a group ID
 *
 * @example
 * ```typescript
 * const id = 'open-e2ee:group:abc123';
 * if (isGroupId(id)) {
 *   // id is now typed as GroupId
 *   const raw = extractGroupId(id);
 * }
 * ```
 */
export function isGroupId(id: string): id is GroupId {
  return id.startsWith(GROUP_ID_PREFIX);
}

/**
 * Create a prefixed group ID from a raw group ID
 *
 * @param rawId - Raw group ID without prefix
 * @returns Prefixed group ID (branded type)
 *
 * @example
 * ```typescript
 * const groupId = createGroupId('abc123');
 * // groupId is 'open-e2ee:group:abc123' with GroupId type
 * ```
 */
export function createGroupId(rawId: string): GroupId {
  if (rawId.startsWith(GROUP_ID_PREFIX)) {
    return rawId as GroupId; // Already prefixed
  }
  return `${GROUP_ID_PREFIX}${rawId}` as GroupId;
}

/**
 * Extract raw group ID from prefixed group ID
 *
 * @param groupId - Group ID with prefix (or plain string)
 * @returns Raw group ID without prefix
 *
 * @example
 * ```typescript
 * extractGroupId('open-e2ee:group:abc123'); // 'abc123'
 * extractGroupId('abc123');                 // 'abc123' (no prefix)
 * ```
 */
export function extractGroupId(groupId: GroupId | string): string {
  if (groupId.startsWith(GROUP_ID_PREFIX)) {
    return groupId.slice(GROUP_ID_PREFIX.length);
  }
  // Already unprefixed
  return groupId;
}
