/**
 * Group Module
 *
 * @module groups
 *
 * Utilities for group identifiers and group messaging.
 *
 * - **group-id.ts**: Group ID prefix handling (V2 format)
 * - Future: cipher.ts for GroupCipher wrapper
 *
 */
export {};
export { GROUP_V2_PREFIX, isGroupId, createGroupId, extractGroupId } from './group-id';

export type { GroupId } from './group-id';
