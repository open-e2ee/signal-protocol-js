/**
 * Storage protection and the content recovery gate.
 *
 * A sender keeps the plaintext of a resendable message to answer a retry
 * request: the pairwise MessageRecord and the group send log. This module
 * reads the protection that a local store declares, derives its level, and
 * decides whether the content recovery policy lets the client keep that
 * plaintext. A declaration states how the store protects its data. It adds
 * no encryption.
 */

import type {
  LocalStoreAtRest,
  LocalStoreKeyCustody,
  LocalStoreProtection,
} from '../types/api';
import type {
  ContentRecoveryMode,
  ContentRecoveryPolicy,
  ContentRecoveryStatus,
  GroupMembershipSource,
  ReceiveQueuePolicy,
  StorageProtectionLevel,
} from '../types/protocol-config';
import {
  MAX_RESENDABLE_CONTENT_RETENTION_MS,
  RECEIVE_QUEUE_DEFAULT_BLOCKED_GROUP_SHARE,
  RECEIVE_QUEUE_DEFAULT_MAX_BYTES,
  RECEIVE_QUEUE_DEFAULT_MAX_ITEMS,
  RESENDABLE_CONTENT_RETENTION_MS,
} from './constants';
import { RECEIVE_HOOK_TIMEOUT_MS } from './receive-hook-bound';

const AT_REST_VALUES: readonly LocalStoreAtRest[] = ['file-cipher', 'record-cipher', 'none'];
const KEY_CUSTODY_VALUES: readonly LocalStoreKeyCustody[] = [
  'os-keychain',
  'app-vault',
  'same-origin',
  'none',
];
const MODES: readonly ContentRecoveryMode[] = ['require-protected', 'allow-co-located-key', 'off'];

/** The content recovery policy after validation, with its defaults applied. */
export interface ResolvedContentRecoveryPolicy {
  readonly mode: ContentRecoveryMode;
  readonly retentionMs: number;
  readonly isCurrentMember?: (groupId: string, userId: string) => Promise<boolean>;
}

/**
 * Read the protection that a local store declares.
 *
 * @throws Error when the store declares no protection, an unknown value, or
 *   a cipher without a key or a key without a cipher.
 */
export function readLocalStoreProtection(storage: unknown): LocalStoreProtection {
  const protection = (storage as { protection?: unknown }).protection;
  if (typeof protection !== 'object' || protection === null) {
    throw new Error(
      'The local store declares no protection. A custom store must set `protection` ' +
        'to { atRest, keyCustody }. See Content Recovery in docs/PROTOCOL_POLICY.md.'
    );
  }
  const { atRest, keyCustody } = protection as { atRest?: unknown; keyCustody?: unknown };
  if (!AT_REST_VALUES.includes(atRest as LocalStoreAtRest)) {
    throw new Error(
      `The local store declares an unknown protection.atRest value. Use one of: ${AT_REST_VALUES.join(', ')}.`
    );
  }
  if (!KEY_CUSTODY_VALUES.includes(keyCustody as LocalStoreKeyCustody)) {
    throw new Error(
      `The local store declares an unknown protection.keyCustody value. Use one of: ${KEY_CUSTODY_VALUES.join(', ')}.`
    );
  }
  if ((atRest === 'none') !== (keyCustody === 'none')) {
    throw new Error(
      'The local store declares a cipher without a key, or a key without a cipher. ' +
        'Set protection.atRest and protection.keyCustody both to none, or neither.'
    );
  }
  return Object.freeze({
    atRest: atRest as LocalStoreAtRest,
    keyCustody: keyCustody as LocalStoreKeyCustody,
  });
}

/** Derive the protection level of a validated declaration. */
export function storageProtectionLevel(protection: LocalStoreProtection): StorageProtectionLevel {
  if (protection.atRest === 'none' || protection.keyCustody === 'none') return 'none';
  if (protection.keyCustody === 'same-origin') return 'co-located';
  return 'protected';
}

/**
 * Validate the content recovery policy and apply its defaults.
 *
 * @throws Error on an unknown mode, a retention that is not a positive
 *   integer or exceeds 30 days, or a membership hook that is not a function.
 */
export function resolveContentRecoveryPolicy(
  policy: ContentRecoveryPolicy | undefined
): ResolvedContentRecoveryPolicy {
  const mode = policy?.mode ?? 'require-protected';
  if (!MODES.includes(mode)) {
    throw new Error(
      `Unsupported protocol.contentRecovery.mode: ${String(mode)}. Use one of: ${MODES.join(', ')}.`
    );
  }
  const retentionMs = policy?.retentionMs ?? RESENDABLE_CONTENT_RETENTION_MS;
  if (
    !Number.isSafeInteger(retentionMs) ||
    retentionMs <= 0 ||
    retentionMs > MAX_RESENDABLE_CONTENT_RETENTION_MS
  ) {
    throw new Error(
      'protocol.contentRecovery.retentionMs must be a positive integer of at most ' +
        `${MAX_RESENDABLE_CONTENT_RETENTION_MS} ms (30 days).`
    );
  }
  const isCurrentMember = policy?.isCurrentMember;
  if (isCurrentMember !== undefined && typeof isCurrentMember !== 'function') {
    throw new Error('protocol.contentRecovery.isCurrentMember must be a function.');
  }
  return Object.freeze({ mode, retentionMs, isCurrentMember });
}

/** The receive queue policy after validation, with its defaults applied. */
export interface ResolvedReceiveQueuePolicy {
  readonly maxItems: number;
  readonly maxBytes: number;
  readonly blockedGroupShare: number;
  readonly receiveHookTimeoutMs: number;
}

/** The longest delay that one timer can hold. */
const MAX_TIMER_DELAY_MS = 2 ** 31 - 1;

/**
 * Validate the receive queue policy and apply its defaults. It reads no
 * content recovery setting and no retry deadline. The receive age is fixed
 * at `MAX_RECEIVE_WORK_AGE_MS`, so the policy carries no age.
 *
 * @throws Error on a `maxAgeMs` field, a bound that is not a positive
 *   integer, a share that is not above 0 and at most 1, or a hook timeout
 *   that is not a positive integer that one timer can hold.
 */
export function resolveReceiveQueuePolicy(
  policy: ReceiveQueuePolicy | undefined
): ResolvedReceiveQueuePolicy {
  // The type has no `maxAgeMs`, but a JavaScript caller or a cast can pass one.
  if ((policy as { maxAgeMs?: unknown } | undefined)?.maxAgeMs !== undefined) {
    throw new Error(
      'protocol.receiveQueue.maxAgeMs is not supported in SDK 12.0.0 and later. ' +
        'Receive retention is fixed at 30 days. Remove the field.'
    );
  }
  const maxItems = policy?.maxItems ?? RECEIVE_QUEUE_DEFAULT_MAX_ITEMS;
  if (!Number.isSafeInteger(maxItems) || maxItems <= 0) {
    throw new Error('protocol.receiveQueue.maxItems must be a positive integer.');
  }
  const maxBytes = policy?.maxBytes ?? RECEIVE_QUEUE_DEFAULT_MAX_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new Error('protocol.receiveQueue.maxBytes must be a positive integer.');
  }
  const blockedGroupShare = policy?.blockedGroupShare ?? RECEIVE_QUEUE_DEFAULT_BLOCKED_GROUP_SHARE;
  if (!Number.isFinite(blockedGroupShare) || blockedGroupShare <= 0 || blockedGroupShare > 1) {
    throw new Error('protocol.receiveQueue.blockedGroupShare must be above 0 and at most 1.');
  }
  const receiveHookTimeoutMs = policy?.receiveHookTimeoutMs ?? RECEIVE_HOOK_TIMEOUT_MS;
  if (
    !Number.isSafeInteger(receiveHookTimeoutMs) ||
    receiveHookTimeoutMs <= 0 ||
    receiveHookTimeoutMs > MAX_TIMER_DELAY_MS
  ) {
    throw new Error(
      'protocol.receiveQueue.receiveHookTimeoutMs must be a positive integer of at most ' +
        `${MAX_TIMER_DELAY_MS} ms.`
    );
  }
  return Object.freeze({ maxItems, maxBytes, blockedGroupShare, receiveHookTimeoutMs });
}

/**
 * Decide whether the client may keep resendable content.
 *
 * - `protected` stores keep it unless the mode is `off`.
 * - `co-located` stores keep it only under `allow-co-located-key`.
 * - Stores with no cipher or no key never keep it.
 *
 * The status also names the group membership source. A missing source
 * does not change the decision: a direct message resend needs none, and a
 * group resend with no source is refused when it is due.
 */
export function decideContentRecovery(
  protection: LocalStoreProtection,
  policy: ResolvedContentRecoveryPolicy,
  groupMembershipSource: GroupMembershipSource
): ContentRecoveryStatus {
  const level = storageProtectionLevel(protection);
  const { mode } = policy;
  const base = {
    level,
    mode,
    atRest: protection.atRest,
    keyCustody: protection.keyCustody,
    groupMembershipSource,
  };
  if (mode === 'off') return Object.freeze({ ...base, enabled: false, reason: 'policy-off' });
  if (level === 'none') {
    return Object.freeze({ ...base, enabled: false, reason: 'unprotected-store' });
  }
  if (level === 'co-located' && mode !== 'allow-co-located-key') {
    return Object.freeze({ ...base, enabled: false, reason: 'co-located-key-not-allowed' });
  }
  return Object.freeze({ ...base, enabled: true });
}
