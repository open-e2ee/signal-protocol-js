/**
 * Shared recipient-identity ID builders.
 *
 * Recipient trust is account-scoped, so the canonical key is the recipient
 * user id itself, independent of remote device id.
 */

import type { IdentityType } from '../../../../keys/types';

export function buildContactIdentityId(userId: string, identityType: IdentityType = 'aci'): string {
  return `${userId}:${identityType}`;
}
