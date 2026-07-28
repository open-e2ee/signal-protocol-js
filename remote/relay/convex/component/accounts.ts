import { v } from 'convex/values';
import {
  base64ToBytes,
  bytesToBase64,
  constantTimeEqual,
} from '../../../../internal/crypto/utils';
import {
  deriveForExpiration,
  deserializeFullToken,
  verifyFullToken,
} from '../../../../internal/protocol/zk/groups/group-send-endorsement';
import {
  SERVICE_ID_ACI,
  type ServiceId,
} from '../../../../internal/protocol/zk/groups/uid-struct';
import { asBase64 } from '../../../../types/utils';
import type { MutationCtx, QueryCtx } from './_generated/server';
import { relayError, unauthorized } from './errors';
import { groupServerSecretParams, serviceIds } from './runtime';

export const callerIdentityArgs = {
  callerUserId: v.string(),
  callerAciBytes: v.bytes(),
  callerPniBytes: v.optional(v.bytes()),
};

type CallerIdentity = {
  callerUserId: string;
  callerAciBytes: ArrayBuffer;
  callerPniBytes?: ArrayBuffer;
};

function requireUserId(userId: string): string {
  if (userId.length === 0) {
    throw unauthorized('the resolved caller has no user ID');
  }
  return userId;
}

function sameBytes(
  a: ArrayBuffer | undefined,
  b: ArrayBuffer | undefined
): boolean {
  if (a === undefined || b === undefined) return a === b;
  const left = new Uint8Array(a);
  const right = new Uint8Array(b);
  if (left.length !== right.length) return false;
  return left.every((byte, index) => byte === right[index]);
}

export async function rememberAccount(
  ctx: MutationCtx,
  input: CallerIdentity
): Promise<void> {
  const userId = requireUserId(input.callerUserId);
  serviceIds({
    aciBytes: input.callerAciBytes,
    pniBytes: input.callerPniBytes,
  });
  // One ACI, one account. The ACI is what sealed-sender authorization and
  // group endorsements actually name — a second userId claiming the same ACI
  // would inherit every authorization decision made about the first. The
  // host's identify hook owns the userId↔ACI mapping; this enforces that the
  // mapping is a function, at write time, on every mutation that passes
  // through here.
  //
  // This is a write-time guard only: it keeps a duplicate from ever being
  // written, but it does not repair one that already exists. If two rows
  // somehow shared an ACI, `authorizeGroupSendToken` binds by reading
  // `by_user_id` and comparing the stored ACI, so a token naming that ACI
  // would bind for both userIds — the very inheritance this prevents. A
  // duplicate must therefore never be allowed to exist. It cannot arise
  // here: the check postdates the table, but no deployment carried data
  // across that window.
  //
  // `.first()`, not `.unique()`: fail closed without an untyped throw. Were a
  // duplicate ever present, `.unique()` would throw on *every* mutation from
  // that ACI — and rememberAccount fronts nearly all of them, so the losing
  // account (whichever this index happens to return second, not whoever
  // registered first) would be locked out of sends, prekey uploads, device
  // and provisioning operations alike until an operator deleted the row.
  // `.first()` degrades that to a clean 409 on the same broad surface.
  const claimant = await ctx.db
    .query('accounts')
    .withIndex('by_aci_bytes', (q) => q.eq('aciBytes', input.callerAciBytes))
    .first();
  if (claimant && claimant.userId !== userId) {
    throw relayError(
      'CONFLICT',
      409,
      'This protocol identity is already registered to another account'
    );
  }
  const existing = await ctx.db
    .query('accounts')
    .withIndex('by_user_id', (q) => q.eq('userId', userId))
    .unique();
  if (existing) {
    // Skip the write when the identity is unchanged. rememberAccount runs
    // at the top of essentially every mutation, and the same row is read
    // by sealed-sender authorization on the recipient side — an
    // unconditional freshness patch would turn this one document into an
    // OCC conflict hotspot between a user's own concurrent mutations and
    // every sealed send addressed to them.
    if (
      sameBytes(existing.aciBytes, input.callerAciBytes) &&
      sameBytes(existing.pniBytes, input.callerPniBytes)
    ) {
      return;
    }
    await ctx.db.patch(existing._id, {
      aciBytes: input.callerAciBytes,
      pniBytes: input.callerPniBytes,
      updatedAt: Date.now(),
    });
    return;
  }
  await ctx.db.insert('accounts', {
    userId,
    aciBytes: input.callerAciBytes,
    pniBytes: input.callerPniBytes,
    updatedAt: Date.now(),
  });
}

export async function setUnidentifiedAccessKey(
  ctx: MutationCtx,
  userId: string,
  accessKey: Uint8Array
): Promise<void> {
  const account = await ctx.db
    .query('accounts')
    .withIndex('by_user_id', (q) => q.eq('userId', userId))
    .unique();
  if (!account) {
    throw unauthorized('the recipient account is not registered');
  }
  await ctx.db.patch(account._id, {
    unidentifiedAccessKey: bytesToBase64(accessKey),
    updatedAt: Date.now(),
  });
}

export async function authorizeAccessKey(
  ctx: QueryCtx | MutationCtx,
  targetUserId: string,
  encodedAccessKey: string
): Promise<void> {
  const account = await ctx.db
    .query('accounts')
    .withIndex('by_user_id', (q) => q.eq('userId', targetUserId))
    .unique();
  if (!account?.unidentifiedAccessKey) {
    throw unauthorized(
      'the recipient has no unidentified-access key'
    );
  }
  let supplied: Uint8Array;
  let expected: Uint8Array;
  try {
    supplied = base64ToBytes(asBase64(encodedAccessKey));
    expected = base64ToBytes(asBase64(account.unidentifiedAccessKey));
  } catch {
    throw unauthorized('the unidentified-access key is malformed');
  }
  if (
    supplied.length !== 16 ||
    expected.length !== 16 ||
    !constantTimeEqual(supplied, expected)
  ) {
    throw unauthorized('the unidentified-access key is invalid');
  }
}

/** A sealed-send recipient as named by the caller: routing ID plus the ACI
 * the caller claims for it. */
export interface GroupSendRecipient {
  userId: string;
  aciBytes: ArrayBuffer;
}

/**
 * Authorize a sealed send by group-send token, verifying before reading.
 *
 * The token endorses a set of ACIs, and the caller supplies the ACI it
 * claims for each recipient, so the entire cryptographic check — parse,
 * expiration, key derivation, signature over the claimed set — runs before
 * this function touches the database. That ordering is what the reference
 * implementation gets by construction (its sealed payloads name recipients
 * by service ID), and it is load-bearing here: with the lookups first, an
 * anonymous caller holding a garbage token could bill the deployment up to
 * one indexed read per named recipient per call, and this path is
 * deliberately exempt from the per-recipient send budget because the token
 * is supposed to be the gate.
 *
 * Only after the token verifies are the claims bound: each recipient's
 * stored account must carry exactly the ACI the caller supplied for it. A
 * caller who lies about a binding fails here — and has necessarily already
 * presented a token our own group server issued over the claimed set, so
 * the reads it spent were an authenticated member's to spend.
 */
export async function authorizeGroupSendToken(
  ctx: QueryCtx | MutationCtx,
  recipients: GroupSendRecipient[],
  serializedToken: ArrayBuffer
): Promise<void> {
  const claimedByUserId = new Map<string, Uint8Array>();
  for (const recipient of recipients) {
    const claimed = new Uint8Array(recipient.aciBytes);
    if (claimed.length !== 16) {
      throw unauthorized('a recipient ACI must be 16 bytes');
    }
    const existing = claimedByUserId.get(recipient.userId);
    if (existing && !constantTimeEqual(existing, claimed)) {
      throw unauthorized('conflicting ACIs claimed for one recipient');
    }
    claimedByUserId.set(recipient.userId, claimed);
  }
  try {
    const fullToken = deserializeFullToken(
      new Uint8Array(serializedToken)
    );
    const serviceIdList: ServiceId[] = [...claimedByUserId.values()].map(
      (uuid) => ({ kind: SERVICE_ID_ACI, uuid })
    );
    verifyFullToken(
      fullToken,
      serviceIdList,
      Math.floor(Date.now() / 1000),
      deriveForExpiration(
        groupServerSecretParams().endorsementKeyPair,
        fullToken.expiration
      )
    );
  } catch {
    throw unauthorized('the group-send token is invalid');
  }
  for (const [userId, claimed] of claimedByUserId) {
    const account = await ctx.db
      .query('accounts')
      .withIndex('by_user_id', (q) => q.eq('userId', userId))
      .unique();
    if (
      !account ||
      !constantTimeEqual(new Uint8Array(account.aciBytes), claimed)
    ) {
      throw unauthorized(
        `recipient ${userId} does not hold the endorsed identity`
      );
    }
  }
}
