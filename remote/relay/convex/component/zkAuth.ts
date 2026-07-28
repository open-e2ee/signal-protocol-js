import { v } from 'convex/values';
import { mutation } from './_generated/server';
import {
  groupServerRuntime,
  groupServerSecretParams,
  serviceIds,
} from './runtime';
import {
  issueAuthCredential,
  serializeAuthCredentialResponse,
} from '../../../../internal/protocol/zk/groups/auth-credential';
import { SECONDS_PER_DAY } from '../../../../internal/protocol/zk/groups/group-params';
import { deriveAccessKey } from '../../../../internal/protocol/sealed-sender/delivery-token';
import {
  issueProfileKeyCredential,
  serializeProfileKeyCredentialResponse,
} from '../../../../internal/protocol/zk/groups/profile-key-credential';
import {
  rememberAccount,
  setUnidentifiedAccessKey,
} from './accounts';

const PROFILE_KEY_LENGTH = 32;

const identityArgs = {
  userId: v.optional(v.string()),
  aciBytes: v.bytes(),
  pniBytes: v.optional(v.bytes()),
};

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(
    value.byteOffset,
    value.byteOffset + value.byteLength
  ) as ArrayBuffer;
}

function requireProfileKey(value: ArrayBuffer): Uint8Array {
  const profileKey = new Uint8Array(value);
  if (profileKey.length !== PROFILE_KEY_LENGTH) {
    throw new Error(`profileKey must be ${PROFILE_KEY_LENGTH} bytes`);
  }
  return profileKey;
}

export const issueAuthCredentialMutation = mutation({
  args: identityArgs,
  returns: v.bytes(),
  handler: async (ctx, input) => {
    const { aci, pni } = serviceIds(input);
    if (input.userId !== undefined) {
      await rememberAccount(ctx, {
        callerUserId: input.userId,
        callerAciBytes: input.aciBytes,
        callerPniBytes: input.pniBytes,
      });
    }
    const runtime = groupServerRuntime();
    const nowSeconds = Math.floor(runtime.now() / 1000);
    const redemptionTime =
      Math.floor(nowSeconds / SECONDS_PER_DAY) * SECONDS_PER_DAY;
    const response = issueAuthCredential(
      groupServerSecretParams().credentialKeyPair,
      aci,
      pni,
      redemptionTime,
      runtime.randomBytes(32)
    );
    return toArrayBuffer(serializeAuthCredentialResponse(response));
  },
});

export const issueProfileKeyCredentialMutation = mutation({
  args: {
    ...identityArgs,
    profileKey: v.bytes(),
  },
  returns: v.bytes(),
  handler: async (ctx, input) => {
    const { aci } = serviceIds(input);
    if (input.userId !== undefined) {
      await rememberAccount(ctx, {
        callerUserId: input.userId,
        callerAciBytes: input.aciBytes,
        callerPniBytes: input.pniBytes,
      });
    }
    const profileKey = requireProfileKey(input.profileKey);
    const runtime = groupServerRuntime();
    const nowSeconds = Math.floor(runtime.now() / 1000);
    const redemptionTime =
      Math.floor(nowSeconds / SECONDS_PER_DAY) * SECONDS_PER_DAY +
      2 * SECONDS_PER_DAY;
    const response = issueProfileKeyCredential(
      groupServerSecretParams().profileKeyCredentialKeyPair,
      aci,
      profileKey,
      redemptionTime,
      runtime.randomBytes(32)
    );
    if (input.userId !== undefined) {
      await setUnidentifiedAccessKey(
        ctx,
        input.userId,
        await deriveAccessKey(profileKey)
      );
    }
    return toArrayBuffer(
      serializeProfileKeyCredentialResponse(response)
    );
  },
});
