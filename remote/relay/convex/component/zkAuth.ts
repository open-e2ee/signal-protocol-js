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
import {
  deserializeProfileKeyCredentialRequest,
  issueProfileKeyCredential,
  serializeProfileKeyCredentialResponse,
} from '../../../../internal/protocol/zk/groups/profile-key-credential';
import {
  rememberAccount,
  setUnidentifiedAccessKey,
} from './accounts';

const UNIDENTIFIED_ACCESS_KEY_LENGTH = 16;

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

function requireAccessKey(value: ArrayBuffer): Uint8Array {
  const accessKey = new Uint8Array(value);
  if (accessKey.length !== UNIDENTIFIED_ACCESS_KEY_LENGTH) {
    throw new Error(`accessKey must be ${UNIDENTIFIED_ACCESS_KEY_LENGTH} bytes`);
  }
  return accessKey;
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
    request: v.bytes(),
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
    const request = deserializeProfileKeyCredentialRequest(new Uint8Array(input.request));
    const runtime = groupServerRuntime();
    const nowSeconds = Math.floor(runtime.now() / 1000);
    const redemptionTime =
      Math.floor(nowSeconds / SECONDS_PER_DAY) * SECONDS_PER_DAY +
      2 * SECONDS_PER_DAY;
    const response = issueProfileKeyCredential(
      groupServerSecretParams().profileKeyCredentialKeyPair,
      aci,
      request,
      redemptionTime,
      runtime.randomBytes(32)
    );
    return toArrayBuffer(
      serializeProfileKeyCredentialResponse(response)
    );
  },
});

export const setUnidentifiedAccessKeyMutation = mutation({
  args: {
    ...identityArgs,
    accessKey: v.bytes(),
  },
  returns: v.null(),
  handler: async (ctx, input) => {
    if (input.userId === undefined) {
      throw new Error('Authenticated userId is required');
    }
    await rememberAccount(ctx, {
      callerUserId: input.userId,
      callerAciBytes: input.aciBytes,
      callerPniBytes: input.pniBytes,
    });
    await setUnidentifiedAccessKey(ctx, input.userId, requireAccessKey(input.accessKey));
    return null;
  },
});
