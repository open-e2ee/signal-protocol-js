import {
  mutationGeneric,
  queryGeneric,
  type GenericDataModel,
  type GenericMutationCtx,
  type GenericQueryCtx,
} from 'convex/server';
import { ConvexError, v } from 'convex/values';
import type { ComponentApi } from './component/_generated/component';

/**
 * The authenticated identity injected into every account-scoped component
 * call.
 *
 * Authorization is **account-scoped**: there is no device field, so every
 * `deviceId` argument on the relay surface is a caller-chosen routing
 * selector, not an authenticated claim. Any session for an account can drain
 * any of that account's device queues and send as any of its device IDs. It
 * can also rotate key material for any of its devices. Deployments needing
 * isolation between an account's own devices must enforce it in their own
 * `identify` wrapper.
 */
export interface ConvexSignalProtocolBackendIdentity {
  /** Application-owned account identifier used by relay routing. */
  userId?: string;
  /** Raw 16-byte ACI UUID. */
  aciBytes: Uint8Array;
  /** Raw 16-byte PNI UUID, absent when the deployment has no PNI concept. */
  pniBytes?: Uint8Array;
}

export interface DefineConvexSignalProtocolBackendConfig<
  Context = DefaultBackendContext,
> {
  /** Resolve the authenticated app session to protocol identifiers. */
  identify(
    ctx: Context
  ): Promise<ConvexSignalProtocolBackendIdentity>;
}

type DefaultBackendContext =
  | GenericQueryCtx<GenericDataModel>
  | GenericMutationCtx<GenericDataModel>;

const changeResultValidator = v.object({
  version: v.number(),
  actions: v.bytes(),
  serverSignature: v.bytes(),
  changeEpoch: v.number(),
  timestamp: v.number(),
});

const snapshotResultValidator = v.object({
  encryptedState: v.bytes(),
  version: v.number(),
  baselineSignature: v.bytes(),
});

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(
    value.byteOffset,
    value.byteOffset + value.byteLength
  ) as ArrayBuffer;
}

function resolvedIdentityArgs(
  identity: ConvexSignalProtocolBackendIdentity | null | undefined
): {
  userId?: string;
  aciBytes: ArrayBuffer;
  pniBytes?: ArrayBuffer;
} {
  if (
    identity === null ||
    typeof identity !== 'object' ||
    !(identity.aciBytes instanceof Uint8Array)
  ) {
    throw new ConvexError({
      code: 'UNAUTHORIZED',
      status: 401,
      message: 'identify() returned no identity',
    });
  }
  return {
    userId: identity.userId,
    aciBytes: toArrayBuffer(identity.aciBytes),
    pniBytes:
      identity.pniBytes === undefined
        ? undefined
        : toArrayBuffer(identity.pniBytes),
  };
}

function resolvedAccountIdentityArgs(identity: {
  userId?: string;
  aciBytes: ArrayBuffer;
  pniBytes?: ArrayBuffer;
}): {
  callerUserId: string;
  callerAciBytes: ArrayBuffer;
  callerPniBytes?: ArrayBuffer;
} {
  if (
    typeof identity.userId !== 'string' ||
    identity.userId.length === 0
  ) {
    throw new ConvexError({
      code: 'UNAUTHORIZED',
      status: 401,
      message:
        'identify() must return userId for relay account operations',
    });
  }
  return {
    callerUserId: identity.userId,
    callerAciBytes: identity.aciBytes,
    callerPniBytes: identity.pniBytes,
  };
}

const messageTypeValidator = v.union(
  v.literal('ciphertext'),
  v.literal('prekey_bundle'),
  v.literal('sender_key'),
  v.literal('server_delivery_receipt'),
  v.literal('unidentified_sender')
);

const messageReceiptValidator = v.object({
  messageId: v.string(),
  serverTimestamp: v.number(),
});

const deviceTypeValidator = v.union(
  v.literal('mobile'),
  v.literal('desktop'),
  v.literal('tablet'),
  v.literal('web')
);

const identityTypeValidator = v.union(
  v.literal('aci'),
  v.literal('pni')
);

const retryReasonValidator = v.union(
  v.literal('NO_SESSION'),
  v.literal('DECRYPTION_FAILED'),
  v.literal('SESSION_EXPIRED'),
  v.literal('STALE_DEVICE_LIST'),
  v.literal('IDENTITY_KEY_MISMATCH')
);

const provisioningStatusValidator = v.union(
  v.literal('waiting'),
  v.literal('connected'),
  v.literal('ready'),
  v.literal('linked_pending_ack'),
  v.literal('completed'),
  v.literal('rolled_back'),
  v.literal('expired')
);

/**
 * Build the public app functions that expose the installed component.
 *
 * The returned namespace bags are additive: later component phases can add
 * more protocol namespaces without changing this factory's arguments.
 */
export function defineConvexSignalProtocolBackend<
  Context = DefaultBackendContext,
>(
  component: ComponentApi,
  config: DefineConvexSignalProtocolBackendConfig<Context>
) {
  const identify = async (
    ctx:
      | GenericQueryCtx<GenericDataModel>
      | GenericMutationCtx<GenericDataModel>
  ) =>
    resolvedIdentityArgs(
      await config.identify(ctx as unknown as Context)
    );
  const identifyAccount = async (
    ctx:
      | GenericQueryCtx<GenericDataModel>
      | GenericMutationCtx<GenericDataModel>
  ) => resolvedAccountIdentityArgs(await identify(ctx));

  return {
    messages: {
      send: mutationGeneric({
        args: {
          targetUserId: v.string(),
          targetDeviceId: v.number(),
          senderDeviceId: v.number(),
          ciphertext: v.string(),
          messageType: messageTypeValidator,
          urgent: v.optional(v.boolean()),
          ephemeral: v.optional(v.boolean()),
          timestamp: v.number(),
          clientMessageId: v.optional(v.string()),
          recipientRegistrationId: v.optional(v.number()),
        },
        returns: messageReceiptValidator,
        handler: async (ctx, input) =>
          await ctx.runMutation(component.messages.send, {
            ...(await identifyAccount(ctx)),
            ...input,
          }),
      }),
      getPendingMessages: queryGeneric({
        args: { deviceId: v.number() },
        returns: v.array(
          v.object({
            id: v.string(),
            targetUserId: v.string(),
            targetDeviceId: v.number(),
            senderUserId: v.string(),
            senderDeviceId: v.number(),
            ciphertext: v.string(),
            messageType: messageTypeValidator,
            urgent: v.optional(v.boolean()),
            ephemeral: v.optional(v.boolean()),
            timestamp: v.number(),
            serverTimestamp: v.number(),
            clientMessageId: v.optional(v.string()),
            expiresAt: v.number(),
          })
        ),
        handler: async (ctx, input) =>
          await ctx.runQuery(component.messages.getPendingMessages, {
            ...(await identifyAccount(ctx)),
            ...input,
          }),
      }),
      markDelivered: mutationGeneric({
        args: { messageId: v.string() },
        returns: v.null(),
        handler: async (ctx, input) =>
          await ctx.runMutation(component.messages.markDelivered, {
            ...(await identifyAccount(ctx)),
            ...input,
          }),
      }),
      getActiveDevices: queryGeneric({
        args: { userId: v.string() },
        returns: v.array(
          v.object({
            userId: v.string(),
            deviceId: v.number(),
          })
        ),
        handler: async (ctx, input) =>
          await ctx.runQuery(component.messages.getActiveDevices, {
            ...(await identifyAccount(ctx)),
            ...input,
          }),
      }),
      // Sealed-sender delivery is bearer-authorized. Resolving an app
      // identity here would both weaken anonymity and break callers that
      // intentionally have no authenticated app session.
      sendUnidentified: mutationGeneric({
        args: {
          targetUserId: v.string(),
          targetDeviceId: v.number(),
          targetAciBytes: v.optional(v.bytes()),
          ciphertext: v.string(),
          timestamp: v.number(),
          clientMessageId: v.optional(v.string()),
          unidentifiedAccessKey: v.optional(v.string()),
          groupSendToken: v.optional(v.bytes()),
        },
        returns: messageReceiptValidator,
        handler: async (ctx, input) =>
          await ctx.runMutation(
            component.messages.sendUnidentified,
            input
          ),
      }),
      sendMultiRecipientUnidentified: mutationGeneric({
        args: {
          recipients: v.array(
            v.object({
              userId: v.string(),
              deviceId: v.number(),
              registrationId: v.number(),
              aciBytes: v.optional(v.bytes()),
              encryptedMessageKeyBase64: v.string(),
              authenticationTagBase64: v.string(),
            })
          ),
          ephemeralPublicBase64: v.string(),
          messageCiphertextBase64: v.string(),
          timestamp: v.number(),
          clientMessageId: v.optional(v.string()),
          unidentifiedAccessKey: v.optional(v.string()),
          groupSendToken: v.optional(v.bytes()),
        },
        returns: v.object({
          messageId: v.string(),
          serverTimestamp: v.number(),
          uuids404: v.array(v.string()),
        }),
        handler: async (ctx, input) =>
          await ctx.runMutation(
            component.messages.sendMultiRecipientUnidentified,
            input
          ),
      }),
      sendRetryRequest: mutationGeneric({
        args: {
          requesterDeviceId: v.number(),
          originalSenderUserId: v.string(),
          originalSenderDeviceId: v.number(),
          failedTimestamp: v.number(),
          timestamp: v.number(),
          reason: retryReasonValidator,
        },
        returns: v.null(),
        handler: async (ctx, input) =>
          await ctx.runMutation(component.messages.sendRetryRequest, {
            ...(await identifyAccount(ctx)),
            ...input,
          }),
      }),
      getPendingRetryRequests: queryGeneric({
        args: { deviceId: v.number() },
        returns: v.array(
          v.object({
            id: v.string(),
            requesterUserId: v.string(),
            requesterDeviceId: v.number(),
            originalSenderUserId: v.string(),
            originalSenderDeviceId: v.number(),
            failedTimestamp: v.number(),
            timestamp: v.number(),
            reason: retryReasonValidator,
          })
        ),
        handler: async (ctx, input) =>
          await ctx.runQuery(
            component.messages.getPendingRetryRequests,
            {
              ...(await identifyAccount(ctx)),
              ...input,
            }
          ),
      }),
      markRetryRequestHandled: mutationGeneric({
        args: { requestId: v.string() },
        returns: v.null(),
        handler: async (ctx, input) =>
          await ctx.runMutation(
            component.messages.markRetryRequestHandled,
            {
              ...(await identifyAccount(ctx)),
              ...input,
            }
          ),
      }),
    },
    devices: {
      getDevices: queryGeneric({
        args: { userId: v.string() },
        returns: v.array(
          v.object({
            deviceId: v.number(),
            encryptedDeviceName: v.optional(v.bytes()),
            deviceType: v.optional(deviceTypeValidator),
            registered: v.boolean(),
            linked: v.boolean(),
            enabled: v.boolean(),
            active: v.boolean(),
            lastSeen: v.number(),
            createdAt: v.number(),
            linkedAt: v.optional(v.number()),
          })
        ),
        handler: async (ctx, input) =>
          await ctx.runQuery(component.devices.getDevices, {
            ...(await identifyAccount(ctx)),
            ...input,
          }),
      }),
      registerDevice: mutationGeneric({
        args: {
          deviceId: v.optional(v.number()),
          encryptedDeviceName: v.optional(v.bytes()),
          deviceType: v.optional(deviceTypeValidator),
        },
        returns: v.object({ deviceId: v.number() }),
        handler: async (ctx, input) =>
          await ctx.runMutation(component.devices.registerDevice, {
            ...(await identifyAccount(ctx)),
            ...input,
          }),
      }),
      removeDevice: mutationGeneric({
        args: { deviceId: v.number() },
        returns: v.null(),
        handler: async (ctx, input) =>
          await ctx.runMutation(component.devices.removeDevice, {
            ...(await identifyAccount(ctx)),
            ...input,
          }),
      }),
      markDeviceConnected: mutationGeneric({
        args: { deviceId: v.number() },
        returns: v.null(),
        handler: async (ctx, input) =>
          await ctx.runMutation(
            component.devices.markDeviceConnected,
            {
              ...(await identifyAccount(ctx)),
              ...input,
            }
          ),
      }),
      markDeviceDisconnected: mutationGeneric({
        args: { deviceId: v.number() },
        returns: v.null(),
        handler: async (ctx, input) =>
          await ctx.runMutation(
            component.devices.markDeviceDisconnected,
            {
              ...(await identifyAccount(ctx)),
              ...input,
            }
          ),
      }),
      presenceHeartbeat: mutationGeneric({
        args: { deviceId: v.number() },
        returns: v.null(),
        handler: async (ctx, input) =>
          await ctx.runMutation(component.devices.presenceHeartbeat, {
            ...(await identifyAccount(ctx)),
            ...input,
          }),
      }),
    },
    keys: {
      uploadIdentityKey: mutationGeneric({
        args: {
          mode: v.union(v.literal('provision'), v.literal('rotate')),
          userId: v.string(),
          deviceId: v.number(),
          compositeIdentity: v.string(),
          registrationId: v.number(),
          identityType: identityTypeValidator,
          expectedCurrentCommitment: v.optional(v.string()),
        },
        returns: v.null(),
        handler: async (ctx, input) => {
          const { userId: _untrustedUserId, ...payload } = input;
          return await ctx.runMutation(
            component.keys.uploadIdentityKey,
            {
              ...(await identifyAccount(ctx)),
              ...payload,
            }
          );
        },
      }),
      getIdentityKey: queryGeneric({
        args: {
          userId: v.string(),
          identityType: identityTypeValidator,
        },
        returns: v.union(v.string(), v.null()),
        handler: async (ctx, input) =>
          await ctx.runQuery(component.keys.getIdentityKey, {
            ...(await identifyAccount(ctx)),
            ...input,
          }),
      }),
      uploadPreKeys: mutationGeneric({
        args: {
          userId: v.string(),
          deviceId: v.number(),
          identityType: identityTypeValidator,
          keys: v.array(
            v.object({
              type: v.union(
                v.literal('ecPreKey'),
                v.literal('ecSignedPreKey'),
                v.literal('kemOneTimePreKey'),
                v.literal('kemLastResortPreKey')
              ),
              keyId: v.number(),
              publicKey: v.string(),
              signature: v.optional(v.string()),
            })
          ),
        },
        returns: v.null(),
        handler: async (ctx, input) => {
          const { userId: _untrustedUserId, ...payload } = input;
          return await ctx.runMutation(component.keys.uploadPreKeys, {
            ...(await identifyAccount(ctx)),
            ...payload,
          });
        },
      }),
      fetchPreKeyBundle: mutationGeneric({
        args: {
          userId: v.string(),
          deviceId: v.number(),
          identityType: identityTypeValidator,
        },
        returns: v.union(
          v.object({
            registrationId: v.number(),
            deviceId: v.number(),
            compositeIdentity: v.string(),
            ecSignedPreKey: v.object({
              keyId: v.number(),
              publicKey: v.string(),
              signature: v.string(),
            }),
            ecOneTimePreKey: v.union(
              v.object({
                keyId: v.number(),
                publicKey: v.string(),
              }),
              v.null()
            ),
            kemLastResortPreKey: v.union(
              v.object({
                keyId: v.number(),
                publicKey: v.string(),
                signature: v.string(),
              }),
              v.null()
            ),
            kemOneTimePreKey: v.union(
              v.object({
                keyId: v.number(),
                publicKey: v.string(),
                signature: v.string(),
              }),
              v.null()
            ),
          }),
          v.null()
        ),
        handler: async (ctx, input) =>
          await ctx.runMutation(component.keys.fetchPreKeyBundle, {
            ...(await identifyAccount(ctx)),
            ...input,
          }),
      }),
      getPreKeyCount: queryGeneric({
        args: {
          userId: v.string(),
          deviceId: v.number(),
          type: v.union(v.literal('ec'), v.literal('kem')),
          identityType: identityTypeValidator,
        },
        returns: v.number(),
        handler: async (ctx, input) => {
          const { userId: _untrustedUserId, ...payload } = input;
          return await ctx.runQuery(component.keys.getPreKeyCount, {
            ...(await identifyAccount(ctx)),
            ...payload,
          });
        },
      }),
      clearStaleKemPreKeys: mutationGeneric({
        args: {
          userId: v.string(),
          deviceId: v.number(),
          identityType: identityTypeValidator,
        },
        returns: v.object({ cleared: v.number() }),
        handler: async (ctx, input) => {
          const { userId: _untrustedUserId, ...payload } = input;
          return await ctx.runMutation(
            component.keys.clearStaleKemPreKeys,
            {
              ...(await identifyAccount(ctx)),
              ...payload,
            }
          );
        },
      }),
      uploadEcSignedPreKey: mutationGeneric({
        args: {
          userId: v.string(),
          identityType: identityTypeValidator,
          ecSignedPreKey: v.object({
            id: v.number(),
            deviceId: v.number(),
            publicKey: v.string(),
            signature: v.string(),
            timestamp: v.number(),
          }),
        },
        returns: v.null(),
        handler: async (ctx, input) => {
          const { userId: _untrustedUserId, ...payload } = input;
          return await ctx.runMutation(
            component.keys.uploadEcSignedPreKey,
            {
              ...(await identifyAccount(ctx)),
              ...payload,
            }
          );
        },
      }),
      uploadKemLastResortPreKey: mutationGeneric({
        args: {
          userId: v.string(),
          identityType: identityTypeValidator,
          kemLastResortPreKey: v.object({
            id: v.number(),
            deviceId: v.number(),
            publicKey: v.string(),
            signature: v.string(),
            timestamp: v.number(),
          }),
        },
        returns: v.null(),
        handler: async (ctx, input) => {
          const { userId: _untrustedUserId, ...payload } = input;
          return await ctx.runMutation(
            component.keys.uploadKemLastResortPreKey,
            {
              ...(await identifyAccount(ctx)),
              ...payload,
            }
          );
        },
      }),
      getEcSignedPreKeyMetadata: queryGeneric({
        args: {
          userId: v.string(),
          deviceId: v.number(),
          identityType: identityTypeValidator,
        },
        returns: v.union(
          v.object({
            keyId: v.number(),
            createdAt: v.number(),
            expiresAt: v.number(),
            publicKey: v.string(),
          }),
          v.null()
        ),
        handler: async (ctx, input) => {
          const { userId: _untrustedUserId, ...payload } = input;
          return await ctx.runQuery(
            component.keys.getEcSignedPreKeyMetadata,
            {
              ...(await identifyAccount(ctx)),
              ...payload,
            }
          );
        },
      }),
      getKemLastResortPreKeyMetadata: queryGeneric({
        args: {
          userId: v.string(),
          deviceId: v.number(),
          identityType: identityTypeValidator,
        },
        returns: v.union(
          v.object({
            keyId: v.number(),
            createdAt: v.number(),
            expiresAt: v.number(),
            publicKey: v.string(),
          }),
          v.null()
        ),
        handler: async (ctx, input) => {
          const { userId: _untrustedUserId, ...payload } = input;
          return await ctx.runQuery(
            component.keys.getKemLastResortPreKeyMetadata,
            {
              ...(await identifyAccount(ctx)),
              ...payload,
            }
          );
        },
      }),
    },
    certificates: {
      issueSenderCertificate: mutationGeneric({
        args: { deviceId: v.number() },
        returns: v.string(),
        handler: async (ctx, input) =>
          await ctx.runMutation(
            component.certificates.issueSenderCertificate,
            {
              ...(await identifyAccount(ctx)),
              ...input,
            }
          ),
      }),
    },
    provisioning: {
      createProvisioningSession: mutationGeneric({
        args: {
          userId: v.string(),
          ephemeralPublicKey: v.string(),
        },
        returns: v.object({ sessionId: v.string() }),
        handler: async (ctx, input) => {
          const { userId: _untrustedUserId, ...payload } = input;
          return await ctx.runMutation(
            component.provisioning.createProvisioningSession,
            {
              ...(await identifyAccount(ctx)),
              ...payload,
            }
          );
        },
      }),
      connectNewDevice: mutationGeneric({
        args: {
          sessionId: v.string(),
          ephemeralPublicKey: v.string(),
          deviceMetadata: v.object({
            platform: v.optional(v.string()),
            appVersion: v.optional(v.string()),
            osVersion: v.optional(v.string()),
          }),
        },
        returns: v.null(),
        handler: async (ctx, input) =>
          await ctx.runMutation(
            component.provisioning.connectNewDevice,
            {
              ...(await identifyAccount(ctx)),
              ...input,
            }
          ),
      }),
      sendProvisioningMessage: mutationGeneric({
        args: {
          userId: v.string(),
          sessionId: v.string(),
          encryptedMessage: v.string(),
        },
        returns: v.null(),
        handler: async (ctx, input) => {
          const { userId: _untrustedUserId, ...payload } = input;
          return await ctx.runMutation(
            component.provisioning.sendProvisioningMessage,
            {
              ...(await identifyAccount(ctx)),
              ...payload,
            }
          );
        },
      }),
      getProvisioningMessage: queryGeneric({
        args: { sessionId: v.string() },
        returns: v.object({
          status: provisioningStatusValidator,
          message: v.union(v.string(), v.null()),
          expiresAt: v.union(v.number(), v.null()),
        }),
        handler: async (ctx, input) =>
          await ctx.runQuery(
            component.provisioning.getProvisioningMessage,
            {
              ...(await identifyAccount(ctx)),
              ...input,
            }
          ),
      }),
      completeProvisioning: mutationGeneric({
        args: {
          sessionId: v.string(),
          deviceMetadata: v.object({
            encryptedDeviceName: v.bytes(),
            platform: v.optional(v.string()),
            appVersion: v.optional(v.string()),
            osVersion: v.optional(v.string()),
          }),
        },
        returns: v.object({ deviceId: v.number() }),
        handler: async (ctx, input) =>
          await ctx.runMutation(
            component.provisioning.completeProvisioning,
            {
              ...(await identifyAccount(ctx)),
              ...input,
            }
          ),
      }),
      acknowledgeProvisioning: mutationGeneric({
        args: { sessionId: v.string() },
        returns: v.null(),
        handler: async (ctx, input) =>
          await ctx.runMutation(
            component.provisioning.acknowledgeProvisioning,
            {
              ...(await identifyAccount(ctx)),
              ...input,
            }
          ),
      }),
      rollbackProvisioning: mutationGeneric({
        args: { sessionId: v.string() },
        returns: v.null(),
        handler: async (ctx, input) =>
          await ctx.runMutation(
            component.provisioning.rollbackProvisioning,
            {
              ...(await identifyAccount(ctx)),
              ...input,
            }
          ),
      }),
      deleteProvisioningSession: mutationGeneric({
        args: {
          userId: v.string(),
          sessionId: v.string(),
        },
        returns: v.null(),
        handler: async (ctx, input) => {
          const { userId: _untrustedUserId, ...payload } = input;
          return await ctx.runMutation(
            component.provisioning.deleteProvisioningSession,
            {
              ...(await identifyAccount(ctx)),
              ...payload,
            }
          );
        },
      }),
    },
    // Group wrappers pass client arguments through untouched. Group reads
    // and writes are authorized solely by the zero-knowledge presentation,
    // so no caller identity is resolved or forwarded for them. The identify()
    // wrapper drives credential issuance (zkAuth) only.
    groups: {
      createGroup: mutationGeneric({
        args: {
          groupId: v.bytes(),
          encryptedState: v.bytes(),
          presentation: v.bytes(),
          groupPublicParams: v.bytes(),
        },
        returns: v.null(),
        handler: async (ctx, input) =>
          await ctx.runMutation(component.groups.createGroup, input),
      }),
      getGroup: queryGeneric({
        args: {
          groupId: v.bytes(),
          presentation: v.bytes(),
          groupPublicParams: v.bytes(),
          version: v.optional(v.number()),
        },
        returns: v.union(snapshotResultValidator, v.null()),
        handler: async (ctx, input) =>
          await ctx.runQuery(component.groups.getGroup, input),
      }),
      getGroupJoinInfo: queryGeneric({
        args: {
          groupId: v.bytes(),
          inviteLinkPassword: v.bytes(),
          presentation: v.bytes(),
          groupPublicParams: v.bytes(),
        },
        returns: v.union(
          v.object({
            encryptedJoinInfo: v.bytes(),
            version: v.number(),
          }),
          v.null()
        ),
        handler: async (ctx, input) =>
          await ctx.runQuery(
            component.groups.getGroupJoinInfo,
            input
          ),
      }),
      getGroupChanges: queryGeneric({
        args: {
          groupId: v.bytes(),
          fromVersion: v.number(),
          presentation: v.bytes(),
          groupPublicParams: v.bytes(),
        },
        returns: v.object({
          entries: v.array(changeResultValidator),
          hasMore: v.boolean(),
        }),
        handler: async (ctx, input) =>
          await ctx.runQuery(component.groups.getGroupChanges, input),
      }),
      submitGroupChange: mutationGeneric({
        args: {
          groupId: v.bytes(),
          expectedVersion: v.number(),
          actions: v.bytes(),
          inviteLinkPassword: v.bytes(),
          presentation: v.bytes(),
          groupPublicParams: v.bytes(),
        },
        returns: changeResultValidator,
        handler: async (ctx, input) =>
          await ctx.runMutation(
            component.groups.submitGroupChange,
            input
          ),
      }),
      refreshGroupSendEndorsements: mutationGeneric({
        args: {
          groupId: v.bytes(),
          presentation: v.bytes(),
          groupPublicParams: v.bytes(),
        },
        returns: v.object({
          endorsements: v.bytes(),
          expiration: v.number(),
        }),
        handler: async (ctx, input) =>
          await ctx.runMutation(
            component.groups.refreshGroupSendEndorsements,
            input
          ),
      }),
    },
    zkAuth: {
      issueAuthCredentialMutation: mutationGeneric({
        args: {},
        returns: v.bytes(),
        handler: async (ctx) =>
          await ctx.runMutation(
            component.zkAuth.issueAuthCredentialMutation,
            await identify(ctx)
          ),
      }),
      issueProfileKeyCredentialMutation: mutationGeneric({
        args: { profileKey: v.bytes() },
        returns: v.bytes(),
        handler: async (ctx, input) =>
          await ctx.runMutation(
            component.zkAuth.issueProfileKeyCredentialMutation,
            {
              ...(await identify(ctx)),
              ...input,
            }
          ),
      }),
    },
  };
}
