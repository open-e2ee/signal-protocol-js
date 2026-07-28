/* eslint-disable */
/**
 * Generated `ComponentApi` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type { FunctionReference } from "convex/server";

/**
 * A utility for referencing a Convex component's exposed API.
 *
 * Useful when expecting a parameter like `components.myComponent`.
 * Usage:
 * ```ts
 * async function myFunction(ctx: QueryCtx, component: ComponentApi) {
 *   return ctx.runQuery(component.someFile.someQuery, { ...args });
 * }
 * ```
 */
export type ComponentApi<Name extends string | undefined = string | undefined> =
  {
    certificates: {
      issueSenderCertificate: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceId: number;
        },
        string,
        Name
      >;
    };
    devices: {
      getDevices: FunctionReference<
        "query",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          userId: string;
        },
        Array<{
          active: boolean;
          createdAt: number;
          deviceId: number;
          deviceType?: "mobile" | "desktop" | "tablet" | "web";
          enabled: boolean;
          encryptedDeviceName?: ArrayBuffer;
          lastSeen: number;
          linked: boolean;
          linkedAt?: number;
          registered: boolean;
        }>,
        Name
      >;
      markDeviceConnected: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceId: number;
        },
        null,
        Name
      >;
      markDeviceDisconnected: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceId: number;
        },
        null,
        Name
      >;
      presenceHeartbeat: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceId: number;
        },
        null,
        Name
      >;
      registerDevice: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceId?: number;
          deviceType?: "mobile" | "desktop" | "tablet" | "web";
          encryptedDeviceName?: ArrayBuffer;
        },
        { deviceId: number },
        Name
      >;
      removeDevice: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceId: number;
        },
        null,
        Name
      >;
    };
    groups: {
      createGroup: FunctionReference<
        "mutation",
        "internal",
        {
          encryptedState: ArrayBuffer;
          groupId: ArrayBuffer;
          groupPublicParams: ArrayBuffer;
          presentation: ArrayBuffer;
        },
        null,
        Name
      >;
      getGroup: FunctionReference<
        "query",
        "internal",
        {
          groupId: ArrayBuffer;
          groupPublicParams: ArrayBuffer;
          presentation: ArrayBuffer;
          version?: number;
        },
        {
          baselineSignature: ArrayBuffer;
          encryptedState: ArrayBuffer;
          version: number;
        } | null,
        Name
      >;
      getGroupChanges: FunctionReference<
        "query",
        "internal",
        {
          fromVersion: number;
          groupId: ArrayBuffer;
          groupPublicParams: ArrayBuffer;
          presentation: ArrayBuffer;
        },
        {
          entries: Array<{
            actions: ArrayBuffer;
            changeEpoch: number;
            serverSignature: ArrayBuffer;
            timestamp: number;
            version: number;
          }>;
          hasMore: boolean;
        },
        Name
      >;
      getGroupJoinInfo: FunctionReference<
        "query",
        "internal",
        {
          groupId: ArrayBuffer;
          groupPublicParams: ArrayBuffer;
          inviteLinkPassword: ArrayBuffer;
          presentation: ArrayBuffer;
        },
        { encryptedJoinInfo: ArrayBuffer; version: number } | null,
        Name
      >;
      refreshGroupSendEndorsements: FunctionReference<
        "mutation",
        "internal",
        {
          groupId: ArrayBuffer;
          groupPublicParams: ArrayBuffer;
          presentation: ArrayBuffer;
        },
        { endorsements: ArrayBuffer; expiration: number },
        Name
      >;
      submitGroupChange: FunctionReference<
        "mutation",
        "internal",
        {
          actions: ArrayBuffer;
          expectedVersion: number;
          groupId: ArrayBuffer;
          groupPublicParams: ArrayBuffer;
          inviteLinkPassword: ArrayBuffer;
          presentation: ArrayBuffer;
        },
        {
          actions: ArrayBuffer;
          changeEpoch: number;
          serverSignature: ArrayBuffer;
          timestamp: number;
          version: number;
        },
        Name
      >;
    };
    keys: {
      clearStaleKemPreKeys: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceId: number;
          identityType: "aci" | "pni";
        },
        { cleared: number },
        Name
      >;
      fetchPreKeyBundle: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceId: number;
          identityType: "aci" | "pni";
          userId: string;
        },
        {
          compositeIdentity: string;
          deviceId: number;
          ecOneTimePreKey: { keyId: number; publicKey: string } | null;
          ecSignedPreKey: {
            keyId: number;
            publicKey: string;
            signature: string;
          };
          kemLastResortPreKey: {
            keyId: number;
            publicKey: string;
            signature: string;
          } | null;
          kemOneTimePreKey: {
            keyId: number;
            publicKey: string;
            signature: string;
          } | null;
          registrationId: number;
        } | null,
        Name
      >;
      getEcSignedPreKeyMetadata: FunctionReference<
        "query",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceId: number;
          identityType: "aci" | "pni";
        },
        {
          createdAt: number;
          expiresAt: number;
          keyId: number;
          publicKey: string;
        } | null,
        Name
      >;
      getIdentityKey: FunctionReference<
        "query",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          identityType: "aci" | "pni";
          userId: string;
        },
        string | null,
        Name
      >;
      getKemLastResortPreKeyMetadata: FunctionReference<
        "query",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceId: number;
          identityType: "aci" | "pni";
        },
        {
          createdAt: number;
          expiresAt: number;
          keyId: number;
          publicKey: string;
        } | null,
        Name
      >;
      getPreKeyCount: FunctionReference<
        "query",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceId: number;
          identityType: "aci" | "pni";
          type: "ec" | "kem";
        },
        number,
        Name
      >;
      uploadEcSignedPreKey: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          ecSignedPreKey: {
            deviceId: number;
            id: number;
            publicKey: string;
            signature: string;
            timestamp: number;
          };
          identityType: "aci" | "pni";
        },
        null,
        Name
      >;
      uploadIdentityKey: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          compositeIdentity: string;
          deviceId: number;
          expectedCurrentCommitment?: string;
          identityType: "aci" | "pni";
          mode: "provision" | "rotate";
          registrationId: number;
        },
        null,
        Name
      >;
      uploadKemLastResortPreKey: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          identityType: "aci" | "pni";
          kemLastResortPreKey: {
            deviceId: number;
            id: number;
            publicKey: string;
            signature: string;
            timestamp: number;
          };
        },
        null,
        Name
      >;
      uploadPreKeys: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceId: number;
          identityType: "aci" | "pni";
          keys: Array<{
            keyId: number;
            publicKey: string;
            signature?: string;
            type:
              | "ecPreKey"
              | "ecSignedPreKey"
              | "kemOneTimePreKey"
              | "kemLastResortPreKey";
          }>;
        },
        null,
        Name
      >;
    };
    messages: {
      getActiveDevices: FunctionReference<
        "query",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          userId: string;
        },
        Array<{ deviceId: number; userId: string }>,
        Name
      >;
      getPendingMessages: FunctionReference<
        "query",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceId: number;
        },
        Array<{
          ciphertext: string;
          clientMessageId?: string;
          ephemeral?: boolean;
          expiresAt: number;
          id: string;
          messageType:
            | "ciphertext"
            | "prekey_bundle"
            | "sender_key"
            | "server_delivery_receipt"
            | "unidentified_sender";
          senderDeviceId: number;
          senderUserId: string;
          serverTimestamp: number;
          targetDeviceId: number;
          targetUserId: string;
          timestamp: number;
          urgent?: boolean;
        }>,
        Name
      >;
      getPendingRetryRequests: FunctionReference<
        "query",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceId: number;
        },
        Array<{
          failedTimestamp: number;
          id: string;
          originalSenderDeviceId: number;
          originalSenderUserId: string;
          reason:
            | "NO_SESSION"
            | "DECRYPTION_FAILED"
            | "SESSION_EXPIRED"
            | "INVALID_MESSAGE"
            | "STALE_DEVICE_LIST"
            | "IDENTITY_KEY_MISMATCH";
          requesterDeviceId: number;
          requesterUserId: string;
          timestamp: number;
        }>,
        Name
      >;
      markDelivered: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          messageId: string;
        },
        null,
        Name
      >;
      markRetryRequestHandled: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          requestId: string;
        },
        null,
        Name
      >;
      send: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          ciphertext: string;
          clientMessageId?: string;
          ephemeral?: boolean;
          messageType:
            | "ciphertext"
            | "prekey_bundle"
            | "sender_key"
            | "server_delivery_receipt"
            | "unidentified_sender";
          recipientRegistrationId?: number;
          senderDeviceId: number;
          targetDeviceId: number;
          targetUserId: string;
          timestamp: number;
          urgent?: boolean;
        },
        { messageId: string; serverTimestamp: number },
        Name
      >;
      sendMultiRecipientUnidentified: FunctionReference<
        "mutation",
        "internal",
        {
          clientMessageId?: string;
          ephemeralPublicBase64: string;
          groupSendToken?: ArrayBuffer;
          messageCiphertextBase64: string;
          recipients: Array<{
            aciBytes?: ArrayBuffer;
            authenticationTagBase64: string;
            deviceId: number;
            encryptedMessageKeyBase64: string;
            registrationId: number;
            userId: string;
          }>;
          timestamp: number;
          unidentifiedAccessKey?: string;
        },
        { messageId: string; serverTimestamp: number; uuids404: Array<string> },
        Name
      >;
      sendRetryRequest: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          failedTimestamp: number;
          originalSenderDeviceId: number;
          originalSenderUserId: string;
          reason:
            | "NO_SESSION"
            | "DECRYPTION_FAILED"
            | "SESSION_EXPIRED"
            | "INVALID_MESSAGE"
            | "STALE_DEVICE_LIST"
            | "IDENTITY_KEY_MISMATCH";
          requesterDeviceId: number;
          timestamp: number;
        },
        null,
        Name
      >;
      sendUnidentified: FunctionReference<
        "mutation",
        "internal",
        {
          ciphertext: string;
          clientMessageId?: string;
          groupSendToken?: ArrayBuffer;
          targetAciBytes?: ArrayBuffer;
          targetDeviceId: number;
          targetUserId: string;
          timestamp: number;
          unidentifiedAccessKey?: string;
        },
        { messageId: string; serverTimestamp: number },
        Name
      >;
    };
    provisioning: {
      acknowledgeProvisioning: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          sessionId: string;
        },
        null,
        Name
      >;
      completeProvisioning: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceMetadata: {
            appVersion?: string;
            encryptedDeviceName: ArrayBuffer;
            osVersion?: string;
            platform?: string;
          };
          sessionId: string;
        },
        { deviceId: number },
        Name
      >;
      connectNewDevice: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          deviceMetadata: {
            appVersion?: string;
            osVersion?: string;
            platform?: string;
          };
          ephemeralPublicKey: string;
          sessionId: string;
        },
        null,
        Name
      >;
      createProvisioningSession: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          ephemeralPublicKey: string;
        },
        { sessionId: string },
        Name
      >;
      deleteProvisioningSession: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          sessionId: string;
        },
        null,
        Name
      >;
      getProvisioningMessage: FunctionReference<
        "query",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          sessionId: string;
        },
        {
          expiresAt: number | null;
          message: string | null;
          status:
            | "waiting"
            | "connected"
            | "ready"
            | "linked_pending_ack"
            | "completed"
            | "rolled_back"
            | "expired";
        },
        Name
      >;
      rollbackProvisioning: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          sessionId: string;
        },
        null,
        Name
      >;
      sendProvisioningMessage: FunctionReference<
        "mutation",
        "internal",
        {
          callerAciBytes: ArrayBuffer;
          callerPniBytes?: ArrayBuffer;
          callerUserId: string;
          encryptedMessage: string;
          sessionId: string;
        },
        null,
        Name
      >;
    };
    zkAuth: {
      issueAuthCredentialMutation: FunctionReference<
        "mutation",
        "internal",
        { aciBytes: ArrayBuffer; pniBytes?: ArrayBuffer; userId?: string },
        ArrayBuffer,
        Name
      >;
      issueProfileKeyCredentialMutation: FunctionReference<
        "mutation",
        "internal",
        {
          aciBytes: ArrayBuffer;
          pniBytes?: ArrayBuffer;
          profileKey: ArrayBuffer;
          userId?: string;
        },
        ArrayBuffer,
        Name
      >;
    };
  };
