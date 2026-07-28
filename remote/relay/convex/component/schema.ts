import { defineSchema, defineTable } from 'convex/server';
import { v } from 'convex/values';

export default defineSchema({
  accounts: defineTable({
    userId: v.string(),
    aciBytes: v.bytes(),
    pniBytes: v.optional(v.bytes()),
    unidentifiedAccessKey: v.optional(v.string()),
    updatedAt: v.number(),
  })
    .index('by_user_id', ['userId'])
    // One ACI, one account: rememberAccount refuses a cross-account claim
    // over this index at write time. (Sealed-sender binding reads by user ID
    // and compares the stored ACI; this index exists for the uniqueness
    // check alone.)
    .index('by_aci_bytes', ['aciBytes']),
  devices: defineTable({
    userId: v.string(),
    deviceId: v.number(),
    encryptedDeviceName: v.optional(v.bytes()),
    deviceType: v.optional(
      v.union(
        v.literal('mobile'),
        v.literal('desktop'),
        v.literal('tablet'),
        v.literal('web')
      )
    ),
    registered: v.boolean(),
    linked: v.boolean(),
    enabled: v.boolean(),
    active: v.boolean(),
    lastSeen: v.number(),
    createdAt: v.number(),
    linkedAt: v.optional(v.number()),
    // Identifies *this* registration of the slot. Device rows are reused
    // across registrations — `db.replace` keeps the row id and the deviceId
    // is a small slot number — so neither identifies which link produced the
    // current occupant. A fresh token is minted on every register and every
    // link, and is never returned to clients.
    linkToken: v.optional(v.string()),
  })
    .index('by_user_id', ['userId'])
    .index('by_user_id_and_device_id', ['userId', 'deviceId']),
  deviceHeartbeats: defineTable({
    userId: v.string(),
    deviceId: v.number(),
    lastSeen: v.number(),
  }).index('by_user_id_and_device_id', ['userId', 'deviceId']),
  identityKeys: defineTable({
    userId: v.string(),
    identityType: v.union(v.literal('aci'), v.literal('pni')),
    compositeIdentity: v.string(),
    createdAt: v.number(),
    updatedAt: v.number(),
  }).index('by_user_id_and_identity_type', [
    'userId',
    'identityType',
  ]),
  identityRegistrations: defineTable({
    userId: v.string(),
    deviceId: v.number(),
    identityType: v.union(v.literal('aci'), v.literal('pni')),
    registrationId: v.number(),
    updatedAt: v.number(),
  })
    .index('by_user_id_and_device_id_and_identity_type', [
      'userId',
      'deviceId',
      'identityType',
    ])
    .index('by_user_id_and_identity_type', [
      'userId',
      'identityType',
    ]),
  ecPreKeys: defineTable({
    userId: v.string(),
    deviceId: v.number(),
    identityType: v.union(v.literal('aci'), v.literal('pni')),
    keyId: v.number(),
    publicKey: v.string(),
    uploadedAt: v.number(),
    consumedAt: v.optional(v.number()),
  })
    .index('by_user_id_and_device_id_and_identity_type_and_key_id', [
      'userId',
      'deviceId',
      'identityType',
      'keyId',
    ])
    .index(
      'by_user_id_and_device_id_and_identity_type_and_consumed_at',
      ['userId', 'deviceId', 'identityType', 'consumedAt']
    )
    .index('by_user_id_and_identity_type', [
      'userId',
      'identityType',
    ]),
  ecSignedPreKeys: defineTable({
    userId: v.string(),
    deviceId: v.number(),
    identityType: v.union(v.literal('aci'), v.literal('pni')),
    keyId: v.number(),
    publicKey: v.string(),
    signature: v.string(),
    createdAt: v.number(),
    expiresAt: v.number(),
  })
    .index('by_user_id_and_device_id_and_identity_type', [
      'userId',
      'deviceId',
      'identityType',
    ])
    .index('by_user_id_and_identity_type', [
      'userId',
      'identityType',
    ]),
  kemOneTimePreKeys: defineTable({
    userId: v.string(),
    deviceId: v.number(),
    identityType: v.union(v.literal('aci'), v.literal('pni')),
    keyId: v.number(),
    publicKey: v.string(),
    signature: v.optional(v.string()),
    uploadedAt: v.number(),
    consumedAt: v.optional(v.number()),
  })
    .index('by_user_id_and_device_id_and_identity_type_and_key_id', [
      'userId',
      'deviceId',
      'identityType',
      'keyId',
    ])
    .index(
      'by_user_id_and_device_id_and_identity_type_and_consumed_at',
      ['userId', 'deviceId', 'identityType', 'consumedAt']
    )
    .index('by_user_id_and_identity_type', ['userId', 'identityType'])
    .index('by_consumed_at_and_uploaded_at', [
      'consumedAt',
      'uploadedAt',
    ])
    .index('by_uploaded_at', ['uploadedAt']),
  kemLastResortPreKeys: defineTable({
    userId: v.string(),
    deviceId: v.number(),
    identityType: v.union(v.literal('aci'), v.literal('pni')),
    keyId: v.number(),
    publicKey: v.string(),
    signature: v.string(),
    createdAt: v.number(),
    expiresAt: v.number(),
  })
    .index('by_user_id_and_device_id_and_identity_type', [
      'userId',
      'deviceId',
      'identityType',
    ])
    .index('by_user_id_and_identity_type', ['userId', 'identityType'])
    .index('by_expires_at', ['expiresAt']),
  messages: defineTable({
    messageId: v.string(),
    targetUserId: v.string(),
    targetDeviceId: v.number(),
    senderUserId: v.string(),
    senderDeviceId: v.number(),
    ciphertext: v.string(),
    messageType: v.union(
      v.literal('ciphertext'),
      v.literal('prekey_bundle'),
      v.literal('sender_key'),
      v.literal('server_delivery_receipt'),
      v.literal('unidentified_sender')
    ),
    urgent: v.optional(v.boolean()),
    ephemeral: v.optional(v.boolean()),
    timestamp: v.number(),
    serverTimestamp: v.number(),
    clientMessageId: v.optional(v.string()),
    // Present on multi-recipient rows: `ciphertext` then holds only the
    // version byte and this recipient's key material, and the shared
    // remainder lives once in `multiRecipientPayloads`.
    sharedPayloadId: v.optional(v.string()),
    expiresAt: v.number(),
  })
    .index('by_message_id', ['messageId'])
    .index('by_target_user_id_and_target_device_id', [
      'targetUserId',
      'targetDeviceId',
    ])
    // Deduplication is per (recipient device, claimed sender): a
    // `clientMessageId` only ever collapses retries from the same sender.
    // Without `senderUserId` two senders that mint non-random client message
    // IDs (a counter, a timestamp) silently suppress each other's messages,
    // and the suppressed sender is handed the other sender's message ID and
    // server timestamp.
    .index('by_target_and_client_message_id', [
      'targetUserId',
      'targetDeviceId',
      'senderUserId',
      'clientMessageId',
    ])
    .index('by_expires_at', ['expiresAt']),
  // The shared portion of a multi-recipient sealed-sender message —
  // ephemeral public key and message ciphertext — stored once per send.
  // The per-recipient message rows carry only their 48 bytes of key
  // material plus a reference here, and delivery reassembles the wire
  // form. This is the reference's shape: its message store inserts one
  // shared multi-recipient payload and hands each recipient a pointer,
  // because storing a copy per recipient turns one send into an
  // amplification of itself. Rows share the message queue's retention
  // and are reaped by TTL, not by delivery — the last reader must not
  // have to know it is last.
  multiRecipientPayloads: defineTable({
    payloadId: v.string(),
    sharedBase64: v.string(),
    expiresAt: v.number(),
  })
    .index('by_payload_id', ['payloadId'])
    .index('by_expires_at', ['expiresAt']),
  retryRequests: defineTable({
    requestId: v.string(),
    requesterUserId: v.string(),
    requesterDeviceId: v.number(),
    originalSenderUserId: v.string(),
    originalSenderDeviceId: v.number(),
    failedTimestamp: v.number(),
    timestamp: v.number(),
    reason: v.union(
      v.literal('NO_SESSION'),
      v.literal('DECRYPTION_FAILED'),
      v.literal('SESSION_EXPIRED'),
      v.literal('INVALID_MESSAGE'),
      v.literal('STALE_DEVICE_LIST'),
      v.literal('IDENTITY_KEY_MISMATCH')
    ),
    // Retry requests share the message queue's seven-day retention: if the
    // original sender never returns to handle one, the row is
    // garbage-collected instead of persisting forever.
    expiresAt: v.number(),
  })
    .index('by_request_id', ['requestId'])
    .index(
      'by_original_sender_user_id_and_original_sender_device_id',
      ['originalSenderUserId', 'originalSenderDeviceId']
    )
    .index('by_expires_at', ['expiresAt']),
  provisioningSessions: defineTable({
    sessionId: v.string(),
    userId: v.string(),
    ephemeralPublicKey: v.string(),
    newDeviceEphemeralPublicKey: v.optional(v.string()),
    deviceMetadata: v.optional(
      v.object({
        platform: v.optional(v.string()),
        appVersion: v.optional(v.string()),
        osVersion: v.optional(v.string()),
      })
    ),
    encryptedMessage: v.optional(v.string()),
    assignedDeviceId: v.optional(v.number()),
    // `linkToken` of the device row this session created at completion;
    // teardown deletes a device only when the tokens match, so a device
    // re-registered into the freed slot is never reaped. A millisecond
    // timestamp was ambiguous here: two links landing in the same
    // millisecond on the same reused slot produce equal stamps, and
    // teardown would then reap the wrong link.
    linkedDeviceToken: v.optional(v.string()),
    // `expired` is deliberately absent: it is never stored. Mutations
    // reject expired sessions with a throw (which rolls back any patch),
    // the cleanup cron deletes expired rows outright, and
    // `getProvisioningMessage` reports expiry as a computed status.
    status: v.union(
      v.literal('waiting'),
      v.literal('connected'),
      v.literal('ready'),
      v.literal('linked_pending_ack'),
      v.literal('completed'),
      v.literal('rolled_back')
    ),
    createdAt: v.number(),
    expiresAt: v.number(),
  })
    .index('by_session_id', ['sessionId'])
    .index('by_user_id', ['userId'])
    .index('by_expires_at', ['expiresAt']),
  senderCertificates: defineTable({
    userId: v.string(),
    deviceId: v.number(),
    identityType: v.union(v.literal('aci'), v.literal('pni')),
    identityKey: v.string(),
    certificate: v.string(),
    issuedAt: v.number(),
    expiresAt: v.number(),
  })
    .index('by_user_id_and_device_id_and_identity_type', [
      'userId',
      'deviceId',
      'identityType',
    ])
    .index('by_user_id_and_identity_type', [
      'userId',
      'identityType',
    ]),
  groups: defineTable({
    groupId: v.string(),
    encryptedState: v.bytes(),
    version: v.number(),
  }).index('by_group_id', ['groupId']),
  groupChanges: defineTable({
    groupId: v.string(),
    version: v.number(),
    actions: v.bytes(),
    serverSignature: v.bytes(),
    changeEpoch: v.number(),
    timestamp: v.number(),
  }).index('by_group_id_version', ['groupId', 'version']),
  groupSnapshots: defineTable({
    groupId: v.string(),
    version: v.number(),
    encryptedState: v.bytes(),
    baselineSignature: v.bytes(),
  }).index('by_group_id_version', ['groupId', 'version']),
});
