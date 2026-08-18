import {
  index,
  integer,
  primaryKey,
  sqliteTable,
  text,
  uniqueIndex,
} from 'drizzle-orm/sqlite-core';

/**
 * SDK-managed SQLite schema fragment for Expo local storage.
 *
 * The app's unified Drizzle schema composes these tables, but the table
 * definitions themselves live with the Signal Protocol storage implementation.
 */

export const profileKeys = sqliteTable(
  'profile_keys',
  {
    userId: text('user_id').primaryKey(),
    profileKey: text('profile_key').notNull(),
    profileKeyVersion: integer('profile_key_version').notNull().default(1),
    receivedAt: integer('received_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
  },
  (table) => [index('idx_profile_keys_version').on(table.profileKeyVersion)]
);

export const identityKeys = sqliteTable('identity_keys', {
  id: text('id').primaryKey(),
  identityType: text('identity_type').notNull().default('aci'),
  publicKey: text('public_key').notNull(),
  registrationId: integer('registration_id'),
  dhPublicKey: text('dh_public_key'),
  dhPrivateKey: text('dh_private_key'),
  signingPublicKey: text('signing_public_key'),
  signingPrivateKey: text('signing_private_key'),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
});

export const recipientIdentities = sqliteTable(
  'recipient_identities',
  {
    recipientId: text('recipient_id').primaryKey(),
    identityType: text('identity_type').notNull(),
    /** JSON ContactIdentityRecord. No independently authoritative commitment. */
    recordJson: text('record_json').notNull(),
    updatedAt: integer('updated_at').notNull(),
  },
  (table) => [index('idx_recipient_identities_updated').on(table.updatedAt)]
);

export const ecSignedPreKeys = sqliteTable(
  'ec_signed_prekeys',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    identityType: text('identity_type').notNull().default('aci'),
    prekeyId: integer('prekey_id').notNull(),
    publicKey: text('public_key').notNull(),
    privateKey: text('private_key').notNull(),
    signature: text('signature').notNull(),
    timestamp: integer('timestamp').notNull(),
    createdAt: integer('created_at').notNull(),
    replacedAt: integer('replaced_at'),
  },
  (table) => [
    uniqueIndex('ec_signed_prekey_identity').on(table.identityType, table.prekeyId),
    index('idx_ec_signed_prekeys_timestamp').on(table.timestamp),
  ]
);

export const ecOneTimePreKeys = sqliteTable(
  'ec_one_time_prekeys',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    identityType: text('identity_type').notNull().default('aci'),
    prekeyId: integer('prekey_id').notNull(),
    publicKey: text('public_key').notNull(),
    privateKey: text('private_key').notNull(),
    createdAt: integer('created_at').notNull(),
    replacedAt: integer('replaced_at'),
  },
  (table) => [uniqueIndex('ec_one_time_prekey_identity').on(table.identityType, table.prekeyId)]
);

export const kyberPreKeys = sqliteTable(
  'kyber_prekeys',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    identityType: text('identity_type').notNull().default('aci'),
    prekeyId: integer('prekey_id').notNull(),
    publicKey: text('public_key').notNull(),
    privateKey: text('private_key').notNull(),
    signature: text('signature'),
    timestamp: integer('timestamp').notNull(),
    createdAt: integer('created_at').notNull(),
    replacedAt: integer('replaced_at'),
  },
  (table) => [
    uniqueIndex('kyber_prekey_identity').on(table.identityType, table.prekeyId),
    index('idx_kyber_prekeys_timestamp').on(table.timestamp),
  ]
);

export const kyberPreKeyUsed = sqliteTable(
  'kyber_prekey_used',
  {
    kyberPreKeyId: integer('kyber_prekey_id').notNull(),
    signedPreKeyIdentity: text('signed_prekey_identity').notNull(),
    signedPreKeyId: integer('signed_prekey_id').notNull(),
    baseKey: text('base_key').notNull(),
  },
  (table) => [
    primaryKey({
      columns: [
        table.kyberPreKeyId,
        table.signedPreKeyIdentity,
        table.signedPreKeyId,
        table.baseKey,
      ],
    }),
  ]
);

export const kyberOneTimePreKeys = sqliteTable(
  'kyber_one_time_prekeys',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    identityType: text('identity_type').notNull().default('aci'),
    prekeyId: integer('prekey_id').notNull(),
    publicKey: text('public_key').notNull(),
    privateKey: text('private_key').notNull(),
    signature: text('signature').notNull(),
    timestamp: integer('timestamp').notNull(),
    createdAt: integer('created_at').notNull(),
    replacedAt: integer('replaced_at'),
  },
  (table) => [
    uniqueIndex('kyber_one_time_prekey_identity').on(table.identityType, table.prekeyId),
    index('idx_kyber_one_time_prekeys_created').on(table.createdAt),
  ]
);

export const sessions = sqliteTable(
  'sessions',
  {
    sessionId: text('session_id').primaryKey(),
    identityType: text('identity_type').notNull().default('aci'),
    record: text('record').notNull(),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
  },
  (table) => [
    index('idx_sessions_updated').on(table.updatedAt),
    index('idx_sessions_identity_type').on(table.identityType),
  ]
);

/**
 * Sender key state for group messaging.
 *
 * `record` holds the whole `SenderKeyState[]` as JSON, current state first,
 * then the superseded states that the rotation window still needs. One column
 * rather than one per field, so a row can never disagree with itself about
 * which state is current.
 *
 * The chain key and the sender's private signature key live in this column.
 * They are stored in the clear because the database file itself is
 * SQLCipher-encrypted with an application-supplied key. They must never leave
 * the device.
 */
export const senderKeys = sqliteTable(
  'sender_keys',
  {
    groupId: text('group_id').notNull(),
    senderId: text('sender_id').notNull(),
    deviceId: integer('device_id').notNull(),
    record: text('record').notNull(),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.groupId, table.senderId, table.deviceId] }),
    index('idx_sender_keys_group').on(table.groupId),
    index('idx_sender_keys_sender').on(table.senderId),
  ]
);

/**
 * Message keys skipped by out-of-order group messages.
 *
 * The composite primary key doubles as the range index for the
 * (group, sender, device) prefix scans that the count and eviction paths use.
 */
export const skippedSenderKeys = sqliteTable(
  'skipped_sender_keys',
  {
    groupId: text('group_id').notNull(),
    senderId: text('sender_id').notNull(),
    senderDeviceId: integer('sender_device_id').notNull(),
    chainIndex: integer('chain_index').notNull(),
    cipherKey: text('cipher_key').notNull(),
    iv: text('iv').notNull(),
    createdAt: integer('created_at').notNull(),
  },
  (table) => [
    primaryKey({
      columns: [table.groupId, table.senderId, table.senderDeviceId, table.chainIndex],
    }),
  ]
);

export const messageRecords = sqliteTable(
  'message_records',
  {
    sessionId: text('session_id').notNull(),
    timestamp: integer('timestamp').notNull(),
    recipientUserId: text('recipient_user_id').notNull(),
    recipientDeviceId: integer('recipient_device_id').notNull(),
    plaintext: text('plaintext').notNull(),
    createdAt: integer('created_at').notNull(),
    sessionStateId: text('session_state_id').notNull().default(''),
  },
  (table) => [
    primaryKey({ columns: [table.sessionId, table.timestamp] }),
    index('idx_message_records_created').on(table.createdAt),
    index('idx_message_records_recipient').on(table.recipientUserId, table.recipientDeviceId),
  ]
);

export const groupMasterKeys = sqliteTable('group_master_keys', {
  groupId: text('group_id').primaryKey(),
  masterKey: text('master_key').notNull(),
  createdAt: integer('created_at').notNull(),
});

export const groupStateCache = sqliteTable('group_state_cache', {
  groupId: text('group_id').primaryKey(),
  decryptedState: text('decrypted_state').notNull(),
  revision: integer('revision').notNull(),
  lastSynced: integer('last_synced').notNull(),
  endorsementExpiration: integer('endorsement_expiration').default(0),
});

export const authCredentialCache = sqliteTable('auth_credential_cache', {
  redemptionDay: integer('redemption_day').primaryKey(),
  credential: text('credential').notNull(),
  expiresAt: integer('expires_at').notNull(),
});

export type ProfileKey = typeof profileKeys.$inferSelect;
export type NewProfileKey = typeof profileKeys.$inferInsert;
export type IdentityKey = typeof identityKeys.$inferSelect;
export type NewIdentityKey = typeof identityKeys.$inferInsert;
export type RecipientIdentity = typeof recipientIdentities.$inferSelect;
export type NewRecipientIdentity = typeof recipientIdentities.$inferInsert;
export type EcSignedPreKey = typeof ecSignedPreKeys.$inferSelect;
export type NewEcSignedPreKey = typeof ecSignedPreKeys.$inferInsert;
export type EcOneTimePreKey = typeof ecOneTimePreKeys.$inferSelect;
export type NewEcOneTimePreKey = typeof ecOneTimePreKeys.$inferInsert;
export type KyberPreKey = typeof kyberPreKeys.$inferSelect;
export type NewKyberPreKey = typeof kyberPreKeys.$inferInsert;
export type KyberOneTimePreKey = typeof kyberOneTimePreKeys.$inferSelect;
export type NewKyberOneTimePreKey = typeof kyberOneTimePreKeys.$inferInsert;
export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
export type SenderKey = typeof senderKeys.$inferSelect;
export type NewSenderKey = typeof senderKeys.$inferInsert;
export type SkippedSenderKeyRow = typeof skippedSenderKeys.$inferSelect;
export type NewSkippedSenderKeyRow = typeof skippedSenderKeys.$inferInsert;
export type MessageRecord = typeof messageRecords.$inferSelect;
export type NewMessageRecord = typeof messageRecords.$inferInsert;
export type GroupMasterKeyRow = typeof groupMasterKeys.$inferSelect;
export type NewGroupMasterKeyRow = typeof groupMasterKeys.$inferInsert;
export type GroupStateCacheRow = typeof groupStateCache.$inferSelect;
export type NewGroupStateCacheRow = typeof groupStateCache.$inferInsert;
export type AuthCredentialCacheRow = typeof authCredentialCache.$inferSelect;
export type NewAuthCredentialCacheRow = typeof authCredentialCache.$inferInsert;
