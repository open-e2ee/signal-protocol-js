/**
 * The SDK tables, as the shared core reads them.
 *
 * The migrations in `./migrations.ts` create these tables. The row types
 * name each column in camelCase, and the `*_COLUMNS` lists select a full row
 * with those aliases.
 */

/**
 * Every SDK table, children before parents, so one DELETE per table in this
 * order empties the store. Tables that the application adds to the same
 * database are not listed and are never touched.
 */
export const SQLITE_STORE_TABLES = [
  'identity_keys',
  'recipient_identities',
  'ec_signed_prekeys',
  'ec_one_time_prekeys',
  'kyber_prekey_used',
  'kyber_prekeys',
  'kyber_one_time_prekeys',
  'sessions',
  'sesame_user_records',
  'sender_keys',
  'skipped_sender_keys',
  'message_records',
  'metadata',
  'profile_keys',
  'group_master_keys',
  'group_state_cache',
  'auth_credential_cache',
] as const;

export type IdentityKeyRow = {
  id: string;
  identityType: string;
  publicKey: string;
  dhPublicKey: string | null;
  dhPrivateKey: string | null;
  signingPublicKey: string | null;
  signingPrivateKey: string | null;
  createdAt: number;
  updatedAt: number;
};

export const IDENTITY_KEY_COLUMNS = `id, identity_type AS identityType, public_key AS publicKey,
  dh_public_key AS dhPublicKey,
  dh_private_key AS dhPrivateKey, signing_public_key AS signingPublicKey,
  signing_private_key AS signingPrivateKey, created_at AS createdAt,
  updated_at AS updatedAt`;

export type EcSignedPreKeyRow = {
  id: number;
  identityType: string;
  prekeyId: number;
  publicKey: string;
  privateKey: string;
  signature: string;
  timestamp: number;
  createdAt: number;
  replacedAt: number | null;
};

export const EC_SIGNED_PREKEY_COLUMNS = `id, identity_type AS identityType,
  prekey_id AS prekeyId, public_key AS publicKey, private_key AS privateKey,
  signature, timestamp, created_at AS createdAt, replaced_at AS replacedAt`;

export type EcOneTimePreKeyRow = {
  id: number;
  identityType: string;
  prekeyId: number;
  publicKey: string;
  privateKey: string;
  createdAt: number;
  replacedAt: number | null;
};

export const EC_ONE_TIME_PREKEY_COLUMNS = `id, identity_type AS identityType,
  prekey_id AS prekeyId, public_key AS publicKey, private_key AS privateKey,
  created_at AS createdAt, replaced_at AS replacedAt`;

export type KyberPreKeyRow = {
  id: number;
  instanceId: string;
  identityType: string;
  prekeyId: number;
  publicKey: string;
  privateKey: string;
  signature: string | null;
  timestamp: number;
  createdAt: number;
  replacedAt: number | null;
};

export const KYBER_PREKEY_COLUMNS = `id, instance_id AS instanceId,
  identity_type AS identityType, prekey_id AS prekeyId, public_key AS publicKey,
  private_key AS privateKey, signature, timestamp, created_at AS createdAt,
  replaced_at AS replacedAt`;

export type KyberOneTimePreKeyRow = {
  id: number;
  identityType: string;
  prekeyId: number;
  publicKey: string;
  privateKey: string;
  signature: string;
  timestamp: number;
  createdAt: number;
  replacedAt: number | null;
};

export const KYBER_ONE_TIME_PREKEY_COLUMNS = `id, identity_type AS identityType,
  prekey_id AS prekeyId, public_key AS publicKey, private_key AS privateKey,
  signature, timestamp, created_at AS createdAt, replaced_at AS replacedAt`;

export type SessionRow = {
  sessionId: string;
  identityType: string;
  record: string;
  createdAt: number;
  updatedAt: number;
};

export const SESSION_COLUMNS = `session_id AS sessionId, identity_type AS identityType,
  record, created_at AS createdAt, updated_at AS updatedAt`;

export type SenderKeyRow = {
  groupId: string;
  senderId: string;
  deviceId: number;
  record: string;
  createdAt: number;
  updatedAt: number;
};

export const SENDER_KEY_COLUMNS = `group_id AS groupId, sender_id AS senderId,
  device_id AS deviceId, record, created_at AS createdAt, updated_at AS updatedAt`;

export type MessageRecordRow = {
  sessionId: string;
  timestamp: number;
  recipientUserId: string;
  recipientDeviceId: number;
  plaintext: string;
  createdAt: number;
  sessionStateId: string;
};

export const MESSAGE_RECORD_COLUMNS = `session_id AS sessionId, timestamp,
  recipient_user_id AS recipientUserId, recipient_device_id AS recipientDeviceId,
  plaintext, created_at AS createdAt, session_state_id AS sessionStateId`;

/** `?, ?, ?` for an `IN (...)` list of `count` values. */
export function placeholders(count: number): string {
  return Array.from({ length: count }, () => '?').join(', ');
}
