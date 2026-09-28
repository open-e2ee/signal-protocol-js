/**
 * The SDK schema, as numbered steps, and the runner that applies them at open.
 *
 * `PRAGMA user_version` records the last applied step. A new file is at 0.
 * The runner applies the missing steps and the new version in one
 * `BEGIN IMMEDIATE` transaction, so a crash leaves the old version and the
 * old schema. A file from a newer SDK has a version above the last step here,
 * and the runner does not touch it.
 *
 * A step never changes after it ships. A schema change adds a step.
 */

import { openSqliteDatabase } from './database';
import type { SqliteDriver, SqliteExecutor, SqliteMigration } from './driver';
import type { SqliteOpenOptions } from './encryption';
import {
  SqliteSchemaTooNewError,
  SqliteStoreInUseError,
  classifySqliteError,
} from './errors';
import type { SqliteRootExecutor } from './executor';

export const SQLITE_STORE_MIGRATIONS: readonly SqliteMigration[] = [
  {
    version: 1,
    statements: [
      `CREATE TABLE identity_keys (
        id text PRIMARY KEY NOT NULL,
        identity_type text DEFAULT 'aci' NOT NULL,
        public_key text NOT NULL,
        dh_public_key text,
        dh_private_key text,
        signing_public_key text,
        signing_private_key text,
        created_at integer NOT NULL,
        updated_at integer NOT NULL
      )`,
      `CREATE TABLE recipient_identities (
        recipient_id text PRIMARY KEY NOT NULL,
        identity_type text NOT NULL,
        record_json text NOT NULL,
        updated_at integer NOT NULL
      )`,
      `CREATE INDEX idx_recipient_identities_updated ON recipient_identities (updated_at)`,
      `CREATE TABLE ec_signed_prekeys (
        id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
        identity_type text DEFAULT 'aci' NOT NULL,
        prekey_id integer NOT NULL,
        public_key text NOT NULL,
        private_key text NOT NULL,
        signature text NOT NULL,
        timestamp integer NOT NULL,
        created_at integer NOT NULL,
        replaced_at integer
      )`,
      `CREATE UNIQUE INDEX ec_signed_prekey_identity ON ec_signed_prekeys (identity_type, prekey_id)`,
      `CREATE INDEX idx_ec_signed_prekeys_timestamp ON ec_signed_prekeys (timestamp)`,
      `CREATE TABLE ec_one_time_prekeys (
        id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
        identity_type text DEFAULT 'aci' NOT NULL,
        prekey_id integer NOT NULL,
        public_key text NOT NULL,
        private_key text NOT NULL,
        created_at integer NOT NULL,
        replaced_at integer
      )`,
      `CREATE UNIQUE INDEX ec_one_time_prekey_identity ON ec_one_time_prekeys (identity_type, prekey_id)`,
      `CREATE TABLE kyber_prekeys (
        id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
        instance_id text NOT NULL,
        identity_type text DEFAULT 'aci' NOT NULL,
        prekey_id integer NOT NULL,
        public_key text NOT NULL,
        private_key text NOT NULL,
        signature text,
        timestamp integer NOT NULL,
        created_at integer NOT NULL,
        replaced_at integer
      )`,
      `CREATE UNIQUE INDEX kyber_prekey_instance ON kyber_prekeys (instance_id)`,
      `CREATE UNIQUE INDEX kyber_prekey_identity ON kyber_prekeys (identity_type, prekey_id)`,
      `CREATE UNIQUE INDEX kyber_prekey_current_identity ON kyber_prekeys (identity_type)
        WHERE replaced_at IS NULL`,
      `CREATE INDEX idx_kyber_prekeys_timestamp ON kyber_prekeys (timestamp)`,
      `CREATE TABLE kyber_prekey_used (
        kyber_prekey_row_id integer NOT NULL,
        signed_prekey_identity text NOT NULL,
        signed_prekey_id integer NOT NULL,
        base_key text NOT NULL,
        PRIMARY KEY (kyber_prekey_row_id, signed_prekey_identity, signed_prekey_id, base_key),
        FOREIGN KEY (kyber_prekey_row_id) REFERENCES kyber_prekeys (id)
          ON UPDATE CASCADE ON DELETE CASCADE
      )`,
      `CREATE TABLE kyber_one_time_prekeys (
        id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
        identity_type text DEFAULT 'aci' NOT NULL,
        prekey_id integer NOT NULL,
        public_key text NOT NULL,
        private_key text NOT NULL,
        signature text NOT NULL,
        timestamp integer NOT NULL,
        created_at integer NOT NULL,
        replaced_at integer
      )`,
      `CREATE UNIQUE INDEX kyber_one_time_prekey_identity ON kyber_one_time_prekeys (identity_type, prekey_id)`,
      `CREATE INDEX idx_kyber_one_time_prekeys_created ON kyber_one_time_prekeys (created_at)`,
      `CREATE TABLE sessions (
        session_id text PRIMARY KEY NOT NULL,
        identity_type text DEFAULT 'aci' NOT NULL,
        record text NOT NULL,
        created_at integer NOT NULL,
        updated_at integer NOT NULL
      )`,
      `CREATE INDEX idx_sessions_updated ON sessions (updated_at)`,
      `CREATE INDEX idx_sessions_identity_type ON sessions (identity_type)`,
      `CREATE TABLE sesame_user_records (
        user_id text PRIMARY KEY NOT NULL,
        record_json text NOT NULL,
        updated_at integer NOT NULL
      )`,
      `CREATE TABLE sender_keys (
        group_id text NOT NULL,
        sender_id text NOT NULL,
        device_id integer NOT NULL,
        record text NOT NULL,
        created_at integer NOT NULL,
        updated_at integer NOT NULL,
        PRIMARY KEY (group_id, sender_id, device_id)
      )`,
      `CREATE INDEX idx_sender_keys_group ON sender_keys (group_id)`,
      `CREATE INDEX idx_sender_keys_sender ON sender_keys (sender_id)`,
      `CREATE TABLE skipped_sender_keys (
        group_id text NOT NULL,
        sender_id text NOT NULL,
        sender_device_id integer NOT NULL,
        chain_index integer NOT NULL,
        cipher_key text NOT NULL,
        iv text NOT NULL,
        created_at integer NOT NULL,
        PRIMARY KEY (group_id, sender_id, sender_device_id, chain_index)
      )`,
      `CREATE TABLE message_records (
        session_id text NOT NULL,
        timestamp integer NOT NULL,
        recipient_user_id text NOT NULL,
        recipient_device_id integer NOT NULL,
        plaintext text NOT NULL,
        created_at integer NOT NULL,
        session_state_id text DEFAULT '' NOT NULL,
        PRIMARY KEY (session_id, timestamp)
      )`,
      `CREATE INDEX idx_message_records_created ON message_records (created_at)`,
      `CREATE INDEX idx_message_records_recipient ON message_records (recipient_user_id, recipient_device_id)`,
      `CREATE TABLE metadata (
        key text PRIMARY KEY NOT NULL,
        value text NOT NULL,
        updated_at integer NOT NULL
      )`,
      `CREATE TABLE profile_keys (
        user_id text PRIMARY KEY NOT NULL,
        profile_key text NOT NULL,
        profile_key_version integer DEFAULT 1 NOT NULL,
        received_at integer NOT NULL,
        updated_at integer NOT NULL
      )`,
      `CREATE INDEX idx_profile_keys_version ON profile_keys (profile_key_version)`,
      `CREATE TABLE group_master_keys (
        group_id text PRIMARY KEY NOT NULL,
        master_key text NOT NULL,
        created_at integer NOT NULL
      )`,
      `CREATE TABLE group_state_cache (
        group_id text PRIMARY KEY NOT NULL,
        decrypted_state text NOT NULL,
        revision integer NOT NULL,
        last_synced integer NOT NULL,
        endorsement_expiration integer DEFAULT 0
      )`,
      `CREATE TABLE auth_credential_cache (
        redemption_day integer PRIMARY KEY NOT NULL,
        credential text NOT NULL,
        expires_at integer NOT NULL
      )`,
    ],
  },
];

/**
 * Turn on foreign keys, then bring the schema to the last step.
 *
 * `PRAGMA foreign_keys` runs first and outside the transaction, because
 * SQLite ignores it inside one.
 *
 * @throws SqliteSchemaTooNewError when a newer SDK wrote the file.
 */
export async function applySqliteMigrations(
  db: SqliteExecutor,
  migrations: readonly SqliteMigration[] = SQLITE_STORE_MIGRATIONS
): Promise<void> {
  await db.run('PRAGMA foreign_keys = ON');
  const last = migrations.at(-1)?.version ?? 0;
  const current = await readUserVersion(db);
  if (current > last) throw new SqliteSchemaTooNewError(current, last);
  if (current === last) return;

  await db.transaction(async (tx) => {
    // Another connection can migrate the file between the read above and the
    // write lock that BEGIN IMMEDIATE takes, so read the version again.
    const from = await readUserVersion(tx);
    if (from > last) throw new SqliteSchemaTooNewError(from, last);
    for (const migration of migrations) {
      if (migration.version <= from) continue;
      for (const statement of migration.statements) await tx.run(statement);
    }
    await tx.run(`PRAGMA user_version = ${last}`);
  });
}

async function readUserVersion(db: SqliteExecutor): Promise<number> {
  const row = await db.first<{ user_version: number }>('PRAGMA user_version');
  return row?.user_version ?? 0;
}

/**
 * Open the file with {@link openSqliteDatabase}, which enforces the
 * encryption setting, then apply the SDK migrations. A migration failure
 * closes the connection.
 */
export async function openMigratedSqliteDatabase(
  driver: SqliteDriver,
  file: string,
  key: Uint8Array | null,
  options: SqliteOpenOptions = {}
): Promise<SqliteRootExecutor> {
  const db = await openSqliteDatabase(driver, file, key, options);
  try {
    await applySqliteMigrations(db);
  } catch (error) {
    await db.close().catch(() => undefined);
    if (classifySqliteError(error) === 'busy') {
      throw new SqliteStoreInUseError(driver.name, error);
    }
    throw error;
  }
  return db;
}
