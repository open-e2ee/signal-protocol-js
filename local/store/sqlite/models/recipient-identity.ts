/** Canonical composite recipient identity persistence. */

import type { SqliteExecutor } from '../driver';
import type { ContactIdentityRecord, IdentityType } from '../../../../keys/types';
import { validateContactIdentityRecord } from '../../../../keys/identity';
import { buildContactIdentityId } from './identity-key-id';

type RecipientIdentityRow = { recordJson: string };

function decodeRow(row: RecipientIdentityRow): ContactIdentityRecord {
  const record = JSON.parse(row.recordJson) as ContactIdentityRecord;
  validateContactIdentityRecord(record);
  return record;
}

export async function getContactIdentity(
  db: SqliteExecutor,
  userId: string,
  identityType: IdentityType = 'aci'
): Promise<ContactIdentityRecord | null> {
  const row = await db.first<RecipientIdentityRow>(
    `SELECT record_json AS recordJson
       FROM recipient_identities WHERE recipient_id = ?`,
    [buildContactIdentityId(userId, identityType)]
  );
  return row ? decodeRow(row) : null;
}

export async function getAllContactIdentities(
  db: SqliteExecutor
): Promise<ContactIdentityRecord[]> {
  const rows = await db.all<RecipientIdentityRow>(
    'SELECT record_json AS recordJson FROM recipient_identities'
  );
  return rows.map(decodeRow);
}

export async function countRecipientIdentities(db: SqliteExecutor): Promise<number> {
  const row = await db.first<{ count: number }>(
    'SELECT COUNT(*) AS count FROM recipient_identities'
  );
  return row?.count ?? 0;
}

export async function deleteContactIdentity(
  db: SqliteExecutor,
  userId: string,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await db.run('DELETE FROM recipient_identities WHERE recipient_id = ?', [
    buildContactIdentityId(userId, identityType),
  ]);
}

export async function deleteAllContactIdentities(db: SqliteExecutor): Promise<void> {
  await db.run('DELETE FROM recipient_identities');
}

export async function saveContactIdentity(
  db: SqliteExecutor,
  userId: string,
  record: ContactIdentityRecord,
  identityType: IdentityType = 'aci'
): Promise<void> {
  validateContactIdentityRecord(record);
  await db.run(
    `INSERT OR REPLACE INTO recipient_identities
       (recipient_id, identity_type, record_json, updated_at) VALUES (?, ?, ?, ?)`,
    [buildContactIdentityId(userId, identityType), identityType, JSON.stringify(record), Date.now()]
  );
}

/** Small model wrapper retained for callers that prefer object persistence. */
export class RecipientIdentity {
  constructor(
    readonly userId: string,
    readonly record: ContactIdentityRecord,
    readonly identityType: IdentityType = 'aci'
  ) {
    validateContactIdentityRecord(record);
  }

  get id(): string {
    return buildContactIdentityId(this.userId, this.identityType);
  }

  async save(db: SqliteExecutor): Promise<void> {
    await saveContactIdentity(db, this.userId, this.record, this.identityType);
  }

  async delete(db: SqliteExecutor): Promise<void> {
    await deleteContactIdentity(db, this.userId, this.identityType);
  }
}

export function createContactIdentity(
  userId: string,
  record: ContactIdentityRecord,
  identityType: IdentityType = 'aci'
): RecipientIdentity {
  return new RecipientIdentity(userId, record, identityType);
}
