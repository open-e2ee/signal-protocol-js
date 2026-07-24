/** Canonical composite recipient identity persistence for Expo SQLite. */

import type { ContactIdentityRecord, IdentityType } from '../../../../keys/types';
import { validateContactIdentityRecord } from '../../../../keys/identity';
import { getDrizzle, getRawDatabase, recipientIdentities } from '../db';
import { buildContactIdentityId } from './identity-key-id';

type RecipientIdentityRow = typeof recipientIdentities.$inferSelect;

export {};

function decodeRow(row: RecipientIdentityRow): ContactIdentityRecord {
  const record = JSON.parse(row.recordJson) as ContactIdentityRecord;
  validateContactIdentityRecord(record);
  return record;
}

export async function getContactIdentity(
  userId: string,
  identityType: IdentityType = 'aci'
): Promise<ContactIdentityRecord | null> {
  await getDrizzle();
  const row = await getRawDatabase().getFirstAsync<RecipientIdentityRow>(
    `SELECT recipient_id, identity_type, record_json, updated_at
       FROM recipient_identities WHERE recipient_id = ?`,
    [buildContactIdentityId(userId, identityType)]
  );
  return row ? decodeRow(row) : null;
}

export async function getAllContactIdentities(): Promise<ContactIdentityRecord[]> {
  await getDrizzle();
  const rows = await getRawDatabase().getAllAsync<RecipientIdentityRow>(
    `SELECT recipient_id, identity_type, record_json, updated_at FROM recipient_identities`
  );
  return rows.map(decodeRow);
}

export async function countRecipientIdentities(): Promise<number> {
  await getDrizzle();
  const row = await getRawDatabase().getFirstAsync<{ count: number }>(
    `SELECT COUNT(*) AS count FROM recipient_identities`
  );
  return row?.count ?? 0;
}

export async function deleteContactIdentity(
  userId: string,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await getDrizzle();
  await getRawDatabase().runAsync(`DELETE FROM recipient_identities WHERE recipient_id = ?`, [
    buildContactIdentityId(userId, identityType),
  ]);
}

export async function deleteAllContactIdentities(): Promise<void> {
  await getDrizzle();
  await getRawDatabase().runAsync(`DELETE FROM recipient_identities`);
}

export async function saveContactIdentity(
  userId: string,
  record: ContactIdentityRecord,
  identityType: IdentityType = 'aci'
): Promise<void> {
  validateContactIdentityRecord(record);
  await getDrizzle();
  await getRawDatabase().runAsync(
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

  async save(): Promise<void> {
    await saveContactIdentity(this.userId, this.record, this.identityType);
  }

  async delete(): Promise<void> {
    await deleteContactIdentity(this.userId, this.identityType);
  }
}

export function createContactIdentity(
  userId: string,
  record: ContactIdentityRecord,
  identityType: IdentityType = 'aci'
): RecipientIdentity {
  return new RecipientIdentity(userId, record, identityType);
}
