/**
 * Local Identity Model
 *
 * Own-device Signal Protocol identity material only. Recipient trust lives in
 * `recipient_identities`, not here.
 *
 * The registration ID of each identity type is one `metadata` row, apart from
 * the key pair, so an application can set it before it stores the key pair.
 */

import type { SqliteExecutor } from '../driver';
import { IDENTITY_KEY_COLUMNS, type IdentityKeyRow } from '../schema';
import { secureZero } from '../../../../internal/crypto';
import type { IdentityType } from '../../../../keys/types';

function primaryId(identityType: IdentityType = 'aci'): string {
  return `primary_${identityType}`;
}

async function getLocalIdentityById(db: SqliteExecutor, id: string): Promise<LocalIdentity | null> {
  const row = await db.first<IdentityKeyRow>(
    `SELECT ${IDENTITY_KEY_COLUMNS} FROM identity_keys WHERE id = ? LIMIT 1`,
    [id]
  );
  return row ? new LocalIdentity(row) : null;
}

export async function getPrimaryIdentityKey(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<LocalIdentity | null> {
  return getLocalIdentityById(db, primaryId(identityType));
}

export async function primaryIdentityKeyExists(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<boolean> {
  return (await getPrimaryIdentityKey(db, identityType)) !== null;
}

export async function countLocalIdentityKeys(db: SqliteExecutor): Promise<number> {
  const row = await db.first<{ count: number }>('SELECT COUNT(*) AS count FROM identity_keys');
  return row?.count ?? 0;
}

export async function deletePrimaryIdentityKey(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<void> {
  const identity = await getPrimaryIdentityKey(db, identityType);
  if (!identity) return;
  await identity.delete(db);
}

export async function deleteAllLocalIdentityKeys(db: SqliteExecutor): Promise<void> {
  await db.transaction(async (tx) => {
    for (const identityType of ['aci', 'pni'] as IdentityType[]) {
      const primary = await getPrimaryIdentityKey(tx, identityType);
      if (primary?.dhKey) {
        secureZero(primary.dhKey.privateKey);
      }
      if (primary?.signingKey) {
        secureZero(primary.signingKey.privateKey);
      }
    }

    await tx.run('DELETE FROM identity_keys');
  });
}

function registrationIdKey(identityType: IdentityType): string {
  return `registrationId:${identityType}`;
}

export async function getLocalRegistrationId(
  db: SqliteExecutor,
  identityType: IdentityType = 'aci'
): Promise<number | null> {
  const row = await db.first<{ value: string }>('SELECT value FROM metadata WHERE key = ?', [
    registrationIdKey(identityType),
  ]);
  return row ? Number(row.value) : null;
}

export async function setLocalRegistrationId(
  db: SqliteExecutor,
  registrationId: number,
  identityType: IdentityType = 'aci'
): Promise<void> {
  await db.run('INSERT OR REPLACE INTO metadata (key, value, updated_at) VALUES (?, ?, ?)', [
    registrationIdKey(identityType),
    String(registrationId),
    Date.now(),
  ]);
}

export function createPrimaryIdentityKey(params: {
  publicKey: string;
  dhKey: { publicKey: string; privateKey: string };
  signingKey: { publicKey: string; privateKey: string };
  identityType?: IdentityType;
}): LocalIdentity {
  const now = Date.now();
  const identityType = params.identityType ?? 'aci';

  return new LocalIdentity({
    id: primaryId(identityType),
    identityType,
    publicKey: params.publicKey,
    dhPublicKey: params.dhKey.publicKey,
    dhPrivateKey: params.dhKey.privateKey,
    signingPublicKey: params.signingKey.publicKey,
    signingPrivateKey: params.signingKey.privateKey,
    createdAt: now,
    updatedAt: now,
  });
}

export class LocalIdentity {
  private readonly data: IdentityKeyRow;

  constructor(row: IdentityKeyRow) {
    this.data = { ...row };
  }

  get id(): string {
    return this.data.id;
  }

  get identityType(): IdentityType {
    return this.data.identityType as IdentityType;
  }

  get publicKey(): string {
    return this.data.publicKey;
  }

  get createdAt(): number {
    return this.data.createdAt;
  }

  get updatedAt(): number {
    return this.data.updatedAt;
  }

  get dhKey(): { publicKey: string; privateKey: string } | undefined {
    if (!this.data.dhPublicKey || !this.data.dhPrivateKey) return undefined;
    return {
      publicKey: this.data.dhPublicKey,
      privateKey: this.data.dhPrivateKey,
    };
  }

  get signingKey(): { publicKey: string; privateKey: string } | undefined {
    if (!this.data.signingPublicKey || !this.data.signingPrivateKey) return undefined;
    return {
      publicKey: this.data.signingPublicKey,
      privateKey: this.data.signingPrivateKey,
    };
  }

  async save(db: SqliteExecutor): Promise<void> {
    await db.run(
      `INSERT INTO identity_keys (id, identity_type, public_key,
         dh_public_key, dh_private_key, signing_public_key, signing_private_key,
         created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         identity_type = excluded.identity_type,
         public_key = excluded.public_key,
         dh_public_key = excluded.dh_public_key,
         dh_private_key = excluded.dh_private_key,
         signing_public_key = excluded.signing_public_key,
         signing_private_key = excluded.signing_private_key,
         updated_at = excluded.updated_at`,
      [
        this.data.id,
        this.data.identityType,
        this.data.publicKey,
        this.data.dhPublicKey,
        this.data.dhPrivateKey,
        this.data.signingPublicKey,
        this.data.signingPrivateKey,
        this.data.createdAt,
        this.data.updatedAt,
      ]
    );
  }

  async delete(db: SqliteExecutor): Promise<void> {
    if (this.data.dhPrivateKey) {
      secureZero(this.data.dhPrivateKey);
    }
    if (this.data.signingPrivateKey) {
      secureZero(this.data.signingPrivateKey);
    }

    await db.run('DELETE FROM identity_keys WHERE id = ?', [this.data.id]);
  }
}
