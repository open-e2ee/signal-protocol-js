/**
 * Local Identity Model
 *
 * Own-device Signal identity material only. Recipient trust lives in
 * `recipient_identities`, not here.
 */

import { getDrizzle, getRawDatabase, identityKeys, type NewIdentityKey, eq, count } from '../db';

type LocalIdentityRow = typeof identityKeys.$inferSelect;

import { secureZero } from '../../../../internal/crypto';
import type { IdentityType } from '../../../../keys/types';

export {};

function primaryId(identityType: IdentityType = 'aci'): string {
  return `primary_${identityType}`;
}

async function getLocalIdentityById(id: string): Promise<LocalIdentity | null> {
  const db = await getDrizzle();
  const results = await db.select().from(identityKeys).where(eq(identityKeys.id, id)).limit(1);

  if (results.length === 0) return null;
  return new LocalIdentity(results[0]);
}

export async function getPrimaryIdentityKey(
  identityType: IdentityType = 'aci'
): Promise<LocalIdentity | null> {
  return getLocalIdentityById(primaryId(identityType));
}

export async function primaryIdentityKeyExists(
  identityType: IdentityType = 'aci'
): Promise<boolean> {
  return (await getPrimaryIdentityKey(identityType)) !== null;
}

export async function countLocalIdentityKeys(): Promise<number> {
  const db = await getDrizzle();
  const results = await db.select({ count: count() }).from(identityKeys);
  return results[0]?.count ?? 0;
}

export async function deletePrimaryIdentityKey(identityType: IdentityType = 'aci'): Promise<void> {
  const identity = await getPrimaryIdentityKey(identityType);
  if (!identity) return;
  await identity.delete();
}

export async function deleteAllLocalIdentityKeys(): Promise<void> {
  const rawDb = getRawDatabase();

  await rawDb.withTransactionAsync(async () => {
    for (const identityType of ['aci', 'pni'] as IdentityType[]) {
      const primary = await getPrimaryIdentityKey(identityType);
      if (primary?.dhKey) {
        secureZero(primary.dhKey.privateKey);
      }
      if (primary?.signingKey) {
        secureZero(primary.signingKey.privateKey);
      }
    }

    const db = await getDrizzle();
    await db.delete(identityKeys);
  });
}

export async function getLocalRegistrationId(
  identityType: IdentityType = 'aci'
): Promise<number | null> {
  const primary = await getPrimaryIdentityKey(identityType);
  return primary?.registrationId ?? null;
}

export async function setLocalRegistrationId(
  registrationId: number,
  identityType: IdentityType = 'aci'
): Promise<void> {
  const primary = await getPrimaryIdentityKey(identityType);
  if (!primary) return;
  await primary.withRegistrationId(registrationId).save();
}

export function createPrimaryIdentityKey(params: {
  publicKey: string;
  dhKey: { publicKey: string; privateKey: string };
  signingKey: { publicKey: string; privateKey: string };
  registrationId: number;
  identityType?: IdentityType;
}): LocalIdentity {
  const now = Date.now();
  const identityType = params.identityType ?? 'aci';

  return new LocalIdentity({
    id: primaryId(identityType),
    identityType,
    publicKey: params.publicKey,
    registrationId: params.registrationId,
    dhPublicKey: params.dhKey.publicKey,
    dhPrivateKey: params.dhKey.privateKey,
    signingPublicKey: params.signingKey.publicKey,
    signingPrivateKey: params.signingKey.privateKey,
    createdAt: now,
    updatedAt: now,
  });
}

export class LocalIdentity {
  private readonly data: LocalIdentityRow;

  constructor(row: LocalIdentityRow) {
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

  get registrationId(): number | undefined {
    return this.data.registrationId ?? undefined;
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

  withRegistrationId(registrationId: number): LocalIdentity {
    return new LocalIdentity({
      ...this.data,
      registrationId,
      updatedAt: Date.now(),
    });
  }

  async save(): Promise<void> {
    const db = await getDrizzle();

    const insertData: NewIdentityKey = {
      id: this.data.id,
      identityType: this.data.identityType,
      publicKey: this.data.publicKey,
      registrationId: this.data.registrationId,
      dhPublicKey: this.data.dhPublicKey,
      dhPrivateKey: this.data.dhPrivateKey,
      signingPublicKey: this.data.signingPublicKey,
      signingPrivateKey: this.data.signingPrivateKey,
      createdAt: this.data.createdAt,
      updatedAt: this.data.updatedAt,
    };

    await db
      .insert(identityKeys)
      .values(insertData)
      .onConflictDoUpdate({
        target: identityKeys.id,
        set: {
          identityType: insertData.identityType,
          publicKey: insertData.publicKey,
          registrationId: insertData.registrationId,
          dhPublicKey: insertData.dhPublicKey,
          dhPrivateKey: insertData.dhPrivateKey,
          signingPublicKey: insertData.signingPublicKey,
          signingPrivateKey: insertData.signingPrivateKey,
          updatedAt: insertData.updatedAt,
        },
      });
  }

  async delete(): Promise<void> {
    if (this.data.dhPrivateKey) {
      secureZero(this.data.dhPrivateKey);
    }
    if (this.data.signingPrivateKey) {
      secureZero(this.data.signingPrivateKey);
    }

    const db = await getDrizzle();
    await db.delete(identityKeys).where(eq(identityKeys.id, this.data.id));
  }
}
