/**
 * Dual Protocol Store — ACI/PNI Identity Router
 *
 * Thin wrapper providing .aci() and .pni() views over KeyStorage,
 * each pre-filling identityType for all operations.
 *
 */

import type {
  IdentityType,
  IdentityKeyPair,
  EcSignedPreKey,
  EcOneTimePreKey,
  KyberPreKey,
  KemOneTimePreKey,
} from '../keys/types';
import type { ISignalProtocolLocalStore } from '../types/api';

/**
 * A view of ISignalProtocolLocalStore scoped to a specific identity type.
 * All identity-type-aware methods are pre-filled with the given type.
 */
export {};
export class IdentityTypedStore {
  constructor(
    private readonly store: ISignalProtocolLocalStore,
    readonly identityType: IdentityType
  ) {}

  // Identity keys
  storeIdentityKey(keyPair: IdentityKeyPair) {
    return this.store.storeIdentityKey(keyPair, this.identityType);
  }

  getIdentityKey() {
    return this.store.getIdentityKey(this.identityType);
  }

  hasIdentityKey() {
    return this.store.hasIdentityKey(this.identityType);
  }

  getLocalRegistrationId() {
    return this.store.getLocalRegistrationId(this.identityType);
  }

  setLocalRegistrationId(id: number) {
    return this.store.setLocalRegistrationId(id, this.identityType);
  }

  // EC signed prekeys
  storeEcSignedPreKey(signedPreKey: EcSignedPreKey) {
    return this.store.storeEcSignedPreKey(signedPreKey, this.identityType);
  }

  getEcSignedPreKey(keyId?: number) {
    return this.store.getEcSignedPreKey(keyId, this.identityType);
  }

  getAllEcSignedPreKeys() {
    return this.store.getAllEcSignedPreKeys?.(this.identityType);
  }

  removeEcSignedPreKey(keyId: number) {
    return this.store.removeEcSignedPreKey?.(keyId, this.identityType);
  }

  getEcSignedPreKeyMaxId() {
    return this.store.getEcSignedPreKeyMaxId(this.identityType);
  }

  // EC one-time prekeys
  storeEcOneTimePreKeys(prekeys: EcOneTimePreKey[]) {
    return this.store.storeEcOneTimePreKeys(prekeys, this.identityType);
  }

  getEcOneTimePreKeys() {
    return this.store.getEcOneTimePreKeys(this.identityType);
  }

  removeEcOneTimePreKey(keyId: number) {
    return this.store.removeEcOneTimePreKey(keyId, this.identityType);
  }

  // Kyber last-resort prekey
  storeKyberPreKey(prekey: KyberPreKey) {
    return this.store.storeKyberPreKey(prekey, this.identityType);
  }

  getKyberPreKey() {
    return this.store.getKyberPreKey(this.identityType);
  }

  markKyberPreKeyUsed(kyberPreKeyId: number, signedPreKeyId: number, baseKeyBytes: Uint8Array) {
    return this.store.markKyberPreKeyUsed(
      kyberPreKeyId,
      signedPreKeyId,
      baseKeyBytes,
      this.identityType
    );
  }

  getKyberPreKeyMaxId() {
    return this.store.getKyberPreKeyMaxId(this.identityType);
  }

  // KEM one-time prekeys
  storeKemOneTimePreKeys(prekeys: KemOneTimePreKey[]) {
    return this.store.storeKemOneTimePreKeys(prekeys, this.identityType);
  }

  getKemOneTimePreKeys() {
    return this.store.getKemOneTimePreKeys(this.identityType);
  }

  getKemOneTimePreKey(keyId: number) {
    return this.store.getKemOneTimePreKey(keyId, this.identityType);
  }

  removeKemOneTimePreKey(keyId: number) {
    return this.store.removeKemOneTimePreKey(keyId, this.identityType);
  }

  getKemOneTimePreKeyCount() {
    return this.store.getKemOneTimePreKeyCount(this.identityType);
  }

  // Bulk operations
  deleteAllPreKeys() {
    return this.store.deleteAllPreKeys(this.identityType);
  }
}

/**
 * Dual protocol store — routes operations to ACI or PNI identity stores.
 *
 * Usage:
 * ```typescript
 * const dual = new DualProtocolStore(localStore);
 * await dual.aci().getIdentityKey();  // ACI identity key
 * await dual.pni().getIdentityKey();  // PNI identity key
 * ```
 */
export class DualProtocolStore {
  private readonly aciStore: IdentityTypedStore;
  private readonly pniStore: IdentityTypedStore;

  constructor(private readonly localStore: ISignalProtocolLocalStore) {
    this.aciStore = new IdentityTypedStore(localStore, 'aci');
    this.pniStore = new IdentityTypedStore(localStore, 'pni');
  }

  /** ACI (Account Identity) protocol store */
  aci(): IdentityTypedStore {
    return this.aciStore;
  }

  /** PNI (Phone/discoverable Number Identity) protocol store */
  pni(): IdentityTypedStore {
    return this.pniStore;
  }

  /** Access the underlying unscoped store (for identity-agnostic operations) */
  get unscoped(): ISignalProtocolLocalStore {
    return this.localStore;
  }
}
