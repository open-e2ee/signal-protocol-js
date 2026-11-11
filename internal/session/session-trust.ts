/**
 * The trust decision for the remote identity of a session, and the commit
 * that stores a session with its trust pin.
 *
 * Every session path asks this decision before it starts, advances, or
 * stores a session: session start from a prekey bundle, encrypt, the
 * PreKeyMessage responder, and decrypt. Each of these paths then stores the
 * session through `commit`.
 *
 * An own device is a device of the local user. Each linked device holds the
 * account identity unchanged (docs/DEVICE_LIFECYCLE.md). So the decision
 * trusts an own device only with the local identity of the same identity
 * type, in both directions. It reads that identity from the store, and it
 * does not read the contact trust state of the store or call
 * `isTrustedIdentity`. A Relay that serves another identity for an own
 * device thus gets no session, no sync copy, and no trust pin for it. The
 * store keeps trust on first use for contacts.
 *
 * The store pins one identity per user and compares each session commit
 * with that pin. An install can hold an own pin that is not the local
 * identity: an earlier release pinned the identity that a Relay served for
 * an own device, or the local identity changed after the pin. That pin
 * would refuse every commit with a real own device. So before it commits a
 * session with an own device, `commit` replaces such a pin with the local
 * identity. The store replaces it in one write, and the same write deletes
 * the sessions with the own devices, which used the replaced identity.
 *
 * The reference clients make an own-address check in their identity stores
 * too. The protocol library leaves the trust decision to the identity store
 * of the app.
 * - One reference client compares the identity with the own ACI identity
 *   public key when the address names the own ACI, the own PNI, or the own
 *   phone number. It does this before it reads a stored record.
 * - Another compares the identity in constant time with the stored identity
 *   record of its own service ID, and trusts the identity when that record
 *   is missing. Its store does not save a changed identity for its own
 *   service ID, so that record keeps the own identity.
 */

import type { CompositeIdentityV1, IdentityType } from '../../keys';
import { compositeIdentitiesEqual, createCompositeIdentityV1 } from '../../keys/identity';
import type { SessionTrustCommit, SignalProtocolLocalStore, TrustDirection } from '../../types';
import type { ProtocolAddress } from '../../types/address';
import { withUserRecordLock } from './record-locks';

export class SessionTrust {
  /**
   * @param keyStorage - The store that holds the local identity and the
   *   contact trust state.
   * @param localUserId - Reads the local user ID. Null before the local
   *   identity is set; then no address is an own device.
   */
  constructor(
    private readonly keyStorage: SignalProtocolLocalStore,
    private readonly localUserId: () => string | null
  ) {}

  /**
   * True when a session with `address` may use `identity`.
   *
   * An own device is trusted only with the local identity of
   * `identityType`, compared in constant time. With no local identity of
   * that type, an own device is not trusted. Other addresses use the trust
   * state of the store.
   */
  async isTrusted(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    direction: TrustDirection,
    identityType: IdentityType = 'aci'
  ): Promise<boolean> {
    if (!this.isOwnAddress(address)) {
      return this.keyStorage.isTrustedIdentity(address, identity, direction, identityType);
    }
    return (await this.localIdentityMatching(identity, identityType)) !== null;
  }

  /**
   * Store a session and its trust pin in one commit of the store.
   *
   * For an own device with the local identity, an own pin with another
   * identity is replaced with the local identity first. The replacement
   * deletes the sessions with the own devices. The caller holds the session
   * lock of `commit.address`, and the commit then stores its session again.
   * The caller asked `isTrusted` before, so the commit of an own device with
   * another identity changes no pin, and the store refuses it.
   */
  async commit(commit: SessionTrustCommit): Promise<void> {
    if (this.isOwnAddress(commit.address)) {
      await this.replaceStaleOwnPin(
        commit.address,
        commit.contactIdentity,
        commit.contactIdentityType
      );
    }
    await this.keyStorage.commitSessionTrust(commit);
  }

  private isOwnAddress(address: ProtocolAddress): boolean {
    const localUserId = this.localUserId();
    return localUserId !== null && address.userId === localUserId;
  }

  /** The local identity of `identityType` when it equals `identity`, else null. */
  private async localIdentityMatching(
    identity: CompositeIdentityV1,
    identityType: IdentityType
  ): Promise<CompositeIdentityV1 | null> {
    const local = await this.keyStorage.getIdentityKey(identityType);
    if (local === null) return null;
    const localIdentity = createCompositeIdentityV1(local);
    return compositeIdentitiesEqual(localIdentity, identity) ? localIdentity : null;
  }

  /**
   * Replace the own pin of `identityType` with the local identity when the
   * pin holds another identity and `identity` is the local identity.
   *
   * The user lock orders the replacements of one store, so a second commit
   * reads the replaced pin and does not delete the sessions again. The
   * session lock comes first, as the lock order requires.
   */
  private async replaceStaleOwnPin(
    address: ProtocolAddress,
    identity: CompositeIdentityV1,
    identityType: IdentityType
  ): Promise<void> {
    const pinIsStale = async (): Promise<CompositeIdentityV1 | null> => {
      const localIdentity = await this.localIdentityMatching(identity, identityType);
      if (localIdentity === null) return null;
      const pin = await this.keyStorage.getContactIdentity(address, identityType);
      if (pin === null || compositeIdentitiesEqual(pin.identity, localIdentity)) return null;
      return localIdentity;
    };
    if ((await pinIsStale()) === null) return;
    await withUserRecordLock(this.keyStorage, address.userId, async () => {
      const localIdentity = await pinIsStale();
      if (localIdentity === null) return;
      await this.keyStorage.acceptContactIdentityRotationAndDeleteSessions(
        address,
        localIdentity,
        identityType
      );
    });
  }
}
