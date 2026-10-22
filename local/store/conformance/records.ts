/**
 * The records that the local store conformance cases write. Each one is a
 * valid value that every store accepts, and none comes from a live protocol
 * run.
 */

import { bytesToBase64 } from '../../../internal/crypto/utils';
import type { SenderKeyState } from '../../../internal/protocol/sender-keys/manager';
import type { CompositeIdentityV1, PrivateKey, PublicKey } from '../../../keys';
import { ProtocolAddress } from '../../../types/address';
import type { ReceiveWorkRecord } from '../../../types/api';
import { CURRENT_SESSION_RECORD_VERSION, type SessionRecord } from '../../../types/session';
import type { Base64 } from '../../../types/utils';
import { sizedReceiveWork } from '../receive-work';

/**
 * A text that no store writes on its own. The ciphertext scan writes it in
 * values that a cipher must protect, then looks for it in the stored bytes.
 */
export const PLAINTEXT_MARKER = 'local-store-conformance-plaintext-marker';

/** A 32-byte key in base64. Each seed gives a different key. */
export function testKey(seed: number): string {
  return bytesToBase64(Uint8Array.from({ length: 32 }, (_, index) => (seed + index * 13) & 0xff));
}

/** A contact identity. Each seed gives a different identity. */
export function contactIdentity(seed: number): CompositeIdentityV1 {
  return {
    version: 1,
    x25519PublicKey: testKey(seed) as PublicKey,
    ed25519PublicKey: testKey(seed + 1) as PublicKey,
  };
}

/**
 * A current session record for `address`. The received message count
 * tells two records apart.
 */
export function sessionRecord(address: ProtocolAddress, receivedMessages: number): SessionRecord {
  return {
    currentSession: {
      baseKey: testKey(20) as Base64,
      localAddress: ProtocolAddress.create('conformance-local-user', 1),
      remoteAddress: address,
      localDeviceId: 1,
      remoteDeviceId: address.deviceId,
      localRegistrationId: 1,
      remoteRegistrationId: 1,
      RK: testKey(21) as Base64,
      DHs: { publicKey: testKey(22) as PublicKey, privateKey: testKey(23) as PrivateKey },
      DHr: testKey(24) as PublicKey,
      CKs: testKey(25) as Base64,
      CKr: testKey(26) as Base64,
      Ns: 0,
      Nr: receivedMessages,
      PN: 0,
      receiverChains: [],
      identityKeyPair: {
        dhKey: { publicKey: testKey(27) as PublicKey, privateKey: testKey(28) as PrivateKey },
        signingKey: { publicKey: testKey(29) as PublicKey, privateKey: testKey(30) as PrivateKey },
        registrationId: 1,
      },
      localIdentity: {
        version: 1,
        x25519PublicKey: testKey(27) as PublicKey,
        ed25519PublicKey: testKey(29) as PublicKey,
      },
      remoteIdentity: {
        version: 1,
        x25519PublicKey: testKey(31) as PublicKey,
        ed25519PublicKey: testKey(32) as PublicKey,
      },
      localIdentityType: 'aci',
      remoteIdentityType: 'aci',
      createdAt: 1_000,
      lastUsedAt: 1_000,
    },
    archivedSessions: {},
    version: CURRENT_SESSION_RECORD_VERSION,
  };
}

/** The sender key ID of every sender key state of the kit. */
export const SENDER_KEY_ID = '00000000-0000-4000-8000-0000000000c1';

/** A sender key state at `chainIndex`. */
export function senderKeyState(chainIndex: number, chainKey = 'chain-key-' + chainIndex): SenderKeyState {
  return {
    senderKeyId: SENDER_KEY_ID,
    senderKeyVersion: 'v2',
    chainId: 1,
    generation: 0,
    chainKey: chainKey,
    signatureKey: 'signature-key',
    publicSignatureKey: 'public-signature-key',
    chainIndex: chainIndex,
    createdAt: 1_000,
  };
}

/** A skipped message key. Each index gives a different key. */
export function skippedMessageKey(index: number): { cipherKey: string; iv: string } {
  return { cipherKey: testKey(40 + index), iv: testKey(80 + index) };
}

/** A valid receive record with its size set. Each override replaces one field. */
export function receiveWork(
  workId: string,
  overrides: Partial<ReceiveWorkRecord> = {}
): ReceiveWorkRecord {
  return sizedReceiveWork({
    workId: workId,
    revision: 0,
    stage: 'decrypted',
    origin: 'relay',
    arrivalSeq: 1,
    receivedAt: 1_000,
    dueAt: 1_000,
    sizeBytes: 0,
    plaintext: 'content of ' + workId,
    ...overrides,
  });
}
