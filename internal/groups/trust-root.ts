/**
 * Serialized trust root for one group-server deployment.
 *
 * The application pins the blob at build time. It never comes
 * from a relay at runtime.
 */

import {
  deserializeCredentialPublicKey,
  serializeCredentialPublicKey,
  type CredentialPublicKey,
} from '../protocol/zk/credentials/credentials';
import { ServerRootPublicKey } from '../protocol/zk/credentials/endorsements';
import { RistrettoPoint } from '../protocol/zk/proofs/sho';

export {};

/** Current serialized group trust-root format. */
export const GROUP_TRUST_ROOT_VERSION = 1;

const CREDENTIAL_PUBLIC_KEY_LENGTH = 7 * 32;
const SERVER_SIGNING_PUBLIC_KEY_LENGTH = 32;
const ENDORSEMENT_ROOT_PUBLIC_KEY_LENGTH = 32;

const GROUP_TRUST_ROOT_BASE_LENGTH =
  2 +
  CREDENTIAL_PUBLIC_KEY_LENGTH +
  CREDENTIAL_PUBLIC_KEY_LENGTH +
  ENDORSEMENT_ROOT_PUBLIC_KEY_LENGTH;

/** The four public keys pinned for one conforming group-server deployment. */
export interface GroupTrustRoot {
  credentialPublicKey: CredentialPublicKey;
  serverSigningPublicKey?: Uint8Array;
  profileKeyCredentialPublicKey: CredentialPublicKey;
  endorsementRootPublicKey: ServerRootPublicKey;
}

/**
 * Encode a group trust root into its versioned binary representation.
 *
 * Version 1 uses a fixed width:
 * `version || signing-key length || credential key || signing key ||
 * profile-key credential key || endorsement root`.
 *
 * The signing-key length is either 32 for a conforming S9/S14 deployment or
 * zero for §12.3's explicitly selected non-conforming mode.
 */
export function encodeGroupTrustRoot(trustRoot: GroupTrustRoot): Uint8Array {
  const credentialPublicKey = serializeCredentialPublicKey(
    trustRoot.credentialPublicKey
  );
  const profileKeyCredentialPublicKey = serializeCredentialPublicKey(
    trustRoot.profileKeyCredentialPublicKey
  );
  const endorsementRootPublicKey =
    trustRoot.endorsementRootPublicKey.PK.toBytes();

  const signingPublicKey =
    trustRoot.serverSigningPublicKey ?? new Uint8Array(0);
  if (
    signingPublicKey.length !== 0 &&
    signingPublicKey.length !== SERVER_SIGNING_PUBLIC_KEY_LENGTH
  ) {
    throw new Error(
      `Group trust-root signing key must be absent or ${SERVER_SIGNING_PUBLIC_KEY_LENGTH} bytes, got ${signingPublicKey.length}`
    );
  }
  if (
    endorsementRootPublicKey.length !== ENDORSEMENT_ROOT_PUBLIC_KEY_LENGTH
  ) {
    throw new Error(
      `Group trust-root endorsement key must be ${ENDORSEMENT_ROOT_PUBLIC_KEY_LENGTH} bytes, got ${endorsementRootPublicKey.length}`
    );
  }

  const encoded = new Uint8Array(
    GROUP_TRUST_ROOT_BASE_LENGTH + signingPublicKey.length
  );
  let offset = 0;
  encoded[offset++] = GROUP_TRUST_ROOT_VERSION;
  encoded[offset++] = signingPublicKey.length;
  encoded.set(credentialPublicKey, offset);
  offset += CREDENTIAL_PUBLIC_KEY_LENGTH;
  encoded.set(signingPublicKey, offset);
  offset += signingPublicKey.length;
  encoded.set(profileKeyCredentialPublicKey, offset);
  offset += CREDENTIAL_PUBLIC_KEY_LENGTH;
  encoded.set(endorsementRootPublicKey, offset);
  return encoded;
}

/** Decode and validate a versioned group trust-root blob. */
export function decodeGroupTrustRoot(encoded: Uint8Array): GroupTrustRoot {
  if (!(encoded instanceof Uint8Array)) {
    throw new TypeError('Group trust root must be a Uint8Array');
  }
  if (encoded.length < 2) {
    throw new Error('Group trust root is truncated');
  }
  if (encoded[0] !== GROUP_TRUST_ROOT_VERSION) {
    throw new Error(
      `Unsupported group trust-root version ${encoded[0]}; expected ${GROUP_TRUST_ROOT_VERSION}`
    );
  }
  const signingPublicKeyLength = encoded[1]!;
  if (
    signingPublicKeyLength !== 0 &&
    signingPublicKeyLength !== SERVER_SIGNING_PUBLIC_KEY_LENGTH
  ) {
    throw new Error(
      `Group trust-root signing-key length must be 0 or ${SERVER_SIGNING_PUBLIC_KEY_LENGTH}, got ${signingPublicKeyLength}`
    );
  }
  const expectedLength =
    GROUP_TRUST_ROOT_BASE_LENGTH + signingPublicKeyLength;
  if (encoded.length !== expectedLength) {
    throw new Error(
      `Group trust-root version ${GROUP_TRUST_ROOT_VERSION} must be ${expectedLength} bytes, got ${encoded.length}`
    );
  }

  let offset = 2;
  const credentialPublicKey = deserializeCredentialPublicKey(
    encoded.subarray(offset, offset + CREDENTIAL_PUBLIC_KEY_LENGTH)
  );
  offset += CREDENTIAL_PUBLIC_KEY_LENGTH;
  const serverSigningPublicKey = encoded.slice(
    offset,
    offset + signingPublicKeyLength
  );
  offset += signingPublicKeyLength;
  const profileKeyCredentialPublicKey = deserializeCredentialPublicKey(
    encoded.subarray(offset, offset + CREDENTIAL_PUBLIC_KEY_LENGTH)
  );
  offset += CREDENTIAL_PUBLIC_KEY_LENGTH;
  const endorsementRootPublicKey = ServerRootPublicKey.fromRaw(
    RistrettoPoint.fromBytes(
      encoded.subarray(offset, offset + ENDORSEMENT_ROOT_PUBLIC_KEY_LENGTH)
    )
  );

  return {
    credentialPublicKey,
    serverSigningPublicKey:
      serverSigningPublicKey.length === 0
        ? undefined
        : serverSigningPublicKey,
    profileKeyCredentialPublicKey,
    endorsementRootPublicKey,
  };
}
