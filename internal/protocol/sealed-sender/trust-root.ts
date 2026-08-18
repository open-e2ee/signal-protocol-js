/**
 * Sealed-sender certificate trust root for one relay deployment.
 *
 * The relay signs sender certificates with an Ed25519 key pair. That key pair
 * derives from the same 32-byte deployment secret that seeds the group server
 * parameters. Distinct KDF labels domain-separate the derived keys from the
 * group signing key, and from each other. Clients verify inbound
 * sealed-sender certificates
 * against the **root** public key, which they pin at build time. It is never
 * discovered from a relay at runtime.
 *
 * This module is the single definition of that derivation. The relay backend
 * derives signing keys from it, and the `oe-groups trust-root` command derives
 * the pinned public key from it. An operator's printed root and the key the
 * deployment actually signs with therefore cannot drift apart.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '../../crypto/hash/sha256';

/** KDF label for the offline root key that signs the server certificate. */
export const SEALED_SENDER_ROOT_LABEL = 'open-e2ee:sealed-sender:root:v1';

/** KDF label for the online server key that signs sender certificates. */
export const SEALED_SENDER_SERVER_LABEL = 'open-e2ee:sealed-sender:server:v1';

const textEncoder = new TextEncoder();

/**
 * Encode a scalar as 32 big-endian bytes.
 *
 * The width is fixed rather than minimal. A length-varying encoding would
 * make the KDF input ambiguous, and leak the scalar's magnitude through the
 * derived key's provenance.
 */
export function scalarBytes(value: bigint): Uint8Array {
  const result = new Uint8Array(32);
  let remaining = value;
  for (let index = result.length - 1; index >= 0; index--) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return result;
}

/**
 * Derive one labelled Ed25519 private key from the deployment's group signing
 * scalar: `SHA-256(label ‖ scalar)`.
 *
 * @param signingKey - `ServerSecretParams.signingKeyPair.signingKey`.
 * @param label - One of the two exported label constants.
 * @returns The raw 32-byte Ed25519 seed.
 */
export async function deriveSealedSenderPrivateKey(
  signingKey: bigint,
  label: string
): Promise<Uint8Array> {
  const scalar = scalarBytes(signingKey);
  const labelBytes = textEncoder.encode(label);
  const material = new Uint8Array(labelBytes.length + scalar.length);
  material.set(labelBytes);
  material.set(scalar, labelBytes.length);
  try {
    return await sha256(material);
  } finally {
    scalar.fill(0);
    material.fill(0);
  }
}

/**
 * Derive the Ed25519 **root** public key clients pin in
 * `sealedSender.trustRoots`.
 *
 * @param signingKey - `ServerSecretParams.signingKeyPair.signingKey`.
 * @returns The raw 32-byte Ed25519 public key.
 */
export async function deriveSealedSenderRootPublicKey(
  signingKey: bigint
): Promise<Uint8Array> {
  const rootPrivateKey = await deriveSealedSenderPrivateKey(
    signingKey,
    SEALED_SENDER_ROOT_LABEL
  );
  try {
    return ed25519.getPublicKey(rootPrivateKey);
  } finally {
    rootPrivateKey.fill(0);
  }
}
