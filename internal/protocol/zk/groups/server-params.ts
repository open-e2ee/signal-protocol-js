/**
 * Group authority parameters
 *
 *
 * The server holds the secret keys for credential issuance and response signatures.
 * Clients use the corresponding `ServerPublicParams` to verify server responses.
 *
 * Key material:
 *  - The credential key authenticates credentials.
 *  - The endorsement key authenticates group-send endorsements.
 *  - The Schnorr signing key authenticates server responses.
 *
 * All keys are derived deterministically from 32 bytes of randomness via
 * domain-separated SHO instances.
 *
 * @see https://eprint.iacr.org/2019/1416.pdf -- Signal Private Group System
 */

import { RistrettoPoint } from '../proofs/sho';

import { schnorrVerifySignature } from '../proofs/sign';

import { type CredentialPublicKey } from '../credentials/credentials';

import { ServerRootPublicKey } from '../credentials/endorsements';

export {};
const Point = RistrettoPoint;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Minimum randomness length in bytes. */
export const RANDOMNESS_LEN = 32;

/** Signature length in bytes (Schnorr proof: 32 challenge + 32 response). */
export const SIGNATURE_LEN = 64;

// ---------------------------------------------------------------------------
// ServerPublicParams
// ---------------------------------------------------------------------------

/**
 * Public keys for client-side verification of server responses.
 *
 * Distributed to all clients. Contains only the public halves of the
 * server's key material.
 */
export interface ServerPublicParams {
  /** Public key for verifying generic credentials. */
  readonly credentialPublicKey: CredentialPublicKey;
  /** Public key for verifying profile key credentials. */
  readonly profileKeyCredentialPublicKey: CredentialPublicKey;
  /** Public key for verifying group-send endorsements. */
  readonly endorsementPublicKey: ServerRootPublicKey;
  /** Public key for verifying server response signatures (32 bytes compressed). */
  readonly signingPublicKey: Uint8Array;
}

/**
 * Verify a server signature against the server's public parameters.
 *
 * @param publicParams - The server's public parameters
 * @param message - The message that was signed
 * @param signature - The signature bytes to verify
 * @returns `true` if the signature is valid, `false` otherwise
 */
export function serverVerifySignature(
  publicParams: Pick<ServerPublicParams, 'signingPublicKey'>,
  message: Uint8Array,
  signature: Uint8Array
): boolean {
  try {
    const publicPoint = Point.fromBytes(publicParams.signingPublicKey);
    schnorrVerifySignature(signature, publicPoint, message);
    return true;
  } catch {
    return false;
  }
}
