/**
 * Server parameters -- ServerSecretParams and ServerPublicParams
 *
 *
 * The server holds a `ServerSecretParams` containing all credential-issuing
 * key material. Clients receive the corresponding `ServerPublicParams` for
 * verifying server responses.
 *
 * Key material:
 *  - credentialKeyPair: for issuing generic (auth) credentials
 *  - endorsementKeyPair: for issuing group-send endorsements
 *  - signingKeyPair: Ed25519-like Schnorr key for signing server responses
 *
 * All keys are derived deterministically from 32 bytes of randomness via
 * domain-separated SHO instances.
 *
 * @see https://eprint.iacr.org/2019/1416.pdf -- Signal Private Group System
 */

import { ShoHmacSha256, RistrettoPoint } from '../proofs/sho';
import { schnorrSign, schnorrVerifySignature } from '../proofs/sign';
import {
  type CredentialKeyPair,
  type CredentialPublicKey,
  generateKeyPair as generateCredentialKeyPair,
} from '../credentials/credentials';
import { ServerRootKeyPair, ServerRootPublicKey } from '../credentials/endorsements';
export {};
const Point = RistrettoPoint;
const enc = new TextEncoder();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Minimum randomness length in bytes. */
export const RANDOMNESS_LEN = 32;

/** Signature length in bytes (Schnorr proof: 32 challenge + 32 response). */
export const SIGNATURE_LEN = 64;

// SHO labels -- must match profile for interoperability
const LABEL_CREDENTIAL_KEY = enc.encode(
  'Signal_ZKGroup_20221011_ServerSecretParams_Generate_GenericCredentialKeyPair'
);
const LABEL_PROFILE_KEY_CREDENTIAL_KEY = enc.encode(
  'Signal_ZKGroup_20221011_ServerSecretParams_Generate_ProfileKeyCredentialKeyPair'
);
const LABEL_ENDORSEMENT_KEY = enc.encode(
  'Signal_ZKGroup_20240215_ServerSecretParams_Generate_EndorsementRootKeyPair'
);
const LABEL_SIGNING_KEY = enc.encode(
  'Signal_ZKGroup_20221011_ServerSecretParams_Generate_SigningKey'
);
const LABEL_SIGN = enc.encode('Signal_ZKGroup_20200424_Random_ServerSecretParams_Sign');

// ---------------------------------------------------------------------------
// SigningKeyPair (internal)
// ---------------------------------------------------------------------------

/**
 * A Schnorr signing key pair: private scalar + public point.
 *
 * Equivalent to `crypto::signature::KeyPair` in the profile.
 */
interface SigningKeyPair {
  /** Private signing scalar. */
  readonly signingKey: bigint;
  /** Public verification point (signingKey * G). */
  readonly publicKey: RistrettoPoint;
}

// ---------------------------------------------------------------------------
// ServerSecretParams
// ---------------------------------------------------------------------------

/**
 * All credential-issuing key material held by the server.
 *
 * Carries only the server-side key pairs used by this package:
 *  - Generic credential issuance (auth credentials)
 *  - Group-send endorsement issuance
 *  - Response signing / verification
 */
export interface ServerSecretParams {
  /** Key pair for issuing generic (auth) credentials. */
  readonly credentialKeyPair: CredentialKeyPair;
  /** Key pair for issuing profile key credentials. */
  readonly profileKeyCredentialKeyPair: CredentialKeyPair;
  /** Root key pair for issuing group-send endorsements. */
  readonly endorsementKeyPair: ServerRootKeyPair;
  /** Schnorr signing key pair for server response signatures. */
  readonly signingKeyPair: SigningKeyPair;
}

/**
 * Derive all server key material deterministically from randomness.
 *
 * Each key pair is derived from its own domain-separated SHO instance,
 * absorbing the provided randomness. This ensures independence between
 * the credential, endorsement, and signing keys.
 *
 * @param randomness - At least 32 bytes of cryptographically secure randomness
 * @returns A fully populated ServerSecretParams
 * @throws If randomness is too short
 */
export function generateServerSecretParams(randomness: Uint8Array): ServerSecretParams {
  if (randomness.length < RANDOMNESS_LEN) {
    throw new Error(
      `generateServerSecretParams: need at least ${RANDOMNESS_LEN} bytes of randomness, got ${randomness.length}`
    );
  }

  // --- Credential key pair (auth) ---
  // Derive randomness for the credential key pair through a domain-separated SHO
  const credSho = new ShoHmacSha256(LABEL_CREDENTIAL_KEY);
  credSho.absorbAndRatchet(randomness);
  const credentialRandomness = credSho.squeezeAndRatchet(RANDOMNESS_LEN);
  const credentialKeyPair = generateCredentialKeyPair(credentialRandomness);

  // --- Profile key credential key pair ---
  // Separate key pair for profile key credentials (distinct from auth credentials)
  const pkCredSho = new ShoHmacSha256(LABEL_PROFILE_KEY_CREDENTIAL_KEY);
  pkCredSho.absorbAndRatchet(randomness);
  const pkCredentialRandomness = pkCredSho.squeezeAndRatchet(RANDOMNESS_LEN);
  const profileKeyCredentialKeyPair = generateCredentialKeyPair(pkCredentialRandomness);

  // --- Endorsement key pair ---
  // Derive randomness for the endorsement key pair through a domain-separated SHO
  const endSho = new ShoHmacSha256(LABEL_ENDORSEMENT_KEY);
  endSho.absorbAndRatchet(randomness);
  const endorsementRandomness = endSho.squeezeAndRatchet(RANDOMNESS_LEN);
  const endorsementKeyPair = ServerRootKeyPair.generate(endorsementRandomness);

  // --- Signing key pair ---
  // Derive the signing scalar directly from the SHO
  const sigSho = new ShoHmacSha256(LABEL_SIGNING_KEY);
  sigSho.absorbAndRatchet(randomness);
  const signingKey = sigSho.getScalar();
  const signingPublicKey = Point.BASE.multiply(signingKey);
  const signingKeyPair: SigningKeyPair = {
    signingKey,
    publicKey: signingPublicKey,
  };

  return {
    credentialKeyPair,
    profileKeyCredentialKeyPair,
    endorsementKeyPair,
    signingKeyPair,
  };
}

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
 * Extract the public parameters from server secret parameters.
 *
 * @param secretParams - The server's secret parameters
 * @returns The corresponding public parameters safe for distribution
 */
export function getServerPublicParams(secretParams: ServerSecretParams): ServerPublicParams {
  return {
    credentialPublicKey: secretParams.credentialKeyPair.publicKey,
    profileKeyCredentialPublicKey: secretParams.profileKeyCredentialKeyPair.publicKey,
    endorsementPublicKey: secretParams.endorsementKeyPair.publicKey(),
    signingPublicKey: secretParams.signingKeyPair.publicKey.toBytes(),
  };
}

// ---------------------------------------------------------------------------
// Signing / Verification
// ---------------------------------------------------------------------------

/**
 * Sign a message using the server's signing key.
 *
 * Uses a Schnorr signature (ZK proof of knowledge of discrete log) via
 * the poksho proof system. The randomness is first passed through a
 * domain-separated SHO to derive the proof nonce.
 *
 * @param secretParams - The server's secret parameters
 * @param randomness - At least 32 bytes of cryptographically secure randomness
 * @param message - The message bytes to sign
 * @returns Signature bytes (64 bytes: 32 challenge + 32 response)
 * @throws If randomness is too short
 */
export function serverSign(
  secretParams: ServerSecretParams,
  randomness: Uint8Array,
  message: Uint8Array
): Uint8Array {
  if (randomness.length < RANDOMNESS_LEN) {
    throw new Error(
      `serverSign: need at least ${RANDOMNESS_LEN} bytes of randomness, got ${randomness.length}`
    );
  }

  // Derive proof randomness through the signing domain before signing.
  const sho = new ShoHmacSha256(LABEL_SIGN);
  sho.absorbAndRatchet(randomness);
  const proofRandomness = sho.squeezeAndRatchet(RANDOMNESS_LEN);

  return schnorrSign(
    secretParams.signingKeyPair.signingKey,
    secretParams.signingKeyPair.publicKey,
    message,
    proofRandomness
  );
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
