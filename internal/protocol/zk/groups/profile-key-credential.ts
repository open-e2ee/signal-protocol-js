/**
 * ExpiringProfileKeyCredential -- ZK proof that encrypted member data is valid
 *
 *
 * Implements the ExpiringProfileKeyCredential flow for group member verification:
 *  1. Server issues a credential over (ACI, ProfileKey, redemptionTime)
 *  2. Client receives and verifies the issuance proof
 *  3. Client presents the credential to a group. ACI is encrypted under the
 *     group's UID encryption key, and ProfileKey under the group's profile
 *     key encryption key. These are two different ElGamal domains.
 *  4. Server verifies the presentation proof
 *
 * The redemption time is a public attribute (visible to both issuer and
 * verifier). ACI and ProfileKey are hidden attributes encrypted under
 * different group encryption keys during presentation.
 *
 * Key difference from AuthCredentialWithPni:
 *  - Auth: both hidden attrs (ACI, PNI) encrypted under uidEncKeyPair
 *  - Profile: ACI under uidEncKeyPair, ProfileKey under profileKeyEncKeyPair
 *
 * @see https://eprint.iacr.org/2019/1416.pdf -- Signal Private Group System
 */

import { ShoHmacSha256, RistrettoPoint } from '../proofs/sho';
import {
  IssuanceProofBuilder,
  type IssuanceProof,
  VerificationFailure,
} from '../credentials/issuance';
import {
  PresentationProofBuilder,
  PresentationProofVerifier,
  type PresentationProof,
} from '../credentials/presentation';
import type {
  Credential,
  CredentialKeyPair,
  CredentialPublicKey,
} from '../credentials/credentials';
import type { PublicAttribute } from '../credentials/attributes';
import { type UidStruct, type ServiceId, uidStructFromServiceId } from './uid-struct';
import { type ProfileKeyStruct, profileKeyStructNew } from './profile-key-struct';
import { type UidEncCiphertext, UidEncryptionDomain } from './uid-encryption';
import { type ProfileKeyEncCiphertext, ProfileKeyEncryptionDomain } from './profile-key-encryption';
import type { GroupSecretParams, GroupPublicParams } from './group-params';
import { SECONDS_PER_DAY } from './group-params';
import { scalarToBytes, bytesToScalarCanonical } from '../proofs/sho';
import { Ciphertext } from '../credentials/attributes';
export {};
const enc = new TextEncoder();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Credential label matching the profile: `Signal_ZKGroup_20220508_ExpiringProfileKeyCredential`. */
const CREDENTIAL_LABEL = enc.encode('Signal_ZKGroup_20220508_ExpiringProfileKeyCredential');

// ---------------------------------------------------------------------------
// Redemption time as a PublicAttribute
// ---------------------------------------------------------------------------

/**
 * Create a PublicAttribute from a redemption timestamp.
 *
 * Encodes the timestamp as unsigned big-endian 64-bit bytes and absorbs it
 * into the SHO.
 */
function redemptionTimePublicAttribute(time: number): PublicAttribute {
  return {
    hashInto(sho: ShoHmacSha256): void {
      const buf = new Uint8Array(8);
      new DataView(buf.buffer).setBigUint64(0, BigInt(time), false);
      sho.absorbAndRatchet(buf);
    },
  };
}

// ---------------------------------------------------------------------------
// ExpiringProfileKeyCredentialResponse (server -> client)
// ---------------------------------------------------------------------------

/**
 * Server response containing an issuance proof for an ExpiringProfileKeyCredential.
 *
 * Created by the server during credential issuance and sent to the client.
 * The client verifies the proof and extracts the credential.
 */
export interface ExpiringProfileKeyCredentialResponse {
  /** ZK issuance proof binding the credential to (ACI, ProfileKey, redemptionTime). */
  readonly issuanceProof: IssuanceProof;
  /** Day-aligned epoch timestamp (must be a multiple of SECONDS_PER_DAY). */
  readonly redemptionTime: number;
}

// ---------------------------------------------------------------------------
// ExpiringProfileKeyCredential (client-side stored credential)
// ---------------------------------------------------------------------------

/**
 * A verified profile key credential binding an ACI and ProfileKey to a
 * redemption time.
 *
 * Stored by the client after receiving and verifying an issuance response.
 * Used to generate presentation proofs for group member verification.
 */
export interface ExpiringProfileKeyCredential {
  /** The raw ZK credential (t, U, V triple). */
  readonly credential: Credential;
  /** The user's ACI as a UidStruct (pair of Ristretto points). */
  readonly aci: UidStruct;
  /** The user's profile key as a ProfileKeyStruct (pair of Ristretto points). */
  readonly profileKey: ProfileKeyStruct;
  /** Day-aligned epoch timestamp (expiration boundary). */
  readonly redemptionTime: number;
}

// ---------------------------------------------------------------------------
// ProfileKeyCredentialPresentation (client -> server)
// ---------------------------------------------------------------------------

/**
 * A presentation proof demonstrating possession of an
 * ExpiringProfileKeyCredential. ACI is encrypted under the group's UID
 * encryption key, and ProfileKey under the group's profile key encryption key.
 *
 * Sent to the server during group creation or member addition. The server
 * verifies the ZK proof, which shows the encrypted member data is valid
 * without being able to decrypt it.
 */
export interface ProfileKeyCredentialPresentation {
  /** ZK presentation proof. */
  readonly proof: PresentationProof;
  /** ACI encrypted under the group's UID encryption key. */
  readonly uidEncCiphertext: UidEncCiphertext;
  /** ProfileKey encrypted under the group's profile key encryption key. */
  readonly profileKeyEncCiphertext: ProfileKeyEncCiphertext;
  /** Day-aligned epoch timestamp matching the credential. */
  readonly redemptionTime: number;
}

// ---------------------------------------------------------------------------
// Issuance (server side)
// ---------------------------------------------------------------------------

/**
 * Issue an ExpiringProfileKeyCredential for the given ACI, ProfileKey, and
 * redemption time.
 *
 * Called by the server. Produces an issuance proof that the client can verify
 * to extract the credential.
 *
 * The builder accumulates attributes in the same order used by the client
 * during verification: ACI (hidden), ProfileKey (hidden), redemptionTime (public).
 *
 * CRITICAL: Use different randomness for each issuance. Reusing randomness
 * effectively reveals the server's private key.
 *
 * @param credentialKeyPair - The server's profile key credential signing key pair
 * @param aci - The user's ACI ServiceId
 * @param profileKeyBytes - The user's 32-byte profile key
 * @param redemptionTime - Day-aligned epoch timestamp (seconds)
 * @param randomness - At least 32 bytes of cryptographically secure randomness
 * @returns The issuance response to send to the client
 */
export function issueProfileKeyCredential(
  credentialKeyPair: CredentialKeyPair,
  aci: ServiceId,
  profileKeyBytes: Uint8Array,
  redemptionTime: number,
  randomness: Uint8Array
): ExpiringProfileKeyCredentialResponse {
  const aciUid = uidStructFromServiceId(aci);
  const profileKey = profileKeyStructNew(profileKeyBytes, aci.uuid);

  const builder = new IssuanceProofBuilder(CREDENTIAL_LABEL);
  builder.addAttribute(aciUid);
  builder.addAttribute(profileKey);
  builder.addPublicAttribute(redemptionTimePublicAttribute(redemptionTime));

  const issuanceProof = builder.issue(credentialKeyPair, randomness);

  return { issuanceProof, redemptionTime };
}

// ---------------------------------------------------------------------------
// Receive (client side)
// ---------------------------------------------------------------------------

/**
 * Receive and verify an ExpiringProfileKeyCredential issuance response.
 *
 * Called by the client. Verifies the issuance proof against the server's
 * public key and extracts the credential for later presentation.
 *
 * The builder must accumulate attributes in the same order used during
 * issuance: ACI (hidden), ProfileKey (hidden), redemptionTime (public).
 *
 * Validates that the credential expires within 1-7 days from currentTime.
 * This prevents a compromised server from
 * issuing absurdly long-lived or already-expired credentials.
 *
 * @param publicKey - The server's profile key credential public key
 * @param response - The issuance response from the server
 * @param aci - The user's ACI ServiceId (must match what the server issued)
 * @param profileKeyBytes - The user's 32-byte profile key (must match)
 * @param redemptionTime - Day-aligned epoch timestamp (must match the response)
 * @param currentTime - Current time in epoch seconds, used for 1-7 day window validation
 * @returns The verified credential for storage and later presentation
 * @throws {VerificationFailure} If the issuance proof is invalid
 * @throws {VerificationFailure} If the redemption time is not day-aligned
 * @throws {VerificationFailure} If the credential is not within 1-7 days of currentTime
 */
export function receiveProfileKeyCredential(
  publicKey: CredentialPublicKey,
  response: ExpiringProfileKeyCredentialResponse,
  aci: ServiceId,
  profileKeyBytes: Uint8Array,
  redemptionTime: number,
  currentTime: number
): ExpiringProfileKeyCredential {
  if (redemptionTime % SECONDS_PER_DAY !== 0) {
    throw new VerificationFailure();
  }

  // Reject credentials not within 1-7 days of currentTime
  const secondsRemaining = Math.max(0, response.redemptionTime - currentTime);
  const daysRemaining = Math.floor(secondsRemaining / SECONDS_PER_DAY);
  if (daysRemaining === 0 || daysRemaining > 7) {
    throw new VerificationFailure();
  }

  const aciUid = uidStructFromServiceId(aci);
  const profileKey = profileKeyStructNew(profileKeyBytes, aci.uuid);

  const builder = new IssuanceProofBuilder(CREDENTIAL_LABEL);
  builder.addAttribute(aciUid);
  builder.addAttribute(profileKey);
  builder.addPublicAttribute(redemptionTimePublicAttribute(redemptionTime));

  const credential = builder.verify(publicKey, response.issuanceProof);

  return {
    credential,
    aci: aciUid,
    profileKey,
    redemptionTime,
  };
}

// ---------------------------------------------------------------------------
// Presentation (client side)
// ---------------------------------------------------------------------------

/**
 * Present an ExpiringProfileKeyCredential to a group for member verification.
 *
 * Called by the client. Generates a ZK presentation proof. The proof encrypts
 * the ACI under the group's UID encryption key, and ProfileKey under the
 * group's profile key encryption key. The server can then verify the encrypted
 * data is valid without decrypting it.
 *
 * KEY DIFFERENCE FROM AUTH: Uses TWO different encryption domains:
 *  - ACI is encrypted under uidEncKeyPair (UidEncryptionDomain)
 *  - ProfileKey is encrypted under profileKeyEncKeyPair (ProfileKeyEncryptionDomain)
 *
 * CRITICAL: Use different randomness for each presentation. Reusing randomness
 * allows different presentations to be linked.
 *
 * @param publicKey - The server's profile key credential public key
 * @param credential - The client's stored ExpiringProfileKeyCredential
 * @param groupSecretParams - The group's secret parameters
 * @param randomness - At least 32 bytes of cryptographically secure randomness
 * @returns The presentation to send to the server
 */
export function presentProfileKeyCredential(
  publicKey: CredentialPublicKey,
  credential: ExpiringProfileKeyCredential,
  groupSecretParams: GroupSecretParams,
  randomness: Uint8Array
): ProfileKeyCredentialPresentation {
  const { aci, profileKey, credential: cred, redemptionTime } = credential;

  const builder = new PresentationProofBuilder(CREDENTIAL_LABEL);
  // ACI attribute encrypted under UID encryption domain
  builder.addAttribute(aci, groupSecretParams.uidEncKeyPair);
  // ProfileKey attribute encrypted under PROFILE KEY encryption domain (different!)
  builder.addAttribute(profileKey, groupSecretParams.profileKeyEncKeyPair);

  const proof = builder.present(publicKey, cred, randomness);

  const uidEncCiphertext = groupSecretParams.uidEncKeyPair.encrypt(aci);
  const profileKeyEncCiphertext = groupSecretParams.profileKeyEncKeyPair.encrypt(profileKey);

  return {
    proof,
    uidEncCiphertext,
    profileKeyEncCiphertext,
    redemptionTime,
  };
}

// ---------------------------------------------------------------------------
// Verification (server side)
// ---------------------------------------------------------------------------

/**
 * Verify a ProfileKeyCredentialPresentation against the server's key pair and
 * the group's public parameters.
 *
 * Called by the server. Checks that:
 *  1. The presentation proof is valid (ZK verification)
 *  2. The credential has not expired (redemptionTime >= currentTime)
 *
 * @param credentialKeyPair - The server's profile key credential signing key pair
 * @param groupPublicParams - The group's public parameters
 * @param presentation - The client's presentation proof
 * @param currentTime - Current time in epoch seconds for expiry check
 * @returns true if the presentation is valid
 * @throws {VerificationFailure} If the presentation proof is invalid or expired
 */
export function verifyProfileKeyCredentialPresentation(
  credentialKeyPair: CredentialKeyPair,
  groupPublicParams: GroupPublicParams,
  presentation: ProfileKeyCredentialPresentation,
  currentTime: number
): boolean {
  const { proof, uidEncCiphertext, profileKeyEncCiphertext, redemptionTime } = presentation;

  // Reject when the current time reaches or exceeds credential expiration.
  if (currentTime >= redemptionTime) {
    throw new VerificationFailure();
  }

  const verifier = new PresentationProofVerifier(CREDENTIAL_LABEL);
  // ACI checked against UID encryption public key
  verifier.addAttribute(uidEncCiphertext, groupPublicParams.uidEncPublicKey);
  // ProfileKey checked against PROFILE KEY encryption public key (different!)
  verifier.addAttribute(profileKeyEncCiphertext, groupPublicParams.profileKeyEncPublicKey);
  verifier.addPublicAttribute(redemptionTimePublicAttribute(redemptionTime));

  verifier.verify(credentialKeyPair, proof);

  return true;
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

const Point = RistrettoPoint;

/**
 * Serialize an ExpiringProfileKeyCredentialResponse to bytes.
 *
 * Format:
 *   [redemptionTime: 8 bytes BE u64]
 *   [credential.t: 32 bytes scalar LE]
 *   [credential.U: 32 bytes point]
 *   [credential.V: 32 bytes point]
 *   [pokshoProof: remaining bytes]
 */
export function serializeProfileKeyCredentialResponse(
  response: ExpiringProfileKeyCredentialResponse
): Uint8Array {
  const { issuanceProof, redemptionTime } = response;
  const tBytes = scalarToBytes(issuanceProof.credential.t);
  const uBytes = issuanceProof.credential.U.toBytes();
  const vBytes = issuanceProof.credential.V.toBytes();
  const proofBytes = issuanceProof.pokshoProof;

  const buf = new Uint8Array(8 + 32 + 32 + 32 + proofBytes.length);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, BigInt(redemptionTime), false);
  buf.set(tBytes, 8);
  buf.set(uBytes, 40);
  buf.set(vBytes, 72);
  buf.set(proofBytes, 104);
  return buf;
}

/**
 * Deserialize an ExpiringProfileKeyCredentialResponse from bytes.
 */
export function deserializeProfileKeyCredentialResponse(
  bytes: Uint8Array
): ExpiringProfileKeyCredentialResponse {
  // 8 (time) + 32*3 (credential) + 320 (issuance proof: 1 challenge + 9 responses)
  if (bytes.length !== 424) {
    throw new Error('deserializeProfileKeyCredentialResponse: invalid length');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const redemptionTime = Number(view.getBigUint64(0, false));

  const t = bytesToScalarCanonical(bytes.subarray(8, 40));
  if (t === null) throw new Error('deserializeProfileKeyCredentialResponse: invalid scalar t');
  const U = Point.fromBytes(bytes.subarray(40, 72));
  const V = Point.fromBytes(bytes.subarray(72, 104));
  const pokshoProof = bytes.slice(104);

  return {
    issuanceProof: {
      credential: { t, U, V },
      pokshoProof,
    },
    redemptionTime,
  };
}

/**
 * Serialize a ProfileKeyCredentialPresentation to bytes.
 *
 * Format:
 *   [redemptionTime: 8 bytes BE u64]
 *   [C_x0: 32] [C_x1: 32] [C_V: 32]
 *   [C_y_count: 4 LE u32] [C_y[]: 32 * n]
 *   [proofLen: 4 LE u32] [pokshoProof: proofLen]
 *   [aci.E_A1: 32] [aci.E_A2: 32]
 *   [profileKey.E_A1: 32] [profileKey.E_A2: 32]
 */
export function serializeProfileKeyCredentialPresentation(
  presentation: ProfileKeyCredentialPresentation
): Uint8Array {
  const { proof, uidEncCiphertext, profileKeyEncCiphertext, redemptionTime } = presentation;
  const cyCount = proof.C_y.length;
  const proofLen = proof.pokshoProof.length;

  const totalLen = 8 + 32 * 3 + 4 + 32 * cyCount + 4 + proofLen + 32 * 4;
  const buf = new Uint8Array(totalLen);
  const view = new DataView(buf.buffer);
  let offset = 0;

  view.setBigUint64(offset, BigInt(redemptionTime), false);
  offset += 8;
  buf.set(proof.C_x0.toBytes(), offset);
  offset += 32;
  buf.set(proof.C_x1.toBytes(), offset);
  offset += 32;
  buf.set(proof.C_V.toBytes(), offset);
  offset += 32;

  view.setUint32(offset, cyCount, true);
  offset += 4;
  for (const cy of proof.C_y) {
    buf.set(cy.toBytes(), offset);
    offset += 32;
  }

  view.setUint32(offset, proofLen, true);
  offset += 4;
  buf.set(proof.pokshoProof, offset);
  offset += proofLen;

  buf.set(uidEncCiphertext.E_A1.toBytes(), offset);
  offset += 32;
  buf.set(uidEncCiphertext.E_A2.toBytes(), offset);
  offset += 32;
  buf.set(profileKeyEncCiphertext.E_A1.toBytes(), offset);
  offset += 32;
  buf.set(profileKeyEncCiphertext.E_A2.toBytes(), offset);

  return buf;
}

/**
 * Deserialize a ProfileKeyCredentialPresentation from bytes.
 */
export function deserializeProfileKeyCredentialPresentation(
  bytes: Uint8Array
): ProfileKeyCredentialPresentation {
  // Minimum: 8 (time) + 96 (C_x0,C_x1,C_V) + 4 (cyCount) + 4 (proofLen) + 128 (4 ciphertext points)
  const MIN_LEN = 240;
  if (bytes.length < MIN_LEN) {
    throw new Error('deserializeProfileKeyCredentialPresentation: too short');
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;

  const redemptionTime = Number(view.getBigUint64(offset, false));
  offset += 8;
  const C_x0 = Point.fromBytes(bytes.subarray(offset, offset + 32));
  offset += 32;
  const C_x1 = Point.fromBytes(bytes.subarray(offset, offset + 32));
  offset += 32;
  const C_V = Point.fromBytes(bytes.subarray(offset, offset + 32));
  offset += 32;

  const cyCount = view.getUint32(offset, true);
  offset += 4;
  // Bounds: cyCount * 32 + proofLen(4) + proof + ciphertexts(128) must fit in remaining bytes
  if (cyCount > 16 || offset + cyCount * 32 + 4 + 128 > bytes.length) {
    throw new Error('deserializeProfileKeyCredentialPresentation: cyCount out of bounds');
  }
  const C_y: RistrettoPoint[] = [];
  for (let i = 0; i < cyCount; i++) {
    C_y.push(Point.fromBytes(bytes.subarray(offset, offset + 32)));
    offset += 32;
  }

  const proofLen = view.getUint32(offset, true);
  offset += 4;
  if (offset + proofLen + 128 > bytes.length) {
    throw new Error('deserializeProfileKeyCredentialPresentation: proofLen out of bounds');
  }
  const pokshoProof = bytes.slice(offset, offset + proofLen);
  offset += proofLen;

  const aciE_A1 = Point.fromBytes(bytes.subarray(offset, offset + 32));
  offset += 32;
  const aciE_A2 = Point.fromBytes(bytes.subarray(offset, offset + 32));
  offset += 32;
  const pkE_A1 = Point.fromBytes(bytes.subarray(offset, offset + 32));
  offset += 32;
  const pkE_A2 = Point.fromBytes(bytes.subarray(offset, offset + 32));
  offset += 32;

  // Reject trailing bytes
  if (offset !== bytes.length) {
    throw new Error('deserializeProfileKeyCredentialPresentation: trailing bytes');
  }

  return {
    proof: { C_x0, C_x1, C_V, C_y, pokshoProof },
    uidEncCiphertext: new Ciphertext(aciE_A1, aciE_A2, UidEncryptionDomain),
    profileKeyEncCiphertext: new Ciphertext(pkE_A1, pkE_A2, ProfileKeyEncryptionDomain),
    redemptionTime,
  };
}
