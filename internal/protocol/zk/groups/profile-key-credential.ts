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
  BlindingKeyPair,
  type BlindedAttribute,
  type BlindedIssuanceProof,
  type BlindingPublicKey,
  VerificationFailure,
} from '../credentials/issuance';
import { PresentationProofBuilder, type PresentationProof } from '../credentials/presentation';

import type { Credential, CredentialPublicKey } from '../credentials/credentials';

import type { PublicAttribute } from '../credentials/attributes';
import { type UidStruct, type ServiceId, uidStructFromServiceId } from './uid-struct';
import { type ProfileKeyStruct, profileKeyStructNew } from './profile-key-struct';
import { type UidEncCiphertext } from './uid-encryption';

import { type ProfileKeyEncCiphertext } from './profile-key-encryption';

import type { GroupSecretParams } from './group-params';

import { SECONDS_PER_DAY } from './group-params';
import { bytesToScalarCanonical } from '../proofs/sho';


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
// Blinded issuance request
// ---------------------------------------------------------------------------

/** Public request sent to the authenticated credential issuer. */
export interface ProfileKeyCredentialRequest {
  /** Ephemeral public key used only for this blind issuance. */
  readonly blindingPublicKey: BlindingPublicKey;
  /** Profile-key attribute encrypted under the ephemeral blinding key. */
  readonly blindedProfileKey: BlindedAttribute;
}

/** Client-only state required to unblind and verify the issuer response. */
export interface ProfileKeyCredentialRequestContext {
  readonly request: ProfileKeyCredentialRequest;
  readonly blindingKey: BlindingKeyPair;
  readonly aci: UidStruct;
  readonly profileKey: ProfileKeyStruct;
}

/**
 * Blind a profile-key attribute before it crosses the Relay boundary.
 *
 * The profile-key structure is ACI-bound before blinding. The returned context
 * stays on the client and must be used only with the matching response.
 */
export function createProfileKeyCredentialRequest(
  aci: ServiceId,
  profileKeyBytes: Uint8Array,
  randomness: Uint8Array
): ProfileKeyCredentialRequestContext {
  if (randomness.length < 32) {
    throw new Error('Profile-key credential request randomness must be at least 32 bytes');
  }

  const profileKey = profileKeyStructNew(profileKeyBytes, aci.uuid);
  const sho = new ShoHmacSha256(
    enc.encode('Signal_ZKGroup_20220508_ExpiringProfileKeyCredential_Blinding')
  );
  sho.absorbAndRatchet(randomness);
  const blindingKey = BlindingKeyPair.generate(sho);
  const encrypted = blindingKey.encrypt(profileKey, sho);
  const request: ProfileKeyCredentialRequest = {
    blindingPublicKey: blindingKey.publicKey,
    blindedProfileKey: {
      blindedPoints: [
        {
          D1: encrypted.blindedPoints[0].D1,
          D2: encrypted.blindedPoints[0].D2,
        },
        {
          D1: encrypted.blindedPoints[1].D1,
          D2: encrypted.blindedPoints[1].D2,
        },
      ],
    },
  };

  return {
    request,
    blindingKey,
    aci: uidStructFromServiceId(aci),
    profileKey,
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
  readonly issuanceProof: BlindedIssuanceProof;
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
 * @param requestContext - Client-only ACI, profile key, request, and blinding state
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
  requestContext: ProfileKeyCredentialRequestContext,
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

  const builder = new IssuanceProofBuilder(CREDENTIAL_LABEL);
  builder.addAttribute(requestContext.aci);
  builder.addPublicAttribute(redemptionTimePublicAttribute(redemptionTime));
  const credential = builder
    .addBlindedAttribute(requestContext.request.blindedProfileKey)
    .verify(publicKey, requestContext.blindingKey, response.issuanceProof);

  return {
    credential,
    aci: requestContext.aci,
    profileKey: requestContext.profileKey,
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
// Serialization helpers
// ---------------------------------------------------------------------------

const Point = RistrettoPoint;

const PROFILE_KEY_CREDENTIAL_REQUEST_LENGTH = 5 * 32;
const BLINDED_PROFILE_KEY_CREDENTIAL_RESPONSE_LENGTH = 8 + 4 * 32 + 352;

/** Serialize the fixed-width blinded request. */
export function serializeProfileKeyCredentialRequest(
  request: ProfileKeyCredentialRequest
): Uint8Array {
  const points = [
    request.blindingPublicKey.Y,
    request.blindedProfileKey.blindedPoints[0].D1,
    request.blindedProfileKey.blindedPoints[0].D2,
    request.blindedProfileKey.blindedPoints[1].D1,
    request.blindedProfileKey.blindedPoints[1].D2,
  ];
  const bytes = new Uint8Array(PROFILE_KEY_CREDENTIAL_REQUEST_LENGTH);
  points.forEach((point, index) => bytes.set(point.toBytes(), index * 32));
  return bytes;
}

/**
 * Deserialize an ExpiringProfileKeyCredentialResponse from bytes.
 */
export function deserializeProfileKeyCredentialResponse(
  bytes: Uint8Array
): ExpiringProfileKeyCredentialResponse {
  // 8 + 32*4 credential points + 352-byte blinded issuance proof.
  if (bytes.length !== BLINDED_PROFILE_KEY_CREDENTIAL_RESPONSE_LENGTH) {
    throw new Error('deserializeProfileKeyCredentialResponse: invalid length');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const redemptionTime = Number(view.getBigUint64(0, false));

  const t = bytesToScalarCanonical(bytes.subarray(8, 40));
  if (t === null) throw new Error('deserializeProfileKeyCredentialResponse: invalid scalar t');
  const U = Point.fromBytes(bytes.subarray(40, 72));
  const S1 = Point.fromBytes(bytes.subarray(72, 104));
  const S2 = Point.fromBytes(bytes.subarray(104, 136));
  const pokshoProof = bytes.slice(136);

  return {
    issuanceProof: {
      credential: { t, U, S1, S2 },
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
