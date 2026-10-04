/**
 * AuthCredentialWithPni -- anonymous group authentication via ZK credentials
 *
 *
 * Implements the AuthCredentialWithPni flow for anonymous group authentication:
 *  1. Server issues a credential over (ACI, PNI, redemptionTime)
 *  2. Client receives and verifies the issuance proof
 *  3. Client presents the credential to a group, encrypting ACI and PNI
 *     under the group's UID encryption key
 *  4. Server verifies the presentation proof
 *
 * The redemption time is a public attribute (visible to both issuer and
 * verifier). ACI and PNI are hidden attributes encrypted under the group's
 * UID encryption key during presentation.
 *
 * @see https://eprint.iacr.org/2019/1416.pdf -- Signal Private Group System
 */

import { ShoHmacSha256, RistrettoPoint } from '../proofs/sho';
import {
  IssuanceProofBuilder,
  type IssuanceProof,
  VerificationFailure,
} from '../credentials/issuance';
import { PresentationProofBuilder, type PresentationProof } from '../credentials/presentation';

import type { Credential, CredentialPublicKey } from '../credentials/credentials';

import type { PublicAttribute } from '../credentials/attributes';
import {
  type UidStruct,
  type ServiceId,
  isNilUuid,
  uidStructFromServiceId,
} from './uid-struct';
import { type UidEncCiphertext } from './uid-encryption';


import type { GroupSecretParams, GroupPublicParams } from './group-params';
import { SECONDS_PER_DAY } from './group-params';
import { bytesToScalarCanonical } from '../proofs/sho';


export {};
const enc = new TextEncoder();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Credential label matching the profile: `20240222_Signal_AuthCredentialZkc`. */
const CREDENTIAL_LABEL = enc.encode('20240222_Signal_AuthCredentialZkc');

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
// AuthCredentialWithPniResponse (server -> client)
// ---------------------------------------------------------------------------

/**
 * Server response containing an issuance proof for an AuthCredentialWithPni.
 *
 * Created by the server during credential issuance and sent to the client.
 * The client verifies the proof and extracts the credential.
 */
export interface AuthCredentialWithPniResponse {
  /** ZK issuance proof binding the credential to (ACI, PNI, redemptionTime). */
  readonly issuanceProof: IssuanceProof;
  /** Whether the proof binds a PNI attribute. Encoded by the proof width on the wire. */
  readonly pniPresent: boolean;
  /** Day-aligned epoch timestamp (must be a multiple of SECONDS_PER_DAY). */
  readonly redemptionTime: number;
}

// ---------------------------------------------------------------------------
// AuthCredentialWithPni (client-side stored credential)
// ---------------------------------------------------------------------------

/**
 * A verified authentication credential binding an ACI and PNI to a
 * redemption time.
 *
 * Stored by the client after receiving and verifying an issuance response.
 * Used to generate presentation proofs for anonymous group authentication.
 */
export interface AuthCredentialWithPni {
  /** The raw ZK credential (t, U, V triple). */
  readonly credential: Credential;
  /** The user's ACI as a UidStruct (pair of Ristretto points). */
  readonly aci: UidStruct;
  /** The user's PNI, absent for accounts that have no PNI. */
  readonly pni?: UidStruct;
  /** Day-aligned epoch timestamp. */
  readonly redemptionTime: number;
}

// ---------------------------------------------------------------------------
// AuthCredentialPresentation (client -> server)
// ---------------------------------------------------------------------------

/**
 * A presentation proof demonstrating possession of an AuthCredentialWithPni,
 * with ACI and PNI encrypted under the group's UID encryption key.
 *
 * Sent to the server for anonymous group authentication. The server verifies
 * the ZK proof without learning which member is authenticating. The proof
 * establishes that the credential was validly issued, and that the
 * ciphertexts encrypt the identifiers it was issued over. The ACI and PNI
 * ciphertexts are decryptable
 * only with the group's secret params, which the server does not hold.
 */
export interface AuthCredentialPresentation {
  /** ZK presentation proof. */
  readonly proof: PresentationProof;
  /** ACI encrypted under the group's UID encryption key. */
  readonly aciCiphertext: UidEncCiphertext;
  /** PNI encrypted under the group's UID encryption key, when the credential has one. */
  readonly pniCiphertext?: UidEncCiphertext;
  /** Day-aligned epoch timestamp matching the credential. */
  readonly redemptionTime: number;
}

// ---------------------------------------------------------------------------
// Receive (client side)
// ---------------------------------------------------------------------------

/**
 * Receive and verify an AuthCredentialWithPni issuance response.
 *
 * Called by the client. Verifies the issuance proof against the server's
 * public key and extracts the credential for later presentation.
 *
 * The builder must accumulate attributes in the same order used during
 * issuance: ACI (hidden), PNI (hidden), redemptionTime (public).
 *
 * @param publicKey - The server's credential public key
 * @param response - The issuance response from the server
 * @param aci - The user's ACI ServiceId (must match what the server issued)
 * @param pni - The user's PNI ServiceId (must match what the server issued)
 * @param redemptionTime - Day-aligned epoch timestamp (must match the response)
 * @returns The verified credential for storage and later presentation
 * @throws {VerificationFailure} If the issuance proof is invalid
 * @throws {Error} If the redemption time is not day-aligned
 */
export function receiveAuthCredential(
  publicKey: CredentialPublicKey,
  response: AuthCredentialWithPniResponse,
  aci: ServiceId,
  pni: ServiceId | undefined,
  redemptionTime: number
): AuthCredentialWithPni {
  if (redemptionTime % SECONDS_PER_DAY !== 0) {
    throw new VerificationFailure();
  }
  if (
    isNilUuid(aci.uuid) ||
    (pni !== undefined && isNilUuid(pni.uuid)) ||
    response.pniPresent !== (pni !== undefined)
  ) {
    throw new VerificationFailure();
  }

  const aciUid = uidStructFromServiceId(aci);
  const pniUid = pni === undefined ? undefined : uidStructFromServiceId(pni);

  const builder = new IssuanceProofBuilder(CREDENTIAL_LABEL);
  builder.addAttribute(aciUid);
  if (pniUid !== undefined) builder.addAttribute(pniUid);
  builder.addPublicAttribute(redemptionTimePublicAttribute(redemptionTime));

  const credential = builder.verify(publicKey, response.issuanceProof);

  return {
    credential,
    aci: aciUid,
    pni: pniUid,
    redemptionTime,
  };
}

// ---------------------------------------------------------------------------
// Presentation (client side)
// ---------------------------------------------------------------------------

/**
 * Present an AuthCredentialWithPni to a group for anonymous authentication.
 *
 * Called by the client. Generates a ZK presentation proof that encrypts the
 * ACI and PNI under the group's UID encryption key. The proof allows the
 * server to identify the member while proving the credential was validly
 * issued.
 *
 * CRITICAL: Use different randomness for each presentation. Reusing randomness
 * allows different presentations to be linked and effectively reveals hidden
 * attributes and their encryption keys.
 *
 * @param publicKey - The server's credential public key
 * @param authCredential - The client's stored AuthCredentialWithPni
 * @param groupSecretParams - The group's secret parameters (contains UID enc key)
 * @param randomness - At least 32 bytes of cryptographically secure randomness
 * @returns The presentation to send to the server
 */
export function presentAuthCredential(
  publicKey: CredentialPublicKey,
  authCredential: AuthCredentialWithPni,
  groupSecretParams: GroupSecretParams,
  randomness: Uint8Array
): AuthCredentialPresentation {
  const { aci, pni, credential, redemptionTime } = authCredential;

  const builder = new PresentationProofBuilder(CREDENTIAL_LABEL);
  builder.addAttribute(aci, groupSecretParams.uidEncKeyPair);
  if (pni !== undefined) builder.addAttribute(pni, groupSecretParams.uidEncKeyPair);

  const proof = builder.present(publicKey, credential, randomness);

  const aciCiphertext = groupSecretParams.uidEncKeyPair.encrypt(aci);
  const pniCiphertext =
    pni === undefined ? undefined : groupSecretParams.uidEncKeyPair.encrypt(pni);

  return {
    proof,
    aciCiphertext,
    pniCiphertext,
    redemptionTime,
  };
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

const Point = RistrettoPoint;

/**
 * Deserialize an AuthCredentialWithPniResponse from bytes.
 */
export function deserializeAuthCredentialResponse(
  bytes: Uint8Array
): AuthCredentialWithPniResponse {
  // With PNI: 8 + 32*3 + 320. Without PNI: 8 + 32*3 + 256.
  if (bytes.length !== 424 && bytes.length !== 360) {
    throw new Error('deserializeAuthCredentialResponse: invalid length');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const redemptionTime = Number(view.getBigUint64(0, false));

  const t = bytesToScalarCanonical(bytes.subarray(8, 40));
  if (t === null) throw new Error('deserializeAuthCredentialResponse: invalid scalar t');
  const U = Point.fromBytes(bytes.subarray(40, 72));
  const V = Point.fromBytes(bytes.subarray(72, 104));
  const pokshoProof = bytes.slice(104);

  return {
    issuanceProof: {
      credential: { t, U, V },
      pokshoProof,
    },
    pniPresent: bytes.length === 424,
    redemptionTime,
  };
}

/**
 * Serialize an AuthCredentialPresentation to bytes.
 *
 * Format:
 *
 * ```
 * [redemptionTime: 8 bytes BE u64]
 * [C_x0: 32] [C_x1: 32] [C_V: 32]
 * [C_y_count: 4 LE u32] [C_y[]: 32 * n]
 * [proofLen: 4 LE u32] [pokshoProof: proofLen]
 * [aci.E_A1: 32] [aci.E_A2: 32]
 * [pni.E_A1: 32] [pni.E_A2: 32]   // present only when credential has PNI
 * ```
 */
export function serializeAuthCredentialPresentation(
  presentation: AuthCredentialPresentation
): Uint8Array {
  const { proof, aciCiphertext, pniCiphertext, redemptionTime } = presentation;
  const cyCount = proof.C_y.length;
  const proofLen = proof.pokshoProof.length;
  const expectedCyCount = pniCiphertext === undefined ? 3 : 5;
  if (cyCount !== expectedCyCount) {
    throw new Error(
      `serializeAuthCredentialPresentation: expected ${expectedCyCount} C_y points`
    );
  }

  const ciphertextPointCount = pniCiphertext === undefined ? 2 : 4;
  const totalLen =
    8 + 32 * 3 + 4 + 32 * cyCount + 4 + proofLen + 32 * ciphertextPointCount;
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

  buf.set(aciCiphertext.E_A1.toBytes(), offset);
  offset += 32;
  buf.set(aciCiphertext.E_A2.toBytes(), offset);
  offset += 32;
  if (pniCiphertext !== undefined) {
    buf.set(pniCiphertext.E_A1.toBytes(), offset);
    offset += 32;
    buf.set(pniCiphertext.E_A2.toBytes(), offset);
  }

  return buf;
}

/**
 * Serialize GroupPublicParams to bytes.
 *
 * Format: [groupId: 32] [uidEncPubKey.A: 32] [profileKeyEncPubKey.A: 32]
 */
export function serializeGroupPublicParams(params: GroupPublicParams): Uint8Array {
  const buf = new Uint8Array(96);
  buf.set(params.groupId, 0);
  buf.set(params.uidEncPublicKey.A.toBytes(), 32);
  buf.set(params.profileKeyEncPublicKey.A.toBytes(), 64);
  return buf;
}
