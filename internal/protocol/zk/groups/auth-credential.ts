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
 * verifier); ACI and PNI are hidden attributes encrypted under the group's
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
import {
  type UidStruct,
  type ServiceId,
  isNilUuid,
  uidStructFromServiceId,
} from './uid-struct';
import { type UidEncCiphertext, UidEncryptionDomain } from './uid-encryption';
import { ProfileKeyEncryptionDomain } from './profile-key-encryption';
import type { GroupSecretParams, GroupPublicParams } from './group-params';
import { SECONDS_PER_DAY } from './group-params';
import { scalarToBytes, bytesToScalarCanonical } from '../proofs/sho';
import { PublicKey, Ciphertext } from '../credentials/attributes';
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
 * the ZK proof — establishing that the credential was validly issued and that
 * the ciphertexts encrypt the identifiers it was issued over — without learning
 * which member is authenticating. The ACI and PNI ciphertexts are decryptable
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
// Issuance (server side)
// ---------------------------------------------------------------------------

/**
 * Issue an AuthCredentialWithPni for the given ACI, PNI, and redemption time.
 *
 * Called by the server. Produces an issuance proof that the client can verify
 * to extract the credential.
 *
 * The builder accumulates attributes in the same order used by the client
 * during verification: ACI (hidden), PNI (hidden), redemptionTime (public).
 *
 * CRITICAL: Use different randomness for each issuance. Reusing randomness
 * effectively reveals the server's private key.
 *
 * @param credentialKeyPair - The server's credential signing key pair
 * @param aci - The user's ACI ServiceId
 * @param pni - The user's PNI ServiceId
 * @param redemptionTime - Day-aligned epoch timestamp (seconds)
 * @param randomness - At least 32 bytes of cryptographically secure randomness
 * @returns The issuance response to send to the client
 */
export function issueAuthCredential(
  credentialKeyPair: CredentialKeyPair,
  aci: ServiceId,
  pni: ServiceId | undefined,
  redemptionTime: number,
  randomness: Uint8Array
): AuthCredentialWithPniResponse {
  if (isNilUuid(aci.uuid) || (pni !== undefined && isNilUuid(pni.uuid))) {
    throw new Error('Auth credential identifiers must not use the nil UUID');
  }
  const aciUid = uidStructFromServiceId(aci);
  const pniUid = pni === undefined ? undefined : uidStructFromServiceId(pni);

  const builder = new IssuanceProofBuilder(CREDENTIAL_LABEL);
  builder.addAttribute(aciUid);
  if (pniUid !== undefined) builder.addAttribute(pniUid);
  builder.addPublicAttribute(redemptionTimePublicAttribute(redemptionTime));

  const issuanceProof = builder.issue(credentialKeyPair, randomness);

  return { issuanceProof, pniPresent: pniUid !== undefined, redemptionTime };
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
 * ACI and PNI under the group's UID encryption key, allowing the server to
 * identify the member while proving the credential was validly issued.
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
// Verification (server side)
// ---------------------------------------------------------------------------

/**
 * Verify an AuthCredentialPresentation against the server's key pair and
 * the group's public parameters.
 *
 * Called by the server. Checks that the presentation proof is valid, meaning
 * the client holds a credential that was issued by this server over a valid
 * (ACI, PNI, redemptionTime) tuple, and that the ACI/PNI ciphertexts in the
 * presentation are consistent with those in the credential.
 *
 * Applies an asymmetric redemption window:
 * `[redemptionTime - 1 day, redemptionTime + 2 days]` (inclusive).
 *
 * @param credentialKeyPair - The server's credential signing key pair
 * @param groupPublicParams - The group's public parameters
 * @param presentation - The client's presentation proof
 * @param currentTime - Current epoch seconds for redemption time validation
 * @returns true if the presentation is valid
 * @throws {VerificationFailure} If the presentation proof is invalid or expired
 */
export function verifyAuthCredentialPresentation(
  credentialKeyPair: CredentialKeyPair,
  groupPublicParams: GroupPublicParams,
  presentation: AuthCredentialPresentation,
  currentTime: number
): boolean {
  const { proof, aciCiphertext, pniCiphertext, redemptionTime } = presentation;

  // Accept [redemptionTime - 1 day, redemptionTime + 2 days].
  const acceptableStart = redemptionTime - SECONDS_PER_DAY;
  const acceptableEnd = redemptionTime + 2 * SECONDS_PER_DAY;
  if (currentTime < acceptableStart || currentTime > acceptableEnd) {
    throw new VerificationFailure();
  }

  const verifier = new PresentationProofVerifier(CREDENTIAL_LABEL);
  verifier.addAttribute(aciCiphertext, groupPublicParams.uidEncPublicKey);
  if (pniCiphertext !== undefined) {
    verifier.addAttribute(pniCiphertext, groupPublicParams.uidEncPublicKey);
  }
  verifier.addPublicAttribute(redemptionTimePublicAttribute(redemptionTime));

  verifier.verify(credentialKeyPair, proof);

  return true;
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

const Point = RistrettoPoint;

/**
 * Serialize an AuthCredentialWithPniResponse to bytes.
 *
 * Format:
 *   [redemptionTime: 8 bytes BE u64]
 *   [credential.t: 32 bytes scalar LE]
 *   [credential.U: 32 bytes point]
 *   [credential.V: 32 bytes point]
 *   [pokshoProof: remaining bytes]
 */
export function serializeAuthCredentialResponse(
  response: AuthCredentialWithPniResponse
): Uint8Array {
  const { issuanceProof, pniPresent, redemptionTime } = response;
  const tBytes = scalarToBytes(issuanceProof.credential.t);
  const uBytes = issuanceProof.credential.U.toBytes();
  const vBytes = issuanceProof.credential.V.toBytes();
  const proofBytes = issuanceProof.pokshoProof;
  const expectedProofLength = pniPresent ? 320 : 256;
  if (proofBytes.length !== expectedProofLength) {
    throw new Error(
      `serializeAuthCredentialResponse: expected ${expectedProofLength}-byte proof`
    );
  }

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
 *   [redemptionTime: 8 bytes BE u64]
 *   [C_x0: 32] [C_x1: 32] [C_V: 32]
 *   [C_y_count: 4 LE u32] [C_y[]: 32 * n]
 *   [proofLen: 4 LE u32] [pokshoProof: proofLen]
 *   [aci.E_A1: 32] [aci.E_A2: 32]
 *   [pni.E_A1: 32] [pni.E_A2: 32]   // present only when credential has PNI
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
 * Deserialize an AuthCredentialPresentation from bytes.
 */
export function deserializeAuthCredentialPresentation(
  bytes: Uint8Array
): AuthCredentialPresentation {
  // Minimum tail is the two-point ACI ciphertext; PNI adds two more points.
  const MIN_LEN = 176;
  if (bytes.length < MIN_LEN) {
    throw new Error('deserializeAuthCredentialPresentation: too short');
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
  if (cyCount > 16 || offset + cyCount * 32 + 4 + 64 > bytes.length) {
    throw new Error('deserializeAuthCredentialPresentation: cyCount out of bounds');
  }
  const C_y: RistrettoPoint[] = [];
  for (let i = 0; i < cyCount; i++) {
    C_y.push(Point.fromBytes(bytes.subarray(offset, offset + 32)));
    offset += 32;
  }

  const proofLen = view.getUint32(offset, true);
  offset += 4;
  const ciphertextTailLength = bytes.length - (offset + proofLen);
  if (ciphertextTailLength > 128) {
    throw new Error('deserializeAuthCredentialPresentation: trailing bytes');
  }
  if (ciphertextTailLength !== 64 && ciphertextTailLength !== 128) {
    throw new Error('deserializeAuthCredentialPresentation: invalid ciphertext tail');
  }
  const pniPresent = ciphertextTailLength === 128;
  const expectedCyCount = pniPresent ? 5 : 3;
  if (cyCount !== expectedCyCount) {
    throw new Error('deserializeAuthCredentialPresentation: attribute count mismatch');
  }
  if (offset + proofLen + ciphertextTailLength !== bytes.length) {
    throw new Error('deserializeAuthCredentialPresentation: proofLen out of bounds');
  }
  const pokshoProof = bytes.slice(offset, offset + proofLen);
  offset += proofLen;

  const aciE_A1 = Point.fromBytes(bytes.subarray(offset, offset + 32));
  offset += 32;
  const aciE_A2 = Point.fromBytes(bytes.subarray(offset, offset + 32));
  offset += 32;
  let pniCiphertext: UidEncCiphertext | undefined;
  if (pniPresent) {
    const pniE_A1 = Point.fromBytes(bytes.subarray(offset, offset + 32));
    offset += 32;
    const pniE_A2 = Point.fromBytes(bytes.subarray(offset, offset + 32));
    offset += 32;
    pniCiphertext = new Ciphertext(pniE_A1, pniE_A2, UidEncryptionDomain);
  }

  if (offset !== bytes.length) {
    throw new Error('deserializeAuthCredentialPresentation: trailing bytes');
  }

  return {
    proof: { C_x0, C_x1, C_V, C_y, pokshoProof },
    aciCiphertext: new Ciphertext(aciE_A1, aciE_A2, UidEncryptionDomain),
    pniCiphertext,
    redemptionTime,
  };
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

/**
 * Deserialize GroupPublicParams from bytes.
 */
export function deserializeGroupPublicParams(bytes: Uint8Array): GroupPublicParams {
  if (bytes.length < 96) {
    throw new Error('deserializeGroupPublicParams: too short');
  }
  const groupId = bytes.slice(0, 32);
  const uidEncA = Point.fromBytes(bytes.subarray(32, 64));
  const profileKeyEncA = Point.fromBytes(bytes.subarray(64, 96));

  return {
    groupId,
    uidEncPublicKey: new PublicKey(uidEncA, UidEncryptionDomain),
    profileKeyEncPublicKey: new PublicKey(profileKeyEncA, ProfileKeyEncryptionDomain),
  };
}
