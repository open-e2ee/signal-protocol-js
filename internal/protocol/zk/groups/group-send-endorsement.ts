/**
 * Group Send Endorsements -- proving send authorization for group messages
 *
 *
 * GroupSendEndorsement is a MAC over:
 *  - a ServiceId (computed from ciphertexts on the group server at issuance,
 *    passed decrypted to the chat server for verification)
 *  - an expiration timestamp, truncated to day granularity (chosen by the group
 *    server at issuance, passed publicly to the chat server for verification)
 *
 * At a high level:
 *   1. Server derives daily key from root key + expiration
 *   2. Server issues endorsements for encrypted member UIDs + batch proof
 *   3. Client receives response, validates proof, extracts endorsements
 *   4. Client may combine/remove endorsements (set operations)
 *   5. Client generates a bearer token by unblinding + hashing
 *   6. Chat server recreates token from revealed attributes and checks match
 *
 * @see https://signal.org/docs/ -- Signal Protocol Specifications
 * @see https://eprint.iacr.org/2019/1416.pdf -- Signal Private Group System
 */

import {
  ServerRootKeyPair,
  ServerRootPublicKey,
  ServerDerivedKeyPair,
  ServerDerivedPublicKey,
  ClientDecryptionKey,
  EndorsementResponse,
  Endorsement,
} from '../credentials/endorsements';
import { VerificationFailure } from '../credentials/issuance';
import { ShoHmacSha256, RistrettoPoint } from '../proofs/sho';
import type { ServiceId } from './uid-struct';
import { seedM1, calcM1 } from './uid-struct';
import type { UidEncCiphertext } from './uid-encryption';
import { type GroupSecretParams, SECONDS_PER_DAY } from './group-params';
export {};
const enc = new TextEncoder();

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Seconds in one hour. */
const SECONDS_PER_HOUR = 60 * 60;

/** Domain separation label for GroupSendEndorsement key derivation. */
const ENDORSEMENT_LABEL = '20240215_Signal_GroupSendEndorsement';

// ---------------------------------------------------------------------------
// GroupSendDerivedKeyPair
// ---------------------------------------------------------------------------

/**
 * A key pair used to sign endorsements for a particular expiration.
 *
 * Derived daily from a {@link ServerRootKeyPair} by absorbing the
 * day-aligned expiration timestamp. Intended to be cheaply cached --
 * regeneration is not expensive, but these are reused frequently
 * enough that caching is worthwhile.
 */
export interface GroupSendDerivedKeyPair {
  /** The derived server key pair for endorsement issuance/verification. */
  readonly keyPair: ServerDerivedKeyPair;
  /** Day-aligned expiration timestamp in epoch seconds. */
  readonly expiration: number;
}

/**
 * Create the tag info SHO that encapsulates the public attributes of an
 * endorsement (the expiration). Used to derive the appropriate signing key.
 *
 * @param expiration - Day-aligned epoch seconds timestamp
 * @returns A SHO with the endorsement label and expiration absorbed
 */
function tagInfo(expiration: number): ShoHmacSha256 {
  const sho = new ShoHmacSha256(enc.encode(ENDORSEMENT_LABEL));
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, BigInt(expiration), false); // big-endian u64
  sho.absorbAndRatchet(buf);
  return sho;
}

/**
 * Derive the appropriate key pair for the given expiration.
 *
 * @param rootKeyPair - The server's root key pair
 * @param expiration - Day-aligned epoch seconds timestamp
 * @returns The derived key pair bound to the expiration
 * @throws Error if expiration is not day-aligned
 */
export function deriveForExpiration(
  rootKeyPair: ServerRootKeyPair,
  expiration: number
): GroupSendDerivedKeyPair {
  if (expiration % SECONDS_PER_DAY !== 0) {
    throw new Error(
      `deriveForExpiration: expiration must be day-aligned (multiple of ${SECONDS_PER_DAY}), got ${expiration}`
    );
  }
  const keyPair = rootKeyPair.deriveKey(tagInfo(expiration));
  return { keyPair, expiration };
}

// ---------------------------------------------------------------------------
// Default expiration
// ---------------------------------------------------------------------------

/**
 * Compute the default expiration for endorsements issued at `currentTime`.
 *
 * Returns the end of the next UTC day, unless that is less than 25 hours
 * away, in which case it returns the end of the following day.
 *
 * This ensures endorsements are always valid for at least 25 hours,
 * providing a comfortable buffer for clock skew and timezone issues.
 *
 * @param currentTime - Current time in epoch seconds
 * @returns Day-aligned expiration timestamp in epoch seconds
 */
export function defaultExpiration(currentTime: number): number {
  const startOfDay = currentTime - (currentTime % SECONDS_PER_DAY);
  let expiration = startOfDay + 2 * SECONDS_PER_DAY;
  if (expiration - currentTime < SECONDS_PER_DAY + SECONDS_PER_HOUR) {
    expiration += SECONDS_PER_DAY;
  }
  return expiration;
}

// ---------------------------------------------------------------------------
// GroupSendEndorsementsResponse
// ---------------------------------------------------------------------------

/**
 * A response from the group server containing endorsements for all group
 * members.
 *
 * The group server may cache this for a particular group as long as the
 * group membership does not change (being careful of expiration). It is
 * the same for every requesting member.
 */
export interface GroupSendEndorsementsResponse {
  /** The endorsement response containing signed points and batch proof. */
  readonly response: EndorsementResponse;
  /** Day-aligned expiration in epoch seconds for all endorsements. */
  readonly expiration: number;
}

// ---------------------------------------------------------------------------
// Point sorting (deterministic ordering)
// ---------------------------------------------------------------------------

/**
 * Sort indexed points in a deterministic order based on their doubled
 * and compressed byte representations.
 *
 * The ordering is defined by each point's doubled-and-compressed bytes.
 * Changing this order is a breaking change, since the issuing server
 * and client must agree on it.
 *
 * Sort keys are precomputed and indexed by original position, then
 * looked up via the original index stored in each tuple during sorting.
 *
 * @param points - Array of [originalIndex, point] pairs (mutated in place)
 * @param sortKeys - Compressed doubled-point bytes, indexed by original position
 */
function sortPointsByKeys(points: Array<[number, RistrettoPoint]>, sortKeys: Uint8Array[]): void {
  points.sort((a, b) => {
    const keyA = sortKeys[a[0]];
    const keyB = sortKeys[b[0]];
    for (let i = 0; i < 32; i++) {
      if (keyA[i] !== keyB[i]) {
        return keyA[i] - keyB[i];
      }
    }
    return 0;
  });
}

// ---------------------------------------------------------------------------
// Issue endorsements (server-side)
// ---------------------------------------------------------------------------

/**
 * Issue endorsements for all group members.
 *
 * Takes an array of UID encryption ciphertexts (one per member), sorts
 * them deterministically, extracts the E_A1 points, and issues
 * endorsements over those points using the derived key pair.
 *
 * @param memberCiphertexts - Encrypted UIDs of group members
 * @param derivedKeyPair - Key pair derived for the target expiration
 * @param randomness - 32 bytes of randomness for the batch proof
 * @returns Response containing endorsements and expiration
 */
export function issueEndorsements(
  memberCiphertexts: UidEncCiphertext[],
  derivedKeyPair: GroupSendDerivedKeyPair,
  randomness: Uint8Array
): GroupSendEndorsementsResponse {
  // Extract E_A1 (first point of each ciphertext) with original indices
  const indexedPoints: Array<[number, RistrettoPoint]> = memberCiphertexts.map((ct, i) => [
    i,
    ct.E_A1,
  ]);

  // Compute sort keys before sorting
  const sortKeys = indexedPoints.map(([_i, point]) => point.add(point).toBytes());
  sortPointsByKeys(indexedPoints, sortKeys);

  // Extract just the sorted points for issuance
  const sortedPoints = indexedPoints.map(([_i, point]) => point);

  // Issue endorsements over the sorted points
  const response = EndorsementResponse.issue(sortedPoints, derivedKeyPair.keyPair, randomness);

  return {
    response,
    expiration: derivedKeyPair.expiration,
  };
}

// ---------------------------------------------------------------------------
// ReceivedEndorsement
// ---------------------------------------------------------------------------

/**
 * An endorsement as extracted from a {@link GroupSendEndorsementsResponse}.
 *
 * Each received endorsement corresponds to one group member and can be
 * converted to a bearer token for sending messages to that member.
 */
export interface ReceivedEndorsement {
  /** The decompressed endorsement, supporting combine/remove/toToken. */
  readonly endorsement: Endorsement;

  /**
   * Generate a bearer token from this endorsement.
   *
   * Uses the group's UID encryption key to unblind the endorsement
   * before hashing. The resulting token can be cached and reused
   * for multiple sends to the same recipient.
   *
   * @param groupSecretParams - The group's secret parameters
   * @returns A GroupSendToken suitable for verification
   */
  toToken(groupSecretParams: GroupSecretParams): GroupSendToken;
}

/**
 * Create a {@link ReceivedEndorsement} wrapping the given endorsement.
 *
 * @param endorsement - The decompressed endorsement point
 * @returns A ReceivedEndorsement with a toToken method
 */
function createReceivedEndorsement(endorsement: Endorsement): ReceivedEndorsement {
  return {
    endorsement,
    toToken(groupSecretParams: GroupSecretParams): GroupSendToken {
      const clientKey = ClientDecryptionKey.forFirstPointOfAttribute(
        groupSecretParams.uidEncKeyPair.a1
      );
      const rawToken = endorsement.toToken(clientKey);
      return { token: rawToken };
    },
  };
}

// ---------------------------------------------------------------------------
// Receive endorsements (client-side)
// ---------------------------------------------------------------------------

/**
 * Validate the endorsement response expiration against the current time
 * and derive the corresponding public signing key.
 *
 * Rejects endorsements that:
 *  - Have a non-day-aligned expiration (server fingerprinting defense)
 *  - Expire in less than 2 hours (allows for clock skew)
 *  - Expire in more than 7 days (server fingerprinting defense)
 *
 * @param expiration - The endorsement expiration timestamp
 * @param now - Current time in epoch seconds
 * @param rootPublicKey - The server's root public key
 * @returns The derived public key for verification
 * @throws VerificationFailure if the expiration is invalid
 */
function derivePublicSigningKeyFromExpiration(
  expiration: number,
  now: number,
  rootPublicKey: ServerRootPublicKey
): ServerDerivedPublicKey {
  if (expiration % SECONDS_PER_DAY !== 0) {
    throw new VerificationFailure();
  }

  const timeRemainingInSeconds = Math.max(0, expiration - now);
  if (timeRemainingInSeconds < 2 * SECONDS_PER_HOUR) {
    throw new VerificationFailure();
  }
  if (timeRemainingInSeconds > 7 * SECONDS_PER_DAY) {
    throw new VerificationFailure();
  }

  return rootPublicKey.deriveKey(tagInfo(expiration));
}

/**
 * Validate and extract endorsements from a server response.
 *
 * The result will be in the same order as `serviceIds`. The caller
 * should include the current user's ServiceId in `serviceIds` as well.
 *
 * This method:
 *  1. Validates the expiration against `now`
 *  2. Derives the public signing key for verification
 *  3. Computes E_A1 = a1 * M1 for each ServiceId (the encrypted first point)
 *  4. Sorts the points to match the server's deterministic ordering
 *  5. Verifies the batch proof against the sorted points
 *  6. Un-sorts the results to match the original serviceIds order
 *
 * @param response - The server's endorsement response
 * @param serviceIds - ServiceIds of all group members (in caller's order)
 * @param now - Current time in epoch seconds
 * @param groupSecretParams - The group's secret parameters
 * @param rootPublicKey - The server's root public key
 * @returns Array of received endorsements in the same order as serviceIds
 * @throws VerificationFailure if validation or proof verification fails
 */
export function receiveEndorsements(
  response: GroupSendEndorsementsResponse,
  serviceIds: ServiceId[],
  now: number,
  groupSecretParams: GroupSecretParams,
  rootPublicKey: ServerRootPublicKey
): ReceivedEndorsement[] {
  const derivedKey = derivePublicSigningKeyFromExpiration(response.expiration, now, rootPublicKey);

  // Compute E_A1 = a1 * M1 for each ServiceId.
  // This is the first point of the encrypted attribute -- the same point
  // the server computed from the ciphertexts at issuance.
  const uidShoSeed = seedM1();
  const a1 = groupSecretParams.uidEncKeyPair.a1;

  const memberPoints: Array<[number, RistrettoPoint]> = serviceIds.map((serviceId, i) => {
    const m1 = calcM1(uidShoSeed.clone(), serviceId);
    const encryptedPoint = m1.multiply(a1);
    return [i, encryptedPoint];
  });

  // Sort to match the server's deterministic ordering
  const sortKeys = memberPoints.map(([_i, point]) => point.add(point).toBytes());
  sortPointsByKeys(memberPoints, sortKeys);

  // Extract sorted points for verification
  const sortedPoints = memberPoints.map(([_i, point]) => point);

  // Verify and extract endorsements
  const received = response.response.receive(sortedPoints, derivedKey);

  // Un-sort: place each endorsement back at its original index
  const result: ReceivedEndorsement[] = new Array(serviceIds.length);
  for (let sortedIdx = 0; sortedIdx < memberPoints.length; sortedIdx++) {
    const originalIdx = memberPoints[sortedIdx][0];
    result[originalIdx] = createReceivedEndorsement(received.decompressed[sortedIdx]);
  }

  return result;
}

// ---------------------------------------------------------------------------
// Combining and removing endorsements
// ---------------------------------------------------------------------------

/**
 * Combine multiple endorsements into a single endorsement.
 *
 * All endorsements must have been generated from the same issuance (same
 * server key and expiration). The combined endorsement can be used to
 * produce a single token that covers all the original recipients.
 *
 * This is a set-like operation: order does not matter.
 *
 * @param endorsements - The endorsements to combine
 * @returns A single combined endorsement
 */
export function combineEndorsements(endorsements: Endorsement[]): Endorsement {
  return Endorsement.combine(endorsements);
}

/**
 * Remove one endorsement from another.
 *
 * Used to remove a member from a previously-combined endorsement.
 * Removing an endorsement not present in `combined` will produce
 * an endorsement that does not generate a valid token.
 *
 * This is a set-like operation: order does not matter.
 *
 * @param combined - The combined endorsement to remove from
 * @param unwanted - The endorsement to remove
 * @returns A new endorsement with `unwanted` removed
 */
export function removeEndorsement(combined: Endorsement, unwanted: Endorsement): Endorsement {
  return combined.remove(unwanted);
}

// ---------------------------------------------------------------------------
// GroupSendToken
// ---------------------------------------------------------------------------

/**
 * A bearer token representing an endorsement.
 *
 * This can be cached by the client for repeatedly sending to the same
 * recipient(s), but must be combined with an expiration to form a
 * {@link GroupSendFullToken} before sending to the chat server.
 */
export interface GroupSendToken {
  /** Raw token bytes (16 bytes -- SHA-256 truncated). */
  readonly token: Uint8Array;
}

// ---------------------------------------------------------------------------
// GroupSendFullToken
// ---------------------------------------------------------------------------

/**
 * A bearer token combined with its expiration timestamp.
 *
 * This is serialized and sent to the chat server for verification.
 */
export interface GroupSendFullToken {
  /** The bearer token. */
  readonly token: GroupSendToken;
  /** Day-aligned expiration in epoch seconds. */
  readonly expiration: number;
}

/**
 * Create a full token by attaching an expiration to a token.
 *
 * If the incorrect expiration is used, the token will fail verification.
 *
 * @param token - The bearer token
 * @param expiration - The expiration from the endorsement response
 * @returns A full token ready for verification
 */
export function createFullToken(token: GroupSendToken, expiration: number): GroupSendFullToken {
  return { token, expiration };
}

/**
 * Verify that a full token is valid for sending to the given ServiceIds
 * at the current time.
 *
 * The chat server calls this to authorize a group send. Verification:
 *  1. Checks that the token has not expired
 *  2. Asserts the expiration matches the derived key pair
 *  3. Sums the M1 points of all recipient ServiceIds
 *  4. Verifies the token against the summed point using the derived key
 *
 * @param fullToken - The full token to verify
 * @param serviceIds - ServiceIds the sender claims to be sending to
 * @param now - Current time in epoch seconds
 * @param derivedKeyPair - Key pair derived for the token's expiration
 * @returns true if the token is valid
 * @throws VerificationFailure if verification fails
 */
export function verifyFullToken(
  fullToken: GroupSendFullToken,
  serviceIds: ServiceId[],
  now: number,
  derivedKeyPair: GroupSendDerivedKeyPair
): boolean {
  if (now > fullToken.expiration) {
    throw new VerificationFailure();
  }
  if (fullToken.expiration !== derivedKeyPair.expiration) {
    throw new Error(
      'verifyFullToken: wrong key pair used for this token ' +
        `(token expiration: ${fullToken.expiration}, ` +
        `key pair expiration: ${derivedKeyPair.expiration})`
    );
  }

  // Sum M1 points for all recipient ServiceIds
  const uidShoSeed = seedM1();
  let userIdSum: RistrettoPoint | null = null;
  for (const serviceId of serviceIds) {
    const m1 = calcM1(uidShoSeed.clone(), serviceId);
    if (userIdSum === null) {
      userIdSum = m1;
    } else {
      userIdSum = userIdSum.add(m1);
    }
  }

  if (userIdSum === null) {
    throw new Error('verifyFullToken: serviceIds must not be empty');
  }

  // ServerDerivedKeyPair.verify throws VerificationFailure on mismatch
  derivedKeyPair.keyPair.verify(userIdSum, fullToken.token.token);
  return true;
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/**
 * Serialize a {@link GroupSendEndorsementsResponse} to bytes.
 *
 * Format: [expiration (8 bytes BE)] [endorsement response bytes]
 *
 * @param response - The response to serialize
 * @returns The serialized bytes
 */
export function serializeEndorsementsResponse(response: GroupSendEndorsementsResponse): Uint8Array {
  const responseBytes = response.response.toBytes();
  const result = new Uint8Array(8 + responseBytes.length);
  const view = new DataView(result.buffer);
  view.setBigUint64(0, BigInt(response.expiration), false);
  result.set(responseBytes, 8);
  return result;
}

/**
 * Deserialize a {@link GroupSendEndorsementsResponse} from bytes.
 *
 * @param bytes - The serialized bytes
 * @returns The deserialized response
 * @throws Error if the bytes are too short or malformed
 */
export function deserializeEndorsementsResponse(bytes: Uint8Array): GroupSendEndorsementsResponse {
  if (bytes.length < 8) {
    throw new Error('deserializeEndorsementsResponse: too short for expiration header');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const expiration = Number(view.getBigUint64(0, false));
  const responseBytes = bytes.slice(8);
  const response = EndorsementResponse.fromBytes(responseBytes);
  return { response, expiration };
}

/**
 * Serialize a {@link GroupSendFullToken} to bytes.
 *
 * Format: [expiration (8 bytes BE)] [token (16 bytes)]
 *
 * @param fullToken - The full token to serialize
 * @returns The serialized bytes (24 bytes)
 */
export function serializeFullToken(fullToken: GroupSendFullToken): Uint8Array {
  const result = new Uint8Array(8 + fullToken.token.token.length);
  const view = new DataView(result.buffer);
  view.setBigUint64(0, BigInt(fullToken.expiration), false);
  result.set(fullToken.token.token, 8);
  return result;
}

/**
 * Deserialize a {@link GroupSendFullToken} from bytes.
 *
 * @param bytes - The serialized bytes (24 bytes)
 * @returns The deserialized full token
 * @throws Error if the bytes are malformed
 */
export function deserializeFullToken(bytes: Uint8Array): GroupSendFullToken {
  if (bytes.length < 24) {
    throw new Error('deserializeFullToken: expected at least 24 bytes, got ' + bytes.length);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const expiration = Number(view.getBigUint64(0, false));
  const token = bytes.slice(8, 24);
  return { token: { token }, expiration };
}
