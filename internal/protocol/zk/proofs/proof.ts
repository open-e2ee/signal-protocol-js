/**
 * ZK Proof serialization
 *
 *
 * A Schnorr proof consists of a challenge scalar and response scalars.
 * Compact format: challenge (32 bytes) + response[0..n] (32 bytes each)
 */

import { bytesToScalarCanonical, scalarToBytes } from './sho';

/**
 * Schnorr ZK proof in compact format.
 * challenge: the Fiat-Shamir challenge scalar
 * response: the response scalars (one per witness variable)
 */
export {};
export interface Proof {
  challenge: bigint;
  response: bigint[];
}

/**
 * Parse a proof from bytes.
 * Format: challenge (32 bytes) + response[0..n] (32 bytes each)
 *
 * Returns null if the input is invalid (not a multiple of 32,
 * non-canonical scalars, or fewer than 2 chunks).
 */
export function proofFromBytes(bytes: Uint8Array): Proof | null {
  if (bytes.length % 32 !== 0) return null;

  const numChunks = bytes.length / 32;
  if (numChunks < 2) return null; // Need at least challenge + 1 response
  if (numChunks > 257) return null; // challenge + max 256 responses

  const challenge = bytesToScalarCanonical(bytes.subarray(0, 32));
  if (challenge === null) return null;

  const response: bigint[] = [];
  for (let i = 1; i < numChunks; i++) {
    const scalar = bytesToScalarCanonical(bytes.subarray(i * 32, (i + 1) * 32));
    if (scalar === null) return null;
    response.push(scalar);
  }

  return { challenge, response };
}

/**
 * Serialize a proof to bytes.
 */
export function proofToBytes(proof: Proof): Uint8Array {
  const totalLen = 32 + proof.response.length * 32;
  const out = new Uint8Array(totalLen);
  out.set(scalarToBytes(proof.challenge), 0);
  for (let i = 0; i < proof.response.length; i++) {
    out.set(scalarToBytes(proof.response[i]), 32 + i * 32);
  }
  return out;
}
