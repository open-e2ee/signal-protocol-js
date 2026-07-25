/**
 * Username zero-knowledge proof (Schnorr/sigma protocol), compatible with the reference implementation
 *
 * Proves knowledge of a username's preimage (nickname + discriminator) without
 * revealing the username itself. The server can verify the proof against the
 * hash point without learning anything about the underlying values.
 *
 * Statement: username_hash = s0*G1 + s1*G2 + s2*G3
 *
 * Proof: 128 bytes (1 challenge + 3 response scalars x 32 bytes each)
 *
 */

import { Statement, PokshoException, PokshoError } from '../zk/proofs/statement';
import { ScalarArgs, PointArgs } from '../zk/proofs/args';
import { RistrettoPoint } from '../zk/proofs/sho';
import { bytesToHex } from '@noble/hashes/utils.js';
import { hashUsername, usernameScalars, G1, G2, G3 } from './hash';

/** Proof length: 1 challenge scalar (32) + 3 response scalars (3 x 32) = 128 bytes */
export {};
export const USERNAME_PROOF_LENGTH = 128;

/**
 * Singleton ZK statement for username hash knowledge.
 *
 * username_hash = username_sha_scalar * G1 + nickname_scalar * G2 + discriminator_scalar * G3
 */
const PROOF_STATEMENT = (() => {
  const st = new Statement();
  st.add('username_hash', [
    ['username_sha_scalar', 'G1'],
    ['nickname_scalar', 'G2'],
    ['discriminator_scalar', 'G3'],
  ]);
  return st;
})();

/**
 * Generate a ZK proof that you know the preimage of a username hash.
 *
 * @param nickname - The nickname component (e.g., "cool_tiger")
 * @param discriminator - The discriminator component (e.g., 42)
 * @param randomness - Optional 32 bytes of randomness for synthetic nonce generation.
 * If omitted, the runtime CSPRNG is used.
 * @returns 128-byte proof
 */
export function proveUsernameKnowledge(
  nickname: string,
  discriminator: number,
  randomness?: Uint8Array
): Uint8Array {
  const proofRandomness = randomness ?? crypto.getRandomValues(new Uint8Array(32));
  const hashBytes = hashUsername(nickname, discriminator);
  const { s0, s1, s2 } = usernameScalars(nickname, discriminator);

  const scalarArgs = new ScalarArgs();
  scalarArgs.add('username_sha_scalar', s0);
  scalarArgs.add('nickname_scalar', s1);
  scalarArgs.add('discriminator_scalar', s2);

  const pointArgs = new PointArgs();
  pointArgs.add('G1', G1);
  pointArgs.add('G2', G2);
  pointArgs.add('G3', G3);
  pointArgs.add('username_hash', RistrettoPoint.fromHex(bytesToHex(hashBytes)));

  return PROOF_STATEMENT.prove(scalarArgs, pointArgs, hashBytes, proofRandomness);
}

/**
 * Verify a ZK proof of username knowledge.
 *
 * @param hashPoint - 32-byte compressed Ristretto point (the username hash)
 * @param proof - 128-byte proof from proveUsernameKnowledge
 * @returns true if the proof is valid, false otherwise
 */
export function verifyUsernameProof(hashPoint: Uint8Array, proof: Uint8Array): boolean {
  try {
    const point = RistrettoPoint.fromHex(bytesToHex(hashPoint));

    const pointArgs = new PointArgs();
    pointArgs.add('G1', G1);
    pointArgs.add('G2', G2);
    pointArgs.add('G3', G3);
    pointArgs.add('username_hash', point);

    PROOF_STATEMENT.verifyProof(proof, pointArgs, hashPoint);
    return true;
  } catch (e) {
    if (e instanceof PokshoException && e.code === PokshoError.VerificationFailure) {
      return false;
    }
    // Invalid Ristretto point or other deserialization error
    return false;
  }
}
