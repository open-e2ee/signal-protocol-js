/**
 * Convenience sign/verify wrappers
 *
 *
 * Signatures are such a common ZKP that we provide special functions.
 * A signature proves knowledge of private_key such that public_key = private_key * G.
 */

import type { RistrettoPoint } from './sho';
import { ScalarArgs, PointArgs } from './args';
import { Statement } from './statement';

/**
 * Sign a message with a Schnorr signature (ZK proof of knowledge of discrete log).
 *
 * @param privateKey The signing private key (scalar)
 * @param publicKey The corresponding public key (point = privateKey * G)
 * @param message The message to sign
 * @param randomness 32 bytes of randomness
 * @returns Signature bytes (64 bytes: 32 challenge + 32 response)
 */
export {};
export function schnorrSign(
  privateKey: bigint,
  publicKey: RistrettoPoint,
  message: Uint8Array,
  randomness: Uint8Array
): Uint8Array {
  const st = new Statement();
  st.add('public_key', [['private_key', 'G']]);

  const scalarArgs = new ScalarArgs();
  scalarArgs.add('private_key', privateKey);

  const pointArgs = new PointArgs();
  pointArgs.add('public_key', publicKey);

  return st.prove(scalarArgs, pointArgs, message, randomness);
}

/**
 * Verify a Schnorr signature.
 *
 * @param signature Signature bytes from schnorrSign
 * @param publicKey The signer's public key
 * @param message The signed message
 * @throws PokshoException on verification failure
 */
export function schnorrVerifySignature(
  signature: Uint8Array,
  publicKey: RistrettoPoint,
  message: Uint8Array
): void {
  const st = new Statement();
  st.add('public_key', [['private_key', 'G']]);

  const pointArgs = new PointArgs();
  pointArgs.add('public_key', publicKey);

  st.verifyProof(signature, pointArgs, message);
}
