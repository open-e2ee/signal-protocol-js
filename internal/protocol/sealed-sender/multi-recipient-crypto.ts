/**
 * Shared V2 Helper Functions
 *
 * Common cryptographic operations used by both V2 encryption and decryption.
 *
 * Key architectural points:
 * - XOR key uses ephemeral-to-recipient ECDH
 * - Auth tag uses identity-to-identity ECDH (binds sender to message)
 * - Auth tag is HKDF output (not HMAC)
 *
 */

import {
  V2_LABEL_R,
  V2_LABEL_K,
  V2_LABEL_DH,
  V2_LABEL_DH_S,
  V2_RANDOM_M_BYTES,
  V2_AUTH_TAG_LEN,
} from './types';
import { hkdf, stringToBytes, concatBytes, constantTimeEqual, secureZeroBytes } from '../../crypto';
import { x25519 } from '@noble/curves/ed25519.js';

/** Generic error message for all V2 failures */
export {};
const GENERIC_ERROR = 'Sealed sender V2 operation failed';

/**
 * Derive symmetric cipher key K from random M.
 *
 * Uses HKDF with info = "Sealed Sender v2: K"
 *
 * @param M 32-byte random material
 * @returns 32-byte AES-256 key
 *
 */
export async function deriveCipherKeyFromM(M: Uint8Array): Promise<Uint8Array> {
  const info = stringToBytes(V2_LABEL_K);
  return hkdf(M, new Uint8Array(0), info, 32);
}

/**
 * Derive ephemeral X25519 private key from random M.
 *
 * Uses HKDF with info = "Sealed Sender v2: r (2023-08)"
 *
 * @param M 32-byte random material
 * @returns 32-byte X25519 private key
 *
 */
export async function deriveEphemeralPrivateFromM(M: Uint8Array): Promise<Uint8Array> {
  const info = stringToBytes(V2_LABEL_R);
  return hkdf(M, new Uint8Array(0), info, 32);
}

/**
 * Derive ephemeral X25519 keypair from random M.
 *
 * Uses HKDF to derive private key, then computes public key.
 *
 * @param M 32-byte random material
 * @returns Ephemeral keypair { privateKey, publicKey }
 */
export async function deriveEphemeralFromM(
  M: Uint8Array
): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
  const privateKey = await deriveEphemeralPrivateFromM(M);
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/** Serialize an X25519 public key with the 0x05 DJB type prefix. */
function serializePublicKey(raw32: Uint8Array): Uint8Array {
  const serialized = new Uint8Array(33);
  serialized[0] = 0x05;
  serialized.set(raw32, 1);
  return serialized;
}

/**
 * Direction of the sealed sender operation.
 * Affects the order of public keys in key derivation.
 */
export type Direction = 'sending' | 'receiving';

/**
 * Apply agreement XOR to encrypt/decrypt message key M.
 *
 * This operation:
 * 1. Computes ECDH between ephemeral and recipient identity
 * 2. Builds IKM = agreement || ephemeral_pub || recipient_identity_pub
 * 3. Derives XOR key via HKDF with LABEL_DH
 * 4. XORs with input
 *
 * Parameter semantics change based on direction:
 *
 * **Sending:**
 * - ourPrivate = ephemeral private key (for ECDH with recipient)
 * - ephemeralPublic = ephemeral public key (for IKM)
 * - theirPublic = recipient's identity public key (for ECDH and IKM)
 *
 * **Receiving:**
 * - ourPrivate = recipient's identity private key (for ECDH with ephemeral)
 * - ephemeralPublic = ephemeral public key (for ECDH and IKM)
 * - theirPublic = ephemeral public key (same as ephemeralPublic, for ECDH)
 *
 * @param ourPrivate For sending: ephemeral private key. For receiving: recipient's identity private key.
 * @param ephemeralPublic The ephemeral public key (always needed for IKM).
 * @param theirPublic For sending: recipient's identity public key. For receiving: ephemeral public key.
 * @param direction Whether we are encrypting (sending) or decrypting (receiving).
 * @param input 32-byte M (when sending) or encrypted key (when receiving).
 * @returns XOR result (encrypted M when sending, decrypted M when receiving).
 *
 */
export async function applyAgreementXor(
  ourPrivate: Uint8Array,
  ephemeralPublic: Uint8Array,
  theirPublic: Uint8Array,
  direction: Direction,
  input: Uint8Array
): Promise<Uint8Array> {
  if (input.length !== V2_RANDOM_M_BYTES) {
    throw new Error(GENERIC_ERROR);
  }

  // Compute ECDH agreement
  // - Sending: ECDH(ephemeral_private, recipient_identity_pub)
  // - Receiving: ECDH(recipient_identity_private, ephemeral_pub)
  const agreement = x25519.getSharedSecret(ourPrivate, theirPublic);

  let ikm: Uint8Array | undefined;
  let xorKey: Uint8Array | undefined;

  try {
    // Build IKM: agreement || ephemeral_pub || recipient_identity_pub
    // This order is the same for both directions
    if (direction === 'sending') {
      // ourPrivate is ephemeral private, theirPublic is recipient identity public
      ikm = concatBytes(
        agreement,
        serializePublicKey(ephemeralPublic),
        serializePublicKey(theirPublic)
      );
    } else {
      // ourPrivate is recipient identity private, theirPublic is ephemeral public
      // Derive recipient's identity public from their private key
      const recipientIdentityPublic = x25519.getPublicKey(ourPrivate);
      ikm = concatBytes(
        agreement,
        serializePublicKey(theirPublic),
        serializePublicKey(recipientIdentityPublic)
      );
    }

    // Derive XOR key using HKDF with LABEL_DH
    const info = stringToBytes(V2_LABEL_DH);
    xorKey = await hkdf(ikm, new Uint8Array(0), info, 32);

    // XOR
    const result = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i++) {
      result[i] = input[i] ^ xorKey[i];
    }

    return result;
  } finally {
    secureZeroBytes(agreement);
    if (ikm) secureZeroBytes(ikm);
    if (xorKey) secureZeroBytes(xorKey);
  }
}

/**
 * Compute authentication tag for a recipient.
 *
 * This operation:
 * 1. Uses IDENTITY-to-IDENTITY ECDH (not ephemeral!)
 * 2. IKM = identity_agreement || ephemeral_pub || encrypted_key || sender_id_pub || recipient_id_pub
 * 3. Returns 16-byte HKDF output with LABEL_DH_S (not HMAC!)
 *
 * @param senderIdentityPrivate Sender's identity private key
 * @param senderIdentityPublic Sender's identity public key
 * @param recipientIdentityPublic Recipient's identity public key
 * @param ephemeralPublic The ephemeral public key
 * @param encryptedMessageKey The XOR-encrypted M
 * @param direction Sending or receiving (affects key order in IKM)
 * @returns 16-byte authentication tag
 *
 */
export async function computeAuthenticationTag(
  ourIdentityPrivate: Uint8Array,
  ourIdentityPublic: Uint8Array,
  theirIdentityPublic: Uint8Array,
  ephemeralPublic: Uint8Array,
  encryptedMessageKey: Uint8Array,
  direction: Direction
): Promise<Uint8Array> {
  // Identity-to-identity ECDH
  const identityAgreement = x25519.getSharedSecret(ourIdentityPrivate, theirIdentityPublic);

  let ikm: Uint8Array | undefined;

  try {
    // Build IKM based on direction
    // IKM = agreement || ephemeral_pub || encrypted_key || our_id_pub || their_id_pub
    if (direction === 'sending') {
      ikm = concatBytes(
        identityAgreement,
        serializePublicKey(ephemeralPublic),
        encryptedMessageKey,
        serializePublicKey(ourIdentityPublic),
        serializePublicKey(theirIdentityPublic)
      );
    } else {
      ikm = concatBytes(
        identityAgreement,
        serializePublicKey(ephemeralPublic),
        encryptedMessageKey,
        serializePublicKey(theirIdentityPublic),
        serializePublicKey(ourIdentityPublic)
      );
    }

    // HKDF output IS the auth tag (16 bytes)
    const info = stringToBytes(V2_LABEL_DH_S);
    return await hkdf(ikm, new Uint8Array(0), info, V2_AUTH_TAG_LEN);
  } finally {
    secureZeroBytes(identityAgreement);
    if (ikm) secureZeroBytes(ikm);
  }
}

/**
 * Verify an authentication tag in constant time.
 *
 * @param expected Expected tag (16 bytes)
 * @param received Received tag (16 bytes)
 * @returns true if tags match
 */
export function verifyAuthenticationTag(expected: Uint8Array, received: Uint8Array): boolean {
  if (expected.length !== V2_AUTH_TAG_LEN || received.length !== V2_AUTH_TAG_LEN) {
    return false;
  }
  return constantTimeEqual(expected, received);
}
