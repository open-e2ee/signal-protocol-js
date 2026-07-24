/**
 * Public username link helpers.
 *
 * Wraps username-link cryptography with the shareable
 * transport encoding used to move `entropy + handle` through URLs or QR
 * payloads without exposing the plaintext username to the service.
 */

import {
  base64ToBytes,
  bytesToUrlSafeBase64,
  concatBytes,
  urlSafeToBase64,
} from '../internal/crypto/utils';
import { bytesToServiceId, serviceIdToBytes } from '../internal/protocol/sealed-sender/v2-binary';
import { asBase64 } from '../types/utils';

export interface UsernameLink {
  entropy: Uint8Array;
  encryptedUsername: Uint8Array;
}

export interface UsernameLinkComponents {
  entropy: Uint8Array;
  handle: string;
}

export interface SerializedUsernameLinkComponents {
  entropy: string;
  handle: string;
}

// Fixed username-link entropy size.
export const USERNAME_LINK_ENTROPY_SIZE = 32;
export const USERNAME_LINK_HANDLE_BYTE_LENGTH = 16;
export const USERNAME_LINK_COMPONENT_BYTE_LENGTH =
  USERNAME_LINK_ENTROPY_SIZE + USERNAME_LINK_HANDLE_BYTE_LENGTH;

/**
 * Create a shareable username link payload for the given username.
 *
 * Reusing `previousEntropy` preserves the visible link data while updating the
 * encrypted username blob on the service.
 */
export async function createUsernameLink(
  username: string,
  previousEntropy?: Uint8Array
): Promise<UsernameLink> {
  const { encryptUsernameForLink } = await loadUsernameLinkCrypto();
  return encryptUsernameForLink(username, previousEntropy);
}

/**
 * Decrypt a username from a previously fetched username link payload.
 */
export async function decryptUsernameLink(link: UsernameLink): Promise<string> {
  const { decryptUsernameFromLink } = await loadUsernameLinkCrypto();
  return decryptUsernameFromLink(link.entropy, link.encryptedUsername);
}

/**
 * Encode SDK username link components as URL-safe base64 without
 * padding: 32-byte entropy followed by the 16-byte UUID handle.
 */
export function encodeUsernameLinkComponents(components: UsernameLinkComponents): string {
  validateUsernameLinkEntropy(components.entropy);

  const handleBytes = serviceIdToBytes(components.handle);
  const payload = concatBytes(components.entropy, handleBytes);

  return bytesToUrlSafeBase64(payload);
}

/**
 * Decode SDK username link components from URL-safe base64 data.
 */
export function decodeUsernameLinkComponents(encoded: string): UsernameLinkComponents {
  const payload = base64ToBytes(asBase64(urlSafeToBase64(encoded)));

  if (payload.length !== USERNAME_LINK_COMPONENT_BYTE_LENGTH) {
    throw new Error(`Username link payload must be ${USERNAME_LINK_COMPONENT_BYTE_LENGTH} bytes`);
  }

  const entropy = payload.slice(0, USERNAME_LINK_ENTROPY_SIZE);
  const handleBytes = payload.slice(USERNAME_LINK_ENTROPY_SIZE);

  return {
    entropy,
    handle: bytesToServiceId(handleBytes),
  };
}

/**
 * Serialize username-link components into a JSON-safe shape for app sync or
 * provisioning payloads.
 */
export function serializeUsernameLinkComponents(
  components: UsernameLinkComponents
): SerializedUsernameLinkComponents {
  validateUsernameLinkEntropy(components.entropy);

  return {
    entropy: bytesToUrlSafeBase64(components.entropy),
    handle: components.handle,
  };
}

/**
 * Restore username-link components from a JSON-safe serialized snapshot.
 */
export function deserializeUsernameLinkComponents(
  serialized: SerializedUsernameLinkComponents
): UsernameLinkComponents {
  const entropy = base64ToBytes(asBase64(urlSafeToBase64(serialized.entropy)));
  validateUsernameLinkEntropy(entropy);

  return {
    entropy,
    handle: serialized.handle,
  };
}

function validateUsernameLinkEntropy(entropy: Uint8Array): void {
  if (entropy.length !== USERNAME_LINK_ENTROPY_SIZE) {
    throw new Error(`Username link entropy must be exactly ${USERNAME_LINK_ENTROPY_SIZE} bytes`);
  }
}

async function loadUsernameLinkCrypto(): Promise<
  typeof import('../internal/protocol/username/link')
> {
  return import('../internal/protocol/username/link');
}
