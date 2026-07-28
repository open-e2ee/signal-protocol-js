/**
 * Group Invite Link Creation and Parsing
 *
 * Serializes the package's versioned group-invite payload.
 *
 * Format:
 * - Byte 0: version (0x01 for v1)
 * - Bytes 1-32: GroupMasterKey (32 bytes)
 * - Bytes 33-48: inviteLinkPassword (16 bytes)
 * - Total: 49 bytes, base64url-encoded
 *
 * Default URL format: https://join.open-e2ee.dev/#<base64url_encoded_data>
 * The link prefix is configurable per call via the `linkPrefix` parameter.
 */

import { GROUP_MASTER_KEY_LEN } from '../protocol/zk/groups';
import { bytesToUrlSafeBase64, urlSafeToBase64, base64ToBytes } from '../crypto/utils';
import { asBase64 } from '../../types/utils';

/**
 * Length of the invite link password in bytes.
 */
export {};
export const INVITE_LINK_PASSWORD_LEN = 16;

/**
 * Current invite link format version.
 */
export const INVITE_LINK_VERSION = 0x01;

/**
 * Default URL prefix for group invite links. Override it per call with the
 * `linkPrefix` parameter on {@link createGroupInviteLink} and
 * {@link parseGroupInviteLink}.
 */
export const INVITE_LINK_PREFIX = 'https://join.open-e2ee.dev/#';

/**
 * Total length of the serialized invite link data.
 * 1 byte version + 32 bytes master key + 16 bytes password = 49 bytes
 */
const INVITE_LINK_DATA_LEN = 1 + GROUP_MASTER_KEY_LEN + INVITE_LINK_PASSWORD_LEN;

/**
 * Generates a cryptographically random invite link password.
 *
 * @returns A 16-byte random password.
 */
export function generateInviteLinkPassword(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(INVITE_LINK_PASSWORD_LEN));
}

/**
 * Creates a group invite link URL from a master key and password.
 *
 * @param masterKey - The group master key (32 bytes).
 * @param inviteLinkPassword - The invite link password (16 bytes).
 * @returns The complete invite link URL.
 * @throws Error if inputs have invalid lengths.
 */
export function createGroupInviteLink(
  masterKey: Uint8Array,
  inviteLinkPassword: Uint8Array,
  linkPrefix: string = INVITE_LINK_PREFIX
): string {
  if (masterKey.length !== GROUP_MASTER_KEY_LEN) {
    throw new Error(
      `Invalid master key length: expected ${GROUP_MASTER_KEY_LEN}, got ${masterKey.length}`
    );
  }
  if (inviteLinkPassword.length !== INVITE_LINK_PASSWORD_LEN) {
    throw new Error(
      `Invalid password length: expected ${INVITE_LINK_PASSWORD_LEN}, got ${inviteLinkPassword.length}`
    );
  }

  // Serialize: [version, masterKey, password]
  const data = new Uint8Array(INVITE_LINK_DATA_LEN);
  data[0] = INVITE_LINK_VERSION;
  data.set(masterKey, 1);
  data.set(inviteLinkPassword, 1 + GROUP_MASTER_KEY_LEN);

  // Encode and create URL
  const encoded = bytesToUrlSafeBase64(data);
  return linkPrefix + encoded;
}

/**
 * Parses a group invite link URL.
 *
 * @param url - The invite link URL to parse.
 * @returns The parsed master key and password, or null if invalid.
 */
export function parseGroupInviteLink(
  url: string,
  linkPrefix: string = INVITE_LINK_PREFIX
): {
  masterKey: Uint8Array;
  inviteLinkPassword: Uint8Array;
} | null {
  // Check and strip prefix
  if (!url.startsWith(linkPrefix)) {
    return null;
  }

  const encoded = url.slice(linkPrefix.length);

  // Decode base64url
  const data = base64urlDecode(encoded);
  if (!data) {
    return null;
  }

  // Validate format
  if (data.length !== INVITE_LINK_DATA_LEN) {
    return null;
  }
  if (data[0] !== INVITE_LINK_VERSION) {
    return null;
  }

  // Extract components
  const masterKey = data.slice(1, 1 + GROUP_MASTER_KEY_LEN);
  const inviteLinkPassword = data.slice(1 + GROUP_MASTER_KEY_LEN, INVITE_LINK_DATA_LEN);

  return { masterKey, inviteLinkPassword };
}

/**
 * Decodes base64url format to bytes.
 *
 * Composes urlSafeToBase64 and base64ToBytes from the shared crypto utilities.
 *
 * @param str - The base64url-encoded string.
 * @returns Decoded bytes, or null on error.
 */
function base64urlDecode(str: string): Uint8Array | null {
  try {
    return base64ToBytes(asBase64(urlSafeToBase64(str)));
  } catch {
    return null;
  }
}
