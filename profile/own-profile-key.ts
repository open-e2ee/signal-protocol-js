/**
 * Own Profile Key
 *
 * The current user's profile key in the application's local secret vault.
 */

import { bytesToBase64 } from '../internal/crypto';
import type { SignalProtocolLocalSecretVault } from '../types/api';
import { requireSecretVault } from '../local/vault/require';
import { generateProfileKey, PROFILE_KEY_SIZE } from './crypto';

/** Vault secret name for the own profile key (the raw 32 bytes) */
export const OWN_PROFILE_KEY_ID = 'signal_profile_key_v1';

/**
 * Get the current user's profile key from the application's local secret vault.
 *
 * The profile key lives only in the vault that the application passes. With no
 * vault, this throws `SECRET_VAULT_REQUIRED`.
 *
 * @param vault - Local secret vault that holds the profile key
 * @returns Profile key as Uint8Array, or null if not set
 */
export async function getOwnProfileKey(
  vault: SignalProtocolLocalSecretVault
): Promise<Uint8Array | null> {
  return requireSecretVault(vault, 'getOwnProfileKey').getSecret(OWN_PROFILE_KEY_ID);
}

/**
 * Set own profile key in the application's local secret vault
 *
 * @param vault - Local secret vault that holds the profile key
 * @param key - 32-byte profile key
 */
export async function setOwnProfileKey(
  vault: SignalProtocolLocalSecretVault,
  key: Uint8Array
): Promise<void> {
  const secretVault = requireSecretVault(vault, 'setOwnProfileKey');
  if (key.length !== PROFILE_KEY_SIZE) {
    throw new Error(`Profile key must be ${PROFILE_KEY_SIZE} bytes, got ${key.length}`);
  }
  await secretVault.setSecret(OWN_PROFILE_KEY_ID, key);
}

/**
 * Get or create own profile key
 *
 * If no profile key exists, generates a new one and stores it.
 *
 * @param vault - Local secret vault that holds the profile key
 * @returns Profile key as Uint8Array
 */
export async function getOrCreateOwnProfileKey(
  vault: SignalProtocolLocalSecretVault
): Promise<Uint8Array> {
  const secretVault = requireSecretVault(vault, 'getOrCreateOwnProfileKey');
  const existing = await getOwnProfileKey(secretVault);
  if (existing) {
    return existing;
  }

  const newKey = await generateProfileKey();
  await setOwnProfileKey(secretVault, newKey);
  return newKey;
}

/**
 * Get own profile key as base64 string (for DataMessage.profileKey)
 *
 * @param vault - Local secret vault that holds the profile key
 * @returns Profile key as base64 string
 */
export async function getOwnProfileKeyBase64(
  vault: SignalProtocolLocalSecretVault
): Promise<string> {
  const key = await getOrCreateOwnProfileKey(
    requireSecretVault(vault, 'getOwnProfileKeyBase64')
  );
  return bytesToBase64(key);
}
