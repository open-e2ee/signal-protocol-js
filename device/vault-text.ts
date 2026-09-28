/**
 * Device state in the local secret vault
 *
 * The device ID, the device name, and the local identity public key are text.
 * The vault keeps them as UTF-8 bytes under the names in `./constants`.
 */

import type { SignalProtocolLocalSecretVault } from '../types/api';
import { bytesToString, stringToBytes } from '../internal/crypto/utils';

export {};

/** Read one text value from the vault, or null when it is absent. */
export async function readVaultText(
  vault: SignalProtocolLocalSecretVault,
  name: string
): Promise<string | null> {
  const bytes = await vault.getSecret(name);
  return bytes ? bytesToString(bytes) : null;
}

/** Write one text value to the vault. */
export async function writeVaultText(
  vault: SignalProtocolLocalSecretVault,
  name: string,
  value: string
): Promise<void> {
  await vault.setSecret(name, stringToBytes(value));
}
