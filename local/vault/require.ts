import type { SignalProtocolLocalSecretVault } from '../../types/api';
import { EncryptionError, EncryptionErrorCode } from '../../types/errors';

/**
 * Return the vault that the application passed, or throw
 * `SECRET_VAULT_REQUIRED`.
 *
 * Local secrets have no fallback store. The type system requires the vault;
 * this check names the fix for a JavaScript caller that omits it.
 */
export function requireSecretVault(
  vault: SignalProtocolLocalSecretVault | null | undefined,
  operation: string
): SignalProtocolLocalSecretVault {
  if (!vault) {
    throw new EncryptionError(
      `${operation} requires a SignalProtocolLocalSecretVault. Pass a vault, such as ` +
        'ExpoSecureStoreSignalProtocolSecretVault, or a vault that the application implements.',
      EncryptionErrorCode.SECRET_VAULT_REQUIRED,
      { operation }
    );
  }
  return vault;
}
