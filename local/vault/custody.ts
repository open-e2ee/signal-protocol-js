import type { SecretVaultCustody, SignalProtocolLocalSecretVault } from '../../types/api';

/**
 * Return where a vault keeps its secrets. A vault that does not declare its
 * custody counts as `same-origin`, so an application earns a stronger level
 * only by declaring it.
 */
export function secretVaultCustody(vault: SignalProtocolLocalSecretVault): SecretVaultCustody {
  return vault.custody ?? 'same-origin';
}
