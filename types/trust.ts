/**
 * trust.ts
 *
 * Trust and identity verification types for the Signal Protocol.
 * Provides Direction and IdentityChange enums.
 *
 * The Signal Protocol uses Trust On First Use (TOFU) combined with
 * ongoing verification to detect man-in-the-middle attacks. These types
 * support identity key change detection and context-aware trust decisions.
 *
 * @see Signal Protocol Specification - Section 3.3: Identity Key Management
 */

/**
 * Direction of message flow for trust verification context.
 *
 * Trust verification behavior differs based on whether you're sending
 * or receiving a message:
 *
 * - SENDING: Stricter verification. Don't send to untrusted identities.
 *   Prevent accidentally leaking information to attackers.
 *
 * - RECEIVING: More permissive. Allow receiving from changed identities
 *   but warn the user. Maintains communication while alerting to risks.
 *
 * Receiving and sending can use different product policies: sending to an
 * untrusted identity risks disclosure, while receiving can surface the change
 * without releasing new plaintext to that identity.
 *
 * @example
 * ```typescript
 * // Before sending
 * const trusted = await isTrustedIdentity(
 *   address,
 *   theirIdentityKey,
 *   TrustDirection.SENDING
 * );
 * if (!trusted) {
 *   throw new UntrustedIdentityError(address, theirIdentityKey);
 * }
 *
 * // When receiving
 * const trusted = await isTrustedIdentity(
 *   address,
 *   theirIdentityKey,
 *   TrustDirection.RECEIVING
 * );
 * if (!trusted) {
 *   // Log warning but allow decryption
 *   logger.warn('Receiving from untrusted identity', { address });
 * }
 * ```
 */
export {};
export enum TrustDirection {
  /**
   * Message is being sent to the remote party.
   *
   * Use stricter verification:
   * - Require explicit user trust for new identities
   * - Block sending if identity key has changed without user confirmation
   * - Prevent information leakage to potential attackers
   */
  SENDING = 'sending',

  /**
   * Message is being received from the remote party.
   *
   * Use more permissive verification:
   * - Allow receiving from new identities (TOFU)
   * - Allow receiving from changed identities with warning
   * - Maintain communication while alerting user to risks
   */
  RECEIVING = 'receiving',
}

/**
 * Result of identity key verification indicating whether the key changed.
 *
 * Used to detect possible man-in-the-middle (MITM) attacks when identity
 * keys change unexpectedly.
 *
 * From Signal Protocol:
 * "Identity keys should rarely change. A change could indicate device
 * reinstallation or an active attack."
 *
 * @example
 * ```typescript
 * const change = await saveContactIdentity(address, newIdentityKey);
 *
 * if (change === IdentityKeyChange.REPLACED_EXISTING) {
 *   // SECURITY ALERT!
 *   // This could be legitimate (device reinstall) or an attack
 *   logger.error('Identity key changed!', {
 *     address,
 *     oldKey: await getContactIdentity(address),
 *     newKey: newIdentityKey
 *   });
 *
 *   // Show UI warning to user
 *   await showSecurityAlert({
 *     title: 'Security Alert',
 *     message: `${address.userId}'s security code has changed. ` +
 *              'This could mean they reinstalled the app, or ' +
 *              'someone is trying to intercept your messages.',
 *     actions: ['Verify Safety Number', 'Accept', 'Cancel']
 *   });
 * }
 * ```
 */
export enum IdentityKeyChange {
  NEW_IDENTITY = 'new_identity',
  UNCHANGED = 'unchanged',
  CHANGED = 'changed',
  ROLLBACK = 'rollback',
}

// TrustVerificationResult type alias was removed as it was just `boolean` with no
// added type safety. Use `boolean` directly in function signatures.

/**
 * Options for trust verification behavior.
 *
 * Allows customizing trust verification policies per-app needs. Identity
 * substitution is fail-closed in both directions and is not configurable.
 *
 * @example
 * ```typescript
 * const options: TrustVerificationOptions = {
 *   // In a high-security app, might want to block all unknowns
 *   trustNewIdentitiesAutomatically: false,
 *
 *   // In a consumer app, might be more permissive for receiving
 *   allowReceivingFromUntrusted: true,
 *
 *   // Require re-verification after identity changes
 *   requireReverificationAfterChange: true,
 * };
 * ```
 */
export interface TrustVerificationOptions {
  /**
   * Automatically trust new identities (TOFU model).
   *
   * true (default): First contact is automatically trusted
   * false: Require manual verification for all new identities
   */
  trustNewIdentitiesAutomatically?: boolean;

  /**
   * Allow receiving messages from untrusted identities.
   *
   * true (default): Receive but warn user
   * false: Reject messages from untrusted sources
   */
  allowReceivingFromUntrusted?: boolean;

  /**
   * Require re-verification after identity key changes.
   *
   * true (default): Block communication until user verifies
   * false: Allow communication with warning only
   */
  requireReverificationAfterChange?: boolean;

  /**
   * Automatically archive old sessions when identity changes.
   *
   * true (default): Start fresh session after identity change
   * false: Keep old session alongside new one
   */
  archiveSessionsOnIdentityChange?: boolean;
}

/**
 * Default trust-verification options for trust on first use.
 */
export const DEFAULT_TRUST_OPTIONS: Required<TrustVerificationOptions> = {
  trustNewIdentitiesAutomatically: true, // Explicitly unverified TOFU
  allowReceivingFromUntrusted: false, // Substitution always fails closed
  requireReverificationAfterChange: true, // Require user action on change
  archiveSessionsOnIdentityChange: true, // Start fresh after change
};
