/**
 * The identity log keys of a hosted connection. The keys are pinned in the
 * build for each managed profile (`MANAGED_IDENTITY_LOG_TRUST`). The
 * connection document cannot select or replace them. A connection to a
 * profile with no pins, or to a Relay that is not a managed profile, has no
 * keys, and its checks give `unavailable`.
 */
import { base64ToBytes } from '../../internal/crypto';
import type { IdentityLogTrust } from '../../internal/protocol/key-transparency/search-verification';
import { TREE_HEAD_PUBLIC_KEY_BYTES } from '../../internal/protocol/key-transparency/tree-head';
import { VRF_PUBLIC_KEY_BYTES } from '../../internal/protocol/key-transparency/vrf';
import type { HostedSignalProtocolRelayConnection } from '../hosted-connection';
import {
  MANAGED_IDENTITY_LOG_TRUST,
  MANAGED_SIGNAL_RELAY_PROFILES,
  type ManagedIdentityLogTrust,
} from '../hosted-trust';

type ManagedProfile = keyof typeof MANAGED_SIGNAL_RELAY_PROFILES;

function pinnedKey(value: string, length: number): Uint8Array {
  const key = base64ToBytes(value as ManagedIdentityLogTrust['vrfPublicKey']);
  if (key.length !== length) {
    throw new Error('The build has an invalid identity log key');
  }
  return key;
}

/**
 * Returns the pinned identity log keys of the profile of `connection`, or
 * `undefined` when the profile has none. Throws when a pinned key has the
 * wrong length, because that is a build defect.
 */
export function identityLogTrustOf(
  connection: Pick<HostedSignalProtocolRelayConnection, 'protocolEndpoint'>,
  pins: Partial<Readonly<Record<ManagedProfile, ManagedIdentityLogTrust>>> = MANAGED_IDENTITY_LOG_TRUST
): IdentityLogTrust | undefined {
  const profile = (Object.keys(MANAGED_SIGNAL_RELAY_PROFILES) as ManagedProfile[]).find(
    (name) => connection.protocolEndpoint === `${MANAGED_SIGNAL_RELAY_PROFILES[name].origin}/signal/v1`
  );
  const pinned = profile === undefined ? undefined : pins[profile];
  if (pinned === undefined || pinned.headPublicKeys.length === 0) return undefined;
  return {
    vrfPublicKey: pinnedKey(pinned.vrfPublicKey, VRF_PUBLIC_KEY_BYTES),
    headPublicKeys: pinned.headPublicKeys.map((key) => pinnedKey(key, TREE_HEAD_PUBLIC_KEY_BYTES)),
  };
}
