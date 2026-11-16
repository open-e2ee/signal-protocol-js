import type { Base64 } from '../types';

/** Build-pinned verification roots. Bootstrap documents cannot select or replace them. */
export const MANAGED_SIGNAL_RELAY_PROFILES = {
  prod: {
    environment: 'production',
    origin: 'https://relay.open-e2ee.dev',
    revokedIssuerKeyIds: [],
    trustRoots: ['c/YUIFyVI2CexJmHTBj0ofqqOH9yiPewipMrTGGBCMc=' as Base64],
  },
  sandbox: {
    environment: 'sandbox',
    origin: 'https://sandbox.relay.open-e2ee.dev',
    revokedIssuerKeyIds: [],
    trustRoots: ['KggSCjrGjvI+qs4FXJmg2Zy9G/1LMM4MBF5ddm1E/40=' as Base64],
  },
  stage: {
    environment: 'production',
    origin: 'https://stage.relay.open-e2ee.dev',
    revokedIssuerKeyIds: [],
    trustRoots: ['dl4g+m9cCgjbaUqOK9XlrWf8dmH/zhNxluXImiM24i4=' as Base64],
  },
  'stage-sandbox': {
    environment: 'sandbox',
    origin: 'https://stage-sandbox.relay.open-e2ee.dev',
    revokedIssuerKeyIds: [],
    trustRoots: ['M5x6m4m8bu1cntLDKaPmYcFwb6Vcgv+no+qGCre+r8w=' as Base64],
  },
} as const;

/** The build-pinned keys of one identity log. */
export interface ManagedIdentityLogTrust {
  /** The Ed25519 VRF public key of the log index. */
  readonly vrfPublicKey: Base64;
  /** The Ed25519 public keys that can sign a tree head. */
  readonly headPublicKeys: readonly Base64[];
}

/**
 * Build-pinned identity log keys of each managed profile. A profile with no
 * entry gets no key transparency checks.
 */
export const MANAGED_IDENTITY_LOG_TRUST: Partial<
  Readonly<Record<keyof typeof MANAGED_SIGNAL_RELAY_PROFILES, ManagedIdentityLogTrust>>
> = {};
