import type { Base64 } from '../types';

/** Build-pinned verification roots. Bootstrap documents cannot select or replace them. */
export const MANAGED_RELAY_PROFILES = {
  'customer-development': {
    environment: 'development',
    origin: 'https://development.relay.open-e2ee.dev',
    revokedIssuerKeyIds: [],
    trustRoots: ['KggSCjrGjvI+qs4FXJmg2Zy9G/1LMM4MBF5ddm1E/40=' as Base64],
  },
  production: {
    environment: 'production',
    origin: 'https://relay.open-e2ee.dev',
    revokedIssuerKeyIds: [],
    trustRoots: ['c/YUIFyVI2CexJmHTBj0ofqqOH9yiPewipMrTGGBCMc=' as Base64],
  },
  staging: {
    environment: 'production',
    origin: 'https://staging.relay.open-e2ee.dev',
    revokedIssuerKeyIds: [],
    trustRoots: ['dl4g+m9cCgjbaUqOK9XlrWf8dmH/zhNxluXImiM24i4=' as Base64],
  },
  'staging-customer-development': {
    environment: 'development',
    origin: 'https://staging-customer-development.relay.open-e2ee.dev',
    revokedIssuerKeyIds: [],
    trustRoots: ['M5x6m4m8bu1cntLDKaPmYcFwb6Vcgv+no+qGCre+r8w=' as Base64],
  },
} as const;
