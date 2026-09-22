import type { EndorsementManager } from './endorsement-manager';

/** One verified issuer selection. Operations retain this value through every await. */
export interface GroupAuthority {
  readonly trustRoot: Uint8Array;
  readonly authorityKeyId?: string;
  readonly endorsementManager?: EndorsementManager;
}
