/**
 * The protection declaration case: the store declares a valid protection,
 * and the result reports it.
 */

import { readLocalStoreProtection } from '../../../../client/storage-protection';
import type { LocalStoreConformanceCase } from '../types';

export const protectionCases: readonly LocalStoreConformanceCase[] = [
  {
    name: 'protection declaration',
    run: async function protectionDeclaration(context) {
      context.reportProtection(readLocalStoreProtection(context.store));
    },
  },
];
