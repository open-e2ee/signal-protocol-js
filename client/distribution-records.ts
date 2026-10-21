/**
 * Sender key distributions and pairwise message records.
 *
 * A distribution carries the chain key of the sender's group chain. The
 * chain key rests only in the sender key store. A MessageRecord keeps the
 * plaintext of a pairwise send so the sender can answer a retry request, so
 * the record of a send keeps the plaintext without its distribution (see
 * `SignalProtocolContentAdapter.withoutSenderKeyDistribution`). A send that
 * carries only a distribution keeps no record.
 *
 * An earlier version kept the whole plaintext. A one-time sweep at client
 * start removes the distribution from each stored record, and the retry
 * handler removes one that it finds at lookup.
 */

import type { Logger } from '../logger';
import type { SignalProtocolLocalStore } from '../types/api';
import type { SignalProtocolContentAdapter } from './content-adapter';

/** The metadata key that records a completed sweep. */
export const DISTRIBUTION_RECORDS_SWEPT_MARKER = 'migration:skdm-records-removed';

type DistributionRecordStore = Pick<
  SignalProtocolLocalStore,
  'getMetadata' | 'setMetadata' | 'rewriteMessageRecords'
>;

/**
 * Remove the sender key distribution from every stored message record, once
 * per store. A record that holds only a distribution is deleted, and the
 * other content of a record is kept. The marker is written only after the
 * sweep succeeds, so a failed sweep runs again at the next start.
 */
export async function removeDistributionsFromMessageRecords(
  storage: DistributionRecordStore,
  adapter: SignalProtocolContentAdapter,
  logger: Required<Logger>
): Promise<void> {
  if ((await storage.getMetadata(DISTRIBUTION_RECORDS_SWEPT_MARKER)) !== null) return;
  const changed = await storage.rewriteMessageRecords((record) =>
    adapter.withoutSenderKeyDistribution(record.plaintext)
  );
  await storage.setMetadata(DISTRIBUTION_RECORDS_SWEPT_MARKER, String(Date.now()));
  logger.info('Removed sender key distributions from message records', {
    category: 'E2EE',
    data: { changed },
  });
}
