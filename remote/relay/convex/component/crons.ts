import { cronJobs } from 'convex/server';
import { internal } from './_generated/api';

const crons = cronJobs();

crons.interval(
  'delete expired relay messages',
  { hours: 1 },
  internal.cleanup.cleanupExpiredMessages,
  {}
);

crons.interval(
  'delete expired provisioning sessions',
  { minutes: 1 },
  internal.cleanup.cleanupExpiredProvisioningSessions,
  {}
);

crons.interval(
  'delete expired retry requests',
  { hours: 1 },
  internal.cleanup.cleanupExpiredRetryRequests,
  {}
);

crons.interval(
  'delete expired multi-recipient payloads',
  { hours: 1 },
  internal.cleanup.cleanupExpiredMultiRecipientPayloads,
  {}
);

crons.interval(
  'delete stale KEM prekeys',
  { hours: 24 },
  internal.cleanup.cleanupStaleKemPreKeys,
  {}
);

export default crons;
