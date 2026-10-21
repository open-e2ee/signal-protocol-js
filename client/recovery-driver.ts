/**
 * The resend job driver of a sender device.
 *
 * A sender writes a pending resend job for each logged group send that a
 * retry request names, before the membership check and the post. The
 * driver runs the pending jobs that the answer did not finish: after a
 * restart, after a reconnect to the Relay, and after a failed post. A pass
 * runs at start(). A pass with a failed job runs again after a full-jitter
 * wait, from a 1 s ceiling that doubles up to 30 s, as the hosted mailbox
 * subscription reconnects. A pass with no failure starts the ceiling again.
 * Each pass is relay work, so a client stop stops it. A job ends at its
 * post, or as abandoned after `SEND_LOG_RESEND_JOB_TTL_MS`, as
 * `runResendJob` tells.
 *
 * @internal
 */

import type { Logger } from '../logger';
import type { SendLogStore } from '../types/api';
import {
  FIRST_RECONNECT_MILLISECONDS,
  MAXIMUM_RECONNECT_MILLISECONDS,
} from './hosted-mailbox-subscription';
import { rethrowRelayWorkStopped, type RelayWork, type RelayWorkTracker } from './relay-work';

/** What one pass of the driver reads and runs, for one relay work. */
export interface ResendJobPass {
  readonly storage: Pick<SendLogStore, 'getPendingResendJobs'>;
  readonly logger: Required<Logger>;
  /** Run one pending job. It throws when the job stays pending. */
  readonly run: (jobId: string) => Promise<void>;
}

/** @internal */
export class ResendJobDriver {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private running: Promise<void> | undefined;
  private again = false;
  private stopped = true;
  private ceiling = FIRST_RECONNECT_MILLISECONDS;

  constructor(
    private readonly relayWork: RelayWorkTracker,
    private readonly pass: (work: RelayWork) => ResendJobPass,
    private readonly random: () => number = Math.random
  ) {}

  /** Run a pass now, or one more pass after the pass that runs. The promise never rejects. */
  start(): Promise<void> {
    this.stopped = false;
    this.clear();
    return this.run();
  }

  /** Clear the retry timer. No pass starts until the next start(). */
  stop(): void {
    this.stopped = true;
    this.clear();
  }

  private clear(): void {
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
  }

  private run(): Promise<void> {
    if (this.running) {
      this.again = true;
      return this.running;
    }
    const running = (async () => {
      do {
        this.again = false;
        if (this.stopped) return;
        // A pass logs its own failures. RelayWorkStopped ends the run.
        await this.relayWork.run((work) => this.runPass(work)).catch(() => undefined);
      } while (this.again);
    })().finally(() => {
      this.running = undefined;
    });
    this.running = running;
    return running;
  }

  private async runPass(work: RelayWork): Promise<void> {
    const { storage, logger, run } = this.pass(work);
    let failed = false;
    try {
      for (const job of await storage.getPendingResendJobs()) {
        work.proceed();
        try {
          await run(job.jobId);
        } catch (error) {
          rethrowRelayWorkStopped(error);
          failed = true;
          logger.warn('A resend job failed and stays pending', {
            category: 'E2EE',
            data: {
              jobId: job.jobId,
              behavior: 'RESEND_JOB_RETRY',
              error: (error as Error).message,
            },
          });
        }
      }
    } catch (error) {
      rethrowRelayWorkStopped(error);
      failed = true;
      logger.warn('The resend job driver failed to list the pending jobs', {
        category: 'E2EE',
        data: { behavior: 'RESEND_JOB_RETRY', error: (error as Error).message },
      });
    }
    if (failed) this.retryLater();
    else this.ceiling = FIRST_RECONNECT_MILLISECONDS;
  }

  /** Arm one pass after a full-jitter wait, and double the ceiling. */
  private retryLater(): void {
    if (this.stopped || this.timer !== undefined) return;
    const delay = Math.floor(this.random() * this.ceiling);
    this.ceiling = Math.min(MAXIMUM_RECONNECT_MILLISECONDS, this.ceiling * 2);
    const timer = setTimeout(() => {
      if (this.timer !== timer) return;
      this.timer = undefined;
      void this.run();
    }, delay);
    (timer as { unref?: () => void }).unref?.();
    this.timer = timer;
  }
}
