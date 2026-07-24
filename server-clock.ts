let serverOffsetMs = 0;
let hasServerOffset = false;
const MAX_TRUSTED_SAMPLE_AGE_MS = 60 * 1000;

export function recordServerClockSample(
  serverTimestamp: number | null | undefined,
  observedLocalTime: number = Date.now()
): void {
  if (typeof serverTimestamp !== 'number' || !Number.isFinite(serverTimestamp)) {
    return;
  }

  if (Math.abs(observedLocalTime - serverTimestamp) > MAX_TRUSTED_SAMPLE_AGE_MS) {
    return;
  }

  serverOffsetMs = serverTimestamp - observedLocalTime;
  hasServerOffset = true;
}

export function estimateServerTimestamp(localTime: number = Date.now()): number {
  return localTime + (hasServerOffset ? serverOffsetMs : 0);
}

/**
 * Clear the learned server-clock offset.
 *
 * Call this when account or relay state is reset so a later session does not
 * reuse a sample from the previous lifecycle.
 */
export function resetServerClock(): void {
  serverOffsetMs = 0;
  hasServerOffset = false;
}
