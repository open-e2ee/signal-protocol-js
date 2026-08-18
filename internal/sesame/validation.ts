/**
 * SESAME Configuration Validation
 *
 * Validates SESAME configuration parameters per Signal Protocol specification.
 * Checks that threshold relationships and values are correct before use.
 *
 * @see https://signal.org/docs/specifications/sesame/
 */

import { DEFAULT_SESAME_CONFIG, type SesameConfig } from './types';

/**
 * Result of SESAME configuration validation
 */
export {};
export interface SesameConfigValidation {
  /** Whether the configuration is valid for use */
  valid: boolean;
  /** Warning messages (non-fatal issues) */
  warnings: string[];
  /** Error messages (fatal issues that prevent use) */
  errors: string[];
}

/**
 * Validate SESAME configuration per Signal Protocol specification.
 *
 * Checks:
 * 1. All threshold values are positive
 * 2. Threshold ordering: MAXLATENCY < MAXSEND < MAXRECV
 * 3. SESAME invariant: MAXRECV > MAXSEND + 2*MAXLATENCY
 * 4. maxInactiveSessions is at least 1
 *
 * The SESAME invariant lets messages in flight still be
 * decrypted even if they arrive after the send threshold.
 *
 * @param config Partial or full SESAME configuration to validate
 * @returns Validation result with errors and warnings
 *
 * @example
 * ```typescript
 * const validation = validateSesameConfig({ maxSend: 1000 });
 * if (!validation.valid) {
 *   throw new Error(validation.errors.join(', '));
 * }
 * ```
 *
 * @see https://signal.org/docs/specifications/sesame/
 */
export function validateSesameConfig(config?: Partial<SesameConfig>): SesameConfigValidation {
  const warnings: string[] = [];
  const errors: string[] = [];

  // If no config provided, defaults are valid
  if (!config) {
    return { valid: true, warnings: [], errors: [] };
  }

  // Resolve final values by merging with defaults
  const maxLatency = config.maxLatency ?? DEFAULT_SESAME_CONFIG.maxLatency;
  const maxSend =
    config.maxUnacknowledgedSessionAge ?? DEFAULT_SESAME_CONFIG.maxUnacknowledgedSessionAge;
  const maxRecv = config.maxRecv ?? DEFAULT_SESAME_CONFIG.maxRecv;
  const maxInactiveSessions =
    config.maxInactiveSessions ?? DEFAULT_SESAME_CONFIG.maxInactiveSessions;

  // Validate positive values
  if (maxLatency <= 0) {
    errors.push('maxLatency must be positive');
  }
  if (maxSend <= 0) {
    errors.push('maxSend must be positive');
  }
  if (maxRecv <= 0) {
    errors.push('maxRecv must be positive');
  }
  if (maxInactiveSessions < 1) {
    errors.push('maxInactiveSessions must be >= 1');
  }

  // Validate threshold ordering: MAXLATENCY <= maxUnacknowledgedSessionAge < MAXRECV
  if (maxLatency > maxSend) {
    errors.push(
      `maxLatency (${formatDuration(maxLatency)}) must be <= maxSend (${formatDuration(maxSend)})`
    );
  }
  if (maxSend >= maxRecv) {
    errors.push(
      `maxSend (${formatDuration(maxSend)}) must be < maxRecv (${formatDuration(maxRecv)})`
    );
  }

  // Validate SESAME invariant: MAXRECV > MAXSEND + 2*MAXLATENCY
  // Messages in flight can then still be decrypted
  const minimumMaxRecv = maxSend + 2 * maxLatency;
  if (maxRecv <= minimumMaxRecv) {
    errors.push(
      `SESAME invariant violated: maxRecv (${formatDuration(maxRecv)}) must be > ` +
        `maxSend + 2*maxLatency (${formatDuration(minimumMaxRecv)})`
    );
  }

  // Warn about unusually short thresholds
  const ONE_DAY_MS = 24 * 60 * 60 * 1000;
  if (maxLatency < ONE_DAY_MS) {
    warnings.push(
      `maxLatency (${formatDuration(maxLatency)}) is less than 1 day - ` +
        'messages may be rejected if delivery is delayed'
    );
  }
  if (maxSend < 7 * ONE_DAY_MS) {
    warnings.push(
      `maxSend (${formatDuration(maxSend)}) is less than 7 days - ` + 'sessions will expire quickly'
    );
  }

  return {
    valid: errors.length === 0,
    warnings,
    errors,
  };
}

/**
 * Format milliseconds duration as human-readable string
 */
function formatDuration(ms: number): string {
  const days = ms / (24 * 60 * 60 * 1000);
  if (days >= 1) {
    return `${days.toFixed(1)} days`;
  }
  const hours = ms / (60 * 60 * 1000);
  if (hours >= 1) {
    return `${hours.toFixed(1)} hours`;
  }
  const minutes = ms / (60 * 1000);
  return `${minutes.toFixed(1)} minutes`;
}

/**
 * Assert SESAME configuration is valid, throwing on errors.
 *
 * Convenience function for use in constructors that should fail
 * immediately on invalid configuration.
 *
 * @param config Configuration to validate
 * @throws {SesameConfigError} if configuration is invalid
 *
 * @example
 * ```typescript
 * constructor(config?: Partial<SesameConfig>) {
 *   assertValidSesameConfig(config);
 *   this.config = { ...DEFAULT_SESAME_CONFIG, ...config };
 * }
 * ```
 */
export function assertValidSesameConfig(config?: Partial<SesameConfig>): void {
  const validation = validateSesameConfig(config);
  if (!validation.valid) {
    throw new SesameConfigError(`Invalid SESAME configuration: ${validation.errors.join('; ')}`);
  }
}

/**
 * Error thrown when SESAME configuration is invalid
 */
export class SesameConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SesameConfigError';
  }
}
