export interface StoreFailureOptions {
  /**
   * Stable offset for cadence-based write failures. The same seed and options
   * always fail the same writes.
   */
  seed?: number;
  /** Fail every Nth mutating store operation. */
  writeFailureEvery?: number;
}

export class InjectedStorageWriteError extends Error {
  constructor(readonly operation: string) {
    super(`Injected storage write failure during ${operation}`);
    this.name = 'InjectedStorageWriteError';
  }
}

/**
 * Deterministic storage-failure controls for recovery examples and tests.
 *
 * Explicit failures and cadence selection are counter/seed based. They never
 * consult Math.random or wall-clock time.
 */
export class StoreFailureController {
  private seed: number;
  private writeFailureEvery?: number;
  private writeOrdinal = 0;
  private scheduled = new Map<string, number>();

  constructor(options?: StoreFailureOptions) {
    this.seed = options?.seed ?? 0;
    this.writeFailureEvery = options?.writeFailureEvery;
    this.validate();
  }

  configure(options: Partial<StoreFailureOptions>): void {
    const candidateSeed = options.seed ?? this.seed;
    const candidateWriteFailureEvery =
      'writeFailureEvery' in options ? options.writeFailureEvery : this.writeFailureEvery;
    this.validate(candidateSeed, candidateWriteFailureEvery);
    this.seed = candidateSeed;
    this.writeFailureEvery = candidateWriteFailureEvery;
  }

  failNextWrite(operation = '*', count = 1): void {
    if (!Number.isInteger(count) || count < 1) {
      throw new RangeError('count must be a positive integer');
    }
    this.scheduled.set(operation, (this.scheduled.get(operation) ?? 0) + count);
  }

  beforeWrite(operation: string): void {
    this.writeOrdinal += 1;
    if (this.consumeScheduled(operation) || this.consumeScheduled('*')) {
      throw new InjectedStorageWriteError(operation);
    }
    if (
      this.writeFailureEvery &&
      (this.writeOrdinal + this.seed) % this.writeFailureEvery === 0
    ) {
      throw new InjectedStorageWriteError(operation);
    }
  }

  reset(): void {
    this.writeOrdinal = 0;
    this.scheduled.clear();
  }

  snapshot(): Readonly<StoreFailureOptions> {
    return { seed: this.seed, writeFailureEvery: this.writeFailureEvery };
  }

  private consumeScheduled(operation: string): boolean {
    const count = this.scheduled.get(operation) ?? 0;
    if (count === 0) return false;
    if (count === 1) this.scheduled.delete(operation);
    else this.scheduled.set(operation, count - 1);
    return true;
  }

  private validate(
    seed = this.seed,
    writeFailureEvery = this.writeFailureEvery
  ): void {
    if (!Number.isInteger(seed) || seed < 0) {
      throw new RangeError('seed must be a non-negative integer');
    }
    if (
      writeFailureEvery !== undefined &&
      (!Number.isInteger(writeFailureEvery) || writeFailureEvery < 1)
    ) {
      throw new RangeError('writeFailureEvery must be a positive integer');
    }
  }
}
