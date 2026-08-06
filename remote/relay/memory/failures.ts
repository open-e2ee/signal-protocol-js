import type { Envelope } from '../types';

export interface RelayFailureOptions {
  /**
   * Stable offset for cadence-based failures. The same seed and options always
   * produce the same delivery schedule.
   */
  seed?: number;
  /** Delay relay acceptance and live delivery by this many milliseconds. */
  latencyMs?: number;
  /** Deliver every Nth live envelope twice. */
  duplicateDeliveryEvery?: number;
  /** Hold live envelopes in pairs and deliver each pair newest-first. */
  reorderDeliveryPairs?: boolean;
  /** Reject sealed-sender authorization so callers exercise identified fallback. */
  rejectAuthorization?: boolean;
  /** Serve no EC or KEM one-time prekeys, while retaining signed/last-resort keys. */
  exhaustOneTimePreKeys?: boolean;
}

type DeliverEnvelope = (targetKey: string, envelope: Envelope) => void;
type DeliverPending = (targetKey: string) => void;

function positiveInteger(value: number | undefined, name: string): void {
  if (value !== undefined && (!Number.isInteger(value) || value < 1)) {
    throw new RangeError(`${name} must be a positive integer`);
  }
}

/**
 * Deterministic controls for educational failure and recovery exercises.
 *
 * Failure selection is counter/seed based. It never consults Math.random or
 * wall-clock time.
 */
export class RelayFailureController {
  private options: Required<
    Pick<
      RelayFailureOptions,
      'seed' | 'latencyMs' | 'reorderDeliveryPairs' | 'rejectAuthorization' | 'exhaustOneTimePreKeys'
    >
  > &
    Pick<RelayFailureOptions, 'duplicateDeliveryEvery'>;
  private disconnectedTargets = new Set<string>();
  private reorderBuffers = new Map<string, Envelope>();
  private deliveryOrdinal = 0;

  constructor(
    options: RelayFailureOptions | undefined,
    private readonly deliverEnvelope: DeliverEnvelope,
    private readonly deliverPending: DeliverPending
  ) {
    this.options = {
      seed: options?.seed ?? 0,
      latencyMs: options?.latencyMs ?? 0,
      duplicateDeliveryEvery: options?.duplicateDeliveryEvery,
      reorderDeliveryPairs: options?.reorderDeliveryPairs ?? false,
      rejectAuthorization: options?.rejectAuthorization ?? false,
      exhaustOneTimePreKeys: options?.exhaustOneTimePreKeys ?? false,
    };
    this.validate();
  }

  configure(options: Partial<RelayFailureOptions>): void {
    const candidate = { ...this.options, ...options };
    this.validate(candidate);
    this.options = candidate;
  }

  snapshot(): Readonly<RelayFailureOptions> {
    return { ...this.options };
  }

  async waitForLatency(): Promise<void> {
    if (this.options.latencyMs === 0) return;
    await new Promise<void>((resolve) => setTimeout(resolve, this.options.latencyMs));
  }

  disconnect(userId: string, deviceId: number): void {
    this.disconnectedTargets.add(`${userId}:${deviceId}`);
  }

  reconnect(userId: string, deviceId: number): void {
    const targetKey = `${userId}:${deviceId}`;
    this.disconnectedTargets.delete(targetKey);
    this.deliverPending(targetKey);
  }

  isDisconnected(targetKey: string): boolean {
    return this.disconnectedTargets.has(targetKey);
  }

  shouldRejectAuthorization(): boolean {
    return this.options.rejectAuthorization;
  }

  shouldExhaustOneTimePreKeys(): boolean {
    return this.options.exhaustOneTimePreKeys;
  }

  deliver(targetKey: string, envelope: Envelope): void {
    if (this.isDisconnected(targetKey)) return;

    if (this.options.reorderDeliveryPairs) {
      const held = this.reorderBuffers.get(targetKey);
      if (!held) {
        this.reorderBuffers.set(targetKey, structuredClone(envelope));
        return;
      }
      this.reorderBuffers.delete(targetKey);
      this.deliverWithDuplicates(targetKey, envelope);
      this.deliverWithDuplicates(targetKey, held);
      return;
    }

    this.deliverWithDuplicates(targetKey, envelope);
  }

  /**
   * Drop transient delivery state before replaying the durable pending mailbox.
   *
   * The mailbox remains the source of truth, so retaining a buffered envelope
   * across replay would deliver that envelope twice when the next pair arrives.
   */
  discardReordered(targetKey: string): void {
    this.reorderBuffers.delete(targetKey);
  }

  isReorderBuffered(targetKey: string, envelopeId: string | undefined): boolean {
    if (!envelopeId) return false;
    return this.reorderBuffers.get(targetKey)?.id === envelopeId;
  }

  flushReordered(): void {
    for (const [targetKey, envelope] of this.reorderBuffers) {
      if (this.isDisconnected(targetKey)) continue;
      this.reorderBuffers.delete(targetKey);
      this.deliverWithDuplicates(targetKey, envelope);
    }
  }

  reset(): void {
    this.disconnectedTargets.clear();
    this.reorderBuffers.clear();
    this.deliveryOrdinal = 0;
  }

  private deliverWithDuplicates(targetKey: string, envelope: Envelope): void {
    this.deliveryOrdinal += 1;
    this.deliverEnvelope(targetKey, envelope);
    const cadence = this.options.duplicateDeliveryEvery;
    if (cadence && (this.deliveryOrdinal + this.options.seed) % cadence === 0) {
      this.deliverEnvelope(targetKey, envelope);
    }
  }

  private validate(options = this.options): void {
    if (!Number.isInteger(options.seed) || options.seed < 0) {
      throw new RangeError('seed must be a non-negative integer');
    }
    if (!Number.isFinite(options.latencyMs) || options.latencyMs < 0) {
      throw new RangeError('latencyMs must be a non-negative finite number');
    }
    positiveInteger(options.duplicateDeliveryEvery, 'duplicateDeliveryEvery');
  }
}
