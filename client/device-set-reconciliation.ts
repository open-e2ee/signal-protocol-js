import {
  deviceSetRefusal,
  type DeviceSetRefusal,
} from '../remote/relay/device-set';
import { relayOperationRefusal, type RelayPostAcceptance } from './relay-acceptance';
import { RelayWorkStopped } from './relay-work';

/**
 * The device-set reconciliation of a declared send.
 *
 * A send that declares its device sets posts every device of one phase in a
 * pass. When the Relay refuses the declaration of a post, the send repairs
 * every device that the refusals of the pass name, adds one to the restart
 * count of the phase in the same write, and posts the phase again. A device
 * that the Relay accepted in an earlier pass gets its stored bytes again,
 * and the Relay answers with the stored receipt. The recipient phase and the
 * sync phase each have at most 10 restarts, so at most 11 posts.
 */

/** The most restarts of one phase of a declared send. */
export const DEVICE_SET_RESTARTS_MAXIMUM = 10;

/**
 * The wait before the next pass after a repair that found no prekey bundle
 * for a listed device: 250 ms, then 500 ms, then 1 s for each later pass.
 */
export function deviceSetBundleRetryDelay(consecutiveMisses: number): number {
  if (consecutiveMisses <= 1) return 250;
  if (consecutiveMisses === 2) return 500;
  return 1000;
}

/** A phase of a declared send. The recipient phase runs first. */
export type DeviceSetPhase = 'recipient' | 'sync';

/** One device of a declared send: an account and one of its devices. */
export interface DeviceSetDevice {
  readonly userId: string;
  readonly deviceId: number;
}

/** The devices of one account that the last refusal of a phase named. */
export interface DeviceSetRefusalAccount {
  readonly userId: string;
  readonly missingDeviceIds: readonly number[];
  readonly extraDeviceIds: readonly number[];
  readonly staleDeviceIds: readonly number[];
}

/**
 * The last refusal of a phase. `DEVICE_SET_MISMATCH` and `STALE_DEVICE` are
 * the Relay's answers. `BUNDLE_NOT_FOUND` is a listed device that had no
 * prekey bundle when the send repaired it.
 */
export interface DeviceSetLastRefusal {
  readonly code: 'DEVICE_SET_MISMATCH' | 'STALE_DEVICE' | 'BUNDLE_NOT_FOUND';
  readonly accounts: readonly DeviceSetRefusalAccount[];
}

/**
 * Why a phase of a declared send ended without the acceptance of every
 * device. `exhausted`: the Relay refused the declaration after the 10th
 * restart. `expired`: the Relay refused a restart post with
 * `OPERATION_EXPIRED`, because the operation epoch of the send is outside
 * its admission window.
 */
export type DeviceSetUnresolvedReason = 'exhausted' | 'expired';

/** The terminal record of a phase that ended without reconciliation. */
export interface DeviceSetUnresolved {
  readonly phase: DeviceSetPhase;
  readonly reason: DeviceSetUnresolvedReason;
  readonly restarts: number;
  /** Absent when the phase resumed from a stored count and ended before a refusal. */
  readonly lastRefusal?: DeviceSetLastRefusal;
}

/**
 * A declared send that ended without the acceptance of every device. The
 * devices in `acceptedDevices` stay accepted. The outbox keeps the send as
 * terminal, and the SDK does not post it again. A call of `send()` with the
 * same `clientMessageId` starts a new run at 0 restarts.
 *
 * `isOutgoingMessageError` is true for this error.
 */
export class DeviceSetReconciliationError extends Error {
  override readonly name = 'DeviceSetReconciliationError';
  readonly reason: DeviceSetUnresolvedReason;
  readonly phase: DeviceSetPhase;
  readonly restarts: number;
  readonly lastRefusal: DeviceSetLastRefusal | undefined;
  readonly acceptedDevices: readonly DeviceSetDevice[];
  readonly unresolvedDevices: readonly DeviceSetDevice[];
  readonly clientMessageId: string;

  constructor(
    unresolved: DeviceSetUnresolved,
    devices: {
      readonly acceptedDevices: readonly DeviceSetDevice[];
      readonly unresolvedDevices: readonly DeviceSetDevice[];
    },
    clientMessageId: string
  ) {
    super(
      unresolved.reason === 'exhausted'
        ? `The Relay refused the device sets of the ${unresolved.phase} phase after ${String(unresolved.restarts)} restarts`
        : `The Relay refused a restart of the ${unresolved.phase} phase because the operation expired`
    );
    this.reason = unresolved.reason;
    this.phase = unresolved.phase;
    this.restarts = unresolved.restarts;
    this.lastRefusal = unresolved.lastRefusal;
    this.acceptedDevices = devices.acceptedDevices;
    this.unresolvedDevices = devices.unresolvedDevices;
    this.clientMessageId = clientMessageId;
  }
}

/**
 * The route of a send whose Relay did not mark a declared post as compared.
 * `identified-direct`: an identified post to one device. `anonymous-direct`:
 * a sealed post to one device. `anonymous-group`: the shared sealed post of a
 * group send.
 */
export type RelayProtocolRoute = 'identified-direct' | 'anonymous-direct' | 'anonymous-group';

/** The code of a Relay answer that does not follow the device-set contract. */
export type RelayProtocolErrorCode = 'DEVICE_SET_UNCHECKED';

/**
 * A Relay accepted a declared post without the `deviceSetChecked` mark. The
 * send is delivered and its result does not change, because a second post
 * could deliver the message twice. The client reports the error once for the
 * send through `onRelayProtocolError`. A sync payload of a method such as
 * `syncReadToLinkedDevices` has no send ID, so its error has no
 * `clientMessageId`.
 */
export class RelayProtocolError extends Error {
  override readonly name = 'RelayProtocolError';

  constructor(
    readonly code: RelayProtocolErrorCode,
    readonly clientMessageId: string | undefined,
    readonly route: RelayProtocolRoute
  ) {
    super('The Relay accepted a declared post without comparing its device set');
  }
}

const relayProtocolErrors = new WeakMap<object, RelayProtocolError>();

/** Mark a send result with the protocol error of its send. */
export function markRelayProtocolError<T extends object>(result: T, error: RelayProtocolError): T {
  if (!relayProtocolErrors.has(result)) relayProtocolErrors.set(result, error);
  return result;
}

/** The protocol error that a send result is marked with, if any. */
export function relayProtocolErrorOf(result: unknown): RelayProtocolError | undefined {
  return result !== null && typeof result === 'object'
    ? relayProtocolErrors.get(result)
    : undefined;
}

/** The receipt of one accepted declared post and the route of the post. */
export type DeclaredPostReceipt = readonly [RelayPostAcceptance, RelayProtocolRoute];

/** The end of the declared sync phase of a send. */
export interface DeclaredSyncOutcome {
  /** True when every sync post was accepted. */
  readonly synced: boolean;
  /** The receipt of each accepted sync post of every pass. */
  readonly accepted: readonly RelayPostAcceptance[];
}

/** The receipts of accepted sync posts. A sync copy is an identified post to an own device. */
export function syncPostReceipts(
  accepted: readonly RelayPostAcceptance[]
): DeclaredPostReceipt[] {
  return accepted.map((acceptance) => [acceptance, 'identified-direct'] as const);
}

/**
 * The protocol error of the first receipt that has no `deviceSetChecked`
 * mark, or undefined when the Relay marked each receipt.
 */
export function uncheckedDeclaredPost(
  receipts: readonly DeclaredPostReceipt[],
  clientMessageId: string | undefined
): RelayProtocolError | undefined {
  const unchecked = receipts.find(([acceptance]) => acceptance.deviceSetChecked !== true);
  return unchecked
    ? new RelayProtocolError('DEVICE_SET_UNCHECKED', clientMessageId, unchecked[1])
    : undefined;
}

/** The repairs of one account that the refusals of a pass name. */
export interface DeviceSetAccountRepair {
  readonly userId: string;
  readonly missingDeviceIds: readonly number[];
  readonly extraDeviceIds: readonly number[];
  readonly staleDeviceIds: readonly number[];
}

/**
 * Merge the refusals of one pass by account. The posts of one account in a
 * pass share one declaration, so no device is both missing and extra. A
 * device that is extra is not also repaired as stale.
 */
export function mergeDeviceSetRefusals(
  refusals: readonly DeviceSetRefusal[]
): DeviceSetAccountRepair[] {
  const accounts = new Map<
    string,
    { missing: Set<number>; extra: Set<number>; stale: Set<number> }
  >();
  const account = (userId: string) => {
    let entry = accounts.get(userId);
    if (!entry) {
      entry = { missing: new Set(), extra: new Set(), stale: new Set() };
      accounts.set(userId, entry);
    }
    return entry;
  };
  for (const refusal of refusals) {
    for (const refused of refusal.accounts) {
      const entry = account(refused.userId);
      if ('staleDeviceIds' in refused) {
        for (const deviceId of refused.staleDeviceIds) entry.stale.add(deviceId);
      } else {
        for (const deviceId of refused.missingDeviceIds) entry.missing.add(deviceId);
        for (const deviceId of refused.extraDeviceIds) entry.extra.add(deviceId);
      }
    }
  }
  const sorted = (devices: Set<number>) => [...devices].sort((a, b) => a - b);
  return [...accounts].map(([userId, entry]) => {
    for (const deviceId of entry.extra) entry.missing.delete(deviceId);
    for (const deviceId of entry.extra) entry.stale.delete(deviceId);
    return {
      userId,
      missingDeviceIds: sorted(entry.missing),
      extraDeviceIds: sorted(entry.extra),
      staleDeviceIds: sorted(entry.stale),
    };
  });
}

function lastRefusalOf(
  refusals: readonly DeviceSetRefusal[],
  repairs: readonly DeviceSetAccountRepair[]
): DeviceSetLastRefusal {
  return {
    code: refusals.some((refusal) => refusal.kind === 'mismatch')
      ? 'DEVICE_SET_MISMATCH'
      : 'STALE_DEVICE',
    accounts: repairs.map((repair) => ({
      userId: repair.userId,
      missingDeviceIds: [...repair.missingDeviceIds],
      extraDeviceIds: [...repair.extraDeviceIds],
      staleDeviceIds: [...repair.staleDeviceIds],
    })),
  };
}

/** The answer to one device post of a pass. */
export interface DeviceSetPost<T> {
  readonly device: DeviceSetDevice;
  readonly outcome: { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: unknown };
}

/** What a repair of one pass did. */
export interface DeviceSetRepairOutcome {
  /** The listed devices that had no prekey bundle. The next pass waits first. */
  readonly bundleMissing: readonly DeviceSetDevice[];
}

/** One phase of a declared send, as the reconciliation runs it. */
export interface DeviceSetPhaseRun<T> {
  readonly phase: DeviceSetPhase;
  readonly clientMessageId: string;
  /** The restart count that the outbox holds for the phase. */
  readonly restarts: number;
  /** Post every device of the phase once with its declaration. */
  pass(): Promise<readonly DeviceSetPost<T>[]>;
  /**
   * Repair the devices that the refusals name, and commit the repair with
   * the new restart count in one write.
   */
  repair(repairs: readonly DeviceSetAccountRepair[], restarts: number): Promise<DeviceSetRepairOutcome>;
  /** Record the terminal state of the phase. */
  unresolve(unresolved: DeviceSetUnresolved): Promise<void>;
  /** Wait before the next pass. Rejects when the send stops. */
  wait(milliseconds: number): Promise<void>;
  /** Log a failure of a pass that does not decide the phase. */
  logFailure?(device: DeviceSetDevice, error: unknown): void;
}

function deviceKey(device: DeviceSetDevice): string {
  return `${device.userId}\u0000${String(device.deviceId)}`;
}

/**
 * Run one phase of a declared send until every device post is accepted.
 *
 * After a pass, the first rule that applies decides:
 * 1. A stopped send throws `RelayWorkStopped`.
 * 2. A restart post that the Relay refused with `OPERATION_EXPIRED` ends the
 *    phase with `expired`. The restart count does not change.
 * 3. A device-set refusal repairs every device that the refusals of the pass
 *    name, and starts the phase again. After the 10th restart it ends the
 *    phase with `exhausted`.
 * 4. Any other failure throws the failure of the first failed device.
 *
 * @returns The answers of the last pass, all accepted
 * @throws {DeviceSetReconciliationError} when the phase ends unresolved
 */
export async function runDeviceSetPhase<T>(
  run: DeviceSetPhaseRun<T>
): Promise<readonly DeviceSetPost<T>[]> {
  let restarts = run.restarts;
  let lastRefusal: DeviceSetLastRefusal | undefined;
  let bundleMisses = 0;
  const accepted = new Map<string, DeviceSetDevice>();
  const unresolve = async (
    reason: DeviceSetUnresolvedReason,
    posts: readonly DeviceSetPost<T>[],
    named: readonly DeviceSetDevice[]
  ): Promise<never> => {
    const unresolved: DeviceSetUnresolved = {
      phase: run.phase,
      reason,
      restarts,
      ...(lastRefusal && { lastRefusal }),
    };
    await run.unresolve(unresolved);
    const unresolvedDevices = new Map<string, DeviceSetDevice>();
    for (const post of posts) {
      if (!post.outcome.ok && !accepted.has(deviceKey(post.device))) {
        unresolvedDevices.set(deviceKey(post.device), post.device);
      }
    }
    for (const device of named) {
      if (!accepted.has(deviceKey(device))) unresolvedDevices.set(deviceKey(device), device);
    }
    throw new DeviceSetReconciliationError(
      unresolved,
      {
        acceptedDevices: [...accepted.values()],
        unresolvedDevices: [...unresolvedDevices.values()],
      },
      run.clientMessageId
    );
  };

  for (;;) {
    const posts = await run.pass();
    for (const post of posts) {
      if (post.outcome.ok) accepted.set(deviceKey(post.device), post.device);
    }
    const failures = posts.flatMap((post) =>
      post.outcome.ok ? [] : [{ device: post.device, error: post.outcome.error }]
    );
    if (failures.length === 0) return posts;

    const stopped = failures.find((failure) => failure.error instanceof RelayWorkStopped);
    if (stopped) throw stopped.error;
    if (
      restarts > 0 &&
      failures.some((failure) => relayOperationRefusal(failure.error) === 'OPERATION_EXPIRED')
    ) {
      return unresolve('expired', posts, []);
    }

    const refusals = failures.flatMap((failure) => {
      const refusal = deviceSetRefusal(failure.error);
      return refusal ? [refusal] : [];
    });
    if (refusals.length === 0) {
      for (const failure of failures.slice(1)) run.logFailure?.(failure.device, failure.error);
      throw failures[0]!.error;
    }

    const repairs = mergeDeviceSetRefusals(refusals);
    lastRefusal = lastRefusalOf(refusals, repairs);
    if (restarts >= DEVICE_SET_RESTARTS_MAXIMUM) {
      const named = repairs.flatMap((repair) =>
        [...repair.missingDeviceIds, ...repair.staleDeviceIds].map((deviceId) => ({
          userId: repair.userId,
          deviceId,
        }))
      );
      return unresolve('exhausted', posts, named);
    }

    restarts += 1;
    const { bundleMissing } = await run.repair(repairs, restarts);
    if (bundleMissing.length === 0) {
      bundleMisses = 0;
      continue;
    }
    bundleMisses += 1;
    lastRefusal = {
      code: 'BUNDLE_NOT_FOUND',
      accounts: [...new Set(bundleMissing.map((device) => device.userId))].map((userId) => ({
        userId,
        missingDeviceIds: bundleMissing
          .filter((device) => device.userId === userId)
          .map((device) => device.deviceId),
        extraDeviceIds: [],
        staleDeviceIds: [],
      })),
    };
    await run.wait(deviceSetBundleRetryDelay(bundleMisses));
  }
}

/**
 * Wait for a time, or reject with `RelayWorkStopped` when the stop signal
 * aborts first.
 */
export function waitUnlessStopped(milliseconds: number, stopSignal?: AbortSignal): Promise<void> {
  if (stopSignal?.aborted) return Promise.reject(new RelayWorkStopped());
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(timer);
      reject(new RelayWorkStopped());
    };
    const timer = setTimeout(() => {
      stopSignal?.removeEventListener('abort', onAbort);
      resolve();
    }, milliseconds);
    stopSignal?.addEventListener('abort', onAbort, { once: true });
  });
}
