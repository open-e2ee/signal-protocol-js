/**
 * Device-set comparison: a relay's check that a declared post names exactly
 * the devices of each recipient account, and the refusal it answers with.
 *
 * A sender declares the device IDs that it holds for each account. A relay
 * that compares refuses the whole post when a declared set misses a device
 * or names a device that the account does not have (`DEVICE_SET_MISMATCH`).
 * When the sets agree but a registration changed, it refuses with a
 * declared `STALE_DEVICE`. Missing and extra devices come first. The SDK
 * repairs every device that a refusal names and posts again.
 *
 * A relay that compares declares itself here. Only a declared relay gets a
 * declaration, so a relay that does not compare keeps the per-send device
 * list reads. No package entry exports this module. The declaration and the
 * refusal mark are internal to the SDK.
 */

/** The devices of one account that a declared post missed or named in excess. */
export interface DeviceSetMismatchAccount {
  readonly userId: string;
  readonly missingDeviceIds: readonly number[];
  readonly extraDeviceIds: readonly number[];
}

/** The devices of one account whose registration changed. */
export interface DeviceSetStaleAccount {
  readonly userId: string;
  readonly staleDeviceIds: readonly number[];
}

/** A relay's refusal of a whole declared post. */
export type DeviceSetRefusal =
  | { readonly kind: 'mismatch'; readonly accounts: readonly DeviceSetMismatchAccount[] }
  | { readonly kind: 'stale'; readonly accounts: readonly DeviceSetStaleAccount[] };

/** One account's declared devices. */
export interface DeclaredAccountDevices {
  readonly userId: string;
  readonly deviceIds: readonly number[];
}

/** The most devices that one account can have, and so can declare. */
export const DECLARED_DEVICES_MAXIMUM = 5;

const comparingRelays = new WeakSet<object>();
const refusals = new WeakMap<object, DeviceSetRefusal>();

/** Declare that this relay compares a declared device set on every route. */
export function declareComparesDeviceSets(relay: object): void {
  comparingRelays.add(relay);
}

/**
 * Withdraw the declaration of a relay, so it acts as a relay that does not
 * compare: the client declares no device set to it and keeps the per-send
 * device list reads. This models such a relay over the in-memory relay.
 */
export function withdrawDeviceSetComparison(relay: object): void {
  comparingRelays.delete(relay);
}

/** True only for the relay object that declared itself. A wrapper is not declared. */
export function comparesDeviceSets(relay: object): boolean {
  return comparingRelays.has(relay);
}

/** Mark an error as the relay's refusal of a declared post. Returns the same error. */
export function markDeviceSetRefusal<T extends Error>(error: T, refusal: DeviceSetRefusal): T {
  refusals.set(error, refusal);
  return error;
}

/** The device-set refusal that a relay marked on this error, if any. */
export function deviceSetRefusal(error: unknown): DeviceSetRefusal | undefined {
  return error !== null && typeof error === 'object' ? refusals.get(error) : undefined;
}

function isDeviceIdList(value: unknown): value is number[] {
  return (
    Array.isArray(value) &&
    value.length <= DECLARED_DEVICES_MAXIMUM &&
    value.every(
      (id) => Number.isSafeInteger(id) && id >= 1 && id <= DECLARED_DEVICES_MAXIMUM
    )
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Reads the `details` of a relay answer to a declared post. A 409
 * `DEVICE_SET_MISMATCH` names the missing and extra devices of each account.
 * A 410 `STALE_DEVICE` with details names the stale devices. Any other
 * answer, and details that do not have this form, give `undefined`: the
 * caller then treats the answer as an ordinary failure.
 */
export function parseDeviceSetRefusal(
  code: string,
  details: unknown
): DeviceSetRefusal | undefined {
  if (!isRecord(details) || !Array.isArray(details.accounts)) return undefined;
  const entries: unknown[] = details.accounts;
  if (entries.length === 0) return undefined;
  if (code === 'DEVICE_SET_MISMATCH') {
    const accounts: DeviceSetMismatchAccount[] = [];
    for (const entry of entries) {
      if (
        !isRecord(entry) ||
        typeof entry.accountAddress !== 'string' ||
        !isDeviceIdList(entry.missingDeviceIds) ||
        !isDeviceIdList(entry.extraDeviceIds)
      ) {
        return undefined;
      }
      accounts.push({
        userId: entry.accountAddress,
        missingDeviceIds: [...entry.missingDeviceIds],
        extraDeviceIds: [...entry.extraDeviceIds],
      });
    }
    return { kind: 'mismatch', accounts };
  }
  if (code === 'STALE_DEVICE') {
    const accounts: DeviceSetStaleAccount[] = [];
    for (const entry of entries) {
      if (
        !isRecord(entry) ||
        typeof entry.accountAddress !== 'string' ||
        !isDeviceIdList(entry.staleDeviceIds)
      ) {
        return undefined;
      }
      accounts.push({ userId: entry.accountAddress, staleDeviceIds: [...entry.staleDeviceIds] });
    }
    return { kind: 'stale', accounts };
  }
  return undefined;
}

/** One listed device of an account, as a comparing relay holds it. */
export interface ListedAccountDevice {
  readonly deviceId: number;
  readonly registrationId?: number;
}

/** One destination of a declared post, with the registration it expects. */
export interface DeclaredDestination {
  readonly userId: string;
  readonly deviceId: number;
  readonly recipientRegistrationId?: number;
}

/**
 * Compares declared device sets with each account's listed devices, in the
 * relay's order: missing and extra devices on any account refuse the post
 * first. When every set agrees, a destination whose expected registration
 * differs from the listed one is stale. A destination without a registration
 * gets no stale check. An account with no list is not found, and the caller
 * answers it by its route.
 *
 * The sender's own device is never part of its own account's set.
 */
export function compareDeclaredDeviceSets(
  declared: readonly DeclaredAccountDevices[],
  destinations: readonly DeclaredDestination[],
  listed: (userId: string) => readonly ListedAccountDevice[] | undefined,
  sender?: { readonly userId: string; readonly deviceId: number }
):
  | { readonly refusal: DeviceSetRefusal }
  | { readonly notFoundUserIds: readonly string[] } {
  const mismatched: DeviceSetMismatchAccount[] = [];
  const notFoundUserIds: string[] = [];
  const devicesByAccount = new Map<string, readonly ListedAccountDevice[]>();
  for (const account of declared) {
    const devices = listed(account.userId);
    if (devices === undefined || devices.length === 0) {
      notFoundUserIds.push(account.userId);
      continue;
    }
    const current = devices.filter(
      (device) => !(sender?.userId === account.userId && sender.deviceId === device.deviceId)
    );
    devicesByAccount.set(account.userId, current);
    const declaredIds = new Set(account.deviceIds);
    const currentIds = new Set(current.map((device) => device.deviceId));
    const missingDeviceIds = [...currentIds].filter((id) => !declaredIds.has(id)).sort((a, b) => a - b);
    const extraDeviceIds = [...declaredIds].filter((id) => !currentIds.has(id)).sort((a, b) => a - b);
    if (missingDeviceIds.length > 0 || extraDeviceIds.length > 0) {
      mismatched.push({ userId: account.userId, missingDeviceIds, extraDeviceIds });
    }
  }
  if (mismatched.length > 0) return { refusal: { kind: 'mismatch', accounts: mismatched } };
  const stale = new Map<string, number[]>();
  for (const destination of destinations) {
    if (destination.recipientRegistrationId === undefined) continue;
    const device = devicesByAccount
      .get(destination.userId)
      ?.find((candidate) => candidate.deviceId === destination.deviceId);
    if (
      device?.registrationId === undefined ||
      device.registrationId === destination.recipientRegistrationId
    ) {
      continue;
    }
    stale.set(destination.userId, [...(stale.get(destination.userId) ?? []), destination.deviceId]);
  }
  if (stale.size > 0) {
    return {
      refusal: {
        kind: 'stale',
        accounts: [...stale].map(([userId, staleDeviceIds]) => ({
          userId,
          staleDeviceIds: [...staleDeviceIds].sort((a, b) => a - b),
        })),
      },
    };
  }
  return { notFoundUserIds };
}
