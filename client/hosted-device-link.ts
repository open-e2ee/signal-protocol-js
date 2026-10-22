import { newGroupReceiveRecord } from "../internal/groups/receive-record";
import type { GroupStateStore } from "../internal/groups/manager";
import type { SignalProtocolLocalStore } from "../types";
import { HostedRelayHttpError } from "./hosted-http-error";

/**
 * The state of a managed device link in the linked store.
 *
 * The link writes one marker before its first identity write and keeps it
 * after the Relay links the device. A later call reads the marker and resumes
 * the link from its phase:
 *
 * - `copying`: the link chose its registration IDs and the groups that it
 *   copies. It clears the records of those groups, writes the identity
 *   records again from the marker, copies the groups again, and then
 *   registers.
 * - `registering`: the link sent its registration. It sends the same
 *   registration again, so the Relay answers with the same device.
 * - `rolling-back`: the Relay refused the link. The call finishes the
 *   rollback and then links as a call with no marker.
 * - `complete`: the Relay linked the device and its first sync succeeded.
 */
export type HostedDeviceLinkPhase =
  | "copying"
  | "registering"
  | "rolling-back"
  | "complete";

export interface HostedDeviceLinkMarker {
  readonly version: 1;
  readonly phase: HostedDeviceLinkPhase;
  /** The ACI registration ID that the link sends to the Relay. */
  readonly registrationId: number;
  /** The registration ID of the PNI record, when the linked store holds one. */
  readonly pniRegistrationId?: number;
  /** The groups whose records the link writes into the linked store. */
  readonly intent: readonly string[];
}

const HOSTED_DEVICE_LINK_METADATA_KEY = "hosted-link:v1";
const PHASES: readonly HostedDeviceLinkPhase[] = [
  "copying",
  "registering",
  "rolling-back",
  "complete",
];

/**
 * The linked store already holds state that a new device link would replace.
 *
 * The link refuses a linked store in two cases, and it writes nothing before
 * either refusal:
 *
 * - The linked group store lists a group that this link did not write. The
 *   link copies the group master keys of the active device into an empty
 *   group store, and a rollback removes each copied group.
 * - The store holds a device-authentication key for this Relay connection,
 *   with no registration of this link. The Relay refuses a key that a device
 *   already holds, and a new registration ID with that key could replace the
 *   registration ID of a live device.
 *
 * Use a new, empty store for the linked device. The SDK does not retry the
 * link.
 */
export class HostedRelayDeviceLinkError extends Error {
  public readonly code = "DEVICE_LINK_STORE_NOT_EMPTY";
  /** Always false: the same store is refused again. */
  public readonly retryable = false;

  public constructor(message: string) {
    super(message);
    this.name = "HostedRelayDeviceLinkError";
  }
}

function isRegistrationId(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= 1 &&
    value <= 0x3fff
  );
}

function invalidMarker(): Error {
  return new Error("Stored Signal Protocol Relay device link state is invalid");
}

/** Reads the link marker of the linked store, or null when it has none. */
export async function readHostedDeviceLinkMarker(
  storage: SignalProtocolLocalStore,
): Promise<HostedDeviceLinkMarker | null> {
  const stored = await storage.getMetadata(HOSTED_DEVICE_LINK_METADATA_KEY);
  if (stored === null || stored === undefined) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(stored);
  } catch {
    throw invalidMarker();
  }
  if (typeof parsed !== "object" || parsed === null) throw invalidMarker();
  const marker = parsed as Record<string, unknown>;
  if (
    marker.version !== 1 ||
    !PHASES.includes(marker.phase as HostedDeviceLinkPhase) ||
    !isRegistrationId(marker.registrationId) ||
    (marker.pniRegistrationId !== undefined &&
      !isRegistrationId(marker.pniRegistrationId)) ||
    !Array.isArray(marker.intent) ||
    !marker.intent.every((groupId) => typeof groupId === "string")
  ) {
    throw invalidMarker();
  }
  return {
    version: 1,
    phase: marker.phase as HostedDeviceLinkPhase,
    registrationId: marker.registrationId,
    ...(marker.pniRegistrationId === undefined
      ? {}
      : { pniRegistrationId: marker.pniRegistrationId as number }),
    intent: [...(marker.intent as string[])],
  };
}

/** Writes the link marker as one metadata value. */
export async function writeHostedDeviceLinkMarker(
  storage: SignalProtocolLocalStore,
  marker: HostedDeviceLinkMarker,
): Promise<void> {
  await storage.setMetadata(
    HOSTED_DEVICE_LINK_METADATA_KEY,
    JSON.stringify(marker),
  );
}

export async function deleteHostedDeviceLinkMarker(
  storage: SignalProtocolLocalStore,
): Promise<void> {
  await storage.deleteMetadata(HOSTED_DEVICE_LINK_METADATA_KEY);
}

/**
 * True for a Relay refusal that shows that no device holds this link.
 *
 * `KEY_PROOF_INVALID` refuses the link body or a device-authentication key
 * that a device already holds. `CONFLICT` refuses a device past the account's
 * device limit. The Relay sends each one before it links a device, and with
 * `retryable` false. Every other error can follow an earlier success, so it
 * keeps the link state.
 */
export function isHostedDeviceLinkRefusal(error: unknown): boolean {
  return (
    error instanceof HostedRelayHttpError &&
    !error.retryable &&
    (error.code === "KEY_PROOF_INVALID" || error.code === "CONFLICT")
  );
}

/**
 * Refuses a linked group store that lists a group outside the link intent.
 *
 * With no marker, the intent is empty, so any listed group refuses the link.
 * The index can list a group with no record, and that group refuses the link
 * too. The check only reads.
 */
export async function refuseLinkedGroupState(
  groupStore: GroupStateStore,
  marker: HostedDeviceLinkMarker | null,
): Promise<void> {
  const intent = new Set(marker?.intent ?? []);
  const groupIds = await groupStore.listGroupReceiveRecords();
  if (groupIds.some((groupId) => !intent.has(groupId))) {
    throw new HostedRelayDeviceLinkError(
      "Signal Protocol Relay linked device store already holds group state",
    );
  }
}

/**
 * Removes the record of each group in `groupIds` from the linked group store.
 *
 * A null update removes a record only when one exists, but the index can list
 * a group with no record. So each group first gets a record, and the null
 * update then removes the record and its index entry.
 */
export async function clearHostedDeviceLinkIntent(
  groupStore: GroupStateStore,
  groupIds: readonly string[],
): Promise<void> {
  for (const groupId of groupIds) {
    await groupStore.updateGroupReceiveRecord(
      groupId,
      (current) => current ?? newGroupReceiveRecord("local"),
    );
    await groupStore.updateGroupReceiveRecord(groupId, () => null);
  }
}

/**
 * Copies the master key of each group in `groupIds` from the active group
 * store to the linked group store. A group with no master key is skipped. A
 * new linked record has source `local`.
 */
export async function copyHostedDeviceLinkGroups(
  activeGroupStore: GroupStateStore,
  groupStore: GroupStateStore,
  groupIds: readonly string[],
): Promise<void> {
  for (const groupId of groupIds) {
    const masterKey = await activeGroupStore.getMasterKey(groupId);
    if (masterKey === null) continue;
    await groupStore.storeMasterKey(groupId, masterKey);
  }
}

/**
 * Finishes a rollback: clears the link intent and deletes the marker. The
 * identity records and the registration snapshot stay, so the next call
 * sends the same registration ID and operation ID.
 */
export async function finishHostedDeviceLinkRollback(
  storage: SignalProtocolLocalStore,
  groupStore: GroupStateStore,
  marker: HostedDeviceLinkMarker,
): Promise<void> {
  await clearHostedDeviceLinkIntent(groupStore, marker.intent);
  await deleteHostedDeviceLinkMarker(storage);
}
