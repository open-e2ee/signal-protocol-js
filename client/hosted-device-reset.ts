/**
 * The reset of a removed device, so that it can join its account again.
 *
 * A removed device keeps its store: the account identity, its sessions, its
 * device key, and the join marker. A join refuses that store with
 * `STORE_NOT_EMPTY`. The reset asks the Relay first, and it deletes the
 * local account state only when the Relay refuses the stored device as
 * revoked.
 */
import type { SignalProtocolLocalStore } from "../types";
import { getExistingDeviceAuthentication } from "./hosted-device-authentication";
import { hostedSignalProtocolRelayUrl, resolveHostedSignalProtocolRelayConnection } from "./hosted-connection";
import { clearHostedDeviceLinkIntent } from "./hosted-device-link";
import { HostedSignalProtocolRelayDeviceProvisioningError } from "./hosted-device-provisioning-error";
import { HostedSignalProtocolRelayDeviceRevokedError } from "./hosted-device-standing";
import type { HostedGroupOptions } from "./hosted-group-authority";
import { resumeHostedSignalProtocolRelayTransport } from "./hosted-transport";

/** The options of `resetRemovedHostedSignalProtocolRelayDevice`. */
export interface HostedSignalProtocolRelayDeviceResetOptions {
  readonly adapters: {
    /**
     * The store of the removed device. Stop each client of this store before
     * the reset, and do not use the store until the reset settles.
     */
    readonly storage: SignalProtocolLocalStore;
  };
  readonly hosted: {
    /** The public environment-scoped Signal Protocol Relay connection URL. */
    readonly relayUrl: string;
  };
  /**
   * The group options of the removed client. Give them when the client had
   * a `groups.store` of its own, so that the reset also deletes each group
   * that the store lists. The SDK group store is in `storage`.
   */
  readonly groups?: HostedGroupOptions;
}

/**
 * Deletes the local account state of a removed device, so that the same
 * store can join the account again with `joinHostedSignalProtocolRelayAccount`.
 *
 * The reset renews the device token of the stored device session. It deletes
 * the state only when the Relay refuses the renewal with
 * `HostedSignalProtocolRelayDeviceRevokedError`, as it does after
 * `removeHostedSignalProtocolRelayDevice` or an account recovery. It deletes
 * the identities, the sessions, the prekeys, the message records, the device
 * key, the device session, the join marker, and the groups. It sends nothing
 * to the Relay after the renewal, and it does not store the renewed token.
 *
 * - When the Relay still serves the device, the reset throws
 *   `HostedSignalProtocolRelayDeviceProvisioningError` with the code
 *   `DEVICE_NOT_REMOVED`. It deletes nothing.
 * - The reset throws each other failure unchanged and deletes nothing.
 *   Examples are a store with no device session and a network failure.
 *
 * A reset that stops before `storage.clearAllKeys()` starts keeps the device
 * session, so call it again. A reset that stops during
 * `storage.clearAllKeys()` can delete the device key. A second call then
 * fails with `HostedSignalProtocolRelayResumeError` before it sends a
 * request. After that failure, call `storage.clearAllKeys()` to delete the
 * remaining state.
 */
export async function resetRemovedHostedSignalProtocolRelayDevice(
  options: HostedSignalProtocolRelayDeviceResetOptions,
): Promise<void> {
  const storage = options.adapters.storage;
  const connection = await resolveHostedSignalProtocolRelayConnection(
    hostedSignalProtocolRelayUrl(options.hosted, "resetRemovedHostedSignalProtocolRelayDevice"),
  );
  try {
    await resumeHostedSignalProtocolRelayTransport({
      connection,
      deviceAuthentication: await getExistingDeviceAuthentication(storage, connection.publishableKey, true),
      storage,
      requireExisting: true,
      persistRefreshedToken: false,
    });
  } catch (error) {
    if (!(error instanceof HostedSignalProtocolRelayDeviceRevokedError)) throw error;
    await deleteAccountState(storage, options.groups);
    return;
  }
  throw new HostedSignalProtocolRelayDeviceProvisioningError(
    "DEVICE_NOT_REMOVED",
    "The Signal Protocol Relay still serves this device, so the reset deleted nothing",
  );
}

/**
 * Deletes the groups of an application group store first, and the SDK
 * store last. A stop between the two keeps the device session, so a second
 * reset can prove the removal again.
 */
async function deleteAccountState(
  storage: SignalProtocolLocalStore,
  groups: HostedGroupOptions | undefined,
): Promise<void> {
  const groupStore = groups?.store;
  if (groupStore !== undefined) {
    const groupIds = await groupStore.listGroupReceiveRecords();
    for (const groupId of groupIds) {
      await groupStore.deleteMasterKey(groupId);
      await groupStore.deleteGroupState(groupId);
    }
    await clearHostedDeviceLinkIntent(groupStore, groupIds);
  }
  await storage.clearAllKeys();
}
