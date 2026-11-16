/**
 * The reason a device link through the Signal Protocol Relay stopped. The
 * one-process `linkHostedSignalProtocolRelayDevice` gives only `NOT_PRIMARY`.
 *
 * - `LINK_CODE_INVALID`: the link code has the wrong form or an unknown
 *   version, or the KEM public key that the Relay returned does not match the
 *   hash in the code.
 * - `LINK_CODE_EXPIRED`: the provisioning channel of the code is closed, or
 *   the link token expired before the new device linked.
 * - `DEVICE_LIMIT_REACHED`: the account has no free device slot.
 * - `NOT_PRIMARY`: only device 1 of the account can approve a link, link a
 *   device with `linkHostedSignalProtocolRelayDevice`, or send a first sync
 *   with `sendHostedSignalProtocolRelayFirstSync`.
 * - `ENVELOPE_INVALID`: the new device cannot open or read the envelope.
 * - `ENVELOPE_TOO_LARGE`: the envelope is larger than the channel accepts.
 * - `STORE_NOT_EMPTY`: the store of the new device holds an identity.
 * - `LINK_TOKEN_REJECTED`: the Relay refused the link token.
 * - `SIGNAL_RELAY_UNSUPPORTED`: the Relay has no provisioning channel.
 * - `CANCELLED`: the `AbortSignal` of the call fired. A first sync also
 *   gives it when the client stops during the send.
 * - `DEVICE_NOT_REMOVED`: `resetRemovedHostedSignalProtocolRelayDevice` found
 *   that the Relay still serves the device of the store.
 * - `DEVICE_NOT_FOUND`: `renameHostedSignalProtocolRelayDevice` found no
 *   device in the slot, or `sendHostedSignalProtocolRelayFirstSync` found no
 *   listed own device with the device ID, or the Relay accepted no copy for
 *   that device.
 */
export type HostedSignalProtocolRelayDeviceProvisioningErrorCode =
  | "LINK_CODE_INVALID"
  | "LINK_CODE_EXPIRED"
  | "DEVICE_LIMIT_REACHED"
  | "NOT_PRIMARY"
  | "ENVELOPE_INVALID"
  | "ENVELOPE_TOO_LARGE"
  | "STORE_NOT_EMPTY"
  | "LINK_TOKEN_REJECTED"
  | "SIGNAL_RELAY_UNSUPPORTED"
  | "CANCELLED"
  | "DEVICE_NOT_REMOVED"
  | "DEVICE_NOT_FOUND";

/**
 * A device link stopped. The same input gives the same refusal, so
 * `retryable` is always false.
 */
export class HostedSignalProtocolRelayDeviceProvisioningError extends Error {
  public readonly code: HostedSignalProtocolRelayDeviceProvisioningErrorCode;
  /** Always false: the same input is refused again. */
  public readonly retryable = false as const;

  public constructor(
    code: HostedSignalProtocolRelayDeviceProvisioningErrorCode,
    message: string,
    options?: { readonly cause?: unknown },
  ) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.code = code;
    this.name = "HostedSignalProtocolRelayDeviceProvisioningError";
  }
}
