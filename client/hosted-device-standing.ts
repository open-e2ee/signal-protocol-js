/**
 * The standing of this device at the Relay.
 *
 * A device that the Relay no longer lists cannot get a device token. Two
 * refusals name that state, and both are terminal for the stored session:
 *
 * - `HostedRelayDeviceUnknownError`: the Relay has no device for the stored
 *   session. The device token request answered `NOT_FOUND`.
 * - `HostedRelayDeviceRevokedError`: an account recovery revoked this device.
 *   Any identity route can answer `DEVICE_REVOKED`.
 *
 * The SDK never retries either request and never registers again on its own.
 * Only the application can decide to register the device again, with the
 * `reregister` assertion purpose.
 */

const DEVICE_REVOKED_MESSAGE = "The device was revoked by an account recovery.";

/**
 * The Relay has no device for the stored session, so the session cannot get
 * a device token. The message is the Relay's own message. It also names the
 * case where the account itself does not exist.
 *
 * The SDK does not retry the request and does not register again. To keep
 * this device, call `createHostedSignalProtocolClient` with the
 * `assertionPurpose` `reregister` after the user confirms it.
 */
export class HostedRelayDeviceUnknownError extends Error {
  public readonly code = "NOT_FOUND";
  /** The HTTP status of the refusal, 404 from a current Relay. */
  public readonly status: number;
  /** Always false: the same request fails again. */
  public readonly retryable = false;

  public constructor(status: number, message: string) {
    super(message);
    this.name = "HostedRelayDeviceUnknownError";
    this.status = status;
  }
}

/**
 * An account recovery revoked this device. The Relay refuses its key on the
 * device token request and on a registration, so both fail the same way. The
 * SDK does not retry the request.
 */
export class HostedRelayDeviceRevokedError extends Error {
  public readonly code = "DEVICE_REVOKED";
  /** The HTTP status of the refusal, 403 from a current Relay. */
  public readonly status: number;
  /** Always false: the Relay refuses these keys for good. */
  public readonly retryable = false;

  public constructor(status: number, message = DEVICE_REVOKED_MESSAGE) {
    super(message);
    this.name = "HostedRelayDeviceRevokedError";
    this.status = status;
  }
}

/**
 * Throws `HostedRelayDeviceRevokedError` when a Relay error body has the code
 * `DEVICE_REVOKED`, at any error status. The body code is the contract, not
 * the status.
 */
export function throwIfDeviceRevoked(status: number, body: unknown): void {
  if (
    typeof body !== "object" ||
    body === null ||
    !("error" in body) ||
    typeof body.error !== "object" ||
    body.error === null ||
    !("code" in body.error) ||
    body.error.code !== "DEVICE_REVOKED"
  )
    return;
  const message =
    "message" in body.error && typeof body.error.message === "string"
      ? body.error.message
      : undefined;
  throw new HostedRelayDeviceRevokedError(status, message);
}
