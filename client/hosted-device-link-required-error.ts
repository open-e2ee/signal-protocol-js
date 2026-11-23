import { HostedSignalProtocolRelayHttpError } from './hosted-http-error';
import { copySignalProtocolRelayResponseReference } from './signal-relay-response-reference';

/** The Relay code of a registration on an account that already has a device. */
export const DEVICE_LINK_REQUIRED_CODE = 'DEVICE_LINK_REQUIRED';

/**
 * The Relay refused a registration, because the account already has a
 * device. A second device joins the account through a device link: call
 * `joinHostedSignalProtocolRelayAccount` on the new device, and approve its
 * link code with `approveHostedSignalProtocolRelayDeviceLink` on the primary
 * device. Without the primary device, recover the account.
 *
 * `status` is 409. `retryable` is false: the same registration is refused
 * again.
 */
export class HostedSignalProtocolRelayDeviceLinkRequiredError extends HostedSignalProtocolRelayHttpError {
  public constructor(status: number, message: string) {
    super(status, DEVICE_LINK_REQUIRED_CODE, message, { retryable: false });
    this.name = 'HostedSignalProtocolRelayDeviceLinkRequiredError';
  }
}

/**
 * @internal Throw a `DEVICE_LINK_REQUIRED` refusal of a registration as
 * `HostedSignalProtocolRelayDeviceLinkRequiredError`. Every other error,
 * and every error of a recovery, is thrown as it is.
 */
export function rethrowDeviceLinkRequired(error: unknown, registration: boolean): never {
  if (
    registration &&
    error instanceof HostedSignalProtocolRelayHttpError &&
    error.code === DEVICE_LINK_REQUIRED_CODE
  ) {
    throw copySignalProtocolRelayResponseReference(
      new HostedSignalProtocolRelayDeviceLinkRequiredError(error.status, error.message), error,
    );
  }
  throw error;
}
