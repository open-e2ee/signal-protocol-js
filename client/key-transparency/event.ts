import type { KeyTransparencyVerificationError } from '../../internal/protocol/key-transparency/errors';

/**
 * A key transparency check that failed.
 *
 * - `subject: 'contact'`: the check of a contact identity that the client
 *   fetched. `userId` is the contact. The client raises one event for each
 *   failed `(userId, identity)` pair for the life of the client. A key
 *   mismatch or a not-logged result raises the event only when a second
 *   check 2 hours later gives one of them again.
 * - `subject: 'self'`: the weekly check of the own account. The client
 *   raises the event on the second consecutive failure, once for each
 *   failing streak. A not-logged result is a failure.
 * - A pending append raises the event only when the append still waits 24
 *   hours after the first pending result.
 *
 * A failed check never refuses a send. A result that the client cannot get,
 * such as a network error, raises no event.
 */
export type KeyTransparencyFailureEvent =
  | {
      readonly subject: 'contact';
      /** The contact whose identity failed the check. */
      readonly userId: string;
      /** The failure. `error.code` names the step that failed. */
      readonly error: KeyTransparencyVerificationError;
      /** The local time of the failure, Unix milliseconds. */
      readonly detectedAt: number;
    }
  | {
      readonly subject: 'self';
      /** The failure. `error.code` names the step that failed. */
      readonly error: KeyTransparencyVerificationError;
      /** The local time of the failure, Unix milliseconds. */
      readonly detectedAt: number;
    };
