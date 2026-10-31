/**
 * The binary attachment of a send. The intent of a binary send stores it, so
 * a repeat of the send reuses its one upload and its one serialized message.
 *
 * A binary send uploads the file and then sends a serialized attachment
 * message that points to the upload. The intent keeps that message and the
 * digest of the file. A send that repeats a stored `clientMessageId` with the
 * same file sends the stored message again under the stored timestamp, and
 * uploads nothing.
 *
 * The client marks the options of a new binary send with the attachment, and
 * the direct and group intent builders copy the mark into the intent. The mark
 * has a symbol key that no package subpath exports, and the client sets it
 * after it spreads the application's options, so an application cannot set it.
 */

import type { StoredOutgoingMessageIntent } from '../local/store/reliability';

/** The key of the binary attachment mark. No package subpath exports it. */
export const SEND_BINARY_ATTACHMENT: unique symbol = Symbol('sendBinaryAttachment');

/** The options of a send, with the mark of its binary attachment. */
export interface SendBinaryAttachment {
  readonly [SEND_BINARY_ATTACHMENT]?: NonNullable<StoredOutgoingMessageIntent['binaryAttachment']>;
}

/**
 * The `binaryAttachment` field of a new intent: the mark of the options, or
 * no field when the options have no mark.
 */
export function intentBinaryAttachment(
  options: object
): Pick<StoredOutgoingMessageIntent, 'binaryAttachment'> {
  const binaryAttachment = (options as SendBinaryAttachment)[SEND_BINARY_ATTACHMENT];
  return binaryAttachment ? { binaryAttachment } : {};
}
