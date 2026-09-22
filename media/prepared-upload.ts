import type { MediaAttachmentPointer } from "./index";
import { bytesToBase64, sha256 } from "../internal/crypto";
import {
  DEFAULT_SEGMENT_SIZE,
  STREAMING_AUTH_TAG_LENGTH,
  STREAMING_HEADER_LENGTH,
} from "../internal/crypto/symmetric/streaming-aead";

/** @internal Exact ciphertext bytes for the attachment encoder's fixed segment size. */
export function preparedUploadCiphertextSize(plaintextSize: number): number {
  if (!Number.isSafeInteger(plaintextSize) || plaintextSize < 0)
    throw new Error(
      "The queued upload size must be a nonnegative safe integer.",
    );
  const first =
    DEFAULT_SEGMENT_SIZE - STREAMING_HEADER_LENGTH - STREAMING_AUTH_TAG_LENGTH;
  const rest = DEFAULT_SEGMENT_SIZE - STREAMING_AUTH_TAG_LENGTH;
  const segments = 1 + Math.ceil(Math.max(0, plaintextSize - first) / rest);
  const bytes =
    plaintextSize +
    STREAMING_HEADER_LENGTH +
    segments * STREAMING_AUTH_TAG_LENGTH;
  if (!Number.isSafeInteger(bytes))
    throw new Error(
      "The queued ciphertext size exceeds the supported numeric range.",
    );
  return bytes;
}

/** Private device-local state. Never put this record in logs or Relay requests. */
export interface PreparedMediaAttachmentUpload {
  readonly requestId: string;
  /** Immutable Unix time in milliseconds when preparation starts. */
  readonly preparedAt: number;
  readonly ciphertext: Uint8Array;
  readonly plaintextDigest: string;
  readonly pointer: Omit<
    MediaAttachmentPointer,
    "storageId" | "uploadTimestamp"
  >;
}

function canonical(value: object): string {
  return JSON.stringify(
    Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
}

/** @internal Binds the private descriptor. Upload also verifies the ciphertext digest. */
export async function preparedUploadFingerprint(
  upload: PreparedMediaAttachmentUpload,
): Promise<string> {
  return bytesToBase64(
    await sha256(
      new TextEncoder().encode(
        JSON.stringify([
          upload.requestId,
          upload.preparedAt,
          upload.plaintextDigest,
          canonical(upload.pointer),
        ]),
      ),
    ),
  );
}

/** @internal Compare concurrent preparations before accepting the store's durable winner. */
export function samePreparedUploadIntent(
  left: PreparedMediaAttachmentUpload,
  right: PreparedMediaAttachmentUpload,
  explicitClientUuid: boolean,
): boolean {
  const metadata = (upload: PreparedMediaAttachmentUpload): string =>
    canonical({
      ...upload.pointer,
      key: undefined,
      readCapability: undefined,
      digest: undefined,
      segmentSize: undefined,
      ciphertextSize: undefined,
      clientUuid: explicitClientUuid ? upload.pointer.clientUuid : undefined,
    });
  return (
    left.requestId === right.requestId &&
    left.plaintextDigest === right.plaintextDigest &&
    metadata(left) === metadata(right)
  );
}

/**
 * Application-owned storage for encrypted files and their private pointer material.
 * Store records outside queue metadata. Protect them like the device-local store.
 */
export interface MediaAttachmentPreparedUploadStore {
  /**
   * Exclude other queue mutations against this store until the callback settles.
   * Coordinate every client, tab, and process that shares the files. Process exit
   * must release ownership. A timestamp must never authorize lock takeover.
   *
   * The callback uses this store's methods. Do not take the same lock again.
   * The SDK uses this boundary for local queue checks and artifact mutations only.
   */
  withExclusiveAccess<T>(operation: () => Promise<T>): Promise<T>;

  /** Return an independent copy, or null when no preparation exists. */
  load(requestId: string): Promise<PreparedMediaAttachmentUpload | null>;

  /**
   * Atomically persist the complete record only if its request ID is absent.
   * Return an independent copy of the durable winner, including after concurrent calls.
   * Resolve only after ciphertext and private pointer material are durable together.
   * Never replace a record or expire it without the owning queue's delete call.
   */
  createIfAbsent(
    upload: PreparedMediaAttachmentUpload,
  ): Promise<PreparedMediaAttachmentUpload>;

  /** Delete the exact record. Repeated deletion must succeed. */
  delete(requestId: string): Promise<void>;
}
