import { preparedUploadCiphertextSize } from "../media/prepared-upload";

/** @internal The queue reserves ciphertext bytes before loading a draft or contacting a broker. */
export function queuedUploadBytes(uploads: Record<string, unknown>): number {
  let total = 0;
  for (const upload of Object.values(uploads)) {
    if (!upload || typeof upload !== "object" || !("size" in upload))
      throw new Error("The saved upload lacks its local byte reservation.");
    if (typeof upload.size !== "number")
      throw new Error(
        "The saved upload has an invalid local byte reservation.",
      );
    total += preparedUploadCiphertextSize(upload.size);
    if (!Number.isSafeInteger(total))
      throw new Error(
        "The queued upload bytes exceed the supported numeric range.",
      );
  }
  return total;
}

export function assertPreparedUploadByteLimit(
  limit: number | undefined,
): asserts limit is number {
  if (typeof limit !== "number" || !Number.isSafeInteger(limit) || limit <= 0)
    throw new Error(
      "Configure media.maxPreparedUploadBytes as a positive safe integer for the device-local upload budget.",
    );
}

export function assertQueuedUploadCapacity(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
  limit: number,
): void {
  assertPreparedUploadByteLimit(limit);
  const next = queuedUploadBytes(after);
  // A lower configured limit must still let retained work settle or delete its artifacts.
  if (next > limit && next > queuedUploadBytes(before))
    throw new Error(
      "The local upload byte budget is full. Complete or abandon existing uploads before adding work.",
    );
}
