/**
 * The checks of the local store conformance kit. A failed check throws an
 * error that names what the store did wrong. The checks avoid class syntax,
 * so they run under any JavaScript engine.
 */

export function fail(message: string): never {
  throw new Error(message);
}

/**
 * A stable text of a value: object keys in sorted order, bytes as a list of
 * numbers, and undefined properties left out. Two stores that return equal
 * data in a different key order give the same text.
 */
function canonical(value: unknown): unknown {
  if (ArrayBuffer.isView(value)) {
    return { bytes: Array.from(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)) };
  }
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const item = (value as Record<string, unknown>)[key];
      if (item !== undefined) sorted[key] = canonical(item);
    }
    return sorted;
  }
  return value;
}

export function sameValue(actual: unknown, expected: unknown): boolean {
  return JSON.stringify(canonical(actual)) === JSON.stringify(canonical(expected));
}

export function assertEqual(actual: unknown, expected: unknown, context: string): void {
  if (!sameValue(actual, expected)) {
    fail(
      context +
        ': expected ' +
        JSON.stringify(canonical(expected)) +
        ', got ' +
        JSON.stringify(canonical(actual))
    );
  }
}

/** Fail unless `value` is null or undefined, the two forms of an absent value. */
export function assertAbsent(value: unknown, context: string): void {
  if (value !== null && value !== undefined) {
    fail(context + ': expected no value, got ' + JSON.stringify(canonical(value)));
  }
}

/** Wait for `promise` and fail when it resolves. */
export async function expectRejection(promise: Promise<unknown>, context: string): Promise<unknown> {
  let error: unknown = null;
  let rejected = false;
  await promise.then(
    function resolved() {},
    function caught(reason: unknown) {
      rejected = true;
      error = reason;
    }
  );
  if (!rejected) fail(context + ': expected the call to reject, but it resolved');
  return error;
}

/** The message of a thrown value. */
export function errorMessage(error: unknown): string {
  return error !== null && typeof error === 'object' && 'message' in error
    ? String((error as { message: unknown }).message)
    : String(error);
}
