const responseReference = Symbol("signal-relay-response-reference");

function responseRequestId(response: Response): string | undefined {
  try {
    const value = response.headers.get("x-signal-relay-request-id");
    return value?.length === 32 && /^[A-Za-z0-9_-]{32}$/u.test(value)
      ? value
      : undefined;
  } catch {
    return undefined;
  }
}

function mark<T>(error: T, requestId: string | undefined): T {
  if (requestId === undefined || !(error instanceof Error)) return error;
  try {
    Object.defineProperties(error, {
      requestId: { value: requestId },
      [responseReference]: { value: requestId },
    });
  } catch {
    // A diagnostic reference cannot replace an immutable platform error.
  }
  return error;
}

/** @internal Attach only this response's reference to a synchronous decoder failure. */
export function readSignalProtocolRelayResponse<T>(response: Response, read: () => T): T {
  try {
    return read();
  } catch (error) {
    throw mark(error, responseRequestId(response));
  }
}

/** @internal Copy one explicitly wrapped response failure. Do not follow error causes. */
export function copySignalProtocolRelayResponseReference<T>(error: T, source: unknown): T {
  try {
    const requestId = source instanceof Error
      ? Object.getOwnPropertyDescriptor(source, responseReference)?.value as unknown
      : undefined;
    return mark(error, typeof requestId === "string" ? requestId : undefined);
  } catch {
    return error;
  }
}
