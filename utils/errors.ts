/**
 * Signal-local error helpers.
 *
 * The Signal package should not depend on app-owned error utilities.
 */

export {};

export function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

export function isError(value: unknown): value is Error {
  return value instanceof Error;
}
