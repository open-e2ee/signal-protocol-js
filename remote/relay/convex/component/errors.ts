import { ConvexError, type Value } from 'convex/values';

export type RelayErrorCode =
  | 'CONFLICT'
  | 'INVALID_REQUEST'
  | 'NOT_FOUND'
  | 'NOT_IMPLEMENTED'
  | 'RATE_LIMITED'
  | 'STALE_DEVICE'
  | 'UNAUTHORIZED';

interface RelayErrorDetails {
  staleDevices?: number[];
  reason?: string;
  retryAfter?: number;
}

export type RelayErrorData = {
  code: RelayErrorCode;
  status: number;
  message: string;
} & RelayErrorDetails & {
    [key: string]: Value | undefined;
  };

export function relayError(
  code: RelayErrorCode,
  status: number,
  message: string,
  details: RelayErrorDetails = {}
): ConvexError<RelayErrorData> {
  return new ConvexError({
    code,
    status,
    message,
    ...details,
  });
}

export function unauthorized(message: string): ConvexError<{
  code: 'UNAUTHORIZED';
  status: 401;
  message: string;
}> {
  return new ConvexError({
    code: 'UNAUTHORIZED',
    status: 401,
    message: `Unauthorized: ${message}`,
  });
}
