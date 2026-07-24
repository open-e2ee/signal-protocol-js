import type { RemoteObjectDownload, RemoteObjectUpload, RemoteObjectUploadRequest } from './types';

function requireNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new TypeError(`${field} must be a non-empty string`);
  }
  return value;
}

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireSecureUrl(value: unknown, field: string): string {
  const url = requireNonEmptyString(value, field);
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new TypeError(`${field} must be an absolute URL`);
  }
  const loopbackHost =
    parsed.hostname === 'localhost' ||
    parsed.hostname === '127.0.0.1' ||
    parsed.hostname === '[::1]';
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopbackHost)) {
    throw new TypeError(
      `${field} must use HTTPS (HTTP is allowed only for loopback development URLs)`
    );
  }
  return url;
}

function requireExpiration(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${field} must be a positive Unix timestamp in milliseconds`);
  }
  return value;
}

function normalizeHeaders(value: unknown, field: string): Record<string, string> | undefined {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${field} must be a string record`);
  }

  const headers: Record<string, string> = {};
  for (const [name, headerValue] of Object.entries(value)) {
    requireNonEmptyString(name, `${field} header name`);
    if (typeof headerValue !== 'string') {
      throw new TypeError(`${field}.${name} must be a string`);
    }
    headers[name] = headerValue;
  }
  return headers;
}

export function validateUploadRequest(
  input: RemoteObjectUploadRequest,
  maxSizeBytes: number
): void {
  requireNonEmptyString(input.requestId, 'requestId');
  requireNonEmptyString(input.contentType, 'contentType');
  if (!Number.isSafeInteger(input.contentLength) || input.contentLength < 0) {
    throw new TypeError('contentLength must be a non-negative safe integer');
  }
  if (input.contentLength > maxSizeBytes) {
    throw new RangeError(
      `Object length ${input.contentLength} exceeds configured limit ${maxSizeBytes}`
    );
  }
}

export function validateObjectId(objectId: string): void {
  requireNonEmptyString(objectId, 'objectId');
}

export function normalizeUpload(value: unknown): RemoteObjectUpload {
  const record = requireRecord(value, 'upload credentials');
  const protocol = record.protocol ?? 'put';
  if (protocol !== 'put' && protocol !== 'tus') {
    throw new TypeError('protocol must be "put" or "tus"');
  }

  const result: RemoteObjectUpload = {
    objectId: requireNonEmptyString(record.objectId, 'objectId'),
    uploadUrl: requireSecureUrl(record.uploadUrl, 'uploadUrl'),
    expiresAt: requireExpiration(record.expiresAt, 'expiresAt'),
    protocol,
  };
  const headers = normalizeHeaders(record.headers, 'headers');
  if (headers !== undefined) result.headers = headers;
  return result;
}

export function normalizeDownload(value: unknown): RemoteObjectDownload {
  const record = requireRecord(value, 'download credentials');
  const result: RemoteObjectDownload = {
    downloadUrl: requireSecureUrl(record.downloadUrl, 'downloadUrl'),
    expiresAt: requireExpiration(record.expiresAt, 'expiresAt'),
  };
  const headers = normalizeHeaders(record.headers, 'headers');
  if (headers !== undefined) result.headers = headers;
  return result;
}
