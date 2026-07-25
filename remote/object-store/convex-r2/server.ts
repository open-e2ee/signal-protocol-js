import {
  actionGeneric,
  mutationGeneric,
  type ApiFromModules,
  type FunctionReference,
  type GenericActionCtx,
  type GenericDataModel,
  type GenericMutationCtx,
} from 'convex/server';
import { v } from 'convex/values';
import type { R2 } from '@convex-dev/r2';
import type {
  RemoteObjectCompleteUploadRequest,
  RemoteObjectDeleteRequest,
  RemoteObjectDownload,
  RemoteObjectDownloadRequest,
  RemoteObjectUpload,
  RemoteObjectUploadRequest,
} from '../types';
import type { ConvexR2ObjectStoreApi } from './storage';

const MAX_PRESIGNED_EXPIRY_SECONDS = 7 * 24 * 60 * 60;
const MAX_IDENTIFIER_LENGTH = 1_024;

type R2ActionContext = Pick<
  GenericActionCtx<GenericDataModel>,
  'runQuery' | 'runMutation' | 'runAction'
>;
type R2MutationContext = Pick<
  GenericMutationCtx<GenericDataModel>,
  'runQuery' | 'runMutation'
>;

/** Stable identifiers reserved by the application for one logical upload. */
export type ConvexR2ObjectReservation = {
  /** Canonical identifier exposed in encrypted attachment pointers. */
  objectId: string;
  /** Private key used only when calling the R2 component. */
  providerKey: string;
};

/** Operation-specific lookup performed by the application data model. */
export type ConvexR2ResolveObjectRequest = {
  objectId: string;
  operation: 'download' | 'complete';
};

/** App-owned object state needed to authorize and complete an R2 operation. */
export type ConvexR2ResolvedObject = {
  providerKey: string;
  contentType: string;
  contentLength: number;
};

/** App-owned deletion result retained long enough to schedule provider removal. */
export type ConvexR2RemovedObject = {
  providerKey: string;
};

/**
 * Internal app functions that own authorization, idempotency, and persistence.
 *
 * Auth identity is propagated by Convex when these references are called from
 * the public functions returned by `defineConvexR2ObjectStore()`.
 */
export interface ConvexR2ObjectCallbacks {
  /**
   * Authorize and reserve one upload.
   *
   * The application must scope `requestId` to the authenticated principal and
   * return the same `objectId` and `providerKey` for every valid retry.
   */
  reserve: FunctionReference<
    'mutation',
    'internal',
    RemoteObjectUploadRequest,
    ConvexR2ObjectReservation
  >;
  /** Authorize and resolve an object for the requested operation. */
  resolve: FunctionReference<
    'query',
    'internal',
    ConvexR2ResolveObjectRequest,
    ConvexR2ResolvedObject | null
  >;
  /**
   * Re-authorize and idempotently mark a provider-verified upload complete.
   *
   * This callback runs in a separate transaction after `resolve`, so it must
   * re-check the authenticated principal and current object state.
   */
  complete: FunctionReference<
    'mutation',
    'internal',
    RemoteObjectCompleteUploadRequest,
    null
  >;
  /**
   * Authorize and logically remove an object.
   *
   * The application must return the same provider key on retries. The mutation
   * that invokes this callback also schedules the component deletion, so a
   * scheduling failure rolls back the logical removal.
   */
  remove: FunctionReference<
    'mutation',
    'internal',
    RemoteObjectDeleteRequest,
    ConvexR2RemovedObject | null
  >;
}

/**
 * Structural subset of `@convex-dev/r2` used by the server helper.
 *
 * The application creates and configures the real `R2` instance. Keeping this
 * interface structural avoids a runtime dependency from the SDK entry point.
 */
export interface ConvexR2ServerClient {
  generateUploadUrl(providerKey: string): Promise<{ key: string; url: string }>;
  getUrl(providerKey: string, options?: { expiresIn?: number }): Promise<string>;
  syncMetadata(ctx: R2ActionContext, providerKey: string): Promise<void>;
  getMetadata(
    ctx: R2ActionContext,
    providerKey: string
  ): Promise<{ contentType?: string; size?: number } | null>;
  deleteObject(ctx: R2MutationContext, providerKey: string): Promise<void>;
}

type RequireServerClient<T extends ConvexR2ServerClient> = T;
type LatestR2IsCompatible = RequireServerClient<R2>;

export interface ConvexR2ObjectStoreLimits {
  /** Maximum encrypted object length accepted by the public upload mutation. */
  maxContentLength: number;
  /**
   * Explicit allowlist for encrypted-object MIME types.
   *
   * Signal Protocol media integrations should allow only `application/octet-stream`.
   */
  allowedContentTypes: readonly string[];
  /** Requested lifetime for download URLs. Upload expiry comes from R2. */
  downloadExpiresInSeconds?: number;
}

export interface DefineConvexR2ObjectStoreConfig {
  /** App-created `R2` client backed by the app-mounted component. */
  r2: ConvexR2ServerClient;
  /** Required backend upload and URL policy. */
  limits: ConvexR2ObjectStoreLimits;
  /** App-owned internal functions for policy and persistence. */
  objects: ConvexR2ObjectCallbacks;
}

function requireIdentifier(value: string, field: string): string {
  if (value.trim().length === 0 || value.length > MAX_IDENTIFIER_LENGTH) {
    throw new Error(`${field} must contain 1-${MAX_IDENTIFIER_LENGTH} characters`);
  }
  return value;
}

function requireContentLength(value: number, maxContentLength: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error('contentLength must be a non-negative safe integer');
  }
  if (value > maxContentLength) {
    throw new Error(`contentLength exceeds the configured limit of ${maxContentLength} bytes`);
  }
  return value;
}

function requireAllowedContentType(
  value: string,
  allowedContentTypes: ReadonlySet<string>
): string {
  if (!allowedContentTypes.has(value)) {
    throw new Error(`contentType is not allowed: ${value}`);
  }
  return value;
}

function findQueryParameter(url: URL, expectedName: string): string {
  const matches = [...url.searchParams.entries()].filter(
    ([name]) => name.toLowerCase() === expectedName.toLowerCase()
  );
  if (matches.length !== 1 || !matches[0]?.[1]) {
    throw new Error(`Presigned URL must contain exactly one ${expectedName} parameter`);
  }
  return matches[0][1];
}

function parseAmzDate(value: string): number {
  const match =
    /^(?<year>\d{4})(?<month>\d{2})(?<day>\d{2})T(?<hour>\d{2})(?<minute>\d{2})(?<second>\d{2})Z$/.exec(
      value
    );
  if (!match?.groups) {
    throw new Error('Presigned URL contains a malformed X-Amz-Date parameter');
  }

  const parts = {
    year: Number(match.groups.year),
    month: Number(match.groups.month),
    day: Number(match.groups.day),
    hour: Number(match.groups.hour),
    minute: Number(match.groups.minute),
    second: Number(match.groups.second),
  };
  const timestamp = Date.UTC(
    parts.year,
    parts.month - 1,
    parts.day,
    parts.hour,
    parts.minute,
    parts.second
  );
  const parsed = new Date(timestamp);
  if (
    parsed.getUTCFullYear() !== parts.year ||
    parsed.getUTCMonth() !== parts.month - 1 ||
    parsed.getUTCDate() !== parts.day ||
    parsed.getUTCHours() !== parts.hour ||
    parsed.getUTCMinutes() !== parts.minute ||
    parsed.getUTCSeconds() !== parts.second
  ) {
    throw new Error('Presigned URL contains an invalid X-Amz-Date parameter');
  }
  return timestamp;
}

/** Extract the real expiry encoded in an AWS Signature Version 4 URL. */
export function getConvexR2PresignedUrlExpiresAt(value: string): number {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('Presigned URL must be absolute');
  }
  if (url.protocol !== 'https:') {
    throw new Error('Presigned URL must use HTTPS');
  }

  const issuedAt = parseAmzDate(findQueryParameter(url, 'X-Amz-Date'));
  const expiresValue = findQueryParameter(url, 'X-Amz-Expires');
  if (!/^\d+$/.test(expiresValue)) {
    throw new Error('Presigned URL contains a malformed X-Amz-Expires parameter');
  }
  const expiresInSeconds = Number(expiresValue);
  if (
    !Number.isSafeInteger(expiresInSeconds) ||
    expiresInSeconds <= 0 ||
    expiresInSeconds > MAX_PRESIGNED_EXPIRY_SECONDS
  ) {
    throw new Error(
      `Presigned URL expiry must be between 1 and ${MAX_PRESIGNED_EXPIRY_SECONDS} seconds`
    );
  }
  const expiresAt = issuedAt + expiresInSeconds * 1_000;
  if (!Number.isSafeInteger(expiresAt)) {
    throw new Error('Presigned URL expiry is outside the supported timestamp range');
  }
  return expiresAt;
}

function validateLimits(limits: ConvexR2ObjectStoreLimits): {
  maxContentLength: number;
  allowedContentTypes: ReadonlySet<string>;
  downloadExpiresInSeconds: number | undefined;
} {
  if (!Number.isSafeInteger(limits.maxContentLength) || limits.maxContentLength <= 0) {
    throw new Error('limits.maxContentLength must be a positive safe integer');
  }
  const contentTypes = [...limits.allowedContentTypes];
  if (
    contentTypes.length === 0 ||
    contentTypes.some((contentType) => contentType.trim().length === 0)
  ) {
    throw new Error('limits.allowedContentTypes must contain at least one MIME type');
  }

  const expiresIn = limits.downloadExpiresInSeconds;
  if (
    expiresIn !== undefined &&
    (!Number.isSafeInteger(expiresIn) ||
      expiresIn <= 0 ||
      expiresIn > MAX_PRESIGNED_EXPIRY_SECONDS)
  ) {
    throw new Error(
      `limits.downloadExpiresInSeconds must be between 1 and ${MAX_PRESIGNED_EXPIRY_SECONDS}`
    );
  }

  return {
    maxContentLength: limits.maxContentLength,
    allowedContentTypes: new Set(contentTypes),
    downloadExpiresInSeconds: expiresIn,
  };
}

const uploadResultValidator = v.object({
  objectId: v.string(),
  uploadUrl: v.string(),
  expiresAt: v.number(),
  headers: v.optional(v.record(v.string(), v.string())),
  protocol: v.optional(v.union(v.literal('put'), v.literal('tus'))),
});

const downloadResultValidator = v.object({
  downloadUrl: v.string(),
  expiresAt: v.number(),
  headers: v.optional(v.record(v.string(), v.string())),
});

/**
 * Register the public Convex broker API around an app-owned R2 component.
 *
 * This helper owns validators, URL expiry extraction, provider calls, and
 * metadata verification. The application still owns the component instance,
 * authentication, authorization, object records, and identifier mappings.
 */
export function defineConvexR2ObjectStore(config: DefineConvexR2ObjectStoreConfig) {
  const limits = validateLimits(config.limits);
  const { r2, objects } = config;

  return {
    createUpload: mutationGeneric({
      args: {
        requestId: v.string(),
        contentType: v.string(),
        contentLength: v.number(),
      },
      returns: uploadResultValidator,
      handler: async (ctx, input): Promise<RemoteObjectUpload> => {
        requireIdentifier(input.requestId, 'requestId');
        requireAllowedContentType(input.contentType, limits.allowedContentTypes);
        requireContentLength(input.contentLength, limits.maxContentLength);

        const reservation = await ctx.runMutation(objects.reserve, input);
        requireIdentifier(reservation.objectId, 'objectId');
        requireIdentifier(reservation.providerKey, 'providerKey');
        const operation = await r2.generateUploadUrl(reservation.providerKey);
        if (operation.key !== reservation.providerKey) {
          throw new Error('R2 returned a provider key that differs from the app reservation');
        }

        return {
          objectId: reservation.objectId,
          uploadUrl: operation.url,
          expiresAt: getConvexR2PresignedUrlExpiresAt(operation.url),
          headers: { 'Content-Type': input.contentType },
          protocol: 'put',
        };
      },
    }),

    createDownload: actionGeneric({
      args: {
        objectId: v.string(),
      },
      returns: v.union(downloadResultValidator, v.null()),
      handler: async (ctx, input): Promise<RemoteObjectDownload | null> => {
        requireIdentifier(input.objectId, 'objectId');
        const resolved = await ctx.runQuery(objects.resolve, {
          objectId: input.objectId,
          operation: 'download',
        });
        if (resolved === null) {
          return null;
        }
        requireIdentifier(resolved.providerKey, 'providerKey');
        const downloadUrl = await r2.getUrl(resolved.providerKey, {
          expiresIn: limits.downloadExpiresInSeconds,
        });
        return {
          downloadUrl,
          expiresAt: getConvexR2PresignedUrlExpiresAt(downloadUrl),
        };
      },
    }),

    completeUpload: actionGeneric({
      args: {
        objectId: v.string(),
      },
      returns: v.null(),
      handler: async (ctx, input): Promise<null> => {
        requireIdentifier(input.objectId, 'objectId');
        const resolved = await ctx.runQuery(objects.resolve, {
          objectId: input.objectId,
          operation: 'complete',
        });
        if (resolved === null) {
          throw new Error(`Remote object not found: ${input.objectId}`);
        }
        requireIdentifier(resolved.providerKey, 'providerKey');
        requireAllowedContentType(resolved.contentType, limits.allowedContentTypes);
        requireContentLength(resolved.contentLength, limits.maxContentLength);

        await r2.syncMetadata(ctx, resolved.providerKey);
        const metadata = await r2.getMetadata(ctx, resolved.providerKey);
        if (metadata === null) {
          throw new Error(`R2 metadata was not found for object: ${input.objectId}`);
        }
        if (metadata.size !== resolved.contentLength) {
          throw new Error(`R2 object length does not match the reserved upload`);
        }
        if (metadata.contentType !== resolved.contentType) {
          throw new Error(`R2 object content type does not match the reserved upload`);
        }

        await ctx.runMutation(objects.complete, input);
        return null;
      },
    }),

    deleteObject: mutationGeneric({
      args: {
        objectId: v.string(),
      },
      returns: v.null(),
      handler: async (ctx, input): Promise<null> => {
        requireIdentifier(input.objectId, 'objectId');
        const removed = await ctx.runMutation(objects.remove, input);
        if (removed !== null) {
          requireIdentifier(removed.providerKey, 'providerKey');
          await r2.deleteObject(ctx, removed.providerKey);
        }
        return null;
      },
    }),
  };
}

type GeneratedConvexR2ObjectStoreApi = ApiFromModules<{
  signalObjectStore: ReturnType<typeof defineConvexR2ObjectStore>;
}>['signalObjectStore'];
type RequireClientApi<T extends ConvexR2ObjectStoreApi> = T;
type GeneratedModuleIsClientCompatible =
  RequireClientApi<GeneratedConvexR2ObjectStoreApi>;

// These aliases intentionally fail compilation if the installed component or
// Convex code-generation shape drifts from the public integration contracts.
type ConvexR2CompatibilityChecks = [
  LatestR2IsCompatible,
  GeneratedModuleIsClientCompatible,
];
