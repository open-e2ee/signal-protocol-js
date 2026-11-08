import { parseUrl, utf8Decode, type ParsedUrl } from '../internal/platform';
import {
  base64ToBytes,
  bytesToUrlSafeBase64,
  concatBytes,
  urlSafeToBase64,
} from '../internal/crypto';
import type { Base64 } from '../types';
import { MANAGED_SIGNAL_RELAY_PROFILES } from './hosted-trust';
import { withSignalProtocolRelayRequestDeadline } from './signal-relay-request-deadline';

export interface HostedSignalProtocolRelayCertificateTrust {
  readonly revokedIssuerKeyIds: readonly number[];
  readonly trustRoots: readonly Uint8Array[];
}

export interface HostedSignalProtocolRelayConnection {
  readonly certificateTrust: HostedSignalProtocolRelayCertificateTrust;
  readonly configurationVersion: number;
  readonly environment: 'sandbox' | 'production';
  readonly protocolEndpoint: string;
  readonly publishableKey: string;
  readonly relayScopeId: Uint8Array;
  readonly signalProtocolRelayUrl: string;
}

type ManagedSignalProtocolRelayProfile = keyof typeof MANAGED_SIGNAL_RELAY_PROFILES;
const CONNECTION_PATH = /^\/signal\/v1\/connection\/([A-Za-z0-9_-]{1,255})$/u;
const CONNECTION_FRESH_MILLISECONDS = 5 * 60 * 1_000;
const CONNECTION_STALE_MILLISECONDS = 60 * 60 * 1_000;
const CONNECTION_DOCUMENT_MAXIMUM_BYTES = 8 * 1_024;
const connectionCache = new Map<
  string,
  { readonly connection: HostedSignalProtocolRelayConnection; readonly resolvedAt: number }
>();
const CONNECTION_DOCUMENT_KEYS = [
  'configurationVersion',
  'environment',
  'protocolEndpoint',
  'publishableKey',
  'relayScopeId',
  'schemaVersion',
] as const;

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseSignalProtocolRelayUrl(value: string): {
  environment: HostedSignalProtocolRelayConnection['environment'];
  locator: string;
  profile: ManagedSignalProtocolRelayProfile;
  signalProtocolRelayUrl: string;
} {
  let url: ParsedUrl;
  try {
    url = parseUrl(value);
  } catch {
    throw new Error('Signal Protocol Relay connection URL is invalid');
  }
  const profile = Object.entries(MANAGED_SIGNAL_RELAY_PROFILES).find(
    ([, candidate]) => url.origin === candidate.origin,
  )?.[0] as ManagedSignalProtocolRelayProfile | undefined;
  const locator = CONNECTION_PATH.exec(url.pathname)?.[1];
  if (
    profile === undefined ||
    locator === undefined ||
    url.search !== '' ||
    url.href !== value
  ) {
    throw new Error('Signal Protocol Relay connection URL is invalid');
  }
  return {
    environment: MANAGED_SIGNAL_RELAY_PROFILES[profile].environment,
    locator,
    profile,
    signalProtocolRelayUrl: url.href,
  };
}

function compiledCertificateTrust(
  profile: ManagedSignalProtocolRelayProfile,
): HostedSignalProtocolRelayCertificateTrust {
  const trust = MANAGED_SIGNAL_RELAY_PROFILES[profile];
  return {
    revokedIssuerKeyIds: [...trust.revokedIssuerKeyIds],
    trustRoots: trust.trustRoots.map((root) => base64ToBytes(root)),
  };
}

function parseSignalProtocolRelayScopeId(value: unknown): Uint8Array | undefined {
  if (
    typeof value !== 'string' ||
    !/^[A-Za-z0-9_-]{22}$/u.test(value)
  ) {
    return undefined;
  }
  try {
    const decoded = base64ToBytes(urlSafeToBase64(value) as Base64);
    return decoded.length === 16 && bytesToUrlSafeBase64(decoded) === value
      ? decoded
      : undefined;
  } catch {
    return undefined;
  }
}

function cloneConnection(
  connection: HostedSignalProtocolRelayConnection,
): HostedSignalProtocolRelayConnection {
  return {
    ...connection,
    certificateTrust: {
      revokedIssuerKeyIds: [
        ...connection.certificateTrust.revokedIssuerKeyIds,
      ],
      trustRoots: connection.certificateTrust.trustRoots.map((root) =>
        root.slice(),
      ),
    },
    relayScopeId: connection.relayScopeId.slice(),
  };
}

async function connectionError(response: Response): Promise<Error> {
  let code: unknown;
  try {
    const body = await boundedJson(response);
    code =
      record(body) && record(body.error) && typeof body.error.code === 'string'
        ? body.error.code
        : undefined;
  } catch {
    code = undefined;
  }
  if (code === 'DEPLOYMENT_SUSPENDED') {
    return new Error('Signal Protocol Relay deployment is suspended');
  }
  if (code === 'PRODUCTION_INACTIVE') {
    return new Error('Signal Protocol Relay production deployment is not active');
  }
  if (response.status === 404) {
    return new Error('Signal Protocol Relay connection does not exist or is stale');
  }
  if (response.status === 403 && code === 'SCOPE_MISMATCH') {
    return new Error('Signal Protocol Relay connection belongs to another environment');
  }
  if (response.status === 410) {
    return new Error('Signal Protocol Relay connection is no longer active');
  }
  return new Error('Signal Protocol Relay connection could not be resolved');
}

async function boundedJson(response: Response): Promise<unknown> {
  const declaredLength = response.headers.get('content-length');
  if (
    declaredLength !== null &&
    (!/^\d+$/.test(declaredLength) ||
      Number(declaredLength) > CONNECTION_DOCUMENT_MAXIMUM_BYTES)
  ) {
    throw new Error('Signal Protocol Relay returned an invalid connection');
  }
  try {
    const body = response.body as ReadableStream<Uint8Array> | null | undefined;
    if (typeof body?.getReader === 'function') {
      const reader = body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      for (;;) {
        const result = await reader.read();
        if (result.done) break;
        size += result.value.byteLength;
        if (size > CONNECTION_DOCUMENT_MAXIMUM_BYTES) {
          await reader.cancel();
          throw new Error('Signal Protocol Relay returned an invalid connection');
        }
        chunks.push(result.value);
      }
      return JSON.parse(utf8Decode(concatBytes(...chunks))) as unknown;
    }

    // React Native and Expo use a fetch implementation without response body
    // streams. Preserve their standard text() path and enforce the same UTF-8
    // byte limit after decoding.
    const text = await response.text();
    if (
      new TextEncoder().encode(text).byteLength >
      CONNECTION_DOCUMENT_MAXIMUM_BYTES
    ) {
      throw new Error('Signal Protocol Relay returned an invalid connection');
    }
    return JSON.parse(text) as unknown;
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === 'Signal Protocol Relay returned an invalid connection'
    ) {
      throw error;
    }
    throw new Error('Signal Protocol Relay returned an invalid connection');
  }
}

/** Resolve one public environment-scoped Signal Protocol Relay connection. */
export async function resolveHostedSignalProtocolRelayConnection(
  value: string,
): Promise<HostedSignalProtocolRelayConnection> {
  const input = parseSignalProtocolRelayUrl(value);
  const cached = connectionCache.get(input.signalProtocolRelayUrl);
  if (
    cached !== undefined &&
    Date.now() - cached.resolvedAt <= CONNECTION_FRESH_MILLISECONDS
  ) {
    return cloneConnection(cached.connection);
  }
  // A Relay that cannot be reached, or that does not answer before the
  // deadline, gives no document. A stale cached connection then still applies.
  const document = await withSignalProtocolRelayRequestDeadline(async (signal) => {
    let response: Response;
    try {
      response = await fetch(input.signalProtocolRelayUrl, {
        credentials: 'omit',
        headers: { accept: 'application/json' },
        method: 'GET',
        signal,
      });
    } catch {
      return undefined;
    }
    if (!response.ok) throw await connectionError(response);
    try {
      return { value: await boundedJson(response) };
    } catch {
      if (signal.aborted) return undefined;
      throw new Error('Signal Protocol Relay returned an invalid connection');
    }
  });
  if (document === undefined) {
    if (
      cached !== undefined &&
      Date.now() - cached.resolvedAt <= CONNECTION_STALE_MILLISECONDS
    ) {
      return cloneConnection(cached.connection);
    }
    throw new Error('Signal Protocol Relay connection could not be resolved');
  }
  const valueFromSignalProtocolRelay = document.value;
  const expectedOrigin = MANAGED_SIGNAL_RELAY_PROFILES[input.profile].origin;
  const signalProtocolRelayScopeId = record(valueFromSignalProtocolRelay)
    ? parseSignalProtocolRelayScopeId(valueFromSignalProtocolRelay.relayScopeId)
    : undefined;
  if (
    !record(valueFromSignalProtocolRelay) ||
    Object.keys(valueFromSignalProtocolRelay).sort().join(',') !==
      [...CONNECTION_DOCUMENT_KEYS].sort().join(',') ||
    valueFromSignalProtocolRelay.schemaVersion !== 1 ||
    !Number.isSafeInteger(valueFromSignalProtocolRelay.configurationVersion) ||
    (valueFromSignalProtocolRelay.configurationVersion as number) < 1 ||
    valueFromSignalProtocolRelay.environment !== input.environment ||
    valueFromSignalProtocolRelay.protocolEndpoint !== `${expectedOrigin}/signal/v1` ||
    valueFromSignalProtocolRelay.publishableKey !== input.locator ||
    signalProtocolRelayScopeId === undefined
  ) {
    throw new Error('Signal Protocol Relay returned an invalid connection');
  }
  const connection: HostedSignalProtocolRelayConnection = {
    certificateTrust: compiledCertificateTrust(input.profile),
    configurationVersion: valueFromSignalProtocolRelay.configurationVersion as number,
    environment: input.environment,
    protocolEndpoint: valueFromSignalProtocolRelay.protocolEndpoint,
    publishableKey: valueFromSignalProtocolRelay.publishableKey,
    relayScopeId: signalProtocolRelayScopeId,
    signalProtocolRelayUrl: input.signalProtocolRelayUrl,
  };
  connectionCache.set(input.signalProtocolRelayUrl, {
    connection,
    resolvedAt: Date.now(),
  });
  if (connectionCache.size > 64) {
    const oldest = connectionCache.keys().next().value;
    if (oldest !== undefined) connectionCache.delete(oldest);
  }
  return cloneConnection(connection);
}
