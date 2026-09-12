import {
  base64ToBytes,
  bytesToUrlSafeBase64,
  urlSafeToBase64,
} from '../internal/crypto';
import type { Base64 } from '../types';

export interface HostedRelayCertificateTrust {
  readonly revokedIssuerKeyIds: readonly number[];
  readonly trustRoots: readonly Uint8Array[];
}

export interface HostedRelayConnection {
  readonly certificateTrust: HostedRelayCertificateTrust;
  readonly configurationVersion: number;
  readonly environment: 'development' | 'production';
  readonly protocolEndpoint: string;
  readonly publishableKey: string;
  readonly relayScopeId: Uint8Array;
  readonly relayUrl: string;
}

const MANAGED_RELAY_PROFILES = {
  'customer-development': {
    environment: 'development',
    origin: 'https://development.relay.open-e2ee.dev',
    revokedIssuerKeyIds: [],
    trustRoots: [
      'KggSCjrGjvI+qs4FXJmg2Zy9G/1LMM4MBF5ddm1E/40=' as Base64,
    ],
  },
  production: {
    environment: 'production',
    origin: 'https://relay.open-e2ee.dev',
    revokedIssuerKeyIds: [],
    trustRoots: [
      'c/YUIFyVI2CexJmHTBj0ofqqOH9yiPewipMrTGGBCMc=' as Base64,
    ],
  },
  staging: {
    environment: 'production',
    origin: 'https://staging.relay.open-e2ee.dev',
    revokedIssuerKeyIds: [],
    trustRoots: [
      'dl4g+m9cCgjbaUqOK9XlrWf8dmH/zhNxluXImiM24i4=' as Base64,
    ],
  },
  'staging-customer-development': {
    environment: 'development',
    origin: 'https://staging-customer-development.relay.open-e2ee.dev',
    revokedIssuerKeyIds: [],
    trustRoots: [
      'M5x6m4m8bu1cntLDKaPmYcFwb6Vcgv+no+qGCre+r8w=' as Base64,
    ],
  },
} as const;
type ManagedRelayProfile = keyof typeof MANAGED_RELAY_PROFILES;
const CONNECTION_PATH = /^\/v1\/connection\/([A-Za-z0-9_-]{1,255})$/u;
const CONNECTION_FRESH_MILLISECONDS = 5 * 60 * 1_000;
const CONNECTION_STALE_MILLISECONDS = 60 * 60 * 1_000;
const CONNECTION_DOCUMENT_MAXIMUM_BYTES = 8 * 1_024;
const connectionCache = new Map<
  string,
  { readonly connection: HostedRelayConnection; readonly resolvedAt: number }
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

function parseRelayUrl(value: string): {
  environment: HostedRelayConnection['environment'];
  locator: string;
  profile: ManagedRelayProfile;
  relayUrl: string;
} {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('Managed Relay connection URL is invalid');
  }
  const profile = Object.entries(MANAGED_RELAY_PROFILES).find(
    ([, candidate]) => url.origin === candidate.origin,
  )?.[0] as ManagedRelayProfile | undefined;
  const locator = CONNECTION_PATH.exec(url.pathname)?.[1];
  if (
    profile === undefined ||
    locator === undefined ||
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== '' ||
    url.href !== value
  ) {
    throw new Error('Managed Relay connection URL is invalid');
  }
  return {
    environment: MANAGED_RELAY_PROFILES[profile].environment,
    locator,
    profile,
    relayUrl: url.href,
  };
}

function compiledCertificateTrust(
  profile: ManagedRelayProfile,
): HostedRelayCertificateTrust {
  const trust = MANAGED_RELAY_PROFILES[profile];
  return {
    revokedIssuerKeyIds: [...trust.revokedIssuerKeyIds],
    trustRoots: trust.trustRoots.map((root) => base64ToBytes(root)),
  };
}

function parseRelayScopeId(value: unknown): Uint8Array | undefined {
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
  connection: HostedRelayConnection,
): HostedRelayConnection {
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
    return new Error('Managed Relay deployment is suspended');
  }
  if (code === 'PRODUCTION_INACTIVE') {
    return new Error('Managed Relay production deployment is not active');
  }
  if (response.status === 404) {
    return new Error('Managed Relay connection does not exist or is stale');
  }
  if (response.status === 403) {
    return new Error('Managed Relay connection belongs to another environment');
  }
  if (response.status === 410) {
    return new Error('Managed Relay connection is no longer active');
  }
  return new Error('Managed Relay connection could not be resolved');
}

async function boundedJson(response: Response): Promise<unknown> {
  const declaredLength = response.headers.get('content-length');
  if (
    declaredLength !== null &&
    (!/^\d+$/.test(declaredLength) ||
      Number(declaredLength) > CONNECTION_DOCUMENT_MAXIMUM_BYTES)
  ) {
    throw new Error('Managed Relay returned an invalid connection');
  }
  try {
    const body = response.body as ReadableStream<Uint8Array> | null | undefined;
    if (typeof body?.getReader === 'function') {
      const reader = body.getReader();
      const decoder = new TextDecoder();
      let size = 0;
      let text = '';
      for (;;) {
        const result = await reader.read();
        if (result.done) break;
        size += result.value.byteLength;
        if (size > CONNECTION_DOCUMENT_MAXIMUM_BYTES) {
          await reader.cancel();
          throw new Error('Managed Relay returned an invalid connection');
        }
        text += decoder.decode(result.value, { stream: true });
      }
      text += decoder.decode();
      return JSON.parse(text) as unknown;
    }

    // React Native and Expo use a fetch implementation without response body
    // streams. Preserve their standard text() path and enforce the same UTF-8
    // byte limit after decoding.
    const text = await response.text();
    if (
      new TextEncoder().encode(text).byteLength >
      CONNECTION_DOCUMENT_MAXIMUM_BYTES
    ) {
      throw new Error('Managed Relay returned an invalid connection');
    }
    return JSON.parse(text) as unknown;
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === 'Managed Relay returned an invalid connection'
    ) {
      throw error;
    }
    throw new Error('Managed Relay returned an invalid connection');
  }
}

/** Resolve one public environment-scoped Managed Relay connection. */
export async function resolveHostedRelayConnection(
  value: string,
): Promise<HostedRelayConnection> {
  const input = parseRelayUrl(value);
  const cached = connectionCache.get(input.relayUrl);
  if (
    cached !== undefined &&
    Date.now() - cached.resolvedAt <= CONNECTION_FRESH_MILLISECONDS
  ) {
    return cloneConnection(cached.connection);
  }
  let response: Response;
  try {
    response = await fetch(input.relayUrl, {
      credentials: 'omit',
      headers: { accept: 'application/json' },
      method: 'GET',
    });
  } catch {
    if (
      cached !== undefined &&
      Date.now() - cached.resolvedAt <= CONNECTION_STALE_MILLISECONDS
    ) {
      return cloneConnection(cached.connection);
    }
    throw new Error('Managed Relay connection could not be resolved');
  }
  if (!response.ok) throw await connectionError(response);
  let valueFromRelay: unknown;
  try {
    valueFromRelay = await boundedJson(response);
  } catch {
    throw new Error('Managed Relay returned an invalid connection');
  }
  const expectedOrigin = MANAGED_RELAY_PROFILES[input.profile].origin;
  const relayScopeId = record(valueFromRelay)
    ? parseRelayScopeId(valueFromRelay.relayScopeId)
    : undefined;
  if (
    !record(valueFromRelay) ||
    Object.keys(valueFromRelay).sort().join(',') !==
      [...CONNECTION_DOCUMENT_KEYS].sort().join(',') ||
    valueFromRelay.schemaVersion !== 1 ||
    !Number.isSafeInteger(valueFromRelay.configurationVersion) ||
    (valueFromRelay.configurationVersion as number) < 1 ||
    valueFromRelay.environment !== input.environment ||
    valueFromRelay.protocolEndpoint !== `${expectedOrigin}/v1/signal` ||
    valueFromRelay.publishableKey !== input.locator ||
    relayScopeId === undefined
  ) {
    throw new Error('Managed Relay returned an invalid connection');
  }
  const connection: HostedRelayConnection = {
    certificateTrust: compiledCertificateTrust(input.profile),
    configurationVersion: valueFromRelay.configurationVersion as number,
    environment: input.environment,
    protocolEndpoint: valueFromRelay.protocolEndpoint,
    publishableKey: valueFromRelay.publishableKey,
    relayScopeId,
    relayUrl: input.relayUrl,
  };
  connectionCache.set(input.relayUrl, {
    connection,
    resolvedAt: Date.now(),
  });
  if (connectionCache.size > 64) {
    const oldest = connectionCache.keys().next().value;
    if (oldest !== undefined) connectionCache.delete(oldest);
  }
  return cloneConnection(connection);
}
