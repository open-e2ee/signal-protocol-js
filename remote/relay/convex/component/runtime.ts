import { ConvexError } from 'convex/values';
import { base64ToBytes, bytesToBase64 } from '../../../../internal/crypto/utils';
import type { GroupServerEngineRuntime } from '../../../../internal/groups/server-engine';
import {
  generateServerSecretParams,
  type ServerSecretParams,
} from '../../../../internal/protocol/zk/groups/server-params';
import {
  SERVICE_ID_ACI,
  SERVICE_ID_PNI,
  type ServiceId,
} from '../../../../internal/protocol/zk/groups/uid-struct';
import { asBase64 } from '../../../../types/utils';
import { CONVEX_GROUP_SERVER_SECRET_ENV_VAR } from '../constants';
import { env } from './_generated/server';

const UUID_LENGTH = 16;

let testDependencies: {
  readonly secretParams: ServerSecretParams;
  readonly runtime?: GroupServerEngineRuntime;
} | null = null;

/**
 * @internal Test-only deterministic secret/runtime injection seam.
 *
 * Module-global by necessity: component functions are module-scope exports
 * with no per-instance closure. Guarded default-deny: injection is allowed
 * only inside a recognized test runner (and never when CONVEX_CLOUD_URL
 * marks a deployment). Component isolates see only their declared
 * environment variables, so a permissive env-based check could be inert in
 * exactly the environment it must protect. An unrecognized environment
 * therefore refuses injection rather than allowing it.
 */
export function configureConvexSignalProtocolComponentForTest(config: {
  secretParams: ServerSecretParams;
  runtime?: GroupServerEngineRuntime;
}): void {
  const inTestRunner =
    process.env.JEST_WORKER_ID !== undefined ||
    process.env.VITEST !== undefined ||
    process.env.NODE_ENV === 'test';
  if (process.env.CONVEX_CLOUD_URL || !inTestRunner) {
    throw new Error(
      'Test-only component configuration is unavailable in deployments'
    );
  }
  testDependencies = config;
}

function defaultConvexRuntime(): GroupServerEngineRuntime {
  return {
    now: () => Date.now(),
    randomBytes: (length) =>
      crypto.getRandomValues(new Uint8Array(length)),
  };
}

/**
 * Derived server parameters, cached per isolate and keyed by the exact
 * environment value so a rotated secret is picked up on the next request.
 * Derivation costs tens of milliseconds. Without the cache every query and
 * mutation would pay it before doing any work.
 */
let cachedSecretParams: {
  readonly encoded: string;
  readonly params: ServerSecretParams;
} | null = null;

function secretParamsFromEnvironment(): ServerSecretParams {
  // Read through the component's *declared* environment (convex.config.ts).
  // Component isolates cannot see undeclared app deployment variables, so
  // the app must forward the secret at mount time:
  // ```ts
  //   app.use(signalProtocol, {
  //     env: { OE_GROUPS_SERVER_SECRET: app.env.OE_GROUPS_SERVER_SECRET },
  //   });
  // ```
  const encoded = env.OE_GROUPS_SERVER_SECRET;
  if (!encoded) {
    throw new Error(
      `${CONVEX_GROUP_SERVER_SECRET_ENV_VAR} is not configured; run npx oe-groups trust-root and forward it to the component with app.use(signalProtocol, { env: { ${CONVEX_GROUP_SERVER_SECRET_ENV_VAR}: app.env.${CONVEX_GROUP_SERVER_SECRET_ENV_VAR} } })`
    );
  }
  if (cachedSecretParams && cachedSecretParams.encoded === encoded) {
    return cachedSecretParams.params;
  }
  let seed: Uint8Array;
  try {
    seed = base64ToBytes(asBase64(encoded));
  } catch {
    throw new Error(
      `${CONVEX_GROUP_SERVER_SECRET_ENV_VAR} must be canonical base64`
    );
  }
  try {
    if (seed.length !== 32) {
      throw new Error(
        `${CONVEX_GROUP_SERVER_SECRET_ENV_VAR} must decode to exactly 32 bytes`
      );
    }
    if (bytesToBase64(seed) !== encoded) {
      throw new Error(
        `${CONVEX_GROUP_SERVER_SECRET_ENV_VAR} must be canonical base64`
      );
    }
    const params = generateServerSecretParams(seed);
    cachedSecretParams = { encoded, params };
    return params;
  } finally {
    seed.fill(0);
  }
}

export function groupServerRuntime(): GroupServerEngineRuntime {
  return testDependencies?.runtime ?? defaultConvexRuntime();
}

export function groupServerSecretParams(): ServerSecretParams {
  return testDependencies?.secretParams ?? secretParamsFromEnvironment();
}

function requireUuid(
  value: Uint8Array,
  label: string
): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== UUID_LENGTH) {
    throw new Error(`${label} must be a ${UUID_LENGTH}-byte UUID`);
  }
  if (value.every((byte) => byte === 0)) {
    throw new Error(`${label} must not be the nil UUID`);
  }
  return value;
}

export function serviceIds(input: {
  aciBytes: ArrayBuffer;
  pniBytes?: ArrayBuffer;
}): { aci: ServiceId; pni?: ServiceId } {
  if (input === null || typeof input !== 'object') {
    throw new ConvexError({
      code: 'UNAUTHORIZED',
      status: 401,
      message: 'identify() returned no identity',
    });
  }
  const aci: ServiceId = {
    kind: SERVICE_ID_ACI,
    uuid: requireUuid(
      new Uint8Array(input.aciBytes),
      'identify().aciBytes'
    ),
  };
  const pni =
    input.pniBytes === undefined
      ? undefined
      : {
          kind: SERVICE_ID_PNI,
          uuid: requireUuid(
            new Uint8Array(input.pniBytes),
            'identify().pniBytes'
          ),
        };
  return { aci, pni };
}

/**
 * Translate an engine rejection into a `ConvexError` so its structured
 * `{ code, status }` data survives serialization to real deployments.
 */
export async function translateEngineErrors<T>(
  operation: () => Promise<T>
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (!(error instanceof ConvexError) && error instanceof Error) {
      const data = (
        error as {
          data?: { code?: unknown; status?: unknown; reason?: unknown };
        }
      ).data;
      if (
        data !== null &&
        typeof data === 'object' &&
        typeof data.code === 'string' &&
        typeof data.status === 'number'
      ) {
        throw new ConvexError({
          code: data.code,
          status: data.status,
          message: error.message,
          ...(typeof data.reason === 'string'
            ? { reason: data.reason }
            : {}),
        });
      }
    }
    throw error;
  }
}
