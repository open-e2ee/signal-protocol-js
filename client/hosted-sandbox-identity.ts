/**
 * Device-owned identity for the Signal Protocol Relay.
 *
 * A Sandbox environment, and a Production environment in device-owned mode,
 * verify a device-owned assertion: a JWT that the device signs with its own
 * Ed25519 key and that carries the public key in its header. The Relay binds
 * the account to the RFC 7638 thumbprint of that key. So the key is the
 * account identity in the environment, and this module keeps it in the
 * device-local store next to the protocol identity. A device that loses its
 * store loses the account. Another device of the account joins through device
 * linking, not with a copy of this key.
 *
 * The helpers sign only registration assertions. `hostedRelaySandboxIdentity`
 * serves only a Sandbox connection. `hostedRelayDeviceOwnedIdentity` serves a
 * Sandbox connection or a device-owned Production connection. An
 * application-bound Production project needs an application callback. Recovery
 * and provider migration need an identity provider that authenticates the user.
 */
import {
  base64ToBytes,
  bytesToBase64,
  bytesToUrlSafeBase64,
  generateSigningKeyPair,
  generateUuidV4,
  sha256,
  sign,
  stringToBytes,
  verify,
} from '../internal/crypto';
import type { PrivateKey, PublicKey } from '../keys';
import type { Base64, SignalProtocolLocalStore } from '../types';
import type { GetIdentityAssertion, IdentityAssertionRequest } from './hosted';

/**
 * The metadata key prefix of the stored device-owned key. It is a persisted
 * format that both helpers keep. A new prefix would orphan the existing keys,
 * and so the existing accounts.
 */
const SANDBOX_IDENTITY_METADATA_PREFIX = 'hostedRelay.sandboxIdentity.v1:';
const DEVICE_OWNED_ISSUER = 'https://relay.open-e2ee.dev/device-owned';
/** The Relay accepts a lifetime of up to 600 seconds. */
const ASSERTION_LIFETIME_SECONDS = 300;
const ED25519_KEY_BYTES = 32;

interface StoredSandboxIdentityKey {
  readonly publicKey: PublicKey;
  readonly privateKey: PrivateKey;
}

/** Key creation in progress, per store and publishable key. */
const pendingKeys = new WeakMap<
  SignalProtocolLocalStore,
  Map<string, Promise<StoredSandboxIdentityKey>>
>();

function decodeStoredKey(value: string): StoredSandboxIdentityKey {
  const invalid = () =>
    new Error('Stored Signal Protocol Relay sandbox identity key is invalid');
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw invalid();
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    !('publicKey' in parsed) ||
    !('privateKey' in parsed) ||
    typeof parsed.publicKey !== 'string' ||
    typeof parsed.privateKey !== 'string'
  ) {
    throw invalid();
  }
  try {
    if (
      base64ToBytes(parsed.publicKey as Base64).length !== ED25519_KEY_BYTES ||
      base64ToBytes(parsed.privateKey as Base64).length !== ED25519_KEY_BYTES
    ) {
      throw invalid();
    }
  } catch {
    throw invalid();
  }
  return {
    publicKey: parsed.publicKey as PublicKey,
    privateKey: parsed.privateKey as PrivateKey,
  };
}

async function metadataKey(publishableKey: string): Promise<string> {
  return `${SANDBOX_IDENTITY_METADATA_PREFIX}${bytesToBase64(
    await sha256(stringToBytes(publishableKey)),
  )}`;
}

async function loadOrCreateKey(
  storage: SignalProtocolLocalStore,
  publishableKey: string,
): Promise<StoredSandboxIdentityKey> {
  const key = await metadataKey(publishableKey);
  const stored = await storage.getMetadata(key);
  if (stored) return decodeStoredKey(stored);
  const created = await generateSigningKeyPair();
  await storage.setMetadata(key, JSON.stringify(created));
  return created;
}

/**
 * Returns the stored key, or creates and stores one. Concurrent calls for the
 * same store and publishable key share one creation, so they cannot store two
 * different keys.
 */
function sandboxIdentityKey(
  storage: SignalProtocolLocalStore,
  publishableKey: string,
): Promise<StoredSandboxIdentityKey> {
  let pending = pendingKeys.get(storage);
  if (pending === undefined) {
    pending = new Map();
    pendingKeys.set(storage, pending);
  }
  const existing = pending.get(publishableKey);
  if (existing !== undefined) return existing;
  const created = loadOrCreateKey(storage, publishableKey).finally(() => {
    pending.delete(publishableKey);
  });
  pending.set(publishableKey, created);
  return created;
}

/** The environments that a helper serves, and its name in errors. */
interface DeviceOwnedIdentityScope {
  readonly name: string;
  readonly environments: readonly IdentityAssertionRequest['environment'][];
  readonly environmentsLabel: string;
}

const SANDBOX_SCOPE: DeviceOwnedIdentityScope = {
  name: 'sandbox identity',
  environments: ['sandbox'],
  environmentsLabel: 'a Sandbox environment',
};

const DEVICE_OWNED_SCOPE: DeviceOwnedIdentityScope = {
  name: 'device-owned identity',
  environments: ['sandbox', 'production'],
  environmentsLabel: 'a Sandbox or Production environment',
};

/**
 * Accepts only a normal-assurance registration request for an environment of
 * the scope. The Relay refuses device-owned recovery and migration away from
 * device-owned mode, so registration is the whole device-owned path.
 */
function assertRegistration(
  request: IdentityAssertionRequest,
  scope: DeviceOwnedIdentityScope,
): void {
  if (!scope.environments.includes(request.environment)) {
    throw new Error(
      `Signal Protocol Relay ${scope.name} works only with ${scope.environmentsLabel}`,
    );
  }
  if (request.purpose !== 'register' || request.migration !== undefined) {
    throw new Error(
      `Signal Protocol Relay ${scope.name} supports only device registration`,
    );
  }
  if (request.assurance !== undefined && request.assurance !== 'normal') {
    throw new Error(
      `Signal Protocol Relay ${scope.name} cannot assert recent or step-up assurance`,
    );
  }
}

function encodeSegment(value: unknown): string {
  return bytesToUrlSafeBase64(stringToBytes(JSON.stringify(value)));
}

function deviceOwnedIdentity(
  storage: SignalProtocolLocalStore,
  scope: DeviceOwnedIdentityScope,
): GetIdentityAssertion {
  return async (request) => {
    assertRegistration(request, scope);
    const key = await sandboxIdentityKey(storage, request.publishableKey);
    const x = bytesToUrlSafeBase64(base64ToBytes(key.publicKey));
    const jwk = { crv: 'Ed25519', kty: 'OKP', x };
    const subject = bytesToUrlSafeBase64(
      await sha256(stringToBytes(JSON.stringify(jwk))),
    );
    const issuedAt = Math.floor(Date.now() / 1000);
    const signingInput = `${encodeSegment({ alg: 'EdDSA', jwk, typ: 'JWT' })}.${encodeSegment({
      assurance: 'normal',
      aud: request.publishableKey,
      exp: issuedAt + ASSERTION_LIFETIME_SECONDS,
      iat: issuedAt,
      iss: DEVICE_OWNED_ISSUER,
      jti: await generateUuidV4(),
      nbf: issuedAt,
      purpose: request.purpose,
      sub: subject,
      token_use: 'identity',
    })}`;
    const signingBytes = stringToBytes(signingInput);
    const signature = await sign(key.privateKey, signingBytes);
    if (!(await verify(key.publicKey, signingBytes, signature))) {
      throw new Error('Stored Signal Protocol Relay sandbox identity key is invalid');
    }
    return `${signingInput}.${bytesToUrlSafeBase64(base64ToBytes(signature))}`;
  };
}

/**
 * Creates the identity assertion callback for a Sandbox environment of the
 * Signal Protocol Relay.
 *
 * The callback signs a short-lived device-owned assertion with an Ed25519 key
 * that it keeps in `storage`. It creates the key on the first call and uses the
 * same key after that, so the Relay returns the same account each time the
 * device registers. The key is separate for each publishable key. Pass the
 * same store as `adapters.storage`. A device that loses the store loses the
 * Sandbox account. Another device of the account joins through device linking.
 *
 * The callback rejects a request for a production environment, for recovery,
 * for provider migration, or for recent or step-up assurance. This helper is
 * the Sandbox-only guard, and it is not deprecated. For a Production project in
 * device-owned mode, use {@link hostedRelayDeviceOwnedIdentity}. For a
 * Production project in application-bound mode, supply a `getIdentityAssertion`
 * callback that returns an assertion from your backend.
 *
 * The key is stored under the metadata key
 * `'hostedRelay.sandboxIdentity.v1:'` followed by the base64 SHA-256 digest of
 * the publishable key. This is a persisted format that both helpers keep. A
 * new prefix would orphan existing Sandbox accounts. So for the same store and
 * publishable key, both helpers sign with the same key.
 *
 * @example
 * ```ts
 * const storage = inMemoryStore();
 * const client = await createHostedSignalProtocolClient({
 *   adapters: { storage },
 *   hosted: {
 *     relayUrl: process.env.OPEN_E2EE_RELAY_URL!,
 *     getIdentityAssertion: hostedRelaySandboxIdentity(storage),
 *   },
 * });
 * ```
 */
export function hostedRelaySandboxIdentity(
  storage: SignalProtocolLocalStore,
): GetIdentityAssertion {
  return deviceOwnedIdentity(storage, SANDBOX_SCOPE);
}

/**
 * Creates the identity assertion callback for a device-owned account in a
 * Sandbox environment, or in a Production environment that is configured in
 * device-owned identity mode.
 *
 * The callback signs a short-lived device-owned assertion with an Ed25519 key
 * that it keeps in `storage`. It creates the key on the first call and uses the
 * same key after that, so the Relay returns the same account each time the
 * device registers. The key is separate for each publishable key. Pass the
 * same store as `adapters.storage`. The key never leaves the store. A device
 * that loses the store loses the account, and its next registration creates a
 * new account: the Relay refuses device-owned recovery. Another device of the
 * account joins through device linking.
 *
 * The assertion is a compact JWS. Its protected header is
 * `{ alg: 'EdDSA', typ: 'JWT', jwk: { kty: 'OKP', crv: 'Ed25519', x } }`,
 * where `x` is the base64url public key. Its claims are:
 *
 * - `iss`: `'https://relay.open-e2ee.dev/device-owned'`.
 * - `aud`: the publishable key of the request.
 * - `sub`: the RFC 7638 SHA-256 thumbprint of the embedded JWK, base64url.
 * - `iat` and `nbf`: the issue time in seconds. `exp`: `iat + 300`.
 * - `jti`: a new UUID for each assertion.
 * - `purpose`: `'register'`. `assurance`: `'normal'`.
 *   `token_use`: `'identity'`.
 *
 * The callback rejects a request for an environment other than Sandbox or
 * Production, for recovery, for refresh or provider migration, or for recent or
 * step-up assurance. It creates no key for a request that it rejects.
 *
 * The Production project must be configured in device-owned identity mode. A
 * project in application-bound mode refuses this assertion with
 * `ASSERTION_INVALID`. For that mode, supply a `getIdentityAssertion` callback
 * that returns an assertion from your backend.
 *
 * The key is stored under the metadata key
 * `'hostedRelay.sandboxIdentity.v1:'` followed by the base64 SHA-256 digest of
 * the publishable key. This is a persisted format that both helpers keep. A
 * new prefix would orphan existing Sandbox accounts. So for the same store
 * and publishable key, this helper and {@link hostedRelaySandboxIdentity} sign
 * with the same key, and the Relay returns the same account.
 *
 * @example
 * ```ts
 * const storage = inMemoryStore();
 * const client = await createHostedSignalProtocolClient({
 *   adapters: { storage },
 *   hosted: {
 *     relayUrl: process.env.OPEN_E2EE_RELAY_URL!,
 *     getIdentityAssertion: hostedRelayDeviceOwnedIdentity(storage),
 *   },
 * });
 * ```
 */
export function hostedRelayDeviceOwnedIdentity(
  storage: SignalProtocolLocalStore,
): GetIdentityAssertion {
  return deviceOwnedIdentity(storage, DEVICE_OWNED_SCOPE);
}
