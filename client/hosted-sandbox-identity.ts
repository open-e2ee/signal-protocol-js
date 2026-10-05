/**
 * Device-owned identity for a Sandbox environment of the Signal Protocol Relay.
 *
 * A Sandbox environment verifies a device-owned assertion: a JWT that the
 * device signs with its own Ed25519 key and that carries the public key in
 * its header. The Relay binds the account to the RFC 7638 thumbprint of that
 * key. So the key is the account identity in the environment, and this module
 * keeps it in the device-local store next to the protocol identity. A device
 * that loses its store loses the account. Another device of the account joins
 * through device linking, not with a copy of this key.
 *
 * The helper signs only registration assertions for a Sandbox connection. A
 * production environment, recovery, and provider migration need an identity
 * provider that authenticates the user.
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

function assertSandboxRegistration(request: IdentityAssertionRequest): void {
  if (request.environment !== 'sandbox') {
    throw new Error(
      'Signal Protocol Relay sandbox identity works only with a Sandbox environment',
    );
  }
  if (request.purpose !== 'register' || request.migration !== undefined) {
    throw new Error(
      'Signal Protocol Relay sandbox identity supports only device registration',
    );
  }
  if (request.assurance !== undefined && request.assurance !== 'normal') {
    throw new Error(
      'Signal Protocol Relay sandbox identity cannot assert recent or step-up assurance',
    );
  }
}

function encodeSegment(value: unknown): string {
  return bytesToUrlSafeBase64(stringToBytes(JSON.stringify(value)));
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
 * for provider migration, or for recent or step-up assurance. A production
 * environment needs a `getIdentityAssertion` that your identity provider
 * supplies.
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
  return async (request) => {
    assertSandboxRegistration(request);
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
