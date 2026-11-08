[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / hostedSignalProtocolRelayDeviceOwnedIdentity

# Function: hostedSignalProtocolRelayDeviceOwnedIdentity()

> **hostedSignalProtocolRelayDeviceOwnedIdentity**(`storage`): [`GetIdentityAssertion`](../type-aliases/GetIdentityAssertion.md)

Creates the identity assertion callback for a device-owned account in a
Sandbox environment, or in a Production environment that is configured in
device-owned identity mode.

The callback signs a short-lived device-owned assertion with an Ed25519 key
that it keeps in `storage`. It creates the key on the first call and uses the
same key after that, so the Relay returns the same account each time the
device registers. The key is separate for each publishable key. Pass the
same store as `adapters.storage`. The key never leaves the store. A device
that loses the store loses the account, and its next registration creates a
new account: the Relay refuses device-owned recovery. Another device of the
account joins through device linking.

The assertion is a compact JWS. Its protected header is
`{ alg: 'EdDSA', typ: 'JWT', jwk: { kty: 'OKP', crv: 'Ed25519', x } }`,
where `x` is the base64url public key. Its claims are:

- `iss`: `'https://relay.open-e2ee.dev/device-owned'`.
- `aud`: the publishable key of the request.
- `sub`: the RFC 7638 SHA-256 thumbprint of the embedded JWK, base64url.
- `iat` and `nbf`: the issue time in seconds. `exp`: `iat + 300`.
- `jti`: a new UUID for each assertion.
- `purpose`: `'register'`. `assurance`: `'normal'`.
  `token_use`: `'identity'`.

The callback rejects a request for an environment other than Sandbox or
Production, for recovery, for refresh or provider migration, or for recent or
step-up assurance. It creates no key for a request that it rejects.

The Production project must be configured in device-owned identity mode. A
project in application-bound mode refuses this assertion with
`ASSERTION_INVALID`. For that mode, supply a `getIdentityAssertion` callback
that returns an assertion from your backend.

The key is stored under a metadata key prefix followed by the base64
SHA-256 digest of the publishable key. The helper reads the prefix
`'signalRelay.sandboxIdentity.v2:'` first and the prefix
`'hostedRelay.sandboxIdentity.v1:'` second. This release stores a new key
under `'hostedRelay.sandboxIdentity.v1:'`, the prefix that SDK 14.1.0 and
earlier read and write. A later release stores a new key under
`'signalRelay.sandboxIdentity.v2:'`. SDK 15 still reads the earlier prefix,
so an existing account keeps its key. Both helpers keep this persisted
format. So for the same store and publishable key, this helper and
[hostedSignalProtocolRelaySandboxIdentity](hostedSignalProtocolRelaySandboxIdentity.md) sign with the same key, and
the Relay returns the same account.

## Parameters

### storage

[`SignalProtocolLocalStore`](../interfaces/SignalProtocolLocalStore.md)

## Returns

[`GetIdentityAssertion`](../type-aliases/GetIdentityAssertion.md)

## Example

```ts
const storage = inMemoryStore();
const client = await createHostedSignalProtocolClient({
  adapters: { storage },
  hosted: {
    signalProtocolRelayUrl: process.env.OPEN_E2EE_SIGNAL_RELAY_URL ?? process.env.OPEN_E2EE_RELAY_URL!,
    getIdentityAssertion: hostedSignalProtocolRelayDeviceOwnedIdentity(storage),
  },
});
```
