# IndexedDB Store

`IndexedDbSignalStore` implements the full `ISignalLocalStore` contract for web
browsers using IndexedDB and Web Crypto.

## Why it exists

Browser applications need durable protocol state without importing mobile or
Node filesystem dependencies. The adapter provides that boundary while making
the browser-origin threat model explicit.

## Usage

```ts
import { createSignalProtocolClient } from "@open-e2ee/signal-protocol-sdk";
import { indexedDbStore } from "@open-e2ee/signal-protocol-sdk/local/store/web";

const storage = await indexedDbStore();

const client = await createSignalProtocolClient({
  identity: { userId },
  adapters: { storage, relay },
});
```

The adapter persists identity keys, contact trust, prekeys, sessions, sender
keys, device records, and retry metadata. Records are encrypted with
AES-256-GCM.

## Security boundary

The adapter generates a random 32-byte database encryption key and persists it
in the IndexedDB metadata store. This protects record contents from a copy that
does not also contain the metadata key. It does not protect against JavaScript
running with the application's origin, because that code can access both the
encrypted records and their encryption key.

A script-injection or compromised-dependency incident can also observe
plaintext and invoke the client as the signed-in user. Encryption at rest is
therefore not an XSS defense.

Browser applications using this adapter should:

- enforce a restrictive Content Security Policy with response headers;
- avoid inline/evaluated scripts and minimize third-party script execution;
- protect authentication with secure, HttpOnly cookies where the application
  architecture permits;
- render untrusted content through framework escaping;
- review dependency and service-worker update paths; and
- provide an account-reset path that deletes the IndexedDB database and other
  same-origin state.

The exact controls depend on the host application's deployment and threat
model. See the [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
and [MDN Content Security Policy guide](https://developer.mozilla.org/docs/Web/HTTP/CSP).

## Operational status

The adapter covers the core store contract, including atomic security commits,
SESAME state, sender-key state, and retry records. It remains experimental
because browser storage, multi-tab coordination, quota behavior, and long-run
operational characteristics require deployment-specific validation.

See the parent [storage guide](../README.md), [adapter guide](../../../ADAPTERS.md),
and [security model](../../../docs/SECURITY.md).
