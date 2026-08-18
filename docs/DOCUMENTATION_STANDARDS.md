# Documentation and Comment Standards

These standards keep the public package understandable without requiring
knowledge of its implementation history or a particular consuming
application.

## Documentation hierarchy

- The root [`README.md`](../README.md) introduces the package. It says what
  the package is, how it compares to the alternatives, and how to install it.
  It also gives one working example and the evidence behind its security
  claims. It links onward rather than documenting the full surface itself.
- [`PACKAGE_SURFACE.md`](./PACKAGE_SURFACE.md) is the complete public surface:
  root exports, every subpath, adapter implementations, and core vocabulary.
- [`RECIPES.md`](./RECIPES.md) holds the working shapes for common operations.
- [`ASSURANCE.md`](./ASSURANCE.md) states what the project verifies, where it
  verifies it, and what it does not publish.
- A module README explains a meaningful exported domain or integration
  boundary. It answers what the module does, why it exists, and how to use it.
- [`ARCHITECTURE.md`](../ARCHITECTURE.md) describes dependency direction and
  ownership across modules.
- [`ADAPTERS.md`](../ADAPTERS.md) describes platform and backend composition.
- A generator builds `docs/api/` from the exported TypeScript declarations and
  source documentation.

A thin leaf module does not need its own README when its parent guide explains
the complete contract. A module that owns a domain, a platform boundary, or an
external provider integration does.

## README structure

Module READMEs should normally include:

1. What the module does, in plain language.
2. Why the module is separate from the client or application layer.
3. The canonical package import path.
4. A minimal, complete example using public exports.
5. Ownership, security, lifecycle, or platform constraints that callers must
   preserve.
6. Links to the nearest parent guide and API reference.

Examples use `@open-e2ee/signal-protocol-sdk` package subpaths. They should name
application-owned values explicitly and use generated framework modules
directly when that is the real integration shape.

## Source comments

Public comments document the code that exists now. Prefer comments that explain:

- invariants and validation rules.
- who owns state or makes a security decision.
- observable side effects and idempotency.
- units, encodings, versioning, and expiry semantics.
- why a boundary exists when the reason is not apparent from its type.
- failure or retry behavior that a caller must handle.

Avoid comments that:

- repeat the implementation line by line.
- describe old file locations, migrations, or application-specific paths.
- narrate implementation provenance or point to another project's source
  files.
- use compatibility shorthand such as “Signal-style” or “Signal-aligned”.
- expose internal assurance artifacts or their organization.
- promise behavior that belongs to an application, backend, or platform.

Use public standards, RFCs, and project policy documents when an external
reference is necessary. A reference should clarify a normative contract, not
substitute for documenting the local behavior.

## Terminology

- **Signal Protocol** means the public protocol specification family.
- **Signal Messenger** means the separate product and service.
- **OpenE2EE** is the project and npm organization.
- **Signal Protocol SDK** or `@open-e2ee/signal-protocol-sdk` names this package.
- **Application** or **host application** names the consuming product.
- **Relay** names the application backend interface for device state, public
  prekeys, and encrypted envelopes.
- **Remote object store** names the brokered ciphertext-storage interface.

Do not imply affiliation with Signal Messenger or general compatibility with
Signal Messenger. Any deliberate format or protocol compatibility claim
belongs in the public
[`PROTOCOL_POLICY.md`](./PROTOCOL_POLICY.md) and must state its exact scope.

## Security and ownership language

State boundaries directly:

- device-local stores own private keys and session state.
- relays own authenticated device/public-key records and encrypted-envelope
  delivery.
- object-store brokers own authorization, canonical object identifiers, and
  provider keys.
- applications own product policy, account authorization, decrypted message
  persistence, and user experience.
- generated framework APIs remain application-owned even when an SDK adapter
  consumes them.

Avoid absolute security claims. Describe the threat boundary and required host
controls instead.

## Generated API documentation

Do not edit `docs/api/` by hand. Update exported JSDoc or public declarations,
regenerate the API reference, and review the generated result.
