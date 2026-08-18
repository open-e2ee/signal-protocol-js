# End-to-End Encryption

> Navigation: [README](../README.md) | [Getting Started](./GETTING_STARTED.md) |
> [Security Model](./SECURITY.md) | [Architecture](../ARCHITECTURE.md)

`@open-e2ee/signal-protocol-sdk` provides end-to-end encryption based on the
Signal Protocol: X3DH / PQXDH key agreement and the Double Ratchet, extended
with the Sparse Post-Quantum Ratchet (SPQR / ML-KEM Braid).

End-to-end encryption means plaintext exists only on the sender's and
recipient's devices. A relay or server sees ciphertext envelopes and routing
metadata, never message contents or long-term private keys.

This page explains what that changes about how you build. If you have only ever
built server-authoritative applications, most of the work of adopting E2EE lies
in these changes. The cryptography itself is the part the SDK already did.

## Security Guarantees

- **End-to-end encryption**. The sender's device encrypts message contents, and
  only recipient devices decrypt them. Intermediaries handle ciphertext only.
- **Forward secrecy**. A ratchet derives per-message keys and deletes them after
  use. An attacker who holds current key material therefore cannot read
  previously captured ciphertext.
- **Break-in recovery** (post-compromise security). The Diffie–Hellman ratchet
  heals the session after a key compromise. Future messages regain
  confidentiality once the peers exchange fresh ratchet keys.
- **Post-quantum confidentiality**. PQXDH and the SPQR ratchet mix ML-KEM
  (FIPS 203) shared secrets into key agreement and continuous ratcheting. This
  resists harvest-now-decrypt-later adversaries.
- **Authentication & integrity**. AEAD and MACs authenticate every message, and
  safety numbers make identities verifiable.

## What changes about your architecture

### The server becomes a relay

In a server-authoritative app, the database holds the truth and the backend
reads it to do its job. With E2EE the relay carries sealed envelopes: it can
route, store, and meter them, but it cannot read, search, filter, moderate, or
render them. Four kinds of server-side feature assume plaintext: full-text
search, content previews, server-rendered notifications, and analytics over
message content. They do not degrade. They stop existing, and their
replacements live on the device.
The [architecture overview](../ARCHITECTURE.md) shows exactly which
responsibilities sit on which side of that line.

### The device becomes the source of truth

Message history, session state, and keys live in device-local storage. That is
why the SDK requires the `storage` adapter, rather than offering it as an
option. Ratchet state mutates on every decrypt and must persist atomically. An
application that treats local storage as a cache to drop and refetch corrupts
sessions irrecoverably. The
[integration interfaces](./INTERFACES.md) exist to make that contract explicit.

### Identity becomes a set of device keys

A user is no longer a row with a password hash. A user is a set of devices,
each with its own identity key. Adding a second device is a protocol operation
(linking), not a login. Removing one is revocation, not a session delete. The
SDK establishes trust per `(userId, identityType)`, and safety numbers verify
it. See [Recipes](./RECIPES.md) for the multi-device and verification flows.

### Recovery becomes a product decision

When the server never has the keys, "forgot password" cannot restore content.
Recovery is an application policy with real security tradeoffs in every
direction. The options are device-to-device transfer, an encrypted backup a
user can lose, or accepted history loss. The SDK does not silently choose one
for you. The considerations are laid out in the hosted guides at
[docs.open-e2ee.dev](https://docs.open-e2ee.dev).

### Metadata remains visible

E2EE protects content, not existence. The relay still observes envelope sizes,
timing, and routing: who talks to whom, when, and how much. Sealed sender
narrows what the relay learns about senders, with published limits stated
plainly in the [security model](./SECURITY.md). Do not describe an E2EE product
as anonymous. The two properties are different, and conflating them is the most
common overclaim in this space.

### Failure modes are new

- Sessions can desynchronize.
- Identity keys change when someone reinstalls.
- Messages arrive out of order or reference skipped keys.
- One-time prekeys run out.

These are protocol realities, not bugs. The SDK surfaces them as explicit
states and errors rather than hiding them. See
[Error Handling](./ERROR_HANDLING.md) for what each one means and what your
application should do about it.

## Verifiability

The implementation uses narrow protocol seams, explicit state transitions, and
injectable storage and relay boundaries, so a reviewer can evaluate its
security properties independently. This documentation describes intended
behavior. It is not a third-party security certification.

See also [SECURITY.md](./SECURITY.md), [ASSURANCE.md](./ASSURANCE.md), and
[ARCHITECTURE.md](../ARCHITECTURE.md).
