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
built server-authoritative applications, most of the work of adopting E2EE is
absorbing these changes — the cryptography itself is the part the SDK already
did.

## Security Guarantees

- **End-to-end encryption** — message contents are encrypted on the sender's
  device and decrypted only on recipient devices. Intermediaries handle
  ciphertext only.
- **Forward secrecy** — per-message keys are derived from a ratchet and deleted
  after use, so compromising current key material does not expose previously
  captured ciphertext.
- **Break-in recovery** (post-compromise security) — the Diffie–Hellman ratchet
  heals the session after a key compromise, so future messages regain
  confidentiality once fresh ratchet keys are exchanged.
- **Post-quantum confidentiality** — PQXDH and the SPQR ratchet mix ML-KEM
  (FIPS 203) shared secrets into key agreement and continuous ratcheting,
  providing resistance against harvest-now-decrypt-later adversaries.
- **Authentication & integrity** — messages are authenticated (AEAD + MACs) and
  identities are verifiable through safety numbers.

## What changes about your architecture

### The server becomes a relay

In a server-authoritative app, the database holds the truth and the backend
reads it to do its job. With E2EE the relay carries sealed envelopes: it can
route, store, and meter them, but it cannot read, search, filter, moderate, or
render them. Server-side features that assume plaintext — full-text search,
content previews, server-rendered notifications, analytics over message
content — do not degrade; they stop existing, and their replacements live on
the device. The [architecture overview](../ARCHITECTURE.md) shows exactly which
responsibilities sit on which side of that line.

### The device becomes the source of truth

Message history, session state, and keys live in device-local storage — that is
why the `storage` adapter is required, not optional. Ratchet state mutates on
every decrypt and must persist atomically; treating local storage as a cache
that can be dropped and refetched corrupts sessions irrecoverably. The
[integration interfaces](./INTERFACES.md) exist to make that contract explicit.

### Identity becomes a set of device keys

A user is no longer a row with a password hash; a user is a set of devices,
each with its own identity key. Adding a second device is a protocol operation
(linking), not a login. Removing one is revocation, not a session delete. Trust
is established per `(userId, identityType)` and verified with safety numbers —
see [Recipes](./RECIPES.md) for the multi-device and verification flows.

### Recovery becomes a product decision

When the server never has the keys, "forgot password" cannot restore content.
What recovery looks like — device-to-device transfer, an encrypted backup a
user can lose, or accepting history loss — is an application policy with real
security tradeoffs in every direction. The SDK does not silently choose one for
you. The considerations are laid out in the hosted guides at
[docs.open-e2ee.dev](https://docs.open-e2ee.dev).

### Metadata remains visible

E2EE protects content, not existence. The relay still observes envelope sizes,
timing, and routing — who is talking to whom, when, and how much. Sealed sender
narrows what the relay learns about senders, with published limits stated
plainly in the [security model](./SECURITY.md). Do not describe an E2EE product
as anonymous; the two properties are different, and conflating them is the most
common overclaim in this space.

### Failure modes are new

Sessions can desynchronize; identity keys change when someone reinstalls;
messages arrive out of order or reference skipped keys; one-time prekeys run
out. These are protocol realities, not bugs, and the SDK surfaces them as
explicit states and errors rather than hiding them — see
[Error Handling](./ERROR_HANDLING.md) for what each one means and what your
application should do about it.

## Verifiability

The implementation uses narrow protocol seams, explicit state transitions, and
injectable storage and relay boundaries so security properties can be evaluated
independently. This documentation describes intended behavior; it is not a
third-party security certification.

See also [SECURITY.md](./SECURITY.md), [ASSURANCE.md](./ASSURANCE.md), and
[ARCHITECTURE.md](../ARCHITECTURE.md).
