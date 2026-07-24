# End-to-End Encryption

`@open-e2ee/signal-protocol-sdk` provides end-to-end encryption based on the Signal
Protocol: X3DH / PQXDH key agreement and the Double Ratchet, extended with the
Sparse Post-Quantum Ratchet (SPQR / ML-KEM-BRAID).

End-to-end encryption means plaintext exists only on the sender's and
recipient's devices. A relay or server sees ciphertext envelopes and routing
metadata, never message contents or long-term private keys.

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
  (Kyber) shared secrets into key agreement and continuous ratcheting, providing
  resistance against harvest-now-decrypt-later adversaries.
- **Authentication & integrity** — messages are authenticated (AEAD + MACs) and
  identities are verifiable through safety numbers.

## Verifiability

The implementation uses narrow protocol seams, explicit state transitions, and
injectable storage and relay boundaries so security properties can be evaluated
independently. This documentation describes intended behavior; it is not a
third-party security certification.

See also [SECURITY.md](../SECURITY.md) and [ARCHITECTURE.md](../ARCHITECTURE.md).
