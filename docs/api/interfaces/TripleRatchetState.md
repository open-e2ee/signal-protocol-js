[**@open-e2ee/signal-protocol-sdk**](../README.md)

***

[@open-e2ee/signal-protocol-sdk](../README.md) / TripleRatchetState

# Interface: TripleRatchetState

Triple Ratchet state (Signal Protocol Section 6).

Signal Protocol Section 6:
"The Triple Ratchet provides hybrid security by running two ratchets in parallel:
1. Elliptic Curve Double Ratchet (Section 3) - Classical security
2. Sparse Post-Quantum Ratchet (Section 5) - Post-quantum security

Message keys are derived by combining both ratchets using KDF_HYBRID(),
ensuring security if EITHER ratchet remains secure."

Security boundary: hybrid confidentiality is intended to survive failure of
one contribution only if the other contribution and the surrounding
authenticated protocol assumptions remain secure. Percentages and absolute
"quantum safe" guarantees are deliberately not assigned here.

Implementation Strategy:
- EC state: Use existing SessionState fields (DHs, DHr, RK, CKs, CKr, etc.)
- SPQR state: New state structure (this interface)
- Message format: Composite headers (EC header + SCKA header)
- Key derivation: KDF_HYBRID(ec_mk, pq_mk) combines both message keys

## Properties

### enabled

> **enabled**: `boolean`

Flag indicating if Triple Ratchet is active.

Set to true once PQXDH has produced the SPQR root material and the
manager has initialized SPQR v1 state for the session.

***

### enabledAt

> **enabledAt**: `number`

Timestamp when Triple Ratchet was enabled.

Used for metrics, debugging, and gradual rollout tracking.

***

### spqrState

> **spqrState**: [`SPQRState`](SPQRState.md)

SPQR state for post-quantum security.

Note: EC Double Ratchet state is stored in the main SessionState fields
(DHs, DHr, RK, CKs, CKr, Ns, Nr, PN, receiverChains, etc.)

This separation keeps the module boundary explicit:
- Main SessionState fields own EC Double Ratchet state
- tripleRatchet owns SPQR state and hybrid key material
