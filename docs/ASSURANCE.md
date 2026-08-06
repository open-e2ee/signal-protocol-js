# Assurance

> Navigation: [README](../README.md) | [Security Model](./SECURITY.md) |
> [Protocol Policy](./PROTOCOL_POLICY.md) |
> [Vulnerability Reporting](../SECURITY.md)

This document exists because of an honest problem: browsing this repository, you
will not find automated checks, and a cryptography package with no visible
checks reasonably reads as an unchecked one. That inference is wrong here, and
the correct answer is not a reassuring adjective — it is an explanation of where
the checks live, what they cover, what is published, and what is not.

## Why this repository looks the way it does

This repository is a mechanized export of a private engineering repository. An
allowlist in the source repository decides, file by file, what becomes public;
an export tool copies exactly that set and refuses to write anything the
allowlist does not name. The published result is the library, its
documentation, and its generated API reference.

The automated checks are deliberately outside that allowlist. They exercise
internal module paths, private protocol scaffolding, and cross-implementation
comparison material that the allowlist keeps unpublished, and the export
strips the development dependencies they require. Publishing them as inert
files that nobody could run would look like assurance without being any.

## What runs, and what it covers

Every change to the source repository runs the full set of automated checks,
and an export is only cut from a revision where they pass.

Most recent full run — 2026-07-28:

| | |
|---|---|
| Modules executed | 372 |
| Assertions | 6,552 |
| Passed | 6,550 |
| Skipped | 2 |
| Failed | 0 |
| Wall time | 395 s |

Longer-running performance and endurance checks are excluded from that figure
and run under separate commands.

The table above is not hand-edited: release tooling regenerates it from a real
run, refuses to write figures from a failing run, and the release gate refuses
to cut an export when the figures are more than three days old.

Coverage spans, in the terms this documentation uses elsewhere:

- **Conformance scenarios** — session, group, and sealed-sender invariants
  checked against known-answer material and against behavior documented in the
  published specifications.
- **Cryptographic known-answer checks** — ML-KEM, hashing, AEAD, and signature
  primitives checked against published vector data.
- **Protocol behavior** — PQXDH establishment, the Double Ratchet, SPQR and
  ML-KEM Braid epochs, skipped-key bounds, replay and reordering handling, and
  fail-closed paths.
- **Property-based checks** — randomized inputs against protocol and encoding
  invariants.
- **Integration flows** — multi-device fanout, group membership lifecycle,
  device linking and provisioning, PNI-to-ACI upgrade, and relay delivery.
- **Adapter behavior** — the Expo, browser, Node, React Native, and in-memory
  storage adapters, plus the Convex relay and object-store adapters.
- **Public surface** — the exported API shape and the quickstart printed in the
  [README](../README.md), which is executed as written on every change.

## What this repository verifies in public

Continuous integration here runs on every push and pull request, and its result
is a badge on the README you can click through to the run logs:

- `npm ci` against the committed lockfile;
- `npm run build` — a full TypeScript compile of the published sources;
- `npm run typecheck`;
- `npm audit --omit=dev` at moderate severity against the production
  dependency tree.

That is a genuine, independently reproducible signal about the code you are
reading: it compiles, its types are consistent, and its six production
dependencies carry no known advisories at moderate or higher severity. It is
not a substitute for the protocol checks, and it is not offered as one.

## What this is not

- **Not an audit.** No independent security audit has been performed. One is
  planned; no firm is engaged and no date is set. Until a report exists and is
  published, treat this package as unaudited.
- **Not a compatibility guarantee.** Conformance work checks this profile
  against the published specifications it cites. It does not establish general
  wire compatibility with Signal Messenger, which this project does not claim.
- **Not a timing proof.** See the JavaScript timing boundary in the
  [security model](./SECURITY.md). Best-effort source-level patterns are not
  constant-time guarantees.

## If you need more

Reviewers evaluating this SDK for production — particularly under a commercial
license or a security-review process — can request a deeper walkthrough of the
assurance material, including the conformance scenarios and their results.
Write to security@open-e2ee.dev for security review, or
licensing@open-e2ee.dev for commercial evaluation.

If you find a vulnerability, follow the private reporting process in
[SECURITY.md](../SECURITY.md) rather than opening a public issue.
