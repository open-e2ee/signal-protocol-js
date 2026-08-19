# Assurance

> Navigation: [README](../README.md) | [Security Model](./SECURITY.md) |
> [Protocol Policy](./PROTOCOL_POLICY.md) |
> [Vulnerability Reporting](../SECURITY.md)

This document exists because of an honest problem. If you browse this
repository, you will not find automated checks. A cryptography package with no
visible checks reasonably reads as an unchecked one. That inference is wrong
here, and the correct answer is not a reassuring adjective. This document
explains where the checks live, what they cover, what the export publishes, and
what it keeps private.

## Why this repository looks the way it does

This repository is a mechanized export of a private engineering repository. An
allowlist in the source repository decides, file by file, what becomes public.
An export tool copies exactly that set, and refuses to write anything the
allowlist does not name. The published result is the library, its
documentation, and its generated API reference.

The automated checks are deliberately outside that allowlist. They exercise
internal module paths, private protocol scaffolding, and cross-implementation
comparison material that the allowlist keeps unpublished. The export also
strips the development dependencies they require. Publishing them as inert
files that nobody could run would look like assurance without being any.

## What runs, and what it covers

Every change to the source repository runs the full set of automated checks,
and an export is only cut from a revision where they pass.

Most recent full run on 2026-08-17:

| | |
|---|---|
| Modules executed | 389 |
| Assertions | 6,922 |
| Passed | 6,920 |
| Skipped | 2 |
| Failed | 0 |
| Wall time | 139 s |

That figure excludes longer-running performance and endurance checks, which run
under separate commands.

Nobody hand-edits the table above. Release tooling regenerates it from a real
run, and refuses to write figures from a failing run. The release gate refuses
to cut an export when the figures are more than three days old.

Coverage spans, in the terms this documentation uses elsewhere:

- **Conformance scenarios**. Session, group, and sealed-sender invariants
  checked against known-answer material and against behavior documented in the
  published specifications.
- **Cryptographic known-answer checks**. ML-KEM, hashing, AEAD, and signature
  primitives checked against published vector data.
- **Protocol behavior**. PQXDH establishment, the Double Ratchet, and SPQR and
  ML-KEM Braid epochs. Skipped-key bounds, replay and reordering handling, and
  fail-closed paths.
- **Property-based checks**. Randomized inputs against protocol and encoding
  invariants.
- **Integration flows**. Multi-device fanout, group membership lifecycle,
  device linking and provisioning, PNI-to-ACI upgrade, and relay delivery.
- **Adapter behavior**. The Expo, browser, Node, React Native, and in-memory
  storage adapters, plus the Convex relay and object-store adapters. The
  browser adapter's contract suites also run inside real Chromium, Firefox,
  and WebKit pages on every change. A soak run drives thousands of full
  open/write/read/close cycles through the browser adapter in Chromium on
  every change. It fails on upward memory or latency drift.
- **React Native adapter behavior**. The exported backend-conformance kit runs
  against its reference backend on the Hermes engine on every change.
  Interruption and storage-pressure suites drive the adapter over that
  backend.
- **Public surface**. The exported API shape, and the quickstart printed in the
  [README](../README.md). CI runs that quickstart as written on every change.
- **Error surface**. Every class in the exported `EncryptionError` family has a
  construction site. Every `EncryptionErrorCode` and
  `MediaAttachmentErrorCode` value also has one. The check rejects unresolved
  code forwarding instead of treating it as proof.

In every adapter case the assertions target the adapter's contract. The engines
are the environment the adapter must honor that contract in, not the subject of
the tests.

## What reviews each change

Tooling automates the checks above, and automation only finds what someone
thought to encode. Alongside them, every change to the source repository passes
an adversarial AI review before it merges. Recurring whole-codebase AI audit
passes run against the same repository, and their findings go through the same
gated process as any other change. AI agents review each change, rather than
reviewers at a firm, and this project does not publish the transcripts. The
reviews therefore describe what the process requires, not a result you can
inspect. This package has no independent firm audit, and an adversarial AI
review is not a substitute for one.

## What this repository verifies in public

Continuous integration here runs on every push and pull request. Its result is
a badge on the README that you can click through to the run logs:

- `npm ci` against the committed lockfile.
- `npm run build`, a full TypeScript compile of the published sources.
- `npm run typecheck`.
- `npm audit --omit=dev` at moderate severity against the production
  dependency tree.
- the [README](../README.md) Quick Start, extracted from the file as printed
  and run against the packed package. A second run adds
  `--disallow-code-generation-from-strings`, which stands in for a strict
  `script-src` policy and for a Chrome MV3 extension.
- every TypeScript snippet in the shipped documentation, checked against the
  packed package. The check runs each complete program and matches its output.
  For a snippet that cannot run, it compiles every SDK name against the
  package's types. A renamed or deleted export therefore fails the build in
  every document that names it. A snippet that previews an unreleased API
  declares which import paths do not exist yet. The build fails if one of them
  resolves, and names each pseudocode block in its log.
- every subpath in the package's export map. A consumer outside the repository
  imports each one, with all of the optional peer dependencies removed from
  its `node_modules`. The check itself names the platform-bound entry points,
  and it verifies that list in both directions. An exemption that stops being
  true therefore fails the check.

That is a genuine, independently reproducible signal about the code you read
here. It compiles. Its types are consistent. Its six production dependencies
carry no known advisories at moderate or higher severity. The code printed in
its documentation runs as printed on a machine that is not ours. That signal is
not a substitute for the protocol checks, and this document does not offer it
as one.

## What this is not

- **Not an independent firm audit**. This package has no independent security
  firm audit, and no audit engagement. The adversarial AI review described
  above is continuous and real, but it is not a third-party assurance result.
  Treat this package as unaudited by any independent firm.
- **Not a compatibility guarantee**. Conformance work checks this profile
  against the published specifications it cites. It does not establish general
  wire compatibility with Signal Messenger, which this project does not claim.
- **Not a timing proof**. See the JavaScript timing boundary in the
  [security model](./SECURITY.md). Best-effort source-level patterns are not
  constant-time guarantees.

## If you need more

Reviewers who evaluate this SDK for production can request a deeper walkthrough
of the assurance material, including the conformance scenarios and their
results. This applies in particular under a commercial license or a
security-review process.
Write to security@open-e2ee.dev for security review, or
licensing@open-e2ee.dev for commercial evaluation.

If you find a vulnerability, follow the private reporting process in
[SECURITY.md](../SECURITY.md) rather than opening a public issue.
