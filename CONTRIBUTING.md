# Contributing

Thanks for your interest. This repository works a little differently from most
open-source projects, and this file explains exactly how — so nothing here is a
surprise after you have done work.

## How this repository is built

This repository is a **mechanized export** of a private engineering
repository. An allowlist decides, file by file, what is published; every
release is exported from a revision where the full internal check suite
passes. The reasons — and what those checks cover — are documented in
[docs/ASSURANCE.md](./docs/ASSURANCE.md).

Practical consequences:

- **`main` is generated.** Commits here are release exports; history is a
  sequence of releases, not a development log.
- **Pull requests cannot be merged directly.** A maintainer ports accepted
  changes into the internal repository, where they run against the full
  internal check suite before appearing in the next export — with your
  authorship credited in the changelog and, where practical, via
  `Co-authored-by` on the release commit. Small, focused patches (a bug fix,
  a doc correction) are the most likely to be ported quickly.
- **Issues are first-class.** Bug reports, API feedback, documentation
  problems, and integration pain are all genuinely useful and are triaged
  here, in public. Issue responsiveness is part of how we think a library
  earns trust — you should expect a reply, not silence.

## Before you open a pull request

- For anything beyond a small fix, **open an issue first** describing the
  change. It may already exist internally, and agreeing on the direction
  before you write code respects your time.
- Match the style of the surrounding code and docs. TypeScript, ESM, no new
  dependencies without discussion.
- Protocol-behavior changes need the paired internal test changes, which you
  cannot see — expect those to be written during porting, and expect questions.

## Security issues

Never open a public issue for a suspected vulnerability. Use the private
channels in [SECURITY.md](./SECURITY.md) — GitHub private vulnerability
reporting or security@open-e2ee.dev.

## Licensing of contributions

The SDK is dual-licensed (AGPL-3.0-or-later, with commercial licenses sold for
proprietary use — see [COMMERCIAL.md](./COMMERCIAL.md)). By submitting a
contribution you agree it is licensed under the repository's AGPL-3.0-or-later
license and that OpenE2EE LLC may also distribute it under its commercial
licenses. If you are not comfortable with that dual grant, please say so in
the PR instead of submitting — an issue describing the fix is still valuable
and carries no licensing implications.

## Conduct

Be professional and assume good faith; see
[CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).
