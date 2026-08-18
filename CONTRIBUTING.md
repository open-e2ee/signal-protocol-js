# Contributing

Thanks for your interest. This repository works a little differently from most
open-source projects. This file explains exactly how, so that nothing here
surprises you after you do the work.

## How we build this repository

This repository is a **mechanized export** of a private engineering
repository. An allowlist decides, file by file, which files the export
publishes. Every release comes from a revision where the full internal check
suite passes. For the reasons, and for what those checks cover, see
[docs/ASSURANCE.md](./docs/ASSURANCE.md).

Practical consequences:

- **The export generates `main`**. Commits here are release exports. The
  history records releases, and it is not a development log.
- **Nobody merges a pull request into `main`**. A maintainer ports accepted
  changes into the internal repository. There they run against the full
  internal check suite before they appear in the next export. The changelog
  credits your authorship, and where practical a `Co-authored-by` trailer on
  the release commit credits it too. A maintainer is most likely to port a
  small, focused patch quickly. A bug fix or a doc correction is the usual
  example.
- **Issues matter here**. Bug reports, API feedback, documentation problems,
  and integration pain are all genuinely useful. We triage them here, in
  public. How fast a project answers issues is part of how we think a library
  earns trust. Expect a reply, not silence.

## Before you open a pull request

- For anything beyond a small fix, **open an issue first** describing the
  change. It may already exist internally, and agreeing on the direction
  before you write code respects your time.
- Match the style of the surrounding code and docs. TypeScript, ESM, no new
  dependencies without discussion.
- Protocol-behavior changes need the paired internal test changes, which you
  cannot see. A maintainer writes those during porting, so expect questions.

## Security issues

Never open a public issue for a suspected vulnerability. Use the private
channels in [SECURITY.md](./SECURITY.md): GitHub private vulnerability
reporting, or security@open-e2ee.dev.

## Licensing of contributions

The SDK is dual-licensed. The license is AGPL-3.0-or-later, and OpenE2EE LLC
also sells commercial licenses for proprietary use (see
[COMMERCIAL.md](./COMMERCIAL.md)). When you submit a contribution, you agree
that it falls under the repository's AGPL-3.0-or-later license. You also agree
that OpenE2EE LLC may distribute it under its commercial licenses. If you are
not comfortable with that dual grant, please say so in the PR instead of
submitting it. An issue that describes the fix is still valuable, and it
carries no licensing implications.

## How we work together

Be professional and assume good faith. See
[CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md).
