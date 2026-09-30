#!/usr/bin/env node
/*
 * Decides whether a pull request changes only documentation that no check
 * reads. The workflows skip their heavy jobs for such a change and run them
 * for every other change.
 *
 * Each doubt resolves to "code". A file that is not on the allowlist, a file
 * list that disagrees with the count GitHub states, an empty list, and a
 * repository without an allowlist all give `code=true`. Input that cannot be
 * read is an error, so the job fails and never reports documentation only.
 *
 *   gh api --paginate "repos/$REPO/pulls/$PR/files" \
 *     --jq '.[] | {filename, previous_filename}' |
 *     node ./scripts/docs-only-change.mjs "$CHANGED_FILES"
 *
 * The one argument is the `changed_files` count of the pull request. Standard
 * input holds one JSON object per line. Standard output gets `code=true` or
 * `code=false` for `$GITHUB_OUTPUT`, and standard error gets the reason.
 */
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/*
 * The allowlist is a separate file so that each repository states its own.
 * A repository without one has no documentation-only change.
 */
export const DOCUMENT_PATHS_FILE = 'scripts/docs-only-paths.json';

/* A control character, a backslash, or an empty, `.`, or `..` segment. */
const UNSAFE_PATH = /[\u0000-\u001f\u007f\\]|(?:^|\/)\.{0,2}(?:\/|$)/;

/**
 * Reads the allowlist: `files` names exact paths, and `markdownRoots` names
 * directories whose Markdown files are all documentation. Returns null when
 * the repository has no allowlist.
 */
export function readDocumentPaths(root = repoRoot) {
  const path = join(root, DOCUMENT_PATHS_FILE);
  if (!existsSync(path)) return null;
  const paths = JSON.parse(readFileSync(path, 'utf8'));
  for (const key of ['files', 'markdownRoots']) {
    const list = paths?.[key];
    const valid = Array.isArray(list) && list.every((entry) => typeof entry === 'string');
    if (!valid) {
      throw new Error(`${DOCUMENT_PATHS_FILE}: "${key}" must be an array of paths`);
    }
    for (const entry of list) {
      if (UNSAFE_PATH.test(entry)) {
        throw new Error(`${DOCUMENT_PATHS_FILE}: "${entry}" is not a normalized path`);
      }
    }
  }
  return { files: paths.files, markdownRoots: paths.markdownRoots };
}

/**
 * True when the allowlist names `path` exactly, or `path` is a `.md` file
 * below one of its Markdown roots. Matching is exact and case-sensitive.
 */
export function isDocument(path, paths) {
  if (typeof path !== 'string' || UNSAFE_PATH.test(path)) return false;
  if (paths.files.includes(path)) return true;
  return path.endsWith('.md') && paths.markdownRoots.some((root) => path.startsWith(`${root}/`));
}

/**
 * Classifies the changed files of a pull request. Each entry is one file from
 * the GitHub pull request files API: `filename`, and `previous_filename` for a
 * rename. A rename is documentation only when both of its names are.
 *
 * Returns `{ code, reason }`. Throws on malformed input.
 */
export function classifyChange(entries, expectedCount, paths) {
  if (!Array.isArray(entries)) throw new Error('the changed files must be an array');
  if (!Number.isSafeInteger(expectedCount) || expectedCount < 0) {
    throw new Error(`the changed file count must be a non-negative integer, not ${expectedCount}`);
  }
  const names = entries.flatMap((entry, index) => {
    const { filename, previous_filename: previous } = entry ?? {};
    if (typeof filename !== 'string' || filename === '') {
      throw new Error(`changed file ${index + 1} has no filename`);
    }
    if (previous === undefined || previous === null) return [filename];
    if (typeof previous !== 'string' || previous === '') {
      throw new Error(`changed file ${index + 1} has a malformed previous_filename`);
    }
    return [filename, previous];
  });

  if (paths === null) {
    return { code: true, reason: `${DOCUMENT_PATHS_FILE} is absent, so every change is code` };
  }
  if (entries.length !== expectedCount) {
    return {
      code: true,
      reason: `the file list has ${entries.length} entries but the pull request states ${expectedCount}`,
    };
  }
  if (entries.length === 0) {
    return { code: true, reason: 'the pull request changes no files' };
  }
  const code = names.find((name) => !isDocument(name, paths));
  if (code !== undefined) {
    return { code: true, reason: `${JSON.stringify(code)} is not on the documentation allowlist` };
  }
  return { code: false, reason: `all ${entries.length} changed files are documentation` };
}

/* One JSON object per line, as `gh api --jq` prints them. */
export function parseEntries(text) {
  return text
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch {
        throw new Error(`line ${index + 1} of the changed files is not JSON`);
      }
    });
}

/*
 * Compared as real paths: a script reached through a symbolic link, such as
 * macOS `/var` for `/private/var`, would otherwise do nothing and exit 0.
 */
if (
  process.argv[1] !== undefined &&
  realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
) {
  try {
    const [count, ...extra] = process.argv.slice(2);
    if (count === undefined || extra.length > 0 || !/^\d+$/.test(count)) {
      throw new Error('usage: docs-only-change.mjs <changed-file-count> < files.jsonl');
    }
    const { code, reason } = classifyChange(
      parseEntries(readFileSync(0, 'utf8')),
      Number(count),
      readDocumentPaths()
    );
    process.stderr.write(`${reason}\n`);
    process.stdout.write(`code=${code}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
    process.exit(1);
  }
}
