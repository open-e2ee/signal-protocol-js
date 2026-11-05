#!/usr/bin/env node
/*
 * Decides which jobs of a workflow a pull request needs. The workflows skip
 * their heavy jobs for a change that cannot affect them and run them for
 * every other change. A change has one of four verdicts:
 *
 * - `docs-only`: each file is documentation that no check reads. Every
 *   workflow skips its heavy jobs.
 * - `workflows-only`: each file is a workflow in `.github/workflows/`. A
 *   workflow runs its heavy jobs only when the change includes its own file.
 * - `fixture-only`: each file is below a fixture root of the allowlist. No
 *   job runs those files yet, so every job runs.
 * - `full`: any other change. Every job runs.
 *
 * Each doubt resolves to "full". A file that is not on the allowlist, a file
 * list that disagrees with the count GitHub states, an empty list, a
 * repository without an allowlist, and a workflows-only change for an unknown
 * workflow all give `code=true`. Input that cannot be read is an error, so the
 * job fails and never skips a job.
 *
 *   gh api --paginate "repos/$REPO/pulls/$PR/files" \
 *     --jq '.[] | {filename, previous_filename}' |
 *     WORKFLOW_REF="$GITHUB_WORKFLOW_REF" \
 *     node ./scripts/docs-only-change.mjs "$CHANGED_FILES"
 *
 * The one argument is the `changed_files` count of the pull request. Standard
 * input holds one JSON object per line. `WORKFLOW_REF` is the
 * `github.workflow_ref` of the workflow that asks, and names its file.
 * Standard output gets `code=true` or `code=false` for `$GITHUB_OUTPUT`, and
 * standard error gets the verdict and the reason.
 */
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/*
 * The allowlist is a separate file so that each repository states its own.
 * A repository without one has no change that skips a job.
 */
export const DOCUMENT_PATHS_FILE = 'scripts/docs-only-paths.json';

/* A control character, a backslash, or an empty, `.`, or `..` segment. */
const UNSAFE_PATH = /[\u0000-\u001f\u007f\\]|(?:^|\/)\.{0,2}(?:\/|$)/;

/* GitHub reads a workflow only from a YAML file directly in this directory. */
const WORKFLOW_PATH = /^\.github\/workflows\/[^/]+\.ya?ml$/;

/* `owner/repository/path@ref`, as `github.workflow_ref` states it. */
const WORKFLOW_REF_FORMAT = /^[^/@]+\/[^/@]+\/([^@]+)@[^@]+$/;

/**
 * Reads the allowlist: `files` names exact paths, `markdownRoots` names
 * directories whose Markdown files are all documentation, and `fixtureRoots`
 * names directories whose files only a fixture reads. Returns null when the
 * repository has no allowlist.
 */
export function readDocumentPaths(root = repoRoot) {
  const path = join(root, DOCUMENT_PATHS_FILE);
  if (!existsSync(path)) return null;
  const paths = JSON.parse(readFileSync(path, 'utf8'));
  for (const key of ['files', 'markdownRoots', 'fixtureRoots']) {
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
  return {
    files: paths.files,
    markdownRoots: paths.markdownRoots,
    fixtureRoots: paths.fixtureRoots,
  };
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

/** True when `path` is a workflow file that GitHub reads. */
export function isWorkflow(path) {
  return typeof path === 'string' && !UNSAFE_PATH.test(path) && WORKFLOW_PATH.test(path);
}

/** True when `path` is a file below one of the fixture roots of the allowlist. */
export function isFixture(path, paths) {
  if (typeof path !== 'string' || UNSAFE_PATH.test(path)) return false;
  return paths.fixtureRoots.some((root) => path.startsWith(`${root}/`));
}

/**
 * The workflow file that `github.workflow_ref` names, or null when no
 * reference is given. Throws on a reference that does not name a workflow.
 */
export function workflowFromRef(ref) {
  if (ref === undefined || ref === '') return null;
  const path = typeof ref === 'string' ? WORKFLOW_REF_FORMAT.exec(ref)?.[1] : undefined;
  if (path === undefined || !isWorkflow(path)) {
    throw new Error(`the workflow reference ${JSON.stringify(ref)} names no workflow file`);
  }
  return path;
}

/**
 * Classifies the changed files of a pull request for one workflow. Each entry
 * is one file from the GitHub pull request files API: `filename`, and
 * `previous_filename` for a rename. A rename has a verdict other than `full`
 * only when both of its names have it. `workflow` is the file of the workflow
 * that asks, or null when it is unknown.
 *
 * Returns `{ verdict, code, reason }`: `code` is true when the workflow must
 * run its heavy jobs. Throws on malformed input.
 */
export function classifyChange(entries, expectedCount, paths, workflow = null) {
  if (!Array.isArray(entries)) throw new Error('the changed files must be an array');
  if (!Number.isSafeInteger(expectedCount) || expectedCount < 0) {
    throw new Error(`the changed file count must be a non-negative integer, not ${expectedCount}`);
  }
  if (workflow !== null && !isWorkflow(workflow)) {
    throw new Error(`${JSON.stringify(workflow)} is not a workflow file`);
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
  const full = (reason) => ({ verdict: 'full', code: true, reason });

  if (paths === null) {
    return full(`${DOCUMENT_PATHS_FILE} is absent, so every change is code`);
  }
  if (entries.length !== expectedCount) {
    return full(
      `the file list has ${entries.length} entries but the pull request states ${expectedCount}`
    );
  }
  if (entries.length === 0) {
    return full('the pull request changes no files');
  }
  const count = entries.length;
  if (names.every((name) => isDocument(name, paths))) {
    return {
      verdict: 'docs-only',
      code: false,
      reason: `all ${count} changed files are documentation`,
    };
  }
  if (names.every(isWorkflow)) {
    if (workflow === null) {
      return {
        verdict: 'workflows-only',
        code: true,
        reason: `all ${count} changed files are workflows, and the asking workflow is unknown`,
      };
    }
    const own = names.includes(workflow);
    return {
      verdict: 'workflows-only',
      code: own,
      reason: `all ${count} changed files are workflows, and ${workflow} is ${own ? '' : 'not '}one of them`,
    };
  }
  if (names.every((name) => isFixture(name, paths))) {
    return {
      verdict: 'fixture-only',
      code: true,
      reason: `all ${count} changed files are below a fixture root, and no job here runs them`,
    };
  }
  const other = names.find(
    (name) => !isDocument(name, paths) && !isWorkflow(name) && !isFixture(name, paths)
  );
  return full(
    other === undefined
      ? `the ${count} changed files are of more than one kind`
      : `${JSON.stringify(other)} is not on the documentation allowlist`
  );
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
    const { verdict, code, reason } = classifyChange(
      parseEntries(readFileSync(0, 'utf8')),
      Number(count),
      readDocumentPaths(),
      workflowFromRef(process.env.WORKFLOW_REF)
    );
    process.stderr.write(`${verdict}: ${reason}\n`);
    process.stdout.write(`code=${code}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
    process.exit(1);
  }
}
