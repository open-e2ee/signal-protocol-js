/*
 * The Markdown files whose code snippets `run-doc-snippets.mjs` runs and
 * checks: each Markdown file that the package ships, and the internal
 * documents below. `scripts/docs-only-paths.json` names a subset of them as
 * snippet documents.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const INTERNAL_MARKDOWN_SOURCES = [
  'docs/DEVICE_LIFECYCLE.md',
  'docs/PREKEY_ARCHITECTURE.md',
  'docs/SIGNAL_RELAY_CONNECTION.md',
];

/** The repository-relative paths of the snippet sources that exist below `root`. */
export function docSnippetSources(root) {
  const packageJson = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  return [
    ...new Set([
      ...packageJson.files.filter((path) => path.endsWith('.md')),
      ...INTERNAL_MARKDOWN_SOURCES,
    ]),
  ].filter((path) => existsSync(join(root, path)));
}
