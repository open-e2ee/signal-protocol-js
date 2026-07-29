import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { transformSync } from 'esbuild';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..');
const typescriptBin = join(repoRoot, 'node_modules', 'typescript', 'bin', 'tsc');
const tarballArgument = process.argv[2];

if (!tarballArgument) {
  throw new Error('Usage: node scripts/run-mock-snippets.mjs <packed-package.tgz>');
}

const tarballPath = resolve(tarballArgument);
const markdownSources = [
  'README.md',
  'docs/GETTING_STARTED.md',
  'docs/RECIPES.md',
  'docs/CLIENT_COMPOSITION.md',
];
const pricingSource = 'docs/pricing-preview.html';
const infrastructureLabel =
  'Real protocol and cryptography; simulated in-memory infrastructure.';

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    stdio: 'pipe',
    ...options,
  });
  if (result.status !== 0) {
    const output = [result.stdout, result.stderr].filter(Boolean).join('\n');
    throw new Error(`${command} ${args.join(' ')} failed\n${output}`.trim());
  }
  return result;
}

function isMockSnippet(code) {
  return (
    code.includes('/local/store/mock') ||
    code.includes('/remote/relay/mock') ||
    code.includes('mockStore(') ||
    code.includes('mockRelay(')
  );
}

function parseDirective(source, mode, value) {
  const directive = value.trim();
  if (mode === 'skip') {
    return { id: directive, expectedOutput: null };
  }

  const parsed = /^(\S+)\s+expect="([^"]*)"$/.exec(directive);
  if (!parsed) {
    throw new Error(
      `${source} runnable mock snippet must declare: mock-snippet:run <id> expect="<stdout>"`
    );
  }
  return { id: parsed[1], expectedOutput: parsed[2] };
}

function parseMarkdown(relativePath) {
  const source = readFileSync(join(repoRoot, relativePath), 'utf8');
  const snippets = [];
  const fence =
    /(?:(<!--\s*mock-snippet:(run|skip)\s+([^>]+?)\s*-->)\s*)?```(?:ts|typescript)\r?\n([\s\S]*?)```/g;
  for (const match of source.matchAll(fence)) {
    const [, marker, mode, idOrReason, code] = match;
    if (!isMockSnippet(code)) continue;
    if (!marker) {
      throw new Error(`${relativePath} contains an unclassified mock snippet`);
    }
    const directive = parseDirective(relativePath, mode, idOrReason);
    snippets.push({
      source: relativePath,
      mode,
      ...directive,
      code,
    });
  }
  return snippets;
}

function decodeHtml(value) {
  return value
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&amp;', '&')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'");
}

function parsePricingPreview() {
  // The pricing preview is internal-only and excluded from the public export,
  // but this script ships in both repositories. Validate its snippets when the
  // file exists; skip cleanly where it was never published.
  if (!existsSync(join(repoRoot, pricingSource))) {
    return [];
  }
  const source = readFileSync(join(repoRoot, pricingSource), 'utf8');
  const codeBlocks = [
    ...source.matchAll(
      /(?:(<!--\s*mock-snippet:(run|skip)\s+([^>]+?)\s*-->)\s*)?<pre><code[^>]*>([\s\S]*?)<\/code><\/pre>/g
    ),
  ];
  const snippets = [];
  for (const match of codeBlocks) {
    const [, marker, mode, idOrReason, highlightedCode] = match;
    const code = decodeHtml(highlightedCode.replace(/<[^>]+>/g, ''));
    if (!isMockSnippet(code)) continue;
    if (!marker) {
      throw new Error(`${pricingSource} contains an unclassified mock snippet`);
    }
    const directive = parseDirective(pricingSource, mode, idOrReason);
    snippets.push({
      source: pricingSource,
      mode,
      ...directive,
      code,
    });
  }
  return snippets;
}

const snippets = [
  ...markdownSources.flatMap(parseMarkdown),
  ...parsePricingPreview(),
];

if (snippets.length === 0) {
  throw new Error('No mock snippets were discovered');
}

for (const snippet of snippets) {
  if (!snippet.code.includes(infrastructureLabel)) {
    throw new Error(`${snippet.source}:${snippet.id} is missing the infrastructure label`);
  }
}

const runnable = snippets.filter((snippet) => snippet.mode === 'run');
const skipped = snippets.filter((snippet) => snippet.mode === 'skip');
const fixtureDir = mkdtempSync(join(tmpdir(), 'signal-mock-snippets-'));

try {
  writeFileSync(
    join(fixtureDir, 'package.json'),
    `${JSON.stringify(
      {
        name: 'signal-mock-snippet-runner',
        private: true,
        type: 'module',
      },
      null,
      2
    )}\n`
  );
  run(
    'npm',
    ['install', '--no-audit', '--no-fund', tarballPath],
    { cwd: fixtureDir }
  );

  for (const [index, snippet] of runnable.entries()) {
    const sourcePath = join(fixtureDir, `snippet-${index + 1}.ts`);
    const executablePath = join(fixtureDir, `snippet-${index + 1}.mjs`);
    writeFileSync(sourcePath, snippet.code);
    run(
      process.execPath,
      [
        typescriptBin,
        sourcePath,
        '--noEmit',
        '--target',
        'ES2022',
        '--module',
        'NodeNext',
        '--moduleResolution',
        'NodeNext',
        '--skipLibCheck',
      ],
      { cwd: fixtureDir }
    );
    const executable = transformSync(snippet.code, {
      loader: 'ts',
      format: 'esm',
      target: 'es2022',
    }).code;
    writeFileSync(executablePath, executable);
    const result = run(process.execPath, [executablePath], {
      cwd: fixtureDir,
      timeout: 120_000,
    });
    const actualOutput = result.stdout.trim();
    const outputMatches =
      snippet.expectedOutput === ''
        ? actualOutput === ''
        : actualOutput.includes(snippet.expectedOutput);
    if (!outputMatches) {
      throw new Error(
        `${snippet.source}:${snippet.id} expected stdout containing ${JSON.stringify(
          snippet.expectedOutput
        )}, received ${JSON.stringify(actualOutput)}`
      );
    }
    process.stdout.write(
      `mock-snippet:ok ${snippet.source}:${snippet.id}${result.stdout ? `\n${result.stdout.trim()}` : ''}\n`
    );
  }

  for (const snippet of skipped) {
    process.stdout.write(`mock-snippet:skip ${snippet.source}:${snippet.id}\n`);
  }
  process.stdout.write(
    `mock-snippets:ok ${runnable.length} run, ${skipped.length} explicitly skipped, package ${basename(tarballPath)}\n`
  );
} finally {
  rmSync(fixtureDir, { recursive: true, force: true });
}
