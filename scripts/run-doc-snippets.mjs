import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { transformSync } from 'esbuild';

import {
  analyseSnippet,
  buildProbeModule,
  buildUnshippedProbe,
  isSdkSpecifier,
  parseUnresolvedSpecifiers,
  SDK_PACKAGE,
} from './doc-snippet-symbols.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..');
const typescriptBin = join(repoRoot, 'node_modules', 'typescript', 'bin', 'tsc');
const tarballArgument = process.argv[2];

if (!tarballArgument) {
  throw new Error('Usage: node scripts/run-doc-snippets.mjs <packed-package.tgz>');
}

const tarballPath = resolve(tarballArgument);
const packageJson = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
const internalMarkdownSources = [
  'docs/DEVICE_LIFECYCLE.md',
  'docs/PREKEY_ARCHITECTURE.md',
];
const markdownSources = [
  ...new Set([
    ...packageJson.files.filter((path) => path.endsWith('.md')),
    ...internalMarkdownSources,
  ]),
].filter((path) => existsSync(join(repoRoot, path)));
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

function probeFileName(snippet) {
  // Name the probe after the snippet it came from: a compiler error names the
  // file, so the failure reads as the documentation that went stale rather than
  // as an anonymous temporary. Reasons repeat across a document, so the ordinal
  // carries the uniqueness the identifier does not.
  const label = `${snippet.source}--${snippet.id}`.replace(/[^A-Za-z0-9]+/g, '-');
  return `${label}-${snippet.ordinal}.ts`;
}

function parseDirective(source, mode, value) {
  const directive = value.trim();

  if (mode === 'run') {
    const parsed = /^(\S+)\s+expect="([^"]*)"$/.exec(directive);
    if (!parsed) {
      throw new Error(
        `${source} runnable doc snippet must declare: doc-snippet:run <id> expect="<stdout>"`
      );
    }
    return { id: parsed[1], expectedOutput: parsed[2], unshipped: [] };
  }

  if (mode === 'planned') {
    const parsed = /^(\S+)\s+unshipped="([^"]*)"$/.exec(directive);
    if (!parsed) {
      throw new Error(
        `${source} planned doc snippet must declare: ` +
          'doc-snippet:planned <id> unshipped="<specifier>[,<specifier>]"'
      );
    }
    const unshipped = parsed[2]
      .split(',')
      .map((specifier) => specifier.trim())
      .filter(Boolean);
    if (unshipped.length === 0) {
      throw new Error(`${source}:${parsed[1]} declares no unshipped specifier`);
    }
    for (const specifier of unshipped) {
      if (!isSdkSpecifier(specifier)) {
        throw new Error(
          `${source}:${parsed[1]} declares ${specifier} unshipped, which is not an SDK specifier`
        );
      }
    }
    return { id: parsed[1], expectedOutput: null, unshipped };
  }

  return { id: directive, expectedOutput: null, unshipped: [] };
}

function parseMarkdown(relativePath) {
  const source = readFileSync(join(repoRoot, relativePath), 'utf8');
  const snippets = [];
  const fence =
    /(?:(<!--\s*doc-snippet:(run|skip|illustrative|planned)\s+([^>]+?)\s*-->)\s*)?```(?:ts|typescript)\r?\n([\s\S]*?)```/g;
  for (const match of source.matchAll(fence)) {
    const [, marker, mode, idOrReason, code] = match;
    if (!marker) {
      throw new Error(`${relativePath} contains an unclassified doc snippet`);
    }
    const directive = parseDirective(relativePath, mode, idOrReason);
    snippets.push({
      source: relativePath,
      mode,
      ordinal: snippets.length + 1,
      ...directive,
      code,
    });
  }
  return snippets;
}

function decodeHtml(value) {
  // Decode `&amp;` last: decoding it earlier turns `&amp;quot;` into
  // `&quot;`, which the later replacements would then decode a second time.
  return value
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'")
    .replaceAll('&amp;', '&');
}

function stripHtmlTags(value) {
  // Re-run until stable: one pass over `<<code>span>` leaves `<span>` behind.
  let text = value;
  for (let previous; text !== previous; ) {
    previous = text;
    text = text.replace(/<[^>]*>/g, '');
  }
  return text;
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
      /(?:(<!--\s*doc-snippet:(run|skip|illustrative|planned)\s+([^>]+?)\s*-->)\s*)?<pre><code[^>]*>([\s\S]*?)<\/code><\/pre>/g
    ),
  ];
  const snippets = [];
  for (const match of codeBlocks) {
    const [, marker, mode, idOrReason, highlightedCode] = match;
    const code = decodeHtml(stripHtmlTags(highlightedCode));
    if (!marker) {
      throw new Error(`${pricingSource} contains an unclassified doc snippet`);
    }
    const directive = parseDirective(pricingSource, mode, idOrReason);
    snippets.push({
      source: pricingSource,
      mode,
      ordinal: snippets.length + 1,
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
  throw new Error('No doc snippets were discovered');
}

for (const snippet of snippets.filter((candidate) => candidate.mode === 'run')) {
  if (!snippet.code.includes(infrastructureLabel)) {
    throw new Error(`${snippet.source}:${snippet.id} is missing the infrastructure label`);
  }
}

const runnable = snippets.filter((snippet) => snippet.mode === 'run');
const skipped = snippets.filter((snippet) => snippet.mode === 'skip');
const planned = snippets.filter((snippet) => snippet.mode === 'planned');
const illustrative = snippets.filter((snippet) => snippet.mode === 'illustrative');
const fixtureDir = mkdtempSync(join(tmpdir(), 'signal-doc-snippets-'));

try {
  writeFileSync(
    join(fixtureDir, 'package.json'),
    `${JSON.stringify(
      {
        name: 'signal-doc-snippet-runner',
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
      `doc-snippet:ok ${snippet.source}:${snippet.id}${result.stdout ? `\n${result.stdout.trim()}` : ''}\n`
    );
  }

  // A snippet marked `skip` or `planned` cannot execute -- it needs a live
  // client, a fixture, or it is a fragment lifted out of a larger program. It
  // still names SDK symbols, and those names are what rots when an export is
  // renamed or deleted. Verify them against the packed tarball's types without
  // running anything, so prose cannot outlive the API it describes.
  const rootValueExports = new Set(
    JSON.parse(
      run(
        process.execPath,
        [
          '--input-type=module',
          '-e',
          `import * as sdk from '${SDK_PACKAGE}';` +
            'process.stdout.write(JSON.stringify(Object.keys(sdk)));',
        ],
        { cwd: fixtureDir }
      ).stdout
    )
  );

  const probeTsconfig = `${JSON.stringify(
    {
      compilerOptions: {
        noEmit: true,
        target: 'ES2022',
        module: 'NodeNext',
        moduleResolution: 'NodeNext',
        skipLibCheck: true,
      },
      include: ['*.ts'],
    },
    null,
    2
  )}\n`;

  const probeDir = join(fixtureDir, 'probes');
  mkdirSync(probeDir);
  writeFileSync(join(probeDir, 'tsconfig.json'), probeTsconfig);

  let verified = 0;
  let referencedSymbols = 0;
  let memberProbes = 0;
  let withoutSymbols = 0;
  const unshippedClaims = [];
  for (const snippet of [...skipped, ...planned]) {
    let analysis;
    try {
      analysis = analyseSnippet(snippet.code);
    } catch (error) {
      throw new Error(
        `${snippet.source}:${snippet.id} is not parseable TypeScript\n${error.message}`
      );
    }

    const specifiers = new Set(
      analysis.imports
        .map((declaration) => declaration.specifier)
        .filter((specifier) => isSdkSpecifier(specifier))
    );
    for (const specifier of snippet.unshipped) {
      // A declaration the snippet no longer backs is a claim about nothing. It
      // would keep passing forever, so reject it rather than carry it.
      if (!specifiers.has(specifier)) {
        throw new Error(
          `${snippet.source}:${snippet.id} declares ${specifier} unshipped but never imports it`
        );
      }
      unshippedClaims.push({ snippet, specifier });
    }

    const probe = buildProbeModule(analysis, rootValueExports, new Set(snippet.unshipped));
    if (!probe) {
      withoutSymbols += 1;
      process.stdout.write(`doc-snippet:no-symbols ${snippet.source}:${snippet.id}\n`);
      continue;
    }
    writeFileSync(join(probeDir, probeFileName(snippet)), probe.source);
    verified += 1;
    referencedSymbols += probe.referencedSymbols;
    memberProbes += probe.memberProbes;
    process.stdout.write(
      `doc-snippet:symbols ${snippet.source}:${snippet.id}` +
        ` imports=${probe.referencedSymbols} members=${probe.memberProbes}\n`
    );
  }

  // Fail closed. An analysis that stopped finding symbols would emit no probes,
  // and an empty probe directory compiles clean -- so the guard would report a
  // pass while checking nothing at all.
  if (verified === 0) {
    throw new Error('No unexecuted doc snippet referenced an SDK symbol to verify');
  }
  run(process.execPath, [typescriptBin, '--project', probeDir], { cwd: fixtureDir });

  // The `planned` tier asserts a negative, so its probe must fail to compile.
  // Compile it apart from the clean pass: an intentional failure mixed into
  // that output would leave nobody able to read either result.
  if (unshippedClaims.length > 0) {
    const unshippedDir = join(fixtureDir, 'unshipped');
    mkdirSync(unshippedDir);
    writeFileSync(join(unshippedDir, 'tsconfig.json'), probeTsconfig);
    writeFileSync(
      join(unshippedDir, 'unshipped.ts'),
      buildUnshippedProbe(unshippedClaims.map((claim) => claim.specifier))
    );
    const compiled = spawnSync(process.execPath, [typescriptBin, '--project', unshippedDir], {
      cwd: fixtureDir,
      encoding: 'utf8',
      stdio: 'pipe',
    });
    const unresolved = parseUnresolvedSpecifiers(
      [compiled.stdout, compiled.stderr].filter(Boolean).join('\n')
    );
    for (const { snippet, specifier } of unshippedClaims) {
      if (!unresolved.has(specifier)) {
        throw new Error(
          `${snippet.source}:${snippet.id} documents ${specifier} as not yet shipped, ` +
            'but the packed package resolves it. Promote the snippet to `skip` or `run`.'
        );
      }
      process.stdout.write(
        `doc-snippet:unshipped ${snippet.source}:${snippet.id} ${specifier}\n`
      );
    }
  }

  // Named one per line rather than counted. This tier is the only one the
  // compiler never sees, so the way it stays honest is that every addition is
  // legible in the build log and in review.
  for (const snippet of illustrative) {
    process.stdout.write(`doc-snippet:illustrative ${snippet.source}:${snippet.id}\n`);
  }

  process.stdout.write(
    `doc-snippets:ok ${runnable.length} executed, ${verified} symbol-verified` +
      ` (${referencedSymbols} imported names, ${memberProbes} member probes),` +
      ` ${withoutSymbols} referencing no SDK symbol,` +
      ` ${planned.length} planned (${unshippedClaims.length} unshipped specifiers),` +
      ` ${illustrative.length} illustrative, package ${basename(tarballPath)}\n`
  );
} finally {
  rmSync(fixtureDir, { recursive: true, force: true });
}
