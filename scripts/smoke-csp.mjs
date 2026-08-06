/*
 * Runs the README quick start against the packed package with runtime code
 * generation disabled, the way a strict Content-Security-Policy denies it in a
 * browser and the way `--disallow-code-generation-from-strings` denies it in
 * Node.
 *
 * This is the acceptance gate for removing protobufjs from the wire path.
 * protobufjs builds its codecs with `new Function`, so today the quick start
 * dies inside the first `send`: the `EvalError` surfaces as a `SesameError`
 * with code `ALL_DEVICES_FAILED`, and this script exits non-zero. It turns
 * green when every wire codec is a hand-written static encoder.
 *
 * Usage:
 *   node ./scripts/smoke-csp.mjs             # build, pack, run the quick start
 *   node ./scripts/smoke-csp.mjs --no-build  # reuse an existing dist/
 *
 * The quick start is extracted from README.md exactly as `.github/workflows/
 * ci.yml` extracts it, so this gate and the published snippet can never drift.
 */

import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..');
const packageJson = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
const packageNameSegments = packageJson.name.split('/');
const QUICKSTART_EXPECTED_OUTPUT = 'alice: hello';
const QUICKSTART_TIMEOUT_MS = 120_000;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: 'pipe',
    ...options,
  });
  if (result.status !== 0) {
    const output = [result.stdout, result.stderr].filter(Boolean).join('\n');
    throw new Error(`${command} ${args.join(' ')} failed\n${output}`.trim());
  }
  return result.stdout;
}

/**
 * The first `ts` fence under `## Quick Start`. The published block is plain
 * ESM with type annotations nowhere in it, which is why CI can rename it to
 * `.mjs` and run it unmodified; this script holds it to the same bargain.
 */
function readQuickStart() {
  const readme = readFileSync(join(repoRoot, 'README.md'), 'utf8');
  const section = readme.indexOf('\n## Quick Start\n');
  if (section === -1) {
    throw new Error('README.md has no `## Quick Start` section');
  }
  const fence = /```ts\r?\n([\s\S]*?)```/.exec(readme.slice(section));
  if (!fence || fence[1].trim() === '') {
    throw new Error('README.md `## Quick Start` section has no non-empty ts block');
  }
  return fence[1];
}

const quickStart = readQuickStart();
const fixtureRoot = mkdtempSync(join(repoRoot, '.signal-csp-smoke-'));
const fixtureDir = join(fixtureRoot, 'consumer');
const fixtureNodeModules = join(fixtureDir, 'node_modules', ...packageNameSegments.slice(0, -1));
const packageInstallDir = join(fixtureDir, 'node_modules', ...packageNameSegments);
let tarballPath = null;

try {
  if (!process.argv.includes('--no-build')) {
    run('npm', ['run', 'build']);
  }

  const packOutput = run('npm', ['pack', '--json', '--cache', '/tmp/npm-cache']);
  const [{ filename }] = JSON.parse(packOutput);
  tarballPath = resolve(repoRoot, filename);

  mkdirSync(fixtureNodeModules, { recursive: true });
  run('tar', ['-xzf', tarballPath, '-C', fixtureNodeModules]);
  renameSync(join(fixtureNodeModules, 'package'), packageInstallDir);

  writeFileSync(
    join(fixtureDir, 'package.json'),
    `${JSON.stringify({ name: 'signal-csp-smoke', private: true, type: 'module' }, null, 2)}\n`
  );
  writeFileSync(join(fixtureDir, 'quickstart.mjs'), quickStart);

  const result = spawnSync(
    process.execPath,
    ['--disallow-code-generation-from-strings', 'quickstart.mjs'],
    {
      cwd: fixtureDir,
      encoding: 'utf8',
      stdio: 'pipe',
      timeout: QUICKSTART_TIMEOUT_MS,
    }
  );
  const output = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();

  // The quick start ends on a live relay subscription, so the process may still
  // be holding handles when the round trip is already done. CI treats the
  // delivered line as the contract; so does this gate.
  if (result.stdout.includes(QUICKSTART_EXPECTED_OUTPUT)) {
    process.stdout.write(`${output}\n`);
    process.stdout.write('smoke-csp:ok quickstart round trip completed without code generation\n');
  } else {
    const cause =
      result.signal !== null
        ? `killed by ${result.signal} after ${QUICKSTART_TIMEOUT_MS} ms`
        : `exited with status ${result.status}`;
    process.stderr.write(`${output}\n`);
    process.stderr.write(
      `smoke-csp:fail quickstart never printed ${JSON.stringify(QUICKSTART_EXPECTED_OUTPUT)} (${cause})\n`
    );
    process.exitCode = 1;
  }
} finally {
  rmSync(fixtureRoot, { recursive: true, force: true });
  if (tarballPath) {
    rmSync(tarballPath, { force: true });
  }
}
