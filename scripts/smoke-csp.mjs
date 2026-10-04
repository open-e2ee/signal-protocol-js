/* Checks packed client cryptography with runtime code generation disabled.
 * The internal checkout also runs its development-relay round trip.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..');
const packageJson = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
const packageNameSegments = packageJson.name.split('/');
const privateRoundTrip = join(scriptDir, 'fixtures', 'local-round-trip.mjs');
const QUICKSTART_EXPECTED_OUTPUT = existsSync(privateRoundTrip) ? 'alice: hello' : 'client crypto: ok';
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

const quickStart = existsSync(privateRoundTrip)
  ? readFileSync(privateRoundTrip, 'utf8')
  : `
import assert from 'node:assert/strict';
import { keys, createDefaultSignalProtocolContentAdapter } from '@open-e2ee/signal-protocol-sdk';
import { deriveGroupSecretParams, encryptBlob, decryptBlob } from '@open-e2ee/signal-protocol-sdk/zk/groups';
const identity = await keys.generateIdentityKeyPair();
assert.equal(Buffer.from(identity.dhKey.publicKey, 'base64').length, 32);
const group = deriveGroupSecretParams(crypto.getRandomValues(new Uint8Array(32)));
const plaintext = new TextEncoder().encode('client crypto');
const ciphertext = encryptBlob(group, crypto.getRandomValues(new Uint8Array(32)), plaintext);
assert.deepEqual(decryptBlob(group, ciphertext), plaintext);
const content = createDefaultSignalProtocolContentAdapter();
assert.ok(content.serializeDataMessage({ body: 'client crypto', timestamp: 1 }).length > 0);
console.log('client crypto: ok');
`;

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

  // CI treats the delivered line as the contract; so does this gate.
  if (result.status === 0 && result.stdout.includes(QUICKSTART_EXPECTED_OUTPUT)) {
    process.stdout.write(`${output}\n`);
    process.stdout.write('smoke-csp:ok packed client operations completed without code generation\n');
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
