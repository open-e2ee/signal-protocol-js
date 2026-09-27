/*
 * Adds the packed SDK to React Native and Expo host projects the way an
 * application developer adds it, and fails if npm refuses the peer ranges.
 *
 * npm treats an optional peer as a constraint once the host installs the peer.
 * A whole-tree `npm install` only warns about a mismatch, but
 * `npm install <sdk>` into an existing project stops with ERESOLVE. So each
 * host first writes its own lockfile, then adds the tarball as a second step,
 * without `--force` or `--legacy-peer-deps`.
 *
 * The host lines are in react-native-hosts.mjs. A peer range edit that
 * excludes one of them fails here. The below-the-floor host must
 * fail with ERESOLVE. It proves that this check can see a peer conflict.
 *
 * Usage:
 *   node ./scripts/smoke-react-native-install.mjs <packed-package.tgz>
 */

import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { installHosts as hosts } from './react-native-hosts.mjs';

const tarballArgument = process.argv[2];

if (!tarballArgument) {
  throw new Error('Usage: node scripts/smoke-react-native-install.mjs <packed-package.tgz>');
}

const tarballPath = resolve(tarballArgument);

// A user or CI .npmrc must not relax peer resolution for this check.
const npmEnvironment = {
  ...process.env,
  npm_config_force: 'false',
  npm_config_legacy_peer_deps: 'false',
  npm_config_strict_peer_deps: 'false',
  npm_config_audit: 'false',
  npm_config_fund: 'false',
  npm_config_update_notifier: 'false',
};

function npm(args, cwd) {
  return new Promise((resolvePromise) => {
    const child = spawn('npm', args, { cwd, env: npmEnvironment, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', (chunk) => { output += chunk; });
    child.stderr.on('data', (chunk) => { output += chunk; });
    child.on('close', (status) => resolvePromise({ status, output }));
  });
}

async function checkHost(host, workRoot, index) {
  const directory = join(workRoot, `host-${index}`);
  mkdirSync(directory);
  writeFileSync(
    join(directory, 'package.json'),
    `${JSON.stringify({ name: `host-${index}`, private: true, dependencies: host.dependencies }, null, 2)}\n`
  );

  const lock = await npm(['install', '--package-lock-only', '--ignore-scripts'], directory);
  if (lock.status !== 0) {
    return { host, ok: false, detail: `the host project did not resolve without the SDK\n${lock.output}` };
  }

  const add = await npm(['install', '--package-lock-only', '--ignore-scripts', tarballPath], directory);
  if (host.expectConflict) {
    const conflict =
      add.status !== 0 &&
      add.output.includes('ERESOLVE') &&
      add.output.includes(`peerOptional ${host.expectConflict}@`);
    return {
      host,
      ok: conflict,
      detail: conflict
        ? `refused as expected: ${host.expectConflict} is outside the peer range`
        : `expected ERESOLVE on ${host.expectConflict}, got exit ${add.status}\n${add.output}`,
    };
  }
  if (add.status !== 0 || add.output.includes('ERESOLVE')) {
    return { host, ok: false, detail: `npm refused the SDK (exit ${add.status})\n${add.output}` };
  }
  return { host, ok: true, detail: 'resolved' };
}

async function runAll(workRoot) {
  const results = new Array(hosts.length);
  let next = 0;
  // npm spends most of each resolution waiting on the registry, so run a few at once.
  async function worker() {
    while (next < hosts.length) {
      const index = next++;
      results[index] = await checkHost(hosts[index], workRoot, index);
    }
  }
  await Promise.all(Array.from({ length: 3 }, worker));
  return results;
}

const npmVersion = spawnSync('npm', ['--version'], { encoding: 'utf8' }).stdout.trim();
console.log(`npm ${npmVersion}, SDK ${tarballPath}`);

const workRoot = mkdtempSync(join(tmpdir(), 'oe-react-native-install-'));
try {
  const results = await runAll(workRoot);
  for (const { host, ok, detail } of results) {
    console.log(`${ok ? 'PASS' : 'FAIL'} ${host.name}: ${detail}`);
  }
  const failed = results.filter((result) => !result.ok);
  if (failed.length > 0) {
    console.error(`${failed.length} of ${results.length} host lines failed.`);
    process.exitCode = 1;
  } else {
    console.log(`All ${results.length} host lines behaved as expected.`);
  }
} finally {
  rmSync(workRoot, { recursive: true, force: true });
}
