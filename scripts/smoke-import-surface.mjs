/*
 * Imports every published export subpath the way a consumer who installed none
 * of the optional peer dependencies imports it.
 *
 * The gap this closes: an entry point can name an optional peer in a static
 * `import` and still pass every other check. `peerDependenciesMeta` marks
 * `react-native`, the `expo-*` packages, `convex`, `idb` and the rest optional,
 * so the package's own contract says a consumer may have none of them — but a
 * static import of an absent package does not degrade, it throws
 * `ERR_MODULE_NOT_FOUND` before a single line of the module runs. The whole
 * entry point becomes unimportable, and nothing else notices. The checks that
 * do name every subpath resolve types rather than load modules, and type
 * resolution never evaluates a module, so a missing runtime package is
 * invisible to them. The checks that do load modules run from inside the
 * repository, where the optional peers are installed as devDependencies and
 * Node's resolver — which walks up from the importing file, not from the entry
 * script — finds every one of them.
 *
 * So this script runs from a temp directory outside the repo, with a
 * node_modules mirrored from the repo's own minus every optional peer. The
 * exclusion set is derived from `peerDependenciesMeta`, not hand-maintained, so
 * a newly optional peer is covered the day it is declared.
 *
 * The allowlist below names the entry points that are honestly platform-bound.
 * It is checked in both directions: an entry that fails without being
 * allowlisted is a defect, and an allowlisted entry that succeeds is a stale
 * allowlist line. The second half is what stops this list from quietly growing
 * into the thing it was meant to prevent.
 *
 * Usage:
 *   node ./scripts/smoke-import-surface.mjs             # build, pack, probe
 *   node ./scripts/smoke-import-surface.mjs --no-build  # reuse an existing dist/
 */

import { spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..');
const packageJson = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));

/**
 * Entry points that cannot load without an optional peer, and should not.
 *
 * Each line is a platform or vendor binding: the module's whole purpose is to
 * adapt this package to that host, so a consumer who has not installed the host
 * has no reason to import it. Anything that is protocol surface belongs on the
 * other side of this list — if a cryptographic or wire-format module ends up
 * here, that is the defect, not the fix.
 */
const PLATFORM_BOUND = new Map([
  ['./convex.config', 'convex — Convex component definition, loaded by the Convex CLI'],
  ['./remote/relay/convex', 'convex — Convex-backed relay adapter'],
  ['./remote/relay/convex/relay', 'convex — Convex-backed relay adapter'],
  ['./remote/object-store/convex-r2/server', '@convex-dev/r2 — Convex R2 server half'],
  ['./hooks', 'react — React hooks, unusable without a renderer'],
  ['./hooks/use-connection-presence', 'react — React hook, unusable without a renderer'],
  ['./local/store/expo', 'expo-sqlite — Expo SQLite-backed store'],
  ['./local/store/expo/db', 'expo-sqlite — Expo SQLite handle'],
  ['./local/store/expo/schema', 'expo-sqlite — Expo SQLite schema'],
  ['./local/store/react-native', 'react-native — React Native store adapter'],
  ['./local/store/web', 'idb — IndexedDB-backed store'],
  ['./local/vault/expo-secure-store', 'expo-secure-store — Expo SecureStore vault'],
  ['./device/expo-metadata', 'react-native, expo-constants — reads the local platform'],
]);

/**
 * Entry points that are platform-bound by accident, and have an owner.
 *
 * These are not exemptions on the merits. Each one is protocol or host surface
 * that a non-Expo consumer has a legitimate reason to import and currently
 * cannot, and each is written up in the maintainers' findings index. They are
 * separated from PLATFORM_BOUND so that the difference between "this belongs to
 * a platform" and "we have not fixed this yet" survives in the file rather than
 * in someone's memory.
 */
const KNOWN_DEFECTS = new Map([
  [
    './device',
    'react-native, expo-constants, expo-secure-store, expo-device — three ' +
      'independent bindings, not one: the barrel re-exports ./transfer ' +
      '(device/index.ts:40), ./device-id (:115) and ./lifecycle (:128), and each ' +
      'reaches a platform on its own. Fixing any one of them leaves the barrel ' +
      'unimportable; only the last of the three lets this line go',
  ],
  [
    './device/device-id',
    'expo-secure-store — the device-ID cache reads Expo SecureStore directly ' +
      'instead of taking an injected vault',
  ],
  [
    './device/lifecycle',
    'expo-device, react-native, react-native-device-info — DeviceLifecycleManager ' +
      'names and registers devices from platform APIs throughout',
  ],
]);

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

/** Every peer the package itself says a consumer may skip. */
function optionalPeers() {
  const meta = packageJson.peerDependenciesMeta ?? {};
  return new Set(
    Object.entries(meta)
      .filter(([, value]) => value?.optional === true)
      .map(([name]) => name)
  );
}

/**
 * Mirror the repo's installed packages into the fixture, minus the optional
 * peers, so the probe resolves real dependencies but cannot reach the ones a
 * consumer would not have. Symlinks rather than copies: this runs on every CI
 * job and the tree is large.
 */
function mirrorNodeModules(sourceDir, targetDir, excluded) {
  mkdirSync(targetDir, { recursive: true });
  for (const entry of readdirSync(sourceDir, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;

    if (entry.name.startsWith('@')) {
      const scope = entry.name;
      const scopeSource = join(sourceDir, scope);
      const scopedExclusions = [...excluded].filter((name) => name.startsWith(`${scope}/`));
      if (scopedExclusions.length === 0) {
        symlinkSync(scopeSource, join(targetDir, scope), 'dir');
        continue;
      }
      /* Something inside this scope is excluded, so the scope directory has to
       * be rebuilt package by package rather than linked whole. */
      mirrorNodeModules(scopeSource, join(targetDir, scope), new Set(
        scopedExclusions.map((name) => name.slice(scope.length + 1))
      ));
      continue;
    }

    if (excluded.has(entry.name)) continue;
    symlinkSync(join(sourceDir, entry.name), join(targetDir, entry.name), 'dir');
  }
}

/*
 * Development-only entry points are dropped from the export map when the
 * package is published, so nothing a consumer installs can reach them and their
 * imports are not part of the surface this check defends. They are the one
 * place a platform peer may be imported statically without answering for it.
 */
const isDevelopmentOnly = (subpath) => subpath.endsWith('/testing');

const subpaths = Object.keys(packageJson.exports).filter(
  (key) => key !== './package.json' && !isDevelopmentOnly(key)
);
const specifierFor = (subpath) =>
  subpath === '.' ? packageJson.name : `${packageJson.name}/${subpath.slice(2)}`;

const excluded = optionalPeers();
const fixtureRoot = mkdtempSync(join(tmpdir(), 'oe-import-surface-'));
const fixtureDir = join(fixtureRoot, 'consumer');
const nameSegments = packageJson.name.split('/');
const fixtureNodeModules = join(fixtureDir, 'node_modules');
const scopeDir = join(fixtureNodeModules, ...nameSegments.slice(0, -1));
let tarballPath = null;

try {
  if (!process.argv.includes('--no-build')) {
    run('npm', ['run', 'build']);
  }

  const packOutput = run('npm', ['pack', '--json', '--cache', '/tmp/npm-cache']);
  const [{ filename }] = JSON.parse(packOutput);
  tarballPath = resolve(repoRoot, filename);

  mirrorNodeModules(join(repoRoot, 'node_modules'), fixtureNodeModules, excluded);
  mkdirSync(scopeDir, { recursive: true });
  run('tar', ['-xzf', tarballPath, '-C', scopeDir]);
  renameSync(join(scopeDir, 'package'), join(fixtureNodeModules, ...nameSegments));

  writeFileSync(
    join(fixtureDir, 'package.json'),
    JSON.stringify({ name: 'oe-import-surface', private: true, type: 'module' }, null, 2) + '\n'
  );

  /*
   * One import per line of NDJSON, flushed synchronously as each one settles.
   * A module that crashes the process on load rather than rejecting would
   * otherwise take the whole report with it; this way the last line written
   * names the entry before the one that died.
   */
  writeFileSync(
    join(fixtureDir, 'probe.mjs'),
    `import { writeFileSync } from 'node:fs';

const specifiers = ${JSON.stringify(subpaths.map((subpath) => [subpath, specifierFor(subpath)]), null, 2)};

for (const [subpath, specifier] of specifiers) {
  let record;
  try {
    await import(specifier);
    record = { subpath, ok: true };
  } catch (error) {
    record = {
      subpath,
      ok: false,
      code: error?.code ?? null,
      message: error instanceof Error ? error.message.split('\\n')[0] : String(error),
    };
  }
  writeFileSync(1, JSON.stringify(record) + '\\n');
}
`
  );

  const probe = spawnSync(process.execPath, ['probe.mjs'], {
    cwd: fixtureDir,
    encoding: 'utf8',
    stdio: 'pipe',
  });

  const results = probe.stdout
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line));

  const reached = new Set(results.map((result) => result.subpath));
  const missing = subpaths.filter((subpath) => !reached.has(subpath));
  if (missing.length > 0) {
    const output = [probe.stdout, probe.stderr].filter(Boolean).join('\n');
    throw new Error(
      `The probe stopped before reporting on ${missing.length} entry point(s), starting at ` +
        `${missing[0]}. A module that kills the process on import is itself the defect.\n${output}`
    );
  }

  const failures = [];
  const stale = [];
  for (const result of results) {
    const exempted = PLATFORM_BOUND.has(result.subpath) || KNOWN_DEFECTS.has(result.subpath);
    if (!result.ok && !exempted) {
      failures.push(result);
    } else if (result.ok && exempted) {
      stale.push(result.subpath);
    }
  }

  const problems = [];
  if (failures.length > 0) {
    problems.push(
      `${failures.length} export subpath(s) cannot be imported without an optional peer ` +
        `dependency:\n` +
        failures
          .map((f) => `  - ${specifierFor(f.subpath)}\n      ${f.code ?? 'error'}: ${f.message}`)
          .join('\n') +
        `\n\n  A published entry point must load with only the required dependencies ` +
        `installed. Move the platform-bound part to its own subpath, or — if the entry ` +
        `genuinely belongs to a platform — add it to PLATFORM_BOUND in this script with ` +
        `the peer it needs and why.`
    );
  }
  if (stale.length > 0) {
    problems.push(
      `${stale.length} entry point(s) are exempted in this script but import cleanly ` +
        `without their peer:\n` +
        stale
          .map((subpath) => {
            const list = KNOWN_DEFECTS.has(subpath) ? 'KNOWN_DEFECTS' : 'PLATFORM_BOUND';
            return `  - ${specifierFor(subpath)} (${list})`;
          })
          .join('\n') +
        `\n\n  Remove them; the exemption is no longer true. If a KNOWN_DEFECTS entry ` +
        `was fixed, close its entry in the findings index in the same change.`
    );
  }
  if (problems.length > 0) {
    throw new Error(problems.join('\n\n'));
  }

  const byDesign = results.filter((result) => PLATFORM_BOUND.has(result.subpath)).length;
  const deferred = results.filter((result) => KNOWN_DEFECTS.has(result.subpath)).length;
  console.log(
    `Import surface: ${results.length - byDesign - deferred} of ${results.length} export ` +
      `subpaths load with no optional peer dependency installed; ${byDesign} are ` +
      `platform-bound by design; ${deferred} are known defects with findings entries.`
  );
} finally {
  rmSync(fixtureRoot, { recursive: true, force: true });
  if (tarballPath) {
    rmSync(tarballPath, { force: true });
  }
}
