/*
 * Builds the bare React Native example's Android release bundle against the
 * packed SDK with the stock `@react-native/babel-preset`, and compiles it with
 * the `hermesc` that React Native pins.
 *
 * The example runs in a copy outside the repository, so the copy has no Hermes
 * gate and bundles only the example's own code. The copy drops its registry SDK
 * pin, installs from the committed lockfile, installs the SDK from the tarball,
 * typechecks the example, and runs `react-native bundle`. A syntax form that
 * the stock preset does not transform stops the bundle here.
 *
 * The bundle's source map names each module that Metro included. The script
 * maps those modules to the package `exports` targets and prints the public
 * entries that the bundle holds. The root entry `.` must be one of them.
 *
 * Usage:
 *   node ./scripts/smoke-react-native-bundle.mjs <packed-package.tgz>
 */

import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { installPackedSdk, removeRegistrySdk, sdkName } from './example-packed-sdk.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..');
const exampleDir = join(repoRoot, 'examples', 'react-native');
const [tarballArgument] = process.argv.slice(2);

if (!tarballArgument) {
  throw new Error('Usage: node scripts/smoke-react-native-bundle.mjs <packed-package.tgz>');
}

const tarballPath = resolve(tarballArgument);
const hermesMagic = 0x1f1903c103bc1fc6n;
const hermesBinaryDirectory = { darwin: 'osx-bin', linux: 'linux64-bin' }[process.platform];

if (!hermesBinaryDirectory) {
  throw new Error(`hermes-compiler ships no hermesc for ${process.platform}.`);
}

const environment = { ...process.env, CI: '1' };

function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, env: environment, encoding: 'utf8', stdio: 'pipe' });
  if (result.status !== 0) {
    const output = [result.stdout, result.stderr].filter(Boolean).join('\n');
    throw new Error(`${command} ${args.join(' ')} failed\n${output}`.trim());
  }
  return result.stdout;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** Returns the package entries whose `exports` target is a module in the bundle. */
function bundledEntries(sdkDir, sourceMap, appDir) {
  const sources = sourceMap.sources ?? sourceMap.sections.flatMap((section) => section.map.sources);
  const bundled = new Set(
    sources.filter((source) => source.includes(sdkName)).map((source) => realpathSync(resolve(appDir, source)))
  );
  const entries = [];
  for (const [entry, target] of Object.entries(readJson(join(sdkDir, 'package.json')).exports)) {
    const file = typeof target === 'string' ? target : target.default;
    if (bundled.has(join(sdkDir, file))) entries.push(entry);
  }
  return entries;
}

const workRoot = mkdtempSync(join(tmpdir(), 'oe-react-native-bundle-'));
try {
  const appDir = join(realpathSync(workRoot), 'app');
  cpSync(exampleDir, appDir, {
    recursive: true,
    filter: (source) => !['node_modules', 'android', 'ios'].includes(basename(source)),
  });

  removeRegistrySdk(appDir);
  run('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], appDir);
  const installed = installPackedSdk(appDir, tarballPath);

  const appRequire = createRequire(join(appDir, 'package.json'));
  const reactNativeManifestPath = appRequire.resolve('react-native/package.json');
  const reactNative = readJson(reactNativeManifestPath);
  const compilerPin = reactNative.dependencies['hermes-compiler'];
  const compilerManifestPath = createRequire(reactNativeManifestPath).resolve('hermes-compiler/package.json');
  const compiler = readJson(compilerManifestPath);
  if (compiler.version !== compilerPin) {
    throw new Error(`react-native ${reactNative.version} pins hermes-compiler ${compilerPin}, but ${compiler.version} resolved.`);
  }
  const hermesc = join(dirname(compilerManifestPath), 'hermesc', hermesBinaryDirectory, 'hermesc');
  const bytecodeMatch = /HBC bytecode version: (\d+)/.exec(run(hermesc, ['-version'], appDir));
  if (!bytecodeMatch) throw new Error(`${hermesc} -version did not report a bytecode version.`);
  const bytecodeVersion = Number(bytecodeMatch[1]);

  run('npx', ['tsc', '--noEmit'], appDir);
  const bundlePath = join(appDir, 'index.android.bundle');
  const sourceMapPath = `${bundlePath}.map`;
  run(
    'npx',
    [
      'react-native',
      'bundle',
      '--platform',
      'android',
      '--dev',
      'false',
      '--entry-file',
      'index.js',
      '--bundle-output',
      bundlePath,
      '--sourcemap-output',
      sourceMapPath,
    ],
    appDir
  );

  const bytecodePath = join(appDir, 'index.android.hbc');
  run(hermesc, ['-emit-binary', '-O', '-out', bytecodePath, bundlePath], appDir);
  const header = readFileSync(bytecodePath).subarray(0, 12);
  const magic = header.readBigUInt64LE(0);
  const version = header.readUInt32LE(8);
  if (magic !== hermesMagic || version !== bytecodeVersion) {
    throw new Error(
      `index.android.hbc has magic 0x${magic.toString(16)} and bytecode version ${version}; ` +
        `hermes-compiler ${compiler.version} writes bytecode version ${bytecodeVersion}.`
    );
  }

  const sdkDir = realpathSync(dirname(appRequire.resolve(`${sdkName}/package.json`)));
  const entries = bundledEntries(sdkDir, readJson(sourceMapPath), appDir);
  if (!entries.includes('.')) {
    throw new Error(`The bundle does not hold the root entry \`.\`. It holds: ${entries.join(', ') || 'no entry'}.`);
  }

  console.log(
    `PASS bare React Native: react-native ${reactNative.version}, SDK ${installed.version} from the tarball, ` +
      `hermes-compiler ${compiler.version}, index.android.hbc is Hermes bytecode version ${version}. ` +
      `The bundle holds ${entries.length} public entries: ${entries.join(', ')}.`
  );
} finally {
  rmSync(workRoot, { recursive: true, force: true });
}
