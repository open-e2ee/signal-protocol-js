/*
 * Builds the Expo example's Android release bundle against the packed SDK, and
 * checks that the Hermes bytecode comes from the compiler that React Native
 * pins.
 *
 * The example runs in a copy outside the repository. The copy drops its
 * registry SDK pin first, because a release pins a version that is not yet on
 * the registry. On the Expo line that the example pins, the copy then installs
 * from the committed lockfile. On another line in react-native-hosts.mjs, the
 * copy takes that line's module versions and resolves a new tree. Both then
 * install the SDK from the tarball, typecheck the example, and run
 * `expo export --platform android`.
 *
 * The example's committed Drizzle migrations must build the store schema that
 * the tarball ships. `drizzle-kit generate` in the copy must find no change.
 *
 * Expo compiles the Metro bundle with the `hermesc` from the `hermes-compiler`
 * package that `react-native` depends on. This script reads that pin, runs the
 * same binary for its bytecode version, and requires the exported .hbc header
 * to carry the Hermes magic and that version.
 *
 * Usage:
 *   node ./scripts/smoke-expo-bundle.mjs <packed-package.tgz> <expo-sdk-major>
 */

import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { installPackedSdk, removeRegistrySdk } from './example-packed-sdk.mjs';
import { expoLines } from './react-native-hosts.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..');
const exampleDir = join(repoRoot, 'examples', 'expo');
const [tarballArgument, lineArgument] = process.argv.slice(2);

if (!tarballArgument || !expoLines[lineArgument]) {
  throw new Error(
    `Usage: node scripts/smoke-expo-bundle.mjs <packed-package.tgz> <${Object.keys(expoLines).join('|')}>`
  );
}

const tarballPath = resolve(tarballArgument);
const line = expoLines[lineArgument];
const hermesMagic = 0x1f1903c103bc1fc6n;
const hermesBinaryDirectory = { darwin: 'osx-bin', linux: 'linux64-bin' }[process.platform];

if (!hermesBinaryDirectory) {
  throw new Error(`hermes-compiler ships no hermesc for ${process.platform}.`);
}

const environment = { ...process.env, CI: '1', EXPO_NO_TELEMETRY: '1' };
// Expo prefers this directory over hermes-compiler. The check is about the pinned compiler.
delete environment.REACT_NATIVE_OVERRIDE_HERMES_DIR;

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

function examplePinsLine(dependencies) {
  return dependencies.expo === line.expo;
}

const workRoot = mkdtempSync(join(tmpdir(), 'oe-expo-bundle-'));
try {
  const appDir = join(workRoot, 'app');
  cpSync(exampleDir, appDir, {
    recursive: true,
    filter: (source) => !['node_modules', '.expo', 'dist', 'android', 'ios'].includes(basename(source)),
  });

  removeRegistrySdk(appDir);
  const manifestPath = join(appDir, 'package.json');
  const manifest = readJson(manifestPath);
  if (examplePinsLine(manifest.dependencies)) {
    for (const [name, version] of Object.entries(line)) {
      if (name in manifest.dependencies && manifest.dependencies[name] !== version) {
        throw new Error(
          `examples/expo pins ${name}@${manifest.dependencies[name]}, but react-native-hosts.mjs lists ${version} for Expo SDK ${lineArgument}.`
        );
      }
    }
    run('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], appDir);
  } else {
    for (const name of Object.keys(manifest.dependencies)) {
      if (name in line) manifest.dependencies[name] = line[name];
    }
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    rmSync(join(appDir, 'package-lock.json'));
    run('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund'], appDir);
  }
  const installed = installPackedSdk(appDir, tarballPath);

  // drizzle-kit exits 0 when it stops at a rename prompt, so only its
  // no-change message counts as a pass.
  const generate = spawnSync('npx', ['drizzle-kit', 'generate'], { cwd: appDir, env: environment, encoding: 'utf8' });
  const generateOutput = [generate.stdout, generate.stderr].filter(Boolean).join('\n');
  if (generate.status !== 0 || !generateOutput.includes('No schema changes')) {
    throw new Error(
      'The examples/expo migrations do not build the schema of the packed SDK. ' +
        `Run \`npm run db:generate\` in examples/expo.\n${generateOutput}`.trim()
    );
  }

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
  run('npx', ['expo', 'export', '--platform', 'android', '--output-dir', 'dist'], appDir);

  const bundleDir = join(appDir, 'dist', '_expo', 'static', 'js', 'android');
  const bundles = readdirSync(bundleDir);
  if (bundles.length !== 1 || !bundles[0].endsWith('.hbc')) {
    throw new Error(`Expected one Hermes bundle in ${bundleDir}, found: ${bundles.join(', ') || 'nothing'}`);
  }
  const header = readFileSync(join(bundleDir, bundles[0])).subarray(0, 12);
  const magic = header.readBigUInt64LE(0);
  const version = header.readUInt32LE(8);
  if (magic !== hermesMagic || version !== bytecodeVersion) {
    throw new Error(
      `${bundles[0]} has magic 0x${magic.toString(16)} and bytecode version ${version}; ` +
        `hermes-compiler ${compiler.version} writes bytecode version ${bytecodeVersion}.`
    );
  }

  console.log(
    `PASS Expo SDK ${lineArgument}: expo ${appRequire('expo/package.json').version}, react-native ${reactNative.version}, ` +
      `SDK ${installed.version} from the tarball, hermes-compiler ${compiler.version}, ` +
      `${bundles[0]} is Hermes bytecode version ${version}.`
  );
} finally {
  rmSync(workRoot, { recursive: true, force: true });
}
