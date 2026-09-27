/*
 * Installs an example app with a packed SDK tarball in place of the registry
 * version that the example pins.
 *
 * Release preparation pins the examples to the version that is about to
 * publish, so the registry does not have that version until the publish runs.
 * For this reason, the pin leaves the manifest and the lockfile before the
 * dependency install, and the tarball installs after it. Every other package
 * still comes from the committed lockfile.
 *
 * Usage (installs from the committed lockfile):
 *   node ./scripts/example-packed-sdk.mjs <example-dir> <packed-package.tgz>
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const sdkName = '@open-e2ee/signal-protocol-sdk';

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function npm(args, cwd) {
  const result = spawnSync('npm', args, { cwd, encoding: 'utf8', stdio: 'pipe' });
  if (result.status !== 0) {
    const output = [result.stdout, result.stderr].filter(Boolean).join('\n');
    throw new Error(`npm ${args.join(' ')} failed\n${output}`.trim());
  }
}

/** Removes the registry SDK pin from the app's manifest and, when present, its lockfile. */
export function removeRegistrySdk(appDir) {
  const manifestPath = join(appDir, 'package.json');
  const manifest = readJson(manifestPath);
  delete manifest.dependencies?.[sdkName];
  writeJson(manifestPath, manifest);

  const lockPath = join(appDir, 'package-lock.json');
  if (!existsSync(lockPath)) return;
  const lock = readJson(lockPath);
  delete lock.packages[''].dependencies?.[sdkName];
  delete lock.packages[`node_modules/${sdkName}`];
  writeJson(lockPath, lock);
}

/** Installs the tarball without saving it, and returns the installed lock entry after an integrity check. */
export function installPackedSdk(appDir, tarballPath) {
  npm(['install', '--no-save', '--ignore-scripts', '--no-audit', '--no-fund', tarballPath], appDir);

  const installed = readJson(join(appDir, 'node_modules', '.package-lock.json')).packages[`node_modules/${sdkName}`];
  const tarballIntegrity = `sha512-${createHash('sha512').update(readFileSync(tarballPath)).digest('base64')}`;
  if (installed?.integrity !== tarballIntegrity) {
    throw new Error(`The example did not install the SDK from ${tarballPath}: ${JSON.stringify(installed)}`);
  }
  return installed;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [appArgument, tarballArgument] = process.argv.slice(2);
  if (!appArgument || !tarballArgument) {
    throw new Error('Usage: node scripts/example-packed-sdk.mjs <example-dir> <packed-package.tgz>');
  }
  const appDir = resolve(appArgument);
  const tarballPath = resolve(tarballArgument);
  removeRegistrySdk(appDir);
  npm(['ci', '--ignore-scripts', '--no-audit', '--no-fund'], appDir);
  const installed = installPackedSdk(appDir, tarballPath);
  console.log(`Installed ${sdkName}@${installed.version} from ${tarballPath} into ${appDir}.`);
}
