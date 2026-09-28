/*
 * Checks the bare React Native example's dependency set.
 *
 * The example proves that the SDK runs in a React Native app with no Expo
 * module, so its lockfile must hold no Expo package, not even a transitive
 * one. Each direct dependency pins an exact version, and each one carries an
 * MIT, Apache-2.0, or BSD license.
 *
 * Usage:
 *   node ./scripts/verify-bare-react-native-example.mjs
 */

import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const exampleDir = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'examples', 'react-native');
const EXPO_PACKAGE = /^(?:expo|expo-.+|@expo\/.+|babel-preset-expo|jest-expo)$/;
const EXACT_VERSION = /^\d+\.\d+\.\d+$/;
const ALLOWED_LICENSES = new Set(['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause']);

const readJson = (name) => JSON.parse(readFileSync(join(exampleDir, name), 'utf8'));
const manifest = readJson('package.json');
const lock = readJson('package-lock.json');
const problems = [];

const lockedNames = Object.keys(lock.packages)
  .filter((path) => path !== '')
  .map((path) => path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length));
for (const name of new Set(lockedNames)) {
  if (EXPO_PACKAGE.test(name)) problems.push(`package-lock.json holds the Expo package ${name}`);
}

const direct = { ...manifest.dependencies, ...manifest.devDependencies };
for (const [name, range] of Object.entries(direct)) {
  if (!EXACT_VERSION.test(range)) problems.push(`package.json pins ${name} as ${range}, not an exact version`);
  const locked = lock.packages[`node_modules/${name}`];
  if (locked?.version !== range) problems.push(`package-lock.json has ${name}@${locked?.version}, package.json pins ${range}`);
  // An SPDX `A OR B` expression lets the user choose, so one allowed choice is enough.
  const choices = String(locked?.license).replace(/^\((.*)\)$/, '$1').split(' OR ');
  if (!choices.some((license) => ALLOWED_LICENSES.has(license))) {
    problems.push(`${name} has the license ${locked?.license}`);
  }
}

if (problems.length > 0) throw new Error(`The bare React Native example failed its dependency check:\n${problems.join('\n')}`);
console.log(
  `PASS: the bare React Native example locks ${lockedNames.length} packages with no Expo package, ` +
    `and its ${Object.keys(direct).length} direct dependencies pin exact versions with allowed licenses.`
);
