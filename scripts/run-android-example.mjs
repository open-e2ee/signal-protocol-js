/*
 * Installs an example's release APK on a running Android emulator, runs it
 * twice, and checks the logcat output of each run.
 *
 * The app starts an encrypted exchange on launch and logs each step through
 * console.log, which React Native writes to logcat under the ReactNativeJS tag.
 * The first run must create Alice in the example's storage and complete the
 * exchange on Hermes. The script then stops the process and launches the app
 * again. The second run must resume the stored Alice identity and complete
 * another exchange.
 *
 * The Expo app opens `expoStore()`, and the bare React Native app opens
 * `reactNativeStore()`, each with the default encryption. Each run must also
 * log a SQLCipher version and the first 16 bytes of the SDK database file.
 * The script requires that these bytes are not the plaintext SQLite header.
 * The version shows only that the app has the SQLCipher build, because
 * SQLCipher reports it also with no key. The header shows that SQLCipher
 * encrypted the file.
 *
 * The bare React Native example also requires that a wrong key fails the
 * open of an SDK database and, in a checkout that has the Hermes gate, runs
 * each gate flow. Each run must log a `CASE PASS` line for every step in the
 * gate manifest. The script compares the app's global names with the gate
 * prelude and prints each difference.
 *
 * Usage:
 *   node ./scripts/run-android-example.mjs <expo|react-native> <app-release.apk> <logcat-output.txt>
 */

import { spawn, spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';

const [exampleArgument, apkArgument, logArgument] = process.argv.slice(2);
const usage = 'Usage: node scripts/run-android-example.mjs <expo|react-native> <app-release.apk> <logcat-output.txt>';

const passLine = 'PASS: both devices decrypted the expected messages.';
const exactly = (line) => new RegExp(line.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
const plaintextHeader = Buffer.from('SQLite format 3\0').toString('hex');
const gateRoot = join(dirname(fileURLToPath(import.meta.url)), '..', 'hermes-tests');

/** The lines that a React Native example logs on each run of the gate flows. */
async function gateLines() {
  const manifest = join(gateRoot, 'flows.mjs');
  if (!existsSync(manifest)) return [exactly('The Hermes gate flows run only in the private repository.')];
  const { flows } = await import(pathToFileURL(manifest).href);
  const steps = flows.flatMap((flow) => flow.steps.map((step) => `CASE PASS ${flow.name}: ${step}`));
  if (steps.length === 0) throw new Error('The gate manifest names no flow steps.');
  return [...steps.map(exactly), exactly(`Gate flows: ${steps.length} cases passed in ${flows.length} flows.`)];
}

/** The lines that show that SQLCipher encrypts the SDK database. */
const encryptedAtRest = [
  /SQLCipher version: \d+\.\d+/,
  new RegExp(`SDK database header: (?!${plaintextHeader})[0-9a-f]{32}(?![0-9a-f])`),
];

const examples = {
  expo: async () => ({
    applicationId: 'dev.opene2ee.exchange',
    runTimeoutMs: 5 * 60 * 1000,
    every: encryptedAtRest,
  }),
  'react-native': async () => ({
    applicationId: 'dev.opene2ee.bare',
    runTimeoutMs: 10 * 60 * 1000,
    every: [
      /Global names: \d+/,
      ...encryptedAtRest,
      exactly('Wrong key: the open failed with SqliteKeyMismatchError (KEY_STORAGE_ERROR).'),
      ...(await gateLines()),
    ],
  }),
};

if (!Object.hasOwn(examples, exampleArgument) || !apkArgument || !logArgument) throw new Error(usage);

const example = await examples[exampleArgument]();
const apkPath = resolve(apkArgument);
const logPath = resolve(logArgument);

const runs = [
  {
    name: 'first launch',
    required: [
      /Hermes: true/,
      /Build: release/,
      ...example.every,
      /Create the first persistent Alice identity\./,
      /alice decrypted: Received: hello from Hermes/,
      exactly(passLine),
    ],
  },
  {
    name: 'relaunch after the process stops',
    required: [
      /Hermes: true/,
      ...example.every,
      /Resumed Alice identity after 1 completed exchanges\./,
      /alice decrypted: Received: hello from Hermes/,
      exactly(passLine),
    ],
  },
];

function adb(args) {
  const result = spawnSync('adb', args, { encoding: 'utf8', stdio: 'pipe', maxBuffer: 64 * 1024 * 1024 });
  if (result.status !== 0) {
    const output = [result.stdout, result.stderr].filter(Boolean).join('\n');
    throw new Error(`adb ${args.join(' ')} failed\n${output}`.trim());
  }
  return result.stdout;
}

// A stream, not a `logcat -d` snapshot: the emulator's main buffer is small,
// and other tags can rotate the app's first lines out before the run ends.
function streamLog() {
  const reader = spawn('adb', ['logcat', '-v', 'brief', '-s', 'ReactNativeJS:V', 'AndroidRuntime:E'], {
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const stream = {
    log: '',
    stop: () => {
      reader.stdout.destroy();
      reader.kill();
    },
  };
  reader.stdout.setEncoding('utf8');
  reader.stdout.on('data', (chunk) => {
    stream.log += chunk;
  });
  return stream;
}

// The app logs its global names in parts: `Globals <part>/<parts>: <names>`.
function reportGlobals(run, log) {
  const prelude = join(gateRoot, 'prelude-globals.json');
  const parts = [...log.matchAll(/Globals (\d+)\/(\d+): (.*)$/gm)];
  if (parts.length === 0 || !existsSync(prelude)) return;
  const app = new Set(parts.flatMap((part) => part[3].trim().split(' ')));
  const gate = new Set(JSON.parse(readFileSync(prelude, 'utf8')));
  const onlyApp = [...app].filter((name) => !gate.has(name)).sort();
  const onlyGate = [...gate].filter((name) => !app.has(name)).sort();
  console.log(`${run.name}: ${app.size} app globals, ${gate.size} gate prelude globals.`);
  console.log(`${run.name}: only in the app: ${onlyApp.join(' ') || 'none'}`);
  console.log(`${run.name}: only in the gate prelude: ${onlyGate.join(' ') || 'none'}`);
}

async function launchAndWait(run) {
  adb(['logcat', '-c']);
  const stream = streamLog();
  try {
    adb(['shell', 'am', 'start', '-W', '-n', `${example.applicationId}/.MainActivity`]);

    const deadline = Date.now() + example.runTimeoutMs;
    while (Date.now() < deadline) {
      await sleep(2000);
      if (stream.log.includes(passLine) || /FAIL: |FATAL EXCEPTION/.test(stream.log)) break;
    }
  } finally {
    stream.stop();
  }
  const { log } = stream;
  appendFileSync(logPath, `===== ${run.name} =====\n${log}\n`);
  reportGlobals(run, log);

  const missing = run.required.filter((pattern) => !pattern.test(log));
  if (missing.length > 0) {
    throw new Error(
      `The ${run.name} did not log ${missing.map(String).join(', ')}.\n${log}`
    );
  }
  for (const pattern of run.required) {
    console.log(`${run.name}: ${log.split('\n').find((line) => pattern.test(line)).trim()}`);
  }
}

writeFileSync(logPath, '');
adb(['wait-for-device']);
adb(['install', '-r', apkPath]);

await launchAndWait(runs[0]);
adb(['shell', 'am', 'force-stop', example.applicationId]);
await launchAndWait(runs[1]);

console.log(`PASS: the release build completed both runs. The logcat output is in ${logPath}.`);
