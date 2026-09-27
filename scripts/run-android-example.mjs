/*
 * Installs the Expo example's release APK on a running Android emulator, runs
 * it twice, and checks the logcat output of each run.
 *
 * The app starts an encrypted exchange on launch and logs each step through
 * console.log, which React Native writes to logcat under the ReactNativeJS tag.
 * The first run must create Alice in SQLCipher and complete the exchange on
 * Hermes. The script then stops the process and launches the app again. The
 * second run must resume the stored Alice identity and complete another
 * exchange.
 *
 * Usage:
 *   node ./scripts/run-android-example.mjs <app-release.apk> <logcat-output.txt>
 */

import { spawn, spawnSync } from 'node:child_process';
import { appendFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const [apkArgument, logArgument] = process.argv.slice(2);

if (!apkArgument || !logArgument) {
  throw new Error('Usage: node scripts/run-android-example.mjs <app-release.apk> <logcat-output.txt>');
}

const apkPath = resolve(apkArgument);
const logPath = resolve(logArgument);
const applicationId = 'dev.opene2ee.exchange';
const runTimeoutMs = 5 * 60 * 1000;
const passLine = 'PASS: both devices decrypted the expected messages.';

const runs = [
  {
    name: 'first launch',
    required: [
      /Hermes: true/,
      /Build: release/,
      /SQLCipher \d+\.\d+\.\d+/,
      /Create the first persistent Alice identity\./,
      /alice decrypted: Received: hello from Hermes/,
      new RegExp(passLine.replace(/\./g, '\\.')),
    ],
  },
  {
    name: 'relaunch after the process stops',
    required: [
      /Hermes: true/,
      /Resumed Alice identity after 1 completed exchanges\./,
      /alice decrypted: Received: hello from Hermes/,
      new RegExp(passLine.replace(/\./g, '\\.')),
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

async function launchAndWait(run) {
  adb(['logcat', '-c']);
  const stream = streamLog();
  try {
    adb(['shell', 'am', 'start', '-W', '-n', `${applicationId}/.MainActivity`]);

    const deadline = Date.now() + runTimeoutMs;
    while (Date.now() < deadline) {
      await sleep(2000);
      if (stream.log.includes(passLine) || /FAIL: |FATAL EXCEPTION/.test(stream.log)) break;
    }
  } finally {
    stream.stop();
  }
  const { log } = stream;
  appendFileSync(logPath, `===== ${run.name} =====\n${log}\n`);

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
adb(['shell', 'am', 'force-stop', applicationId]);
await launchAndWait(runs[1]);

console.log(`PASS: the release build completed both runs. The logcat output is in ${logPath}.`);
